import fs from "node:fs";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type * as x509Types from "@peculiar/x509";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  POST as planPost,
  setCorePlanHandlerForTests,
  setPlanGenAIClientForTests,
} from "@/app/api/gemini/plan/route";
import * as geminiRouteModule from "@/app/api/gemini/route";
import { POST as relayHopAttestationPost } from "@/app/api/relay/[relayId]/attestation/route";
import { POST as relayAttestationPost } from "@/app/api/relay/attestation/route";
import {
  buildPlainTimelineSteps,
  DEVICE_PREPARATION_PLAIN_SENTENCE,
  findForbiddenPlainTerms,
  formatEgressReceiptDisplay,
  formatPlainDataHandling,
  resolvePlannerModeBadgeText,
  resolvePlannerSubtitleText,
} from "@/components/argon/argon-helpers";
import {
  assertClosedPlanSchema,
  assertFilterFingerprintAllowsSend,
  buildBrowserRedactedTaskAndDescriptor,
  buildGeminiCreateRequestFromDescriptor,
  clearCorpusCache,
  COMMITTED_CORE_IMAGE_DIGESTS,
  computeCorpusContentSha256,
  FilterFingerprintMismatchError,
  geminiEgressSigningPayload,
  getExpectedCoreImageDigests,
  NEXT_SERVER_RECEIPT_LABEL,
  requestAgentPlanFromBrowser,
  resolveModelAttestationFromMatrix,
  runBrowserAgentWorkflow,
  runBrowserRedactionPipeline,
  SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
  sortCorpusDocuments,
  verifyCoreAttestationForEgressKey,
  verifyEgressReceiptClient,
} from "@/lib/agent-client";
import {
  setFilterFingerprintStatusForTests,
  setFilterFingerprintVerifyOptionsForTests,
} from "@/lib/privacy/fingerprint";
import { MECHANICAL_RULESET } from "@/lib/privacy/mechanical-ruleset";
import { openTinfoilSession } from "@/lib/tinfoil/client";
import { ATLAS_SEED_DOCS } from "@/lib/atlas/knowledge-base";
import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  ensureReflectMetadata,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
} from "@/lib/attestation/confidential-space";
import expectedCoreDigestsJson from "@/lib/attestation/expected-core-digests.json";
import { parseCoreImageDigests } from "@/lib/core-proxy";
import {
  assertContentFree,
  assertGoogleBoundMessage,
  buildTaskDescriptor,
} from "@/lib/gemini/egress-schemas";
import {
  ALLOWED_PLANNER_TOOLS,
  assertOutboundPrivacyInvariant,
  ContentFreeEgressError,
  GEMINI_4_ARGON_MODEL_ID,
  HONEST_DATA_HANDLING_STATEMENT,
  type ClosedAgentPlan,
  type GeminiEgressReceipt,
  type GenAIInteractionsClientLike,
} from "@/lib/gemini/shared";
import {
  attestedPiiFilter,
  clearAttestedPiiFilterCacheForTests,
  setAttestedPiiFilterClientForTests,
  setAttestedPiiSecureClientFactoryForTests,
  TINFOIL_PII_FILTER_CONFIG_REPO,
  TINFOIL_PII_FILTER_ENCLAVE_URL,
} from "@/lib/privacy/attested-filter";
import { canonicalJson, coarsenEpochSecToHour } from "@/lib/transparency/log";
import { resetAnchorRateLimitState } from "@/lib/transparency/store";

const TEST_NOW_SEC = 1_792_886_400;
const TEST_CORE_IMAGE_DIGEST =
  "sha256:82be4787cf95bc8776b1e4c0b91dabfc4e0b6fe967d0200203be7dd0c6c64c86";
const SEALED_SECRET_KEY = new Uint8Array(32).fill(0x42);
const SEALED_PUBLIC_KEY_HEX = bytesToHex(
  ed25519.getPublicKey(SEALED_SECRET_KEY),
).toLowerCase();
const SEALED_TREE_PUBLIC_KEY_HEX = "22".repeat(32);

let coreAttestationFixture: {
  pinnedRootCaPem: string;
  attestationResponseJson: Record<string, unknown>;
};

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(view)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function jsonToBase64Url(obj: unknown): string {
  return bytesToBase64Url(Buffer.from(JSON.stringify(obj), "utf8"));
}

function certToDerBase64(cert: x509Types.X509Certificate): string {
  return Buffer.from(cert.rawData).toString("base64");
}

beforeAll(async () => {
  ensureReflectMetadata();
  const x509 = await import("@peculiar/x509");
  const genRsa = () =>
    globalThis.crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );

  const [rootKeys, interKeys, leafKeys] = await Promise.all([
    genRsa(),
    genRsa(),
    genRsa(),
  ]);
  const notBefore = new Date((TEST_NOW_SEC - 86_400) * 1000);
  const notAfter = new Date((TEST_NOW_SEC + 86_400 * 365) * 1000);
  const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "C=US, O=Google LLC, CN=Test Confidential Space Root CA",
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const interCert = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "C=US, O=Google LLC, CN=Test Confidential Space Intermediate CA",
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: interKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: "03",
    subject: "C=US, O=Google LLC, CN=confidentialcomputing.googleapis.com",
    issuer: interCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: alg,
    publicKey: leafKeys.publicKey,
    signingKey: interKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });

  const tlsKeys = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const tlsCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "10",
    name: "CN=deroute-core.internal",
    notBefore,
    notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: tlsKeys,
  });

  const tlsCertPem = tlsCert.toString("pem");
  const tlsSpkiSha256 = await computeTlsCertSpkiSha256(tlsCertPem);
  const keys = {
    egress: SEALED_PUBLIC_KEY_HEX,
    tree: SEALED_TREE_PUBLIC_KEY_HEX,
  };
  const keysDigest = await computeAttestedKeysDigest(keys);

  const header = {
    alg: "RS256",
    typ: "JWT",
    x5c: [
      certToDerBase64(leafCert),
      certToDerBase64(interCert),
      certToDerBase64(rootCert),
    ],
  };
  const payload = {
    iss: EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
    aud: DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
    iat: TEST_NOW_SEC - 30,
    nbf: TEST_NOW_SEC - 30,
    exp: TEST_NOW_SEC + 3600,
    swname: "CONFIDENTIAL_SPACE",
    swversion: ["261000"],
    dbgstat: "disabled-since-boot",
    secboot: true,
    hwmodel: "GCP_AMD_SEV",
    oemid: 11129,
    eat_nonce: [keysDigest, tlsSpkiSha256],
    submods: {
      confidential_space: {
        support_attributes: ["LATEST", "STABLE", "USABLE"],
        monitoring_enabled: { memory: false },
      },
      container: {
        image_digest: TEST_CORE_IMAGE_DIGEST,
        image_reference: `ghcr.io/thepigdestroyer/deroute-core@${TEST_CORE_IMAGE_DIGEST}`,
        restart_policy: "Always",
        env_override: {
          CORE_KEY_SOURCE: "boot",
          CORE_PUBLIC_ORIGIN: "https://drouter-demo.vercel.app",
        },
      },
    },
  };

  const h = jsonToBase64Url(header);
  const p = jsonToBase64Url(payload);
  const sig = await globalThis.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    leafKeys.privateKey,
    new TextEncoder().encode(`${h}.${p}`),
  );
  const token = `${h}.${p}.${bytesToBase64Url(sig)}`;

  coreAttestationFixture = {
    pinnedRootCaPem: rootCert.toString("pem"),
    attestationResponseJson: {
      token,
      keys,
      keysDigest,
      tlsSpkiSha256,
      tlsCertPem,
      expiresAtSec: TEST_NOW_SEC + 3600,
      refreshedAtSec: TEST_NOW_SEC,
    },
  };
});

afterEach(() => {
  setCorePlanHandlerForTests(null);
  setPlanGenAIClientForTests(null, null);
  setAttestedPiiFilterClientForTests(null);
  setAttestedPiiSecureClientFactoryForTests(null);
  clearAttestedPiiFilterCacheForTests();
  clearCorpusCache();
  resetAnchorRateLimitState();
  setFilterFingerprintStatusForTests(null);
  setFilterFingerprintVerifyOptionsForTests(null);
  vi.restoreAllMocks();
});

function buildMockEnclaveMatrix() {
  const dmVerityRootHash =
    "8b4029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f1a";
  const register0 = `${dmVerityRootHash}980bb51973cdf396404412ebb7c1a7b7`;
  return {
    status: "verified" as const,
    routerHost: "router-0.tinfoil.sh",
    routerReleaseTag: "v0.1.0",
    routerReleaseDigest:
      "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    routerConfigRepo: "tinfoilsh/confidential-model-router",
    routerReleaseUrl:
      "https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.1.0",
    routerSigstoreUrl:
      "https://search.sigstore.dev/?hash=5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    amdKdsUrl: "",
    proxyWellKnownUrl: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    fetchedAt: "2026-10-25T00:00:00.000Z",
    models: {
      "gemma4-31b": {
        modelId: "gemma4-31b",
        status: "router-attested" as const,
        repo: "tinfoilsh/confidential-gemma4-31b",
        tag: "v0.0.12",
        hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tierClassification:
          "Tier B (Intel TDX + 8x Confidential GPU)" as const,
        configuredHosts: 1,
        verifiedHosts: 1,
        healthyHosts: 1,
        unverifiedHosts: 0,
        enclaveHosts: [
          {
            host: "gemma4-31b-inf10.tinfoil.containers.tinfoil.dev",
            hpkeKey:
              "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
            predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
            tlsKeyFp:
              "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
            codeTag: "v0.0.12",
          },
        ],
        measurementRegisters: [register0],
        vmShape: { cpus: 32, memoryMb: 262144, gpus: 8, disks: 1 },
        dmVerityRootHash,
        kernelHash:
          "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff",
        initrdHash:
          "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e7",
        containerImageDigest: `sha256:${dmVerityRootHash}`,
        weightRepoCommit: "tinfoilsh/confidential-gemma4-31b@v0.0.12",
        weightMpkHash: dmVerityRootHash,
        ccGpuFlagsVerified: true,
        releaseUrl:
          "https://github.com/tinfoilsh/confidential-gemma4-31b/releases/tag/v0.0.12",
        sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityRootHash}`,
      },
      "kimi-k3": {
        modelId: "kimi-k3",
        status: "router-attested" as const,
        repo: "tinfoilsh/confidential-kimi-k3",
        tag: "v0.0.15",
        hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tierClassification:
          "Tier B (Intel TDX + 8x Confidential GPU)" as const,
        configuredHosts: 1,
        verifiedHosts: 1,
        healthyHosts: 1,
        unverifiedHosts: 0,
        enclaveHosts: [
          {
            host: "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
            hpkeKey:
              "5df270bc5c4329725ce4a4a37dac06977355db702ee2de3e834803f825ea492d",
            predicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
            tlsKeyFp:
              "6758bad98341283b96ddfe1a7db25b270dc26ae789de9dbb17d66566c9b2aa2d",
            codeTag: "v0.0.15",
          },
        ],
        measurementRegisters: [register0],
        vmShape: { cpus: 32, memoryMb: 262144, gpus: 8, disks: 1 },
        dmVerityRootHash,
        kernelHash:
          "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff",
        initrdHash:
          "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e7",
        containerImageDigest: `sha256:${dmVerityRootHash}`,
        weightRepoCommit: "tinfoilsh/confidential-kimi-k3@v0.0.15",
        weightMpkHash: dmVerityRootHash,
        ccGpuFlagsVerified: true,
        releaseUrl:
          "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
        sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityRootHash}`,
      },
    },
  };
}

function buildMockCorpusResponse() {
  const docs = sortCorpusDocuments(
    ATLAS_SEED_DOCS.map((seed) => ({
      title: seed.title,
      summary: seed.summary,
      tags: [...seed.tags],
      sourceUrl: seed.sourceUrl,
      retrievedAt: seed.retrievedAt,
      embedding: [...seed.embedding],
    })),
  );
  const contentSha256 = computeCorpusContentSha256(docs);
  return {
    database: "drouter",
    collection: "enclave_intelligence",
    documentCount: docs.length,
    contentSha256,
    documents: docs,
  };
}

function buildMockSealedComputerPlanAndReceipt(descriptor: unknown): {
  plan: ClosedAgentPlan;
  egressReceipt: GeminiEgressReceipt;
} {
  const { validatedDescriptor, canonicalRequest, requestSha256 } =
    buildGeminiCreateRequestFromDescriptor(descriptor);
  const secretKey = new Uint8Array(32).fill(0x42);
  const publicKeyHex = bytesToHex(ed25519.getPublicKey(secretKey)).toLowerCase();
  const epochHourSec = coarsenEpochSecToHour(1_792_886_400);
  const signingBytes = geminiEgressSigningPayload({
    sha256: requestSha256,
    epochHourSec,
  });
  const signatureHex = bytesToHex(
    ed25519.sign(signingBytes, secretKey),
  ).toLowerCase();

  const steps: ClosedAgentPlan["steps"] = [
    {
      step: 1,
      id: "call-1",
      tool: "scrub_and_symmetry_mask",
      arguments: { inputHandle: "$INPUT", bucketQuantumBytes: 4096 },
    },
    {
      step: 2,
      id: "call-2",
      tool: "verify_two_hop_enclave_and_quorum",
      arguments: { providerId: "tinfoil", enclaveModel: "gemma4-31b" },
    },
    {
      step: 3,
      id: "call-3",
      tool: "search_atlas_hybrid_kb",
      arguments: {
        topic: "tinfoil_enclave",
        inputHandle: "$RESULT_1",
        category: "provider",
      },
    },
    {
      step: 4,
      id: "call-4",
      tool: "invoke_attested_enclave",
      arguments: {
        inputHandle: "$RESULT_1",
        enclaveModel: "gemma4-31b",
        taskKind: validatedDescriptor.taskKind,
      },
    },
    {
      step: 5,
      id: "call-5",
      tool: "anchor_arc_settlement_with_human_gate",
      arguments: {
        actionKind: "anchor_receipt",
        resultHandle: "$RESULT_3",
        humanApproved: false,
      },
    },
  ];

  const plan: ClosedAgentPlan = {
    taskKind: validatedDescriptor.taskKind,
    inputHandle: "$INPUT",
    inputTokenEstimate: validatedDescriptor.inputTokenEstimate,
    steps,
    toolCalls: steps.map((s) => ({
      id: s.id,
      name: s.tool,
      arguments: s.arguments,
    })),
    summary:
      "Gemini 4 Argon control-plane plan verified (5 tool calls over content-free handles).",
  };

  const egressReceipt: GeminiEgressReceipt = {
    canonicalRequest,
    sha256: requestSha256,
    epochHourSec,
    kind: "gemini-egress",
    signer: "sealed-google-computer",
    signerLabel: SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
    signature: signatureHex,
    publicKey: publicKeyHex,
    keyId: "egress-signing",
  };

  return { plan, egressReceipt };
}

describe("W6-A Browser Agent Client & POST /api/gemini/plan", () => {
  it("removes the old full-text POST /api/gemini path so /api/gemini only serves content-free GET metadata", async () => {
    expect("POST" in geminiRouteModule).toBe(false);
    expect(typeof geminiRouteModule.GET).toBe("function");

    const getRes = await geminiRouteModule.GET();
    expect(getRes.status).toBe(200);
    const getJson = (await getRes.json()) as Record<string, unknown>;
    expect(getJson.ok).toBe(true);
    expect(getJson.dataSentToGoogle).toBe("content-free task descriptor only");
    expect(() =>
      assertGoogleBoundMessage("taskDescriptor", getJson.taskDescriptor),
    ).not.toThrow();
  });

  it("runs a mocked end-to-end agent workflow in the browser proving NO request body leaving the browser except the enclave call contains any word of the task", async () => {
    const privateTask =
      "Examine our oncology survival study protocol for Priya Natarajan at Halden & Moss LLP dated 2026-05-10 " +
      "(grant budget £125,000.00, contact priya.natarajan@example.org, mobile +44 7911 123456, test key sk-test-4f9a2c7e1b8d6a3f5e0c). " +
      "Explain the main findings in plain words.";

    // Extract every word (>= 2 chars) from the private task
    const taskWords = Array.from(
      new Set(privateTask.toLowerCase().match(/[a-z0-9]{2,}/g) ?? []),
    );
    expect(taskWords.length).toBeGreaterThan(20);

    const recordedFetches: Array<{
      url: string;
      method: string;
      body: string | undefined;
    }> = [];

    const mockFetch: typeof fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        const body =
          typeof init?.body === "string"
            ? init.body
            : init?.body !== undefined
              ? String(init.body)
              : undefined;

        recordedFetches.push({ url, method, body });

        if (url === "/api/gemini/plan") {
          const parsedDesc = JSON.parse(body ?? "{}");
          const { plan, egressReceipt } =
            buildMockSealedComputerPlanAndReceipt(parsedDesc);
          return new Response(
            JSON.stringify({
              ok: true,
              planner: GEMINI_4_ARGON_MODEL_ID,
              plannerSource: "sealed-google-computer",
              model: GEMINI_4_ARGON_MODEL_ID,
              interactionId: "inter-argon-turn-1",
              status: "completed",
              dataSentToGoogle: "content-free task descriptor only",
              egressFirewallVerified: true,
              plan,
              egressReceipt,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        if (url === "/api/core/attestation") {
          return new Response(
            JSON.stringify(coreAttestationFixture.attestationResponseJson),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/relay/enclave-matrix") {
          return new Response(JSON.stringify(buildMockEnclaveMatrix()), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }

        if (url === "/api/registry") {
          return new Response(
            JSON.stringify({
              source: "arc",
              nodes: [
                {
                  id: "tinfoil-router",
                  kind: "tinfoil",
                  status: "active",
                  stake: "100",
                },
              ],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        if (url === "/api/knowledge/corpus") {
          const corpusPayload = buildMockCorpusResponse();
          return new Response(JSON.stringify(corpusPayload), {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              ETag: corpusPayload.contentSha256,
            },
          });
        }

        if (url === "/api/relay/v1/chat/completions" || url === "chat/completions") {
          const reqHeaders = new Headers(init?.headers);
          const tinfoilModel = reqHeaders.get("X-Tinfoil-Model");
          const parsedEnclaveReq = JSON.parse(body ?? "{}") as {
            model?: string;
            messages?: Array<{ role: string; content: string }>;
          };
          const userMsg = parsedEnclaveReq.messages?.[0]?.content ?? "";

          if (
            tinfoilModel === "pii-filter" ||
            parsedEnclaveReq.model === "pii-filter"
          ) {
            return new Response(
              JSON.stringify({
                redacted_text: userMsg,
                summary: { span_count: 0 },
                detected_spans: [],
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }

          // Enclave call: extract placeholders from the redacted prompt and echo them in the response
          const placeholdersInPrompt = Array.from(
            new Set(
              userMsg.match(
                /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\d+\]/g,
              ) ?? [],
            ),
          );
          return new Response(
            JSON.stringify({
              completion: `Completed private analysis for ${placeholdersInPrompt.join(", ")}.`,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        throw new Error(`Unexpected fetch URL in browser agent run: ${url}`);
      },
    );

    // Exercise the D4 attested second-pass filter via the relay path so its request is captured in recordedFetches
    setAttestedPiiFilterClientForTests({
      ready: async () => {},
      getVerificationDocument: () => ({
        securityVerified: true,
        enclaveHost: "pii-filter.tinfoil.sh",
      }),
      fetch: (input, init) =>
        mockFetch(
          String(input) === "chat/completions"
            ? "/api/relay/v1/chat/completions"
            : input,
          init,
        ),
    });

    const openSessionSpy = vi.fn(async (model: "gemma4-31b" | "kimi-k3") => {
      void model;
      return {
        async *send(
          mdl: string,
          messages: { role: "user" | "assistant"; content: string }[],
        ) {
          const res = await mockFetch("/api/relay/v1/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ model: mdl, messages }),
          });
          const data = (await res.json()) as { completion: string };
          yield data.completion;
        },
      };
    });

    const outcome = await runBrowserAgentWorkflow({
      taskPrompt: privateTask,
      alwaysHide: ["Halden & Moss LLP"],
      thinkingLevel: "high",
      background: true,
      humanApprovedExternalAction: false,
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: mockFetch,
      openSessionFn: openSessionSpy,
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });

    expect(openSessionSpy).toHaveBeenCalledTimes(1);
    expect(outcome.plannerUnavailable).toBe(false);
    expect(outcome.run.overallPassed).toBe(true);
    expect(outcome.run.mode).toBe("live");
    expect(outcome.run.egressReceipt?.signer).toBe("sealed-google-computer");
    expect(outcome.run.stages.stage1.attestedFilter.verified).toBe(true);
    expect(
      outcome.run.taskDescriptor.verification.attestedPiiFilterVerified,
    ).toBe(true);
    expect(
      outcome.run.stages.stage4.liveGeminiCall.toolCallsExecuted,
    ).toEqual([
      "scrub_and_symmetry_mask",
      "verify_two_hop_enclave_and_quorum",
      "search_atlas_hybrid_kb",
      "invoke_attested_enclave",
      "anchor_arc_settlement_with_human_gate",
    ]);

    // Verify names and personal details were restored on the device
    const restoredOutput = outcome.run.stages.stage4.restoredClientOutput;
    expect(restoredOutput).toContain("Priya Natarajan");
    expect(restoredOutput).toContain("Halden & Moss LLP");
    expect(restoredOutput).toContain("priya.natarajan@example.org");
    expect(restoredOutput).toContain("sk-test-4f9a2c7e1b8d6a3f5e0c");
    expect(
      outcome.run.stages.stage4.verificationSignal.homomorphicRestoreVerified,
    ).toBe(true);

    // Collect every original sensitive value from stage1.placeholders and stage1.appliedSymmetryMasks
    const allStage1Originals = [
      ...Object.values(outcome.run.stages.stage1.placeholders),
      ...outcome.run.stages.stage1.appliedSymmetryMasks.map((m) => m.original),
    ];
    expect(allStage1Originals.length).toBeGreaterThanOrEqual(6);
    expect(allStage1Originals).toEqual(
      expect.arrayContaining([
        "Priya Natarajan",
        "Halden & Moss LLP",
        "priya.natarajan@example.org",
        "sk-test-4f9a2c7e1b8d6a3f5e0c",
        "2026-05-10",
      ]),
    );
    expect(allStage1Originals.some((v) => v.includes("125,000.00"))).toBe(true);

    // Assert on EVERY mocked fetch call leaving the browser:
    expect(recordedFetches.length).toBeGreaterThanOrEqual(6);
    const nonEnclaveCalls = recordedFetches.filter(
      (f) => f.url !== "/api/relay/v1/chat/completions",
    );
    const enclaveCalls = recordedFetches.filter(
      (f) => f.url === "/api/relay/v1/chat/completions",
    );
    expect(nonEnclaveCalls.length).toBeGreaterThanOrEqual(4);
    // 2 enclave calls: 1 to pii-filter (D4 second-pass filter) and 1 to gemma4-31b (Stage 4 enclave execution)
    expect(enclaveCalls).toHaveLength(2);

    for (const call of nonEnclaveCalls) {
      const lowerBody = (call.body ?? "").toLowerCase();
      const lowerUrl = call.url.toLowerCase();
      // Every word of the task must be completely absent from every non-enclave request body!
      for (const word of taskWords) {
        const wordRe = new RegExp(`\\b${word}\\b`, "i");
        expect(
          wordRe.test(lowerBody),
          `Expected task word '${word}' to be absent from body of ${call.url}: ${lowerBody}`,
        ).toBe(false);
        expect(
          wordRe.test(lowerUrl),
          `Expected task word '${word}' to be absent from url ${call.url}`,
        ).toBe(false);
      }
      for (const origVal of allStage1Originals) {
        expect(lowerBody).not.toContain(origVal.toLowerCase());
      }

      if (call.url === "/api/gemini/plan") {
        expect(call.body).toBeDefined();
        const parsedPlanReq = JSON.parse(call.body!);
        expect(() =>
          assertGoogleBoundMessage("taskDescriptor", parsedPlanReq),
        ).not.toThrow();
        expect(() => assertContentFree(parsedPlanReq)).not.toThrow();
      } else {
        // Verification and whole-corpus requests have no body and no query string
        expect(call.body).toBeUndefined();
        expect(call.url).not.toContain("?");
      }
    }

    // And EVERY enclave call (both pii-filter and gemma4-31b) contains zero original values from stage1.placeholders or stage1.appliedSymmetryMasks
    for (const encCall of enclaveCalls) {
      const encBody = encCall.body ?? "";
      expect(encBody).toContain("oncology survival study protocol");
      expect(() =>
        assertOutboundPrivacyInvariant(encBody, allStage1Originals),
      ).not.toThrow();
      for (const origVal of allStage1Originals) {
        expect(
          encBody.toLowerCase(),
          `Expected original sensitive value '${origVal}' to be absent from enclave body`,
        ).not.toContain(origVal.toLowerCase());
      }
      expect(encBody).not.toContain("2026-05-10");
      expect(encBody).not.toContain("125,000");
      expect(encBody).not.toContain("7911 123456");
    }
  });

  it("rejects any payload with text, extra keys, missing keys, duplicate keys, or unknown values on POST /api/gemini/plan", async () => {
    const validDescriptor = buildTaskDescriptor({
      taskKind: "review",
      inputTokenEstimate: 128,
      redactionCounts: { SECRET: 1, EMAIL: 1, TOTAL: 2 },
      verification: {
        mechanicalRedactionPassed: true,
        attestedPiiFilterVerified: false,
        bucketAligned4096: true,
      },
      allowedTools: ALLOWED_PLANNER_TOOLS,
    });

    const invalidBodies: Array<{ label: string; rawBody: string }> = [
      {
        label: "taskPrompt text field",
        rawBody: JSON.stringify({
          ...validDescriptor,
          taskPrompt: "Review our survival study",
        }),
      },
      {
        label: "text field",
        rawBody: JSON.stringify({
          ...validDescriptor,
          text: "Summarize the findings",
        }),
      },
      {
        label: "extra unknown key",
        rawBody: JSON.stringify({
          ...validDescriptor,
          extraKey: "ok",
        }),
      },
      {
        label: "free text in inputHandle",
        rawBody: JSON.stringify({
          ...validDescriptor,
          inputHandle: "Priya Natarajan",
        }),
      },
      {
        label: "unknown taskKind enum value",
        rawBody: JSON.stringify({
          ...validDescriptor,
          taskKind: "exfiltrate",
        }),
      },
      {
        label: "non-power-of-two inputTokenEstimate",
        rawBody: JSON.stringify({
          ...validDescriptor,
          inputTokenEstimate: 100,
        }),
      },
      {
        label: "out-of-range redactionCounts value (> 2)",
        rawBody: JSON.stringify({
          ...validDescriptor,
          redactionCounts: { EMAIL: 5, TOTAL: 5 },
        }),
      },
      {
        label: "unknown allowedTools entry",
        rawBody: JSON.stringify({
          ...validDescriptor,
          allowedTools: ["unknown_tool"],
        }),
      },
      {
        label: "missing required verification key",
        rawBody: JSON.stringify({
          taskKind: "review",
          inputHandle: "$INPUT",
          inputTokenEstimate: 128,
          redactionCounts: { TOTAL: 0 },
          allowedTools: ALLOWED_PLANNER_TOOLS,
        }),
      },
      {
        label: "duplicate JSON key smuggling text",
        rawBody:
          '{"taskKind":"Patient Jane Doe","taskKind":"review","inputHandle":"$INPUT","inputTokenEstimate":128,"redactionCounts":{"TOTAL":0},"verification":{"mechanicalRedactionPassed":true},"allowedTools":["scrub_and_symmetry_mask"]}',
      },
    ];

    for (const item of invalidBodies) {
      const req = new Request("http://localhost:3000/api/gemini/plan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "198.51.100.21",
        },
        body: item.rawBody,
      });
      const res = await planPost(req);
      expect(res.status, `Expected 400 for ${item.label}`).toBe(400);
      const data = (await res.json()) as Record<string, unknown>;
      expect(data.ok).toBe(false);
    }

    // Also reject query parameters on POST /api/gemini/plan
    const queryReq = new Request(
      "http://localhost:3000/api/gemini/plan?task=secret",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "198.51.100.22",
        },
        body: canonicalJson(validDescriptor),
      },
    );
    const queryRes = await planPost(queryReq);
    expect(queryRes.status).toBe(400);

    // Also verify assertClosedPlanSchema rejects empty 0-step plans, extra keys, or invalid tool arguments in plan output
    const { plan: validPlan } =
      buildMockSealedComputerPlanAndReceipt(validDescriptor);
    expect(() => assertClosedPlanSchema(validPlan)).not.toThrow();
    expect(() =>
      assertClosedPlanSchema({ ...validPlan, steps: [], toolCalls: [] }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertClosedPlanSchema({ ...validPlan, extraField: "bad" }),
    ).toThrow(ContentFreeEgressError);
    expect(() =>
      assertClosedPlanSchema({
        ...validPlan,
        steps: [
          {
            step: 1,
            id: "call-1",
            tool: "invoke_attested_enclave",
            arguments: {
              inputHandle: "leaked prompt text",
              enclaveModel: "gemma4-31b",
            },
          },
        ],
        toolCalls: [
          {
            id: "call-1",
            name: "invoke_attested_enclave",
            arguments: {
              inputHandle: "leaked prompt text",
              enclaveModel: "gemma4-31b",
            },
          },
        ],
      }),
    ).toThrow(ContentFreeEgressError);
  });

  it("handles planner-unavailable state honestly (never a fake plan) in POST /api/gemini/plan, runBrowserAgentWorkflow, and UI helpers", async () => {
    setCorePlanHandlerForTests(async () => ({
      status: 503,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ core: "not-deployed" }),
    }));
    setPlanGenAIClientForTests(null, "");

    const { taskDescriptor } = buildBrowserRedactedTaskAndDescriptor({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
    });

    const req = new Request("http://localhost:3000/api/gemini/plan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.25",
      },
      body: canonicalJson(taskDescriptor),
    });

    const res = await planPost(req);
    expect(res.status).toBe(503);
    const json = (await res.json()) as Record<string, unknown>;
    expect(json.ok).toBe(false);
    expect(json.planner).toBe("unavailable");
    expect(json.plan).toBeNull();
    expect(json.egressReceipt).toBeNull();

    // Now test runBrowserAgentWorkflow when POST /api/gemini/plan returns 503 planner: "unavailable"
    const mockUnavailableFetch: typeof fetch = vi.fn(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/gemini/plan") {
          return new Response(JSON.stringify(json), {
            status: 503,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url === "/api/core/attestation") {
          return new Response(
            JSON.stringify(coreAttestationFixture.attestationResponseJson),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/relay/enclave-matrix") {
          return new Response(JSON.stringify(buildMockEnclaveMatrix()), {
            status: 200,
          });
        }
        if (url === "/api/registry") {
          return new Response(JSON.stringify({ nodes: [] }), { status: 200 });
        }
        if (url === "/api/knowledge/corpus") {
          const corpusPayload = buildMockCorpusResponse();
          return new Response(JSON.stringify(corpusPayload), {
            status: 200,
            headers: { ETag: corpusPayload.contentSha256 },
          });
        }
        return new Response("{}", { status: 200 });
      },
    );

    const openSessionSpy = vi.fn();
    const outcome = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
      fetchFn: mockUnavailableFetch,
      openSessionFn: openSessionSpy,
    });

    expect(outcome.plannerUnavailable).toBe(true);
    expect(outcome.run.mode).toBe("planner-unavailable");
    expect(outcome.run.plannerStatus).toBe("unavailable");
    expect(outcome.run.plan).toBeNull();
    expect(outcome.run.egressReceipt).toBeNull();
    expect(outcome.run.overallPassed).toBe(false);
    // Enclave session is not called with a fake plan
    expect(openSessionSpy).not.toHaveBeenCalled();

    const badge = resolvePlannerModeBadgeText({
      planner: outcome.run.planner,
      plannerStatus: outcome.run.plannerStatus,
      mode: outcome.run.mode,
    });
    expect(badge).toBe("Planner unavailable (no Gemini key is set)");
    expect(findForbiddenPlainTerms(badge)).toEqual([]);

    const subtitle = resolvePlannerSubtitleText({
      isLiveGeminiBadge: false,
      plannerUnavailable: true,
    });
    expect(subtitle).toContain("Gemini planner is unavailable");
    expect(subtitle).toContain("No fake plan is ever generated");
    expect(findForbiddenPlainTerms(subtitle)).toEqual([]);

    const steps = buildPlainTimelineSteps({
      run: outcome.run,
      plannerBadgeText: badge,
    });
    expect(steps[0].passed).toBe(true); // Stage 1 on-device detail hiding still passed
    expect(steps[2].passed).toBe(false); // Stage 4 Thinking reports unavailable
    expect(steps[2].statusText).toBe("Unavailable");
    expect(steps[2].plainResult).toContain("no fake plan was generated");
    expect(steps[3].passed).toBe(false);
    expect(steps[3].statusText).toBe("Not needed");
    for (const s of steps) {
      expect(findForbiddenPlainTerms(s.plainResult)).toEqual([]);
    }

    // Also verify that when GEMINI_API_KEY IS set and the Gemini API call fails, POST /api/gemini/plan returns gemini_call_failed and attemptedLiveCall: true
    setPlanGenAIClientForTests(
      {
        interactions: {
          create: vi.fn(async () => {
            throw new Error("Upstream Gemini 500 error");
          }),
        },
      },
      "test-configured-gemini-key",
    );
    const failedCallReq = new Request("http://localhost:3000/api/gemini/plan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.26",
      },
      body: canonicalJson(taskDescriptor),
    });
    const failedCallRes = await planPost(failedCallReq);
    expect(failedCallRes.status).toBe(503);
    const failedCallJson = (await failedCallRes.json()) as Record<string, unknown>;
    expect(failedCallJson.error).toBe("gemini_call_failed");
    expect(failedCallJson.attemptedLiveCall).toBe(true);

    const failedBadge = resolvePlannerModeBadgeText({
      planner: { provider: "gemini", model: "unavailable" },
      plannerStatus: "unavailable",
      mode: "planner-unavailable",
      attemptedLiveCall: true,
    });
    expect(failedBadge).toBe("Planner unavailable (the Gemini call failed)");
  });

  it("verifies and formats egress receipts honestly for both signers: sealed Google computer vs recorded by our server", async () => {
    const descriptor = buildTaskDescriptor({
      taskKind: "review",
      inputTokenEstimate: 64,
      redactionCounts: { SECRET: 1, EMAIL: 1, TOTAL: 2 },
      verification: {
        mechanicalRedactionPassed: true,
        attestedPiiFilterVerified: false,
        bucketAligned4096: true,
      },
      allowedTools: ALLOWED_PLANNER_TOOLS,
    });

    // 1. Signer A: Sealed Google computer (`/api/core/agent/plan` available)
    const mockCore = buildMockSealedComputerPlanAndReceipt(descriptor);
    setCorePlanHandlerForTests(
      async () => ({
        status: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ok: true,
          planner: GEMINI_4_ARGON_MODEL_ID,
          model: GEMINI_4_ARGON_MODEL_ID,
          interactionId: "inter-argon-turn-1",
          status: "completed",
          dataSentToGoogle: "content-free task descriptor only",
          egressFirewallVerified: true,
          plan: mockCore.plan,
          egressReceipt: mockCore.egressReceipt,
        }),
      }),
      SEALED_PUBLIC_KEY_HEX,
    );

    const coreReq = new Request("http://localhost:3000/api/gemini/plan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.31",
      },
      body: canonicalJson(descriptor),
    });
    const coreRes = await planPost(coreReq);
    expect(coreRes.status).toBe(200);
    const coreJson = (await coreRes.json()) as {
      ok: boolean;
      plannerSource: string;
      plan: ClosedAgentPlan;
      egressReceipt: GeminiEgressReceipt;
    };
    expect(coreJson.ok).toBe(true);
    expect(coreJson.plannerSource).toBe("sealed-google-computer");
    expect(coreJson.egressReceipt.signer).toBe("sealed-google-computer");
    expect(coreJson.egressReceipt.keyId).toBe("egress-signing");

    // Must reject sealed-computer receipt if expectedPublicKeyHex is omitted (never trust receipt.publicKey itself)
    expect(verifyEgressReceiptClient(coreJson.egressReceipt).ok).toBe(false);

    // Must reject receipt if bound to a different TaskDescriptor
    const otherDescriptor = buildTaskDescriptor({
      taskKind: "summarize",
      inputTokenEstimate: 64,
      redactionCounts: { SECRET: 1, EMAIL: 1, TOTAL: 2 },
      verification: {
        mechanicalRedactionPassed: true,
        attestedPiiFilterVerified: false,
        bucketAligned4096: true,
      },
      allowedTools: ALLOWED_PLANNER_TOOLS,
    });
    expect(
      verifyEgressReceiptClient(
        coreJson.egressReceipt,
        SEALED_PUBLIC_KEY_HEX,
        otherDescriptor,
      ).ok,
    ).toBe(false);

    // Passes when verified with the attested egress key from /api/core/attestation and matching descriptor
    const verifiedCore = verifyEgressReceiptClient(
      coreJson.egressReceipt,
      SEALED_PUBLIC_KEY_HEX,
      descriptor,
    );
    expect(verifiedCore.ok).toBe(true);

    const displayCore = formatEgressReceiptDisplay(coreJson.egressReceipt);
    expect(displayCore.hasReceipt).toBe(true);
    expect(displayCore.signer).toBe("sealed-google-computer");
    expect(displayCore.signerHeading).toBe(SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL);
    expect(displayCore.canonicalBytes).toBe(
      mockCore.egressReceipt.canonicalRequest,
    );
    expect(displayCore.sha256Hex).toBe(mockCore.egressReceipt.sha256);
    expect(displayCore.signatureHex).toBe(mockCore.egressReceipt.signature);
    expect(displayCore.publicKeyHex).toBe(mockCore.egressReceipt.publicKey);

    // 2. Signer B: Recorded by our Next server (when `/api/core/agent/plan` is 503 not-deployed and GEMINI_API_KEY is set)
    setCorePlanHandlerForTests(async () => ({
      status: 503,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ core: "not-deployed" }),
    }));

    const mockNextGenAIClient: GenAIInteractionsClientLike = {
      interactions: {
        create: vi.fn(async (params: Record<string, unknown>) => {
          expect(() =>
            assertGoogleBoundMessage("createRequest", params),
          ).not.toThrow();
          expect(() => assertContentFree(params)).not.toThrow();
          return {
            id: "inter-argon-turn-1",
            status: "completed",
            steps: [
              {
                type: "function_call",
                id: "call-1",
                name: "scrub_and_symmetry_mask",
                arguments: { inputHandle: "$INPUT", bucketQuantumBytes: 4096 },
              },
              {
                type: "function_call",
                id: "call-2",
                name: "verify_two_hop_enclave_and_quorum",
                arguments: { providerId: "tinfoil", enclaveModel: "gemma4-31b" },
              },
              {
                type: "function_call",
                id: "call-3",
                name: "invoke_attested_enclave",
                arguments: {
                  inputHandle: "$RESULT_1",
                  enclaveModel: "gemma4-31b",
                  taskKind: "review",
                },
              },
            ],
            output_text:
              "Planned 3 confidential steps over content-free handles.",
          };
        }),
      },
    };
    setPlanGenAIClientForTests(mockNextGenAIClient, "test-server-key");

    const nextReq = new Request("http://localhost:3000/api/gemini/plan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.32",
      },
      body: canonicalJson(descriptor),
    });
    const nextRes = await planPost(nextReq);
    expect(nextRes.status).toBe(200);
    const nextJson = (await nextRes.json()) as {
      ok: boolean;
      plannerSource: string;
      plan: ClosedAgentPlan;
      egressReceipt: GeminiEgressReceipt;
    };
    expect(nextJson.ok).toBe(true);
    expect(nextJson.plannerSource).toBe("next-server");
    expect(nextJson.egressReceipt.signer).toBe("next-server");
    expect(nextJson.egressReceipt.keyId).toBe("operator-tree-head");
    expect(nextJson.egressReceipt.signerLabel).toBe(NEXT_SERVER_RECEIPT_LABEL);
    expect(nextJson.egressReceipt.transparencyLog).toBeDefined();
    expect(
      Array.isArray(nextJson.egressReceipt.transparencyLog?.auditPath),
    ).toBe(true);

    const verifiedNext = verifyEgressReceiptClient(
      nextJson.egressReceipt,
      undefined,
      descriptor,
    );
    expect(verifiedNext.ok).toBe(true);

    // Append a second server-recorded receipt so treeSize === 2 and auditPath is non-empty, and verify RFC 6962 inclusion proof
    const nextReq2 = new Request("http://localhost:3000/api/gemini/plan", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.33",
      },
      body: canonicalJson(otherDescriptor),
    });
    const nextRes2 = await planPost(nextReq2);
    expect(nextRes2.status).toBe(200);
    const nextJson2 = (await nextRes2.json()) as {
      egressReceipt: GeminiEgressReceipt;
    };
    expect(nextJson2.egressReceipt.transparencyLog?.treeSize).toBeGreaterThanOrEqual(
      2,
    );
    expect(
      nextJson2.egressReceipt.transparencyLog?.leafIndex,
    ).toBeGreaterThanOrEqual(1);
    expect(
      nextJson2.egressReceipt.transparencyLog?.auditPath.length,
    ).toBeGreaterThanOrEqual(1);
    expect(
      verifyEgressReceiptClient(
        nextJson2.egressReceipt,
        undefined,
        otherDescriptor,
      ).ok,
    ).toBe(true);

    // Reject if leafHash does not commit to receipt.sha256
    expect(
      verifyEgressReceiptClient(
        {
          ...nextJson2.egressReceipt,
          transparencyLog: {
            ...nextJson2.egressReceipt.transparencyLog!,
            leafHash: nextJson2.egressReceipt.sha256,
          },
        },
        undefined,
        otherDescriptor,
      ).ok,
    ).toBe(false);

    // Reject if auditPath is tampered or missing
    expect(
      verifyEgressReceiptClient(
        {
          ...nextJson2.egressReceipt,
          transparencyLog: {
            ...nextJson2.egressReceipt.transparencyLog!,
            auditPath: [],
          },
        },
        undefined,
        otherDescriptor,
      ).ok,
    ).toBe(false);

    const displayNext = formatEgressReceiptDisplay(nextJson.egressReceipt);
    expect(displayNext.hasReceipt).toBe(true);
    expect(displayNext.signer).toBe("next-server");
    expect(displayNext.signerHeading).toBe(NEXT_SERVER_RECEIPT_LABEL);
    expect(displayNext.signerHeading.toLowerCase()).toContain(
      "recorded by our server",
    );
    expect(displayNext.canonicalBytes).toBe(
      mockCore.egressReceipt.canonicalRequest,
    );
    expect(displayNext.sha256Hex).toBe(mockCore.egressReceipt.sha256);
    expect(displayNext.transparencySummary).toContain("leaf #");
    expect(displayNext.transparencySummary).toContain("rootHash=0x");
  });

  it("runs the attested second-pass filter (attestedPiiFilter) on mechanically redacted text in the browser, applies extra redactions, and falls back honestly when unavailable", async () => {
    const samplePrompt =
      "Review the clinical protocol with handle alex_rivera_private for Dana Reyes at dana.reyes@example.org on 2026-08-14.";

    // 1. When attestedPiiFilter is verified and catches an extra span ("alex_rivera_private")
    const verifiedPrep = await runBrowserRedactionPipeline({
      taskPrompt: samplePrompt,
      attestedFilterRunner: async (mechText) => ({
        text: mechText.replace("alex_rivera_private", "<PRIVATE_PERSON>"),
        redactionCount: 1,
        model: "pii-filter",
        verified: true,
        detectedSpans: [
          {
            label: "private_person",
            start: mechText.indexOf("alex_rivera_private"),
            end:
              mechText.indexOf("alex_rivera_private") +
              "alex_rivera_private".length,
            text: "alex_rivera_private",
            placeholder: "<PRIVATE_PERSON>",
          },
        ],
      }),
    });

    expect(verifiedPrep.stage1.attestedFilter.verified).toBe(true);
    expect(verifiedPrep.stage1.attestedFilter.fallbackToMechanicalOnly).toBe(
      false,
    );
    expect(verifiedPrep.stage1.attestedFilter.redactionCount).toBe(1);
    expect(
      verifiedPrep.taskDescriptor.verification.attestedPiiFilterVerified,
    ).toBe(true);
    expect(verifiedPrep.papillonGeneralizedPrompt).not.toContain(
      "alex_rivera_private",
    );
    expect(verifiedPrep.papillonGeneralizedPrompt).toContain("[ATTESTED_PII_1]");
    expect(
      verifiedPrep.restoreAll(verifiedPrep.papillonGeneralizedPrompt),
    ).toBe(samplePrompt);

    // 2. When attestedPiiFilter fails, continues with the mechanical result and says so honestly
    const fallbackPrep = await runBrowserRedactionPipeline({
      taskPrompt: samplePrompt,
      attestedFilterRunner: async () => {
        throw new Error("Enclave unreachable");
      },
    });
    expect(fallbackPrep.stage1.attestedFilter.verified).toBe(false);
    expect(fallbackPrep.stage1.attestedFilter.fallbackToMechanicalOnly).toBe(
      true,
    );
    expect(
      fallbackPrep.taskDescriptor.verification.attestedPiiFilterVerified,
    ).toBe(false);
    expect(fallbackPrep.stage1.attestedFilter.note).toContain("unavailable");

    // 3. Also test attestedPiiFilter via the browser relay path using setAttestedPiiSecureClientFactoryForTests
    // to prove SecureClient is constructed with enclaveURL: "https://pii-filter.tinfoil.sh" and configRepo: "tinfoilsh/confidential-pii-cpu"
    let capturedRelayOptions: Record<string, unknown> = {};
    setAttestedPiiSecureClientFactoryForTests((opts) => {
      capturedRelayOptions = opts;
      return {
        ready: async () => {},
        getVerificationDocument: () => ({
          securityVerified: true,
          enclaveHost: "pii-filter.tinfoil.sh",
        }),
        fetch: async (_url, init) => {
          const headers = new Headers(init?.headers);
          expect(headers.get("X-Tinfoil-Model")).toBe("pii-filter");
          expect(headers.get("Authorization")).toBe("Bearer drouter-demo");
          expect(typeof init?.body).toBe("string");
          expect(new TextEncoder().encode(String(init?.body)).byteLength).toBe(
            4096,
          );
          return new Response(
            JSON.stringify({
              redacted_text: "Review the protocol with <PRIVATE_PERSON>",
              summary: { span_count: 1 },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        },
      };
    });
    const directRes = await attestedPiiFilter(
      "Review the protocol with Cousin Leo",
      { useRelay: true, relayOrigin: "https://drouter.example" },
    );
    expect(directRes.verified).toBe(true);
    expect(directRes.redactionCount).toBe(1);
    expect(capturedRelayOptions.enclaveURL).toBe(
      TINFOIL_PII_FILTER_ENCLAVE_URL,
    );
    expect(capturedRelayOptions.configRepo).toBe(
      TINFOIL_PII_FILTER_CONFIG_REPO,
    );
    expect(capturedRelayOptions.baseURL).toBe(
      "https://drouter.example/api/relay/v1/",
    );
    expect(capturedRelayOptions.attestationBundleURL).toBe(
      "https://drouter.example/api/relay",
    );

    // Verify /api/relay/attestation and /api/relay/[relayId]/attestation allow tinfoilsh/confidential-pii-cpu and reject unknown repos
    const prevStub = process.env.DROUTER_STUB_UPSTREAM;
    process.env.DROUTER_STUB_UPSTREAM = "1";
    try {
      const piiAttestReq = new Request(
        "http://localhost:3000/api/relay/attestation",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "198.51.100.41",
          },
          body: JSON.stringify({
            enclaveUrl: TINFOIL_PII_FILTER_ENCLAVE_URL,
            repo: TINFOIL_PII_FILTER_CONFIG_REPO,
          }),
        },
      );
      const piiAttestRes = await relayAttestationPost(piiAttestReq);
      // Passes validation (503 stub upstream, NOT 400 unsupported repo)
      expect(piiAttestRes.status).toBe(503);

      const piiHopAttestReq = new Request(
        "http://localhost:3000/api/relay/relay-eu-zurich/attestation",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "198.51.100.42",
          },
          body: JSON.stringify({
            enclaveUrl: TINFOIL_PII_FILTER_ENCLAVE_URL,
            repo: TINFOIL_PII_FILTER_CONFIG_REPO,
          }),
        },
      );
      const piiHopAttestRes = await relayHopAttestationPost(piiHopAttestReq, {
        params: Promise.resolve({ relayId: "relay-eu-zurich" }),
      });
      expect(piiHopAttestRes.status).toBe(503);

      const badRepoReq = new Request(
        "http://localhost:3000/api/relay/attestation",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "198.51.100.43",
          },
          body: JSON.stringify({
            enclaveUrl: TINFOIL_PII_FILTER_ENCLAVE_URL,
            repo: "attacker/rogue-pii-repo",
          }),
        },
      );
      const badRepoRes = await relayAttestationPost(badRepoReq);
      expect(badRepoRes.status).toBe(400);
    } finally {
      if (prevStub === undefined) {
        delete process.env.DROUTER_STUB_UPSTREAM;
      } else {
        process.env.DROUTER_STUB_UPSTREAM = prevStub;
      }
    }

    // 4. Plain data handling includes the explicit device preparation sentence
    const plainView = formatPlainDataHandling(HONEST_DATA_HANDLING_STATEMENT);
    expect(plainView.devicePreparationSentence).toBe(
      DEVICE_PREPARATION_PLAIN_SENTENCE,
    );
    expect(findForbiddenPlainTerms(plainView.devicePreparationSentence)).toEqual(
      [],
    );

    // 5. Verify core attestation helper extracts the attested egress key using committed expected-core-digests.json
    expect(expectedCoreDigestsJson).toEqual({
      digests: [
        "sha256:82be4787cf95bc8776b1e4c0b91dabfc4e0b6fe967d0200203be7dd0c6c64c86",
      ],
      updated: "2026-10-25",
    });
    expect(COMMITTED_CORE_IMAGE_DIGESTS).toEqual([TEST_CORE_IMAGE_DIGEST]);
    expect(getExpectedCoreImageDigests()).toEqual([TEST_CORE_IMAGE_DIGEST]);

    // Verify parseCoreImageDigests in src/lib/core-proxy uses the committed file and only allows env to narrow, never widen
    expect(parseCoreImageDigests(undefined, "")).toEqual([
      TEST_CORE_IMAGE_DIGEST,
    ]);
    expect(
      parseCoreImageDigests(
        undefined,
        `${TEST_CORE_IMAGE_DIGEST},sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`,
      ),
    ).toEqual([TEST_CORE_IMAGE_DIGEST]);
    expect(
      parseCoreImageDigests(
        undefined,
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    ).toEqual([]);

    const verifiedEgressKey = await verifyCoreAttestationForEgressKey({
      fetchFn: async () =>
        new Response(
          JSON.stringify(coreAttestationFixture.attestationResponseJson),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
      nowSec: TEST_NOW_SEC,
    });
    expect(verifiedEgressKey).toBe(SEALED_PUBLIC_KEY_HEX);

    // 6. requestAgentPlanFromBrowser rejects a receipt signed by an unattested key
    const rogueSecretKey = new Uint8Array(32).fill(0x99);
    const roguePubKeyHex = bytesToHex(
      ed25519.getPublicKey(rogueSecretKey),
    ).toLowerCase();
    const { canonicalRequest, requestSha256 } =
      buildGeminiCreateRequestFromDescriptor(verifiedPrep.taskDescriptor);
    const epochHourSec = coarsenEpochSecToHour(TEST_NOW_SEC);
    const rogueSigHex = bytesToHex(
      ed25519.sign(
        geminiEgressSigningPayload({ sha256: requestSha256, epochHourSec }),
        rogueSecretKey,
      ),
    ).toLowerCase();

    const { plan } = buildMockSealedComputerPlanAndReceipt(
      verifiedPrep.taskDescriptor,
    );
    await expect(
      requestAgentPlanFromBrowser(verifiedPrep.taskDescriptor, {
        fetchFn: async (input) => {
          const url = String(input);
          if (url === "/api/gemini/plan") {
            return new Response(
              JSON.stringify({
                ok: true,
                plannerSource: "sealed-google-computer",
                plan,
                egressReceipt: {
                  canonicalRequest,
                  sha256: requestSha256,
                  epochHourSec,
                  kind: "gemini-egress",
                  signer: "sealed-google-computer",
                  signature: rogueSigHex,
                  publicKey: roguePubKeyHex,
                  keyId: "egress-signing",
                },
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }
          if (url === "/api/core/attestation") {
            return new Response(
              JSON.stringify(coreAttestationFixture.attestationResponseJson),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }
          return new Response("{}", { status: 404 });
        },
        coreAttestationOptions: {
          expectedImageDigests: [TEST_CORE_IMAGE_DIGEST],
          pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
          nowSec: TEST_NOW_SEC,
        },
      }),
    ).rejects.toThrow(/Invalid or mismatched Ed25519 public key/);
  });

  it("statically walks all imports from src/app/argon/page.tsx and src/lib/agent-client/index.ts and fails if any reachable module imports @google/genai, mongodb, node:*, or a server-only module", () => {
    const repoRoot = path.resolve(__dirname, "../..");
    const srcRoot = path.join(repoRoot, "src");

    function resolveLocalImport(
      fromFile: string,
      specifier: string,
    ): string | null {
      let baseCandidate: string;
      if (specifier.startsWith("@/")) {
        baseCandidate = path.join(srcRoot, specifier.slice(2));
      } else if (specifier.startsWith(".")) {
        baseCandidate = path.resolve(path.dirname(fromFile), specifier);
      } else {
        return null;
      }

      const candidates = [
        baseCandidate,
        `${baseCandidate}.ts`,
        `${baseCandidate}.tsx`,
        `${baseCandidate}.json`,
        path.join(baseCandidate, "index.ts"),
        path.join(baseCandidate, "index.tsx"),
      ];
      for (const c of candidates) {
        if (fs.existsSync(c) && fs.statSync(c).isFile()) {
          return c;
        }
      }
      throw new Error(
        `Could not resolve local import '${specifier}' from ${path.relative(repoRoot, fromFile)}`,
      );
    }

    function extractModuleSpecifiers(sourceText: string): string[] {
      const strippedComments = sourceText
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      const specs = new Set<string>();
      const staticImportExportRe =
        /^\s*(?:import|export)\s+(?:[^`"']*?\s+from\s+)?["']([^"']+)["']/gm;
      const dynamicImportRe = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
      let match: RegExpExecArray | null;
      while ((match = staticImportExportRe.exec(strippedComments)) !== null) {
        specs.add(match[1]);
      }
      while ((match = dynamicImportRe.exec(strippedComments)) !== null) {
        specs.add(match[1]);
      }
      return Array.from(specs);
    }

    // 1. Direct check on src/app/argon/page.tsx and src/lib/agent-client/**
    const directClientEntryFiles = [
      path.join(srcRoot, "app/argon/page.tsx"),
      path.join(srcRoot, "lib/agent-client/index.ts"),
      path.join(srcRoot, "lib/agent-client/plan-schema.ts"),
      path.join(srcRoot, "lib/agent-client/corpus.ts"),
    ];
    for (const file of directClientEntryFiles) {
      const specs = extractModuleSpecifiers(fs.readFileSync(file, "utf8"));
      for (const s of specs) {
        expect(
          ["@/lib/gemini", "@/lib/gemini/index", "@/lib/gemini/interactions"].includes(
            s,
          ),
          `File ${path.relative(repoRoot, file)} must not import from '${s}'`,
        ).toBe(false);
      }
    }

    // 2. Transitive walk from src/app/argon/page.tsx and src/lib/agent-client/index.ts
    const visited = new Set<string>();
    const queue = [
      path.join(srcRoot, "app/argon/page.tsx"),
      path.join(srcRoot, "lib/agent-client/index.ts"),
    ];

    const forbiddenBareBuiltins = new Set([
      "fs",
      "path",
      "crypto",
      "https",
      "http",
      "tls",
      "net",
      "child_process",
      "os",
      "dns",
      "dgram",
      "cluster",
      "worker_threads",
    ]);

    const serverOnlyPathSegments = [
      "src/app/api/",
      "src/lib/core-proxy/",
      "src/lib/mongo/",
      "src/lib/ratelimit.ts",
      "src/lib/transparency/store.ts",
    ];

    while (queue.length > 0) {
      const currentFile = queue.shift()!;
      if (visited.has(currentFile)) continue;
      visited.add(currentFile);

      const relCurrent = path
        .relative(repoRoot, currentFile)
        .replace(/\\/g, "/");
      for (const serverSeg of serverOnlyPathSegments) {
        expect(
          relCurrent.startsWith(serverSeg) || relCurrent === serverSeg,
          `Reachable client module '${relCurrent}' is a server-only module`,
        ).toBe(false);
      }

      if (currentFile.endsWith(".json")) continue;

      const source = fs.readFileSync(currentFile, "utf8");
      const specifiers = extractModuleSpecifiers(source);

      for (const spec of specifiers) {
        expect(
          spec === "@google/genai" || spec.startsWith("@google/genai/"),
          `Module ${relCurrent} must not import '@google/genai' (found '${spec}')`,
        ).toBe(false);
        expect(
          spec === "mongodb" || spec.startsWith("mongodb/"),
          `Module ${relCurrent} must not import 'mongodb' (found '${spec}')`,
        ).toBe(false);
        expect(
          spec.startsWith("node:") || forbiddenBareBuiltins.has(spec),
          `Module ${relCurrent} must not import Node built-in '${spec}'`,
        ).toBe(false);
        expect(
          spec === "next/server" || spec === "server-only",
          `Module ${relCurrent} must not import server-only package '${spec}'`,
        ).toBe(false);

        const resolved = resolveLocalImport(currentFile, spec);
        if (resolved && !visited.has(resolved)) {
          queue.push(resolved);
        }
      }
    }

    expect(visited.size).toBeGreaterThan(15);
  });

  it("maps each model (gemma4-31b and kimi-k3) to its own enclave record and never borrows another model's record when a record is missing", async () => {
    const matrix = buildMockEnclaveMatrix();
    matrix.models["gemma4-31b"].dmVerityRootHash =
      "1111111111111111111111111111111111111111111111111111111111111111";
    matrix.models["gemma4-31b"].measurementRegisters = [
      "1111111111111111111111111111111111111111111111111111111111111111980bb51973cdf396404412ebb7c1a7b7",
    ];
    matrix.models["kimi-k3"].dmVerityRootHash =
      "2222222222222222222222222222222222222222222222222222222222222222";
    matrix.models["kimi-k3"].measurementRegisters = [
      "2222222222222222222222222222222222222222222222222222222222222222980bb51973cdf396404412ebb7c1a7b7",
    ];

    // 1. Both models present in matrix -> each model resolves its own host, repo, and measurement
    const gemmaAtt = resolveModelAttestationFromMatrix("gemma4-31b", matrix);
    expect(gemmaAtt.hasSeparateRecord).toBe(true);
    expect(gemmaAtt.modelAttestation.modelId).toBe("gemma4-31b");
    expect(gemmaAtt.modelAttestation.repo).toBe(
      "tinfoilsh/confidential-gemma4-31b",
    );
    expect(gemmaAtt.modelAttestation.enclaveHosts[0].host).toBe(
      "gemma4-31b-inf10.tinfoil.containers.tinfoil.dev",
    );
    expect(gemmaAtt.modelAttestation.dmVerityRootHash).toBe(
      "1111111111111111111111111111111111111111111111111111111111111111",
    );

    const kimiAtt = resolveModelAttestationFromMatrix("kimi-k3", matrix);
    expect(kimiAtt.hasSeparateRecord).toBe(true);
    expect(kimiAtt.modelAttestation.modelId).toBe("kimi-k3");
    expect(kimiAtt.modelAttestation.repo).toBe("tinfoilsh/confidential-kimi-k3");
    expect(kimiAtt.modelAttestation.enclaveHosts[0].host).toBe(
      "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
    );
    expect(kimiAtt.modelAttestation.dmVerityRootHash).toBe(
      "2222222222222222222222222222222222222222222222222222222222222222",
    );

    // 2. When gemma4-31b is missing from the matrix (only kimi-k3 present), resolveModelAttestationFromMatrix
    // reports gemma4-31b as unavailable rather than borrowing kimi-k3's record
    const matrixWithoutGemma = {
      ...matrix,
      models: {
        "kimi-k3": matrix.models["kimi-k3"],
      },
    };
    const missingGemmaAtt = resolveModelAttestationFromMatrix(
      "gemma4-31b",
      matrixWithoutGemma,
    );
    expect(missingGemmaAtt.hasSeparateRecord).toBe(false);
    expect(missingGemmaAtt.modelAttestation.modelId).toBe("gemma4-31b");
    expect(missingGemmaAtt.modelAttestation.status).toBe("unavailable");
    expect(missingGemmaAtt.modelAttestation.repo).toBe(
      "tinfoilsh/confidential-gemma4-31b",
    );
    expect(missingGemmaAtt.modelAttestation.enclaveHosts).toEqual([]);
    expect(missingGemmaAtt.modelAttestation.dmVerityRootHash).toBe("");
    expect(missingGemmaAtt.modelAttestation.unavailableReason).toContain(
      "No separate enclave record for gemma4-31b",
    );

    // 3. End-to-end runBrowserAgentWorkflow when gemma4-31b has no record in /api/relay/enclave-matrix:
    // attempt #1 records gemma4-31b's missing record honestly (never kimi-k3's host) and fails over to kimi-k3
    const mockFetchMissingGemma: typeof fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === "/api/gemini/plan") {
          const parsedDesc = JSON.parse(String(init?.body ?? "{}"));
          const { plan, egressReceipt } =
            buildMockSealedComputerPlanAndReceipt(parsedDesc);
          return new Response(
            JSON.stringify({
              ok: true,
              planner: GEMINI_4_ARGON_MODEL_ID,
              plannerSource: "sealed-google-computer",
              model: GEMINI_4_ARGON_MODEL_ID,
              interactionId: "inter-argon-turn-1",
              status: "completed",
              dataSentToGoogle: "content-free task descriptor only",
              egressFirewallVerified: true,
              plan,
              egressReceipt,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/core/attestation") {
          return new Response(
            JSON.stringify(coreAttestationFixture.attestationResponseJson),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/relay/enclave-matrix") {
          return new Response(JSON.stringify(matrixWithoutGemma), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url === "/api/registry") {
          return new Response(JSON.stringify({ nodes: [] }), { status: 200 });
        }
        if (url === "/api/knowledge/corpus") {
          const corpusPayload = buildMockCorpusResponse();
          return new Response(JSON.stringify(corpusPayload), {
            status: 200,
            headers: { ETag: corpusPayload.contentSha256 },
          });
        }
        return new Response("{}", { status: 200 });
      },
    );

    const outcomeMissingGemma = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: mockFetchMissingGemma,
      openSessionFn: async () => ({
        async *send() {
          yield "Reviewed [ENTITY_1] for [EMAIL_1].";
        },
      }),
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });

    const stage3 = outcomeMissingGemma.run.stages.stage3;
    expect(stage3.failedOver).toBe(true);
    expect(stage3.attempts).toHaveLength(2);
    expect(stage3.attempts[0].candidateModelId).toBe("gemma4-31b");
    expect(stage3.attempts[0].passed).toBe(false);
    expect(stage3.attempts[0].candidateNodeId).toContain(
      "gemma4-31b (no separate enclave record",
    );
    expect(stage3.attempts[0].candidateNodeId).not.toContain("kimi-k3");
    expect(stage3.attempts[0].failedInvariants).toContain(
      "ModelEnclaveRecordMissingFromMatrix",
    );
    expect(stage3.attempts[0].remediationApplied).toContain(
      "No separate enclave attestation record for gemma4-31b",
    );
    expect(stage3.attempts[1].candidateModelId).toBe("kimi-k3");
    expect(stage3.attempts[1].candidateNodeId).toBe(
      "kimi-k3-inf14.tinfoil.containers.tinfoil.dev",
    );
    expect(stage3.attempts[1].passed).toBe(true);
    expect(outcomeMissingGemma.run.stages.stage2.selectedEnclaveModel).toBe(
      "kimi-k3",
    );
    expect(outcomeMissingGemma.run.stages.stage4.routedEnclaveModel).toBe(
      "kimi-k3",
    );

    const steps = buildPlainTimelineSteps({
      run: outcomeMissingGemma.run,
      plannerBadgeText: "Planned by Gemini 4 Argon",
    });
    expect(steps[1].passed).toBe(true);
    expect(steps[1].plainResult).toContain(
      "No separate seal record was published for the first sealed computer (gemma4-31b), so we switched to an alternate sealed computer (kimi-k3) whose seal check passed",
    );
    expect(findForbiddenPlainTerms(steps[1].plainResult)).toEqual([]);
  });

  it("F-05: Stage 4 refuses to open a Tinfoil session or send the prompt when C5 or C7 fails for both primary and failover models (or any of the 7 checks fails)", async () => {
    const createMatrixFetch = (
      mutateMatrix: (m: ReturnType<typeof buildMockEnclaveMatrix>) => void,
      options?: { emptyCorpus?: boolean },
    ): typeof fetch =>
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === "/api/gemini/plan") {
          const parsedDesc = JSON.parse(String(init?.body ?? "{}"));
          const { plan, egressReceipt } =
            buildMockSealedComputerPlanAndReceipt(parsedDesc);
          return new Response(
            JSON.stringify({
              ok: true,
              planner: GEMINI_4_ARGON_MODEL_ID,
              plannerSource: "sealed-google-computer",
              model: GEMINI_4_ARGON_MODEL_ID,
              interactionId: "inter-argon-turn-1",
              status: "completed",
              dataSentToGoogle: "content-free task descriptor only",
              egressFirewallVerified: true,
              plan,
              egressReceipt,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/core/attestation") {
          return new Response(
            JSON.stringify(coreAttestationFixture.attestationResponseJson),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url === "/api/relay/enclave-matrix") {
          const matrix = buildMockEnclaveMatrix();
          mutateMatrix(matrix);
          return new Response(JSON.stringify(matrix), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url === "/api/registry") {
          return new Response(JSON.stringify({ nodes: [] }), { status: 200 });
        }
        if (url === "/api/knowledge/corpus") {
          if (options?.emptyCorpus) {
            return new Response("unavailable", { status: 503 });
          }
          const corpusPayload = buildMockCorpusResponse();
          return new Response(JSON.stringify(corpusPayload), {
            status: 200,
            headers: { ETag: corpusPayload.contentSha256 },
          });
        }
        return new Response("{}", { status: 200 });
      });

    // 1. Both primary (gemma4-31b) and failover (kimi-k3) fail C5 (unverified hosts / confidential GPU check failed)
    const openSessionC5Spy = vi.fn(async () => ({
      async *send() {
        yield "Should never be called when C5 fails";
      },
    }));
    const c5Outcome = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: createMatrixFetch((m) => {
        m.models["gemma4-31b"].ccGpuFlagsVerified = false;
        m.models["kimi-k3"].ccGpuFlagsVerified = false;
      }),
      openSessionFn: openSessionC5Spy,
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });

    expect(c5Outcome.run.stages.stage2.passed).toBe(false);
    expect(c5Outcome.run.stages.stage3.passed).toBe(false);
    expect(c5Outcome.run.stages.stage3.attempts).toHaveLength(2);
    expect(c5Outcome.run.stages.stage3.attempts[0].passed).toBe(false);
    expect(c5Outcome.run.stages.stage3.attempts[1].passed).toBe(false);
    expect(c5Outcome.run.stages.stage4.passed).toBe(false);
    expect(openSessionC5Spy).not.toHaveBeenCalled();

    // 2. Both primary (gemma4-31b) and failover (kimi-k3) fail C7 (missing dmVerityRootHash / pinned weight manifest)
    const openSessionC7Spy = vi.fn(async () => ({
      async *send() {
        yield "Should never be called when C7 fails";
      },
    }));
    const c7Outcome = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: createMatrixFetch((m) => {
        m.models["gemma4-31b"].dmVerityRootHash = "";
        m.models["kimi-k3"].dmVerityRootHash = "";
      }),
      openSessionFn: openSessionC7Spy,
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });

    expect(c7Outcome.run.stages.stage2.passed).toBe(false);
    expect(c7Outcome.run.stages.stage3.passed).toBe(false);
    expect(c7Outcome.run.stages.stage4.passed).toBe(false);
    expect(openSessionC7Spy).not.toHaveBeenCalled();

    // 3. Even when C5 and C7 pass, if another of the 7 checks (e.g., check-6 corpus verification) fails, Stage 4 refuses to send
    const openSessionCheck6Spy = vi.fn(async () => ({
      async *send() {
        yield "Should never be called when any of the 7 checks fails";
      },
    }));
    const check6Outcome = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review agreement for Priya Natarajan at Halden & Moss LLP (contact priya.natarajan@example.org).",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: createMatrixFetch(() => {}, { emptyCorpus: true }),
      openSessionFn: openSessionCheck6Spy,
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });

    expect(check6Outcome.run.stages.stage3.passed).toBe(true);
    expect(check6Outcome.run.stages.stage2.passed).toBe(false);
    expect(check6Outcome.run.stages.stage4.passed).toBe(false);
    expect(openSessionCheck6Spy).not.toHaveBeenCalled();
  });

  it("F-05 & F-08: openTinfoilSession(...).send() throws on any failed check and filter fingerprint mismatch blocks runBrowserRedactionPipeline and runBrowserAgentWorkflow before anything leaves the device", async () => {
    // 1. openTinfoilSession(...).send() throws when session.checks contains a failed check
    let transmitted = false;
    const session = await openTinfoilSession("kimi-k3", {
      origin: "https://localhost:3000",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            ...buildMockEnclaveMatrix(),
            models: {
              "kimi-k3": {
                ...buildMockEnclaveMatrix().models["kimi-k3"],
                dmVerityRootHash: "",
              },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      clientFactory: () => ({
        ready: async () => {},
        getVerificationDocument: () => ({
          enclaveHost: "router-0.tinfoil.sh",
          releaseTag: "v0.0.167",
          releaseDigest:
            "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
          codeFingerprint: "abc",
          enclaveFingerprint: "def",
          hpkePublicKey: "123",
          tlsPublicKey: "456",
          selectedRouterEndpoint: "router-0.tinfoil.sh",
          configRepo: "tinfoilsh/confidential-model-router",
          securityVerified: true,
          enclaveMeasurement: {
            measurement: {
              type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
              registers: ["abc"],
            },
          },
          codeMeasurement: {
            type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            registers: ["abc"],
          },
          steps: {
            fetchDigest: { status: "success" as const },
            verifyCode: { status: "success" as const },
            verifyEnclave: { status: "success" as const },
            compareMeasurements: { status: "success" as const },
            verifyCertificate: { status: "success" as const },
          },
        }),
        chat: {
          completions: {
            create: async () => {
              transmitted = true;
              return (async function* () {
                yield { choices: [{ delta: { content: "leaked" } }] };
              })();
            },
          },
        },
      }),
    });

    expect(session.checks.find((c) => c.id === "C7")?.status).toBe("fail");
    await expect(
      (async () => {
        for await (const chunk of session.send("kimi-k3", [
          { role: "user", content: "Hello" },
        ])) {
          void chunk;
        }
      })(),
    ).rejects.toThrow(/Not verified: C7/);
    expect(transmitted).toBe(false);

    // 2. Filter fingerprint mismatch blocks runBrowserRedactionPipeline and runBrowserAgentWorkflow before anything leaves the device
    setFilterFingerprintVerifyOptionsForTests({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: `0x${"ff".repeat(32)}`,
        anchorTx: `0x${"cd".repeat(32)}`,
      },
    });

    const attestedRunnerSpy = vi.fn();
    const fetchSpy = vi.fn();
    const openSessionSpy = vi.fn();

    expect(() => assertFilterFingerprintAllowsSend()).toThrow(
      FilterFingerprintMismatchError,
    );

    await expect(
      runBrowserRedactionPipeline({
        taskPrompt: "Review agreement for Priya Natarajan.",
        attestedFilterRunner: attestedRunnerSpy,
      }),
    ).rejects.toThrow(FilterFingerprintMismatchError);
    expect(attestedRunnerSpy).not.toHaveBeenCalled();

    await expect(
      runBrowserAgentWorkflow({
        taskPrompt: "Review agreement for Priya Natarajan.",
        fetchFn: fetchSpy as unknown as typeof fetch,
        openSessionFn: openSessionSpy,
        attestedFilterRunner: attestedRunnerSpy,
      }),
    ).rejects.toThrow(FilterFingerprintMismatchError);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(openSessionSpy).not.toHaveBeenCalled();
    expect(attestedRunnerSpy).not.toHaveBeenCalled();
  });
});
