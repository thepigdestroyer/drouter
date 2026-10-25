import fs from "node:fs";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type * as x509Types from "@peculiar/x509";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ATLAS_SEED_DOCS, runAtlasHybridSearch } from "@/lib/atlas";
import {
  computeAttestedKeysDigest,
  computeTlsCertSpkiSha256,
  DEFAULT_CONFIDENTIAL_SPACE_AUDIENCE,
  ensureReflectMetadata,
  EXPECTED_CONFIDENTIAL_SPACE_ISSUER,
} from "@/lib/attestation/confidential-space";
import {
  buildGeminiCreateRequestFromDescriptor,
  clearCorpusCache,
  computeCorpusContentSha256,
  geminiEgressSigningPayload,
  NEXT_SERVER_RECEIPT_LABEL,
  runBrowserAgentWorkflow,
  SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
  sortCorpusDocuments,
} from "@/lib/agent-client";
import {
  GEMINI_4_ARGON_MODEL_ID,
  HONEST_DATA_HANDLING_STATEMENT,
  type ClosedAgentPlan,
  type GeminiEgressReceipt,
} from "@/lib/gemini";
import { coarsenEpochSecToHour, signTreeHead } from "@/lib/transparency/log";
import {
  AGENT_INTRO_SENTENCE,
  APPROVAL_CARD_QUESTION,
  buildPlainTimelineSteps,
  DEFAULT_PLAIN_TASK_PROMPT,
  DEVICE_PREPARATION_PLAIN_SENTENCE,
  EXAMPLE_AGENT_TASKS,
  findForbiddenPlainTerms,
  formatCleanRunJsonForDisplay,
  formatEgressReceiptDisplay,
  formatPlainAtlasResult,
  formatPlainDataHandling,
  formatPlainRedactionCounts,
  formatPlainRestoredOutput,
  formatPlainStage1Summary,
  PLAIN_ATLAS_PRESET_QUERIES,
  resolveEffectiveAtlasQuery,
  resolvePlannerModeBadgeText,
  resolvePlannerSubtitleText,
  sanitizeJargonToPlainWords,
  WHAT_GOOGLE_RECEIVED_PROMPT,
} from "@/components/argon/argon-helpers";

const TEST_NOW_SEC = 1_792_886_400;
const TEST_CORE_IMAGE_DIGEST =
  "sha256:4a5d8e2c79a416b1f81c36f0b9e1e2c5f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4";
const SEALED_SECRET_KEY = new Uint8Array(32).fill(0x21);
const SEALED_PUBLIC_KEY_HEX = bytesToHex(
  ed25519.getPublicKey(SEALED_SECRET_KEY),
).toLowerCase();

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
    tree: "22".repeat(32),
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

  process.env.NEXT_PUBLIC_CORE_IMAGE_DIGESTS = TEST_CORE_IMAGE_DIGEST;
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

const BANNED_SCRIPTED_STRINGS = [
  "Riverside",
  "Northvale",
  "ASSAY-774",
  "quarantined",
  "self-heal",
  "faulty computer",
] as const;

function buildMockEnclaveMatrix(opts?: { breakGemma?: boolean }) {
  const dmVerityGemma =
    "8b4029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f1a";
  const dmVerityKimi =
    "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c";

  return {
    status: "verified",
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
        status: "router-attested",
        repo: "tinfoilsh/confidential-gemma4-31b",
        tag: "v0.0.12",
        hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)",
        configuredHosts: 1,
        verifiedHosts: opts?.breakGemma ? 0 : 1,
        healthyHosts: opts?.breakGemma ? 0 : 1,
        unverifiedHosts: opts?.breakGemma ? 1 : 0,
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
        measurementRegisters: opts?.breakGemma
          ? []
          : [`${dmVerityGemma}980bb51973cdf396404412ebb7c1a7b7`],
        vmShape: { cpus: 32, memoryMb: 262144, gpus: 8, disks: 1 },
        dmVerityRootHash: opts?.breakGemma ? "" : dmVerityGemma,
        kernelHash:
          "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff",
        initrdHash:
          "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e7",
        containerImageDigest: `sha256:${dmVerityGemma}`,
        weightRepoCommit: "tinfoilsh/confidential-gemma4-31b@v0.0.12",
        weightMpkHash: dmVerityGemma,
        ccGpuFlagsVerified: !opts?.breakGemma,
        releaseUrl:
          "https://github.com/tinfoilsh/confidential-gemma4-31b/releases/tag/v0.0.12",
        sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityGemma}`,
      },
      "kimi-k3": {
        modelId: "kimi-k3",
        status: "router-attested",
        repo: "tinfoilsh/confidential-kimi-k3",
        tag: "v0.0.15",
        hardwarePredicate: "https://tinfoil.sh/predicate/tdx-guest/v2",
        tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)",
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
        measurementRegisters: [
          `${dmVerityKimi}980bb51973cdf396404412ebb7c1a7b7`,
        ],
        vmShape: { cpus: 32, memoryMb: 262144, gpus: 8, disks: 1 },
        dmVerityRootHash: dmVerityKimi,
        kernelHash:
          "7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff",
        initrdHash:
          "2c23dba70e90589414b334be5b648fab4ead1d5b17ef355f04fd7ede2a9e2e7",
        containerImageDigest: `sha256:${dmVerityKimi}`,
        weightRepoCommit: "tinfoilsh/confidential-kimi-k3@v0.0.15",
        weightMpkHash: dmVerityKimi,
        ccGpuFlagsVerified: true,
        releaseUrl:
          "https://github.com/tinfoilsh/confidential-kimi-k3/releases/tag/v0.0.15",
        sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${dmVerityKimi}`,
      },
    },
  };
}

function createMockBrowserFetch(opts?: {
  signer?: "sealed-google-computer" | "next-server";
  plannerUnavailable?: boolean;
  breakGemma?: boolean;
}): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "/api/gemini/plan") {
      if (opts?.plannerUnavailable) {
        return new Response(
          JSON.stringify({
            ok: false,
            planner: "unavailable",
            error: "planner_unavailable",
            message: "Gemini planner is unavailable.",
            dataSentToGoogle: "none (planner unavailable)",
            egressFirewallVerified: true,
            plan: null,
            egressReceipt: null,
          }),
          { status: 503, headers: { "Content-Type": "application/json" } },
        );
      }

      const descriptor = JSON.parse(String(init?.body ?? "{}"));
      const { validatedDescriptor, canonicalRequest, requestSha256 } =
        buildGeminiCreateRequestFromDescriptor(descriptor);
      const epochHourSec = coarsenEpochSecToHour(1_792_886_400);

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

      const signer = opts?.signer ?? "next-server";
      let egressReceipt: GeminiEgressReceipt;

      if (signer === "sealed-google-computer") {
        const secretKey = new Uint8Array(32).fill(0x21);
        const publicKeyHex = bytesToHex(
          ed25519.getPublicKey(secretKey),
        ).toLowerCase();
        const sigBytes = ed25519.sign(
          geminiEgressSigningPayload({ sha256: requestSha256, epochHourSec }),
          secretKey,
        );
        egressReceipt = {
          canonicalRequest,
          sha256: requestSha256,
          epochHourSec,
          kind: "gemini-egress",
          signer: "sealed-google-computer",
          signerLabel: SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
          signature: bytesToHex(sigBytes).toLowerCase(),
          publicKey: publicKeyHex,
          keyId: "egress-signing",
        };
      } else {
        const sth = signTreeHead({
          treeSize: 1,
          rootHash: requestSha256,
          timestampSec: epochHourSec,
        });
        egressReceipt = {
          canonicalRequest,
          sha256: requestSha256,
          epochHourSec: sth.timestampSec,
          kind: "gemini-egress",
          signer: "next-server",
          signerLabel: NEXT_SERVER_RECEIPT_LABEL,
          signature: sth.signature,
          publicKey: sth.operatorPublicKey,
          keyId: "operator-tree-head",
          transparencyLog: {
            leafIndex: 0,
            leafHash: requestSha256,
            treeSize: 1,
            rootHash: sth.rootHash,
            operatorPublicKey: sth.operatorPublicKey,
            treeHeadSignature: sth.signature,
          },
        };
      }

      return new Response(
        JSON.stringify({
          ok: true,
          planner: GEMINI_4_ARGON_MODEL_ID,
          plannerSource: signer,
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
      return new Response(
        JSON.stringify(
          buildMockEnclaveMatrix({ breakGemma: opts?.breakGemma }),
        ),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
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
      return new Response(
        JSON.stringify({
          database: "drouter",
          collection: "enclave_intelligence",
          documentCount: docs.length,
          contentSha256,
          documents: docs,
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ETag: contentSha256,
          },
        },
      );
    }

    if (url === "/api/anchor") {
      return new Response(
        JSON.stringify({
          txHash: `0x${"ab".repeat(32)}`,
          explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
          onChain: true,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    return new Response("{}", { status: 200 });
  });
}

function createEchoPlaceholderSession(prefixText = "Completed private analysis.") {
  return async (_model: "gemma4-31b" | "kimi-k3") => ({
    async *send(
      _mdl: string,
      messages: { role: "user" | "assistant"; content: string }[],
    ) {
      const userContent =
        messages.find((m) => m.role === "user")?.content ?? "";
      const placeholderMatches = Array.from(
        new Set(
          userContent.match(
            /\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY|URL|ADDRESS|DATE|NAME|DIGITS|ENTROPY)_\d+\]/g,
          ) ?? [],
        ),
      );
      yield `${prefixText} Verified items: ${placeholderMatches.join(", ")}.`;
    },
  });
}

afterEach(() => {
  clearCorpusCache();
});

describe("deRoute wave 6 Argon browser agent & plain-language helpers", () => {
  it("uses exact required intro sentence, approval question, Google descriptor heading, and 2 plain example tasks with zero forbidden terms", () => {
    expect(AGENT_INTRO_SENTENCE).toBe(
      "Give it a private task. It hides your personal details, checks the sealed computer, does the work, and asks you before it records anything in public.",
    );
    expect(APPROVAL_CARD_QUESTION).toBe(
      "Allow the agent to record a receipt in the public receipt book?",
    );
    expect(WHAT_GOOGLE_RECEIVED_PROMPT).toBe(
      "Gemini planned the steps without seeing your words. What Google received:",
    );
    expect(EXAMPLE_AGENT_TASKS).toHaveLength(2);
    expect(DEFAULT_PLAIN_TASK_PROMPT).toBe(EXAMPLE_AGENT_TASKS[0].prompt);

    const dataHandlingView = formatPlainDataHandling(
      HONEST_DATA_HANDLING_STATEMENT,
    );

    for (const str of [
      AGENT_INTRO_SENTENCE,
      APPROVAL_CARD_QUESTION,
      WHAT_GOOGLE_RECEIVED_PROMPT,
      dataHandlingView.headline,
      dataHandlingView.sentToGooglePlain,
      dataHandlingView.sealedComputerCanSeePlain,
      ...dataHandlingView.googleCanSeePlain,
      ...dataHandlingView.googleCannotSeePlain,
      ...EXAMPLE_AGENT_TASKS.flatMap((t) => [t.label, t.description, t.prompt]),
    ]) {
      expect(findForbiddenPlainTerms(str)).toEqual([]);
      expect(str).not.toContain("dRouter");
      expect(str).not.toMatch(/[\u2013\u2014]/);
      expect(str.toLowerCase()).not.toContain("simulat");
      expect(str.toLowerCase()).not.toContain("practice");
    }
  });

  it("formats honest planner line, subtitle, and egress receipt display for Gemini 4 Argon, planner unavailable, and both receipt signers", async () => {
    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "gemini", model: "gemini-4-argon" },
        mode: "live",
      }),
    ).toBe("Planned by Gemini 4 Argon");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "gemini", model: "unavailable" },
        plannerStatus: "unavailable",
        mode: "planner-unavailable",
      }),
    ).toBe("Planner unavailable (no Gemini key is set)");

    expect(
      resolvePlannerModeBadgeText({
        planner: { provider: "tinfoil", model: "gemma4-31b" },
      }),
    ).toBe("Planned by gemma4-31b because no Gemini key is set");

    const liveSub = resolvePlannerSubtitleText({
      isLiveGeminiBadge: true,
      attemptedLiveCall: true,
      liveGeminiReached: true,
    });
    expect(liveSub).toContain(
      "Gemini planned the steps without seeing your words.",
    );
    expect(findForbiddenPlainTerms(liveSub)).toEqual([]);

    const unavailableSub = resolvePlannerSubtitleText({
      isLiveGeminiBadge: false,
      plannerUnavailable: true,
    });
    expect(unavailableSub).toContain("Gemini planner is unavailable");
    expect(findForbiddenPlainTerms(unavailableSub)).toEqual([]);

    // Receipt display for Signer 1 (sealed Google computer) and Signer 2 (recorded by our server)
    const runSealed = await runBrowserAgentWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      fetchFn: createMockBrowserFetch({ signer: "sealed-google-computer" }),
      openSessionFn: createEchoPlaceholderSession(),
      coreAttestationOptions: {
        pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
        nowSec: TEST_NOW_SEC,
      },
    });
    const receiptDisplaySealed = formatEgressReceiptDisplay(
      runSealed.run.egressReceipt,
    );
    expect(receiptDisplaySealed.hasReceipt).toBe(true);
    expect(receiptDisplaySealed.signer).toBe("sealed-google-computer");
    expect(receiptDisplaySealed.signerHeading).toBe(
      SEALED_GOOGLE_COMPUTER_RECEIPT_LABEL,
    );
    expect(receiptDisplaySealed.canonicalBytes).toContain("gemini-4-argon");

    const runServer = await runBrowserAgentWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      fetchFn: createMockBrowserFetch({ signer: "next-server" }),
      openSessionFn: createEchoPlaceholderSession(),
    });
    const receiptDisplayServer = formatEgressReceiptDisplay(
      runServer.run.egressReceipt,
    );
    expect(receiptDisplayServer.hasReceipt).toBe(true);
    expect(receiptDisplayServer.signer).toBe("next-server");
    expect(receiptDisplayServer.signerHeading).toBe(NEXT_SERVER_RECEIPT_LABEL);
    expect(receiptDisplayServer.signerHeading.toLowerCase()).toContain(
      "recorded by our server",
    );
    expect(receiptDisplayServer.canonicalBytes).toBe(
      receiptDisplaySealed.canonicalBytes,
    );
  });

  it("builds 5 plain timeline steps using checksPassed/checksTotal with zero forbidden jargon words and passes all stages for arbitrary tasks in the browser", async () => {
    const arbitraryTasks = [
      {
        prompt:
          "Draft a legal memo for Priya Natarajan at Halden & Moss LLP regarding the 2026-05-10 acquisition ($250,000.00, contact priya.natarajan@haldenmoss.example, key sk-live-9a8b7c6d5e4f3a2b1c0d).",
        alwaysHide: ["Halden & Moss LLP"],
        expectedRestored: [
          "Priya Natarajan",
          "Halden & Moss LLP",
          "priya.natarajan@haldenmoss.example",
        ],
      },
      {
        prompt:
          "Review our authentication middleware configured by dev-sec@acme-corp.example using API key sk-proj-8f7e6d5c4b3a2918273645 and token ghp_1234567890abcdefghijklmnopqrstuvwx on 2026-11-01.",
        alwaysHide: [],
        expectedRestored: [
          "dev-sec@acme-corp.example",
          "sk-proj-8f7e6d5c4b3a2918273645",
        ],
      },
    ];

    for (const task of arbitraryTasks) {
      const { run } = await runBrowserAgentWorkflow({
        taskPrompt: task.prompt,
        alwaysHide: task.alwaysHide,
        thinkingLevel: "medium",
        background: true,
        humanApprovedExternalAction: false,
        preferredEnclaveModel: "gemma4-31b",
        fetchFn: createMockBrowserFetch({ signer: "sealed-google-computer" }),
        openSessionFn: createEchoPlaceholderSession("Completed review."),
        coreAttestationOptions: {
          pinnedRootCaPem: coreAttestationFixture.pinnedRootCaPem,
          nowSec: TEST_NOW_SEC,
        },
      });

      expect(run.mode).toBe("live");
      expect(run.overallPassed).toBe(true);
      expect(run.stages.stage1.redactionCount).toBeGreaterThanOrEqual(3);
      expect(
        run.stages.stage4.verificationSignal.homomorphicRestoreVerified,
      ).toBe(true);

      const summaryNo = formatPlainStage1Summary(run.stages.stage1);
      expect(summaryNo).toContain(
        `${run.stages.stage1.redactionCount} personal details hidden; second check inside a sealed computer: no`,
      );
      expect(findForbiddenPlainTerms(summaryNo)).toEqual([]);

      const countsStr = formatPlainRedactionCounts(
        run.stages.stage1.redactionCounts,
      );
      expect(countsStr).toContain("email");
      expect(countsStr).toContain("secret key");
      expect(findForbiddenPlainTerms(countsStr)).toEqual([]);

      const plannerBadgeText = resolvePlannerModeBadgeText({
        planner: run.planner,
        mode: run.mode,
      });

      const steps = buildPlainTimelineSteps({
        run,
        plannerBadgeText,
        arcAnchor: null,
      });

      expect(steps.map((s) => s.title)).toEqual([
        "Hiding your details",
        "Checking the seal",
        "Thinking",
        "Waiting for you",
        "Done",
      ]);

      expect(steps[0].passed).toBe(true);
      expect(steps[1].passed).toBe(true);
      expect(steps[1].plainResult).toContain(
        `${run.stages.stage2.verificationSignal.checksPassed} of ${run.stages.stage2.verificationSignal.checksTotal} safety checks passed`,
      );
      expect(steps[2].passed).toBe(true);
      expect(steps[2].plainResult).toContain(
        "Gemini planned the steps without seeing your words.",
      );
      expect(steps[3].passed).toBe(false);
      expect(steps[4].passed).toBe(true);
      expect(steps[4].plainResult).not.toContain("$INPUT");

      for (const step of steps) {
        expect(findForbiddenPlainTerms(step.title)).toEqual([]);
        expect(findForbiddenPlainTerms(step.statusText)).toEqual([]);
        expect(findForbiddenPlainTerms(step.plainResult)).toEqual([]);
        expect(step.plainResult).not.toContain("dRouter");
        expect(step.plainResult).not.toMatch(/[\u2013\u2014]/);
        expect(step.plainResult.toLowerCase()).not.toContain("simulat");
        expect(step.plainResult.toLowerCase()).not.toContain("practice");
      }

      const plainRestored = formatPlainRestoredOutput(
        run.stages.stage4.restoredClientOutput,
        true,
      );
      expect(findForbiddenPlainTerms(plainRestored)).toEqual([]);
      for (const expStr of task.expectedRestored) {
        expect(plainRestored).toContain(expStr);
      }
      expect(plainRestored).not.toContain("$INPUT");

      const cleanJson = JSON.stringify(formatCleanRunJsonForDisplay(run));
      for (const banned of BANNED_SCRIPTED_STRINGS) {
        expect(cleanJson.toLowerCase()).not.toContain(banned.toLowerCase());
      }
    }
  });

  it("handles model returning nothing, planner unavailable, and real node verification failover honestly in buildPlainTimelineSteps", async () => {
    // 1. Enclave model returns nothing -> Stage 4 fails honestly with "The sealed computer did not return an answer"
    const { run: noAnswerRun } = await runBrowserAgentWorkflow({
      taskPrompt:
        "Review code for dev@acme.example with key sk-live-9f8e7d6c5b4a3210fedcba98.",
      fetchFn: createMockBrowserFetch(),
      openSessionFn: async () => ({
        async *send() {
          // yield nothing
        },
      }),
    });

    expect(noAnswerRun.stages.stage4.passed).toBe(false);
    expect(noAnswerRun.stages.stage4.restoredClientOutput).toBe(
      "The sealed computer did not return an answer",
    );
    expect(noAnswerRun.overallPassed).toBe(false);

    const noAnswerSteps = buildPlainTimelineSteps({
      run: noAnswerRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      arcAnchor: null,
    });
    expect(noAnswerSteps[2].passed).toBe(false);
    expect(noAnswerSteps[2].plainResult).toContain(
      "The sealed computer did not return an answer",
    );
    expect(noAnswerSteps[4].passed).toBe(false);
    expect(noAnswerSteps[4].plainResult).toContain(
      "The sealed computer did not return an answer",
    );

    // 2. Selected node fails real verification -> honest failover message
    const { run: failoverRun } = await runBrowserAgentWorkflow({
      taskPrompt:
        "Draft a legal memo for Priya Natarajan at Halden & Moss LLP.",
      alwaysHide: ["Halden & Moss LLP"],
      preferredEnclaveModel: "gemma4-31b",
      fetchFn: createMockBrowserFetch({ breakGemma: true }),
      openSessionFn: createEchoPlaceholderSession("Completed on backup."),
    });

    expect(failoverRun.stages.stage3.failedOver).toBe(true);
    expect(failoverRun.overallPassed).toBe(true);

    const failoverSteps = buildPlainTimelineSteps({
      run: failoverRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      arcAnchor: null,
    });
    expect(failoverSteps[1].passed).toBe(true);
    expect(failoverSteps[1].plainResult).toContain(
      "The seal check on the first sealed computer (gemma4-31b) failed, so we switched to an alternate sealed computer (kimi-k3) whose seal check passed",
    );
    expect(findForbiddenPlainTerms(failoverSteps[1].plainResult)).toEqual([]);
  });

  it("translates all 16 Atlas seed docs and preset queries into plain words with zero forbidden terms", async () => {
    for (const preset of PLAIN_ATLAS_PRESET_QUERIES) {
      expect(findForbiddenPlainTerms(preset.label)).toEqual([]);
      expect(findForbiddenPlainTerms(preset.query)).toEqual([]);
      expect(resolveEffectiveAtlasQuery(preset.label)).toBe(preset.query);
      const res = await runAtlasHybridSearch(preset.query, { limit: 4 });
      expect(res.results.length).toBeGreaterThan(0);
    }

    for (const doc of ATLAS_SEED_DOCS) {
      const plain = formatPlainAtlasResult(doc);
      expect(findForbiddenPlainTerms(plain.title)).toEqual([]);
      expect(findForbiddenPlainTerms(plain.categoryLabel)).toEqual([]);
      expect(findForbiddenPlainTerms(plain.summary)).toEqual([]);
      expect(plain.title).not.toContain("dRouter");
      expect(plain.summary).not.toContain("dRouter");
      expect(plain.summary).not.toMatch(/[\u2013\u2014]/);
      expect(plain.summary).not.toContain("1,344");
    }

    const dynamic = sanitizeJargonToPlainWords(
      "dRouter verifies AMD SEV-SNP and Intel TDX enclave attestation with HPKE RFC 9180, RSA nullifiers, Sigstore Rekor, dm-verity measurement, ciphertext digest, and Arc testnet.",
    );
    expect(findForbiddenPlainTerms(dynamic)).toEqual([]);
    expect(dynamic).toContain("deRoute");
    expect(dynamic).not.toContain("dRouter");
  });

  it("handles Allow (broadcast and fallback) and Not now states in buildPlainTimelineSteps with zero forbidden terms", async () => {
    const { run: approvedRun } = await runBrowserAgentWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[1].prompt,
      thinkingLevel: "high",
      background: true,
      humanApprovedExternalAction: true,
      preferredEnclaveModel: "kimi-k3",
      fetchFn: createMockBrowserFetch(),
      openSessionFn: createEchoPlaceholderSession(),
    });

    const stepsBroadcast = buildPlainTimelineSteps({
      run: approvedRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      arcAnchor: {
        broadcast: true,
        txHash: `0x${"ab".repeat(32)}`,
        explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
        receiptHash: `0x${"cd".repeat(32)}`,
      },
      hasLiveModelCalls: true,
    });

    expect(stepsBroadcast[3].title).toBe("Waiting for you");
    expect(stepsBroadcast[3].passed).toBe(true);
    expect(stepsBroadcast[3].statusText).toBe("Recorded");
    expect(stepsBroadcast[3].plainResult).toContain(
      "A receipt was recorded in the public receipt book.",
    );

    for (const s of stepsBroadcast) {
      expect(findForbiddenPlainTerms(s.plainResult)).toEqual([]);
      expect(findForbiddenPlainTerms(s.statusText)).toEqual([]);
    }

    const stepsSkippedBroadcast = buildPlainTimelineSteps({
      run: approvedRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      arcAnchor: {
        broadcast: false,
        reason: "Run digest is not a 32-byte hash on Arc testnet.",
      },
    });

    expect(stepsSkippedBroadcast[3].passed).toBe(true);
    expect(
      findForbiddenPlainTerms(stepsSkippedBroadcast[3].plainResult),
    ).toEqual([]);

    const { run: pendingRun } = await runBrowserAgentWorkflow({
      taskPrompt: EXAMPLE_AGENT_TASKS[0].prompt,
      humanApprovedExternalAction: false,
      fetchFn: createMockBrowserFetch(),
      openSessionFn: createEchoPlaceholderSession(),
    });

    const stepsNotNow = buildPlainTimelineSteps({
      run: pendingRun,
      plannerBadgeText: "Planned by Gemini 4 Argon",
      userDeclinedApproval: true,
    });

    expect(stepsNotNow[3].passed).toBe(false);
    expect(stepsNotNow[3].statusText).toBe("Not recorded");
    expect(stepsNotNow[3].plainResult).toContain("Not now");
    expect(findForbiddenPlainTerms(stepsNotNow[3].plainResult)).toEqual([]);
  });

  it("ensures unexpanded JSX outside TechDetails and page/helper copy contain zero forbidden jargon, dRouter, simulated items, or scripted hospital/fault terms", () => {
    const repoRoot = path.resolve(__dirname, "../..");
    const filesToCheck = [
      "src/app/argon/page.tsx",
      "src/components/argon/argon-helpers.ts",
      "src/components/atlas-explorer.tsx",
    ];

    for (const relPath of filesToCheck) {
      const fullSource = fs.readFileSync(path.join(repoRoot, relPath), "utf8");

      expect(fullSource).not.toContain("slash_faulty_node");
      expect(fullSource).not.toContain("pipelineReport");
      expect(fullSource).not.toContain("quorumValidSignatures");
      expect(fullSource).not.toContain("vmpl0StatesChecked");
      expect(fullSource).not.toContain("memory-bus");
      expect(fullSource).not.toContain("unlockVaultWithKeyMaterial");
      for (const banned of BANNED_SCRIPTED_STRINGS) {
        expect(fullSource.toLowerCase()).not.toContain(banned.toLowerCase());
      }

      if (relPath.endsWith(".tsx")) {
        expect(fullSource.toLowerCase()).not.toContain("simulat");
        expect(fullSource.toLowerCase()).not.toContain("practice");

        const withoutTechDetails = fullSource.replace(
          /<TechDetails[\s\S]*?<\/TechDetails>/g,
          "",
        );

        const jsxTextNodes = Array.from(
          withoutTechDetails.matchAll(/>([^<>{}]+)</g),
        )
          .map((m) => m[1].trim())
          .filter((t) => t.length > 0);

        for (const textNode of jsxTextNodes) {
          expect(findForbiddenPlainTerms(textNode)).toEqual([]);
          expect(textNode).not.toContain("dRouter");
          expect(textNode).not.toMatch(/[\u2013\u2014]/);
        }
      }
    }
  });
});
