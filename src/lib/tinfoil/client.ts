import { TinfoilAI, type VerificationDocument } from "tinfoil";
import { RELAY_HOPS, padJsonPayloadToBucket } from "@/lib/relay";
import { toHex } from "@/lib/sim/bytes";
import {
  verifyModelEnclaveStatus,
  type DeepAttestationBundle,
  type ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import type { CheckResult } from "@/lib/types";

export { RELAY_HOPS };

/** Models served inside Tinfoil's attested enclaves that the demo offers. */
export const TINFOIL_MODELS = [
  { id: "kimi-k3", label: "Kimi K3 (2.8T MoE)" },
  { id: "glm-5-3", label: "GLM-5.3" },
  { id: "deepseek-v4-1-flash", label: "DeepSeek V4.1 Flash" },
  { id: "gpt-oss-120b", label: "GPT-OSS 120B" },
  { id: "llama3-3-70b", label: "Llama 3.3 70B" },
] as const;

export interface TinfoilEvidence {
  enclaveHost: string;
  releaseTag?: string;
  releaseDigest: string;
  codeFingerprint: string;
  enclaveFingerprint: string;
  measurementType: string;
  hpkePublicKey: string;
  configRepo: string;
  verifiedAt?: string;
  relayHop?: string;
  lastBucketBytes?: number;
  chipId?: string;
  tcb?: string;
  guestPolicy?: string;
  gpuEnclaveHost?: string;
  gpuVmShape?: string;
  pinnedWeights?: string;
  dmVerityRoot?: string;
  "Chip ID"?: string;
  TCB?: string;
  "Guest policy"?: string;
  "GPU enclave host"?: string;
  "GPU VM shape"?: string;
  "Pinned weights"?: string;
  "dm-verity root"?: string;
  "Relay hop"?: string;
  "Padded upload bucket"?: string;
}

export interface TinfoilSession {
  checks: CheckResult[];
  evidence: TinfoilEvidence;
  relayHop: string;
  lastBucketBytes?: number;
  deepBundle?: DeepAttestationBundle;
  selectedModelAttestation?: ModelEnclaveAttestation;
  send(model: string, messages: { role: "user" | "assistant"; content: string }[]): AsyncIterable<string>;
}

type Step = VerificationDocument["steps"][keyof VerificationDocument["steps"]];

function stepStatus(step: Step | undefined): CheckResult["status"] {
  if (!step) return "skip";
  if (step.status === "success") return "pass";
  if (step.status === "failed") return "fail";
  return "skip";
}

function stepDetail(step: Step | undefined, ok: string): string {
  if (!step) return "Not reported by the verifier";
  if (step.status === "failed") return step.error ?? "Failed";
  if (step.status === "success") return ok;
  return `Status: ${step.status}`;
}

/** Maps Tinfoil's verification document onto the dRouter checklist (C1–C7). */
export function checksFromDocument(
  doc: VerificationDocument,
  modelAttestation?: ModelEnclaveAttestation,
): CheckResult[] {
  const s = doc.steps;
  const both = (a: Step | undefined, b: Step | undefined): CheckResult["status"] =>
    stepStatus(a) === "fail" || stepStatus(b) === "fail"
      ? "fail"
      : stepStatus(a) === "pass" && stepStatus(b) === "pass"
        ? "pass"
        : "skip";

  const modelStatus = modelAttestation ? verifyModelEnclaveStatus(modelAttestation) : null;

  return [
    {
      id: "C1",
      label: "Hardware signature chain",
      status: stepStatus(s.verifyEnclave),
      detail: stepDetail(
        s.verifyEnclave,
        `AMD SEV-SNP report verified to AMD's root (${doc.enclaveMeasurement.measurement.type})`,
      ),
    },
    {
      id: "C2",
      label: "Approved software",
      status: both(s.fetchDigest, s.verifyCode),
      detail:
        both(s.fetchDigest, s.verifyCode) === "pass"
          ? `Signed release ${doc.releaseTag ?? doc.releaseDigest.slice(0, 12)} of ${doc.configRepo}, checked in the Sigstore transparency log`
          : stepDetail(s.verifyCode ?? s.fetchDigest, ""),
    },
    {
      id: "C3",
      label: "Fresh and bound to this session",
      status: stepStatus(s.verifyCertificate),
      detail: stepDetail(
        s.verifyCertificate,
        "Encryption key is committed to by the attestation; requests are HPKE-encrypted to it",
      ),
    },
    {
      id: "C4",
      label: "Running code = released code",
      status: stepStatus(s.compareMeasurements),
      detail: stepDetail(s.compareMeasurements, "Launch measurement equals the signed release measurement"),
    },
    {
      id: "C5",
      label: "GPUs in confidential mode",
      status: modelStatus ? (modelStatus.c5Pass ? "pass" : "fail") : "skip",
      detail: modelStatus
        ? modelStatus.c5Detail
        : "Tinfoil's browser verifier does not expose GPU reports; the router enclave attests the model enclaves",
    },
    {
      id: "C6",
      label: "Registry admission",
      status: "skip",
      detail: "Checked against the Arc registry by the app",
    },
    {
      id: "C7",
      label: "Committed model",
      status: modelStatus ? (modelStatus.c7Pass ? "pass" : "fail") : "pass",
      detail: modelStatus
        ? modelStatus.c7Detail
        : "Model name is sent in a header and the enclave rejects requests whose encrypted body names a different model",
    },
  ];
}

function evidenceFromDocument(
  doc: VerificationDocument,
  deepBundle?: DeepAttestationBundle,
  modelAttestation?: ModelEnclaveAttestation,
  relayHop?: string,
): TinfoilEvidence {
  const snp = deepBundle?.routerSnpReport;
  const chipId = snp ? `${snp.chipIdHex.slice(0, 16)}…${snp.chipIdHex.slice(-8)}` : undefined;
  const tcb = snp
    ? `bl=${snp.tcb.bootloader} tee=${snp.tcb.tee} snp=${snp.tcb.snp} ucode=${snp.tcb.microcode} fmc=${snp.tcb.fmc}`
    : undefined;
  const guestPolicy = snp
    ? `${snp.policyHex} (debug=${snp.debugAllowed ? "on" : "off"}, smt=${snp.smtAllowed ? "on" : "off"}, migrate=${snp.migrationAllowed ? "on" : "off"})`
    : undefined;

  const primaryGpuHost = modelAttestation?.enclaveHosts[0]?.host;
  const gpuEnclaveHost = modelAttestation
    ? `${primaryGpuHost ?? modelAttestation.repo} (${modelAttestation.healthyHosts}/${modelAttestation.configuredHosts} healthy)`
    : undefined;
  const gpuVmShape = modelAttestation
    ? `${modelAttestation.vmShape.gpus}× GPU · ${modelAttestation.vmShape.cpus} vCPU · ${Math.round(modelAttestation.vmShape.memoryMb / 1024)} GB RAM`
    : undefined;
  const pinnedWeights = modelAttestation
    ? `${modelAttestation.weightRepoCommit} (mpk-${modelAttestation.weightMpkHash.replace(/^mpk-/, "").slice(0, 12)}…)`
    : undefined;
  const dmVerityRoot = modelAttestation?.dmVerityRootHash;

  return {
    enclaveHost: doc.enclaveHost,
    releaseTag: doc.releaseTag,
    releaseDigest: doc.releaseDigest,
    codeFingerprint: doc.codeFingerprint,
    enclaveFingerprint: doc.enclaveFingerprint,
    measurementType: doc.enclaveMeasurement.measurement.type,
    hpkePublicKey: doc.hpkePublicKey,
    configRepo: doc.configRepo,
    verifiedAt: doc.verifiedAt,
    ...(relayHop ? { relayHop, "Relay hop": relayHop } : {}),
    ...(chipId ? { chipId, "Chip ID": chipId } : {}),
    ...(tcb ? { tcb, TCB: tcb } : {}),
    ...(guestPolicy ? { guestPolicy, "Guest policy": guestPolicy } : {}),
    ...(gpuEnclaveHost ? { gpuEnclaveHost, "GPU enclave host": gpuEnclaveHost } : {}),
    ...(gpuVmShape ? { gpuVmShape, "GPU VM shape": gpuVmShape } : {}),
    ...(pinnedWeights ? { pinnedWeights, "Pinned weights": pinnedWeights } : {}),
    ...(dmVerityRoot ? { dmVerityRoot, "dm-verity root": dmVerityRoot } : {}),
  };
}

/**
 * Verifies a Tinfoil enclave in this browser, then returns a session whose requests are encrypted
 * to that enclave and sent through the dRouter relay. The relay adds the API key but cannot read
 * prompts or completions.
 */
export async function openTinfoilSession(
  selectedModel = "kimi-k3",
  opts?: { relayId?: string; rotateRelayPerTurn?: boolean },
): Promise<TinfoilSession> {
  const origin = window.location.origin;
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const userCacheSecret = toHex(secretBytes);

  const initialRelayId = opts?.relayId;
  const baseURL = initialRelayId
    ? `${origin}/api/relay/${initialRelayId}/v1/`
    : `${origin}/api/relay/v1/`;
  const attestationBundleURL = initialRelayId
    ? `${origin}/api/relay/${initialRelayId}`
    : `${origin}/api/relay`;

  const client = new TinfoilAI({
    bearerToken: "drouter-demo",
    baseURL,
    attestationBundleURL,
    userCacheSecret,
  });

  const matrixPromise: Promise<DeepAttestationBundle | undefined> = fetch(
    `${origin}/api/relay/enclave-matrix`,
  )
    .then(async (res) => (res.ok ? ((await res.json()) as DeepAttestationBundle) : undefined))
    .catch(() => undefined);

  let deepBundle: DeepAttestationBundle | undefined;
  try {
    const [, fetchedBundle] = await Promise.all([client.ready(), matrixPromise]);
    deepBundle = fetchedBundle;
  } catch (error) {
    let checks: CheckResult[] = [];
    try {
      checks = checksFromDocument(await client.getVerificationDocument());
    } catch {
      // Verification failed before a document existed.
    }
    const failed = checks.find((c) => c.status === "fail");
    throw Object.assign(
      new Error(failed ? `${failed.id} ${failed.label}: ${failed.detail}` : String(error)),
      { checks },
    );
  }

  const doc = await client.getVerificationDocument();
  const selectedModelAttestation =
    deepBundle?.models[selectedModel] ?? deepBundle?.models["kimi-k3"];

  let activeRelayHop: string = initialRelayId ?? RELAY_HOPS[0].id;
  let turnCounter = Math.max(
    0,
    RELAY_HOPS.findIndex((h) => h.id === activeRelayHop),
  );

  // Intercept the internal encrypted transport fetch so that:
  // 1. Plaintext JSON bodies are padded to a power-of-two byte bucket (RFC 8259 trailing spaces)
  //    immediately before HPKE sealing.
  // 2. Multi-relay hop rotation rewrites the relay hop route per turn when enabled.
  const internalTransport = (
    client as unknown as {
      secureClient?: { _transport?: { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> } };
    }
  ).secureClient?._transport;
  if (internalTransport && typeof internalTransport.fetch === "function") {
    const origFetch = internalTransport.fetch.bind(internalTransport);
    internalTransport.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      let nextInput = input;
      if (opts?.rotateRelayPerTurn && typeof input === "string") {
        nextInput = input.replace(
          /\/api\/relay\/(?:[^/]+\/)?v1\//,
          `/api/relay/${activeRelayHop}/v1/`,
        );
      }
      if (init && typeof init.body === "string") {
        try {
          const parsed = JSON.parse(init.body) as Record<string, unknown>;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            if (!parsed.user_cache_secret) {
              parsed.user_cache_secret = userCacheSecret;
            }
            const { paddedJson } = padJsonPayloadToBucket(JSON.stringify(parsed));
            init = { ...init, body: paddedJson };
          }
        } catch {
          // Non-JSON body; leave unchanged.
        }
      }
      return origFetch(nextInput, init);
    };
  }

  const evidence = evidenceFromDocument(doc, deepBundle, selectedModelAttestation, activeRelayHop);

  const session: TinfoilSession = {
    checks: checksFromDocument(doc, selectedModelAttestation),
    evidence,
    relayHop: activeRelayHop,
    deepBundle,
    selectedModelAttestation,
    async *send(model, messages) {
      if (opts?.rotateRelayPerTurn) {
        turnCounter = (turnCounter + 1) % RELAY_HOPS.length;
        activeRelayHop = RELAY_HOPS[turnCounter].id;
        session.relayHop = activeRelayHop;
        evidence.relayHop = activeRelayHop;
        evidence["Relay hop"] = activeRelayHop;
      }
      const { bucketBytes } = padJsonPayloadToBucket(
        JSON.stringify({ model, messages, stream: true }),
      );
      session.lastBucketBytes = bucketBytes;
      evidence.lastBucketBytes = bucketBytes;
      evidence["Padded upload bucket"] = `${bucketBytes.toLocaleString("en-US")} B (RFC 8259 padded)`;

      const stream = await client.chat.completions.create(
        { model, messages, stream: true },
        { headers: { "X-Tinfoil-Model": model, "X-DRouter-Cadence-Ms": "50" } },
      );
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta?.content;
        if (delta) yield delta;
      }
    },
  };

  return session;
}
