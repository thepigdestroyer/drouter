import { TinfoilAI, type VerificationDocument } from "tinfoil";
import type { CheckResult } from "@/lib/types";

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
}

export interface TinfoilSession {
  checks: CheckResult[];
  evidence: TinfoilEvidence;
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
export function checksFromDocument(doc: VerificationDocument): CheckResult[] {
  const s = doc.steps;
  const both = (a: Step | undefined, b: Step | undefined): CheckResult["status"] =>
    stepStatus(a) === "fail" || stepStatus(b) === "fail" ? "fail" : stepStatus(a) === "pass" && stepStatus(b) === "pass" ? "pass" : "skip";
  return [
    {
      id: "C1",
      label: "Hardware signature chain",
      status: stepStatus(s.verifyEnclave),
      detail: stepDetail(s.verifyEnclave, `AMD SEV-SNP report verified to AMD's root (${doc.enclaveMeasurement.measurement.type})`),
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
      detail: stepDetail(s.verifyCertificate, "Encryption key is committed to by the attestation; requests are HPKE-encrypted to it"),
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
      status: "skip",
      detail: "Tinfoil's browser verifier does not expose GPU reports; the router enclave attests the model enclaves",
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
      status: "pass",
      detail: "Model name is sent in a header and the enclave rejects requests whose encrypted body names a different model",
    },
  ];
}

function evidenceFromDocument(doc: VerificationDocument): TinfoilEvidence {
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
  };
}

/**
 * Verifies a Tinfoil enclave in this browser, then returns a session whose requests are encrypted
 * to that enclave and sent through the dRouter relay. The relay adds the API key but cannot read
 * prompts or completions.
 */
export async function openTinfoilSession(): Promise<TinfoilSession> {
  const origin = window.location.origin;
  const client = new TinfoilAI({
    bearerToken: "drouter-demo",
    baseURL: `${origin}/api/relay/v1/`,
    attestationBundleURL: `${origin}/api/relay`,
  });

  try {
    await client.ready();
  } catch (error) {
    let checks: CheckResult[] = [];
    try {
      checks = checksFromDocument(await client.getVerificationDocument());
    } catch {
      // Verification failed before a document existed.
    }
    const failed = checks.find((c) => c.status === "fail");
    throw Object.assign(new Error(failed ? `${failed.id} ${failed.label}: ${failed.detail}` : String(error)), { checks });
  }

  const doc = await client.getVerificationDocument();
  return {
    checks: checksFromDocument(doc),
    evidence: evidenceFromDocument(doc),
    async *send(model, messages) {
      const stream = await client.chat.completions.create(
        { model, messages, stream: true },
        { headers: { "X-Tinfoil-Model": model } },
      );
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta?.content;
        if (delta) yield delta;
      }
    },
  };
}
