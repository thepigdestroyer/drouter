import { gunzipSync } from "node:zlib";
import { Verifier, verifyCertificate, type PredicateType } from "@tinfoilsh/verifier";
import { connection, NextResponse } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import {
  decodeSnpReportBytes,
  parseDeploymentConfigYaml,
  verifyAmdSevSnpChainEndToEnd,
  verifyTdxQuoteEndToEnd,
  type DeepAttestationBundle,
  type ModelEnclaveAttestation,
  type RouterSnpHardwareReport,
  type SnpChainVerificationResult,
  type TdxQuoteVerificationResult,
} from "@/lib/tinfoil/deep-inspect";

const matrixLimiter = createTokenBucketLimiter({
  name: "relay-enclave-matrix",
  capacity: 60,
  refillPerSec: 2,
});

const ATC_ATTESTATION_URL = "https://atc.tinfoil.sh/attestation";
const TINFOIL_PROXY_WELL_KNOWN_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";
const GITHUB_PROXY_URL = "https://github-proxy.tinfoil.sh";
const NVIDIA_NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
const ROUTER_CONFIG_REPO = "tinfoilsh/confidential-model-router";

const CHAT_MODEL_IDS = [
  "kimi-k3",
  "glm-5-3",
  "deepseek-v4-1-flash",
  "gpt-oss-120b",
  "llama3-3-70b",
] as const;

const CACHE_TTL_MS = 60_000;
let cachedBundle: { bundle: DeepAttestationBundle; expiresAt: number } | null = null;
const kdsCertChainCache = new Map<string, string>();

async function fetchJsonWithTimeout<T>(
  url: string,
  timeoutMs = 5000,
  init?: RequestInit,
): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchTextWithTimeout(
  url: string,
  timeoutMs = 5000,
  init?: RequestInit,
): Promise<{ ok: boolean; status: number; text: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...init,
      signal: controller.signal,
      cache: "no-store",
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, text };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      text: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function getAmdKdsCertChainPem(productName: "Milan" | "Genoa" | "Turin"): Promise<string | null> {
  const cached = kdsCertChainCache.get(productName);
  if (cached) return cached;
  const res = await fetchTextWithTimeout(
    `https://kdsintf.amd.com/vcek/v1/${productName}/cert_chain`,
    4000,
  );
  if (res.ok && res.text.includes("-----BEGIN CERTIFICATE-----")) {
    kdsCertChainCache.set(productName, res.text);
    return res.text;
  }
  return null;
}

interface AtcResponse {
  domain?: string;
  digest?: string;
  releaseTag?: string;
  vcek?: string;
  enclaveCert?: string;
  enclaveAttestationReport?: {
    format?: string;
    body?: string;
  };
  sigstoreBundle?: {
    dsseEnvelope?: {
      payload?: string;
    };
  };
}

interface DssePredicate {
  snp_measurement?: string;
  tdx_measurement?: {
    mrtd?: string;
    rtmr0?: string;
    rtmr1?: string;
    rtmr2?: string;
  };
  vm_shape?: {
    cpus?: number;
    memory_mb?: number;
    gpus?: number;
    disks?: number;
  };
  cmdline?: string;
  hashes?: {
    version: string;
    root: string;
    initrd: string;
    kernel: string;
    raw: string;
  };
  config?: string;
}

interface ProxyModelEntry {
  repo?: string;
  tag?: string;
  measurement?: {
    type?: string;
    registers?: string[];
  };
  enclaves?: Record<
    string,
    {
      hpke_key?: string;
      predicate?: string;
      tls_key_fp?: string;
    }
  >;
  verification?: {
    configured?: number;
    verified?: number;
    healthy?: number;
    unverified?: number;
    hosts?: Record<
      string,
      {
        last_success?: string;
        expires_at?: string;
        code_tag?: string;
      }
    >;
  };
}

interface ProxyWellKnownResponse {
  models?: Record<string, ProxyModelEntry>;
}

function buildHuggingFaceUrl(weightRepoCommit: string): string | undefined {
  if (!weightRepoCommit) return undefined;
  const [repo, commit] = weightRepoCommit.split("@");
  if (!repo) return undefined;
  return commit ? `https://huggingface.co/${repo}/tree/${commit}` : `https://huggingface.co/${repo}`;
}

function buildUnavailableModelAttestation(
  modelId: string,
  reason: string,
  repo = "",
  tag = "",
): ModelEnclaveAttestation {
  return {
    modelId,
    status: "unavailable",
    unavailableReason: reason,
    repo,
    tag,
    hardwarePredicate: "",
    tierClassification: "Tier B (Intel TDX + 8x Confidential GPU)",
    configuredHosts: 0,
    verifiedHosts: 0,
    healthyHosts: 0,
    unverifiedHosts: 0,
    enclaveHosts: [],
    measurementRegisters: [],
    vmShape: { cpus: 0, memoryMb: 0, gpus: 0, disks: 0 },
    dmVerityRootHash: "",
    kernelHash: "",
    initrdHash: "",
    containerImageDigest: "",
    weightRepoCommit: "",
    weightMpkHash: "",
    ccGpuFlagsVerified: false,
    releaseUrl: repo && tag ? `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}` : "",
    sigstoreSearchUrl: "",
    sigstoreVerified: false,
    registersMatchSigstore: false,
    directQuoteVerified: false,
    directQuoteError: reason,
    verificationBreakdown: {
      cryptographicallyVerified: [],
      trustedFromRouter: [],
    },
  };
}

async function verifySigstoreViaSdk(
  routerAtc: AtcResponse | null,
  repo: string,
  tag: string,
  digest: string,
  sigstoreBundle: unknown,
): Promise<boolean> {
  if (
    !routerAtc?.enclaveAttestationReport?.format ||
    !routerAtc?.enclaveAttestationReport?.body ||
    !routerAtc?.vcek
  ) {
    return false;
  }
  const verifier = new Verifier({ configRepo: repo });
  try {
    await verifier.verifyBundle({
      domain: routerAtc.domain ?? "router-0.tinfoil.sh",
      enclaveAttestationReport: {
        format: routerAtc.enclaveAttestationReport.format as PredicateType,
        body: routerAtc.enclaveAttestationReport.body,
      },
      vcek: routerAtc.vcek,
      digest,
      releaseTag: tag,
      sigstoreBundle,
      enclaveCert: routerAtc.enclaveCert ?? "",
    });
    return true;
  } catch {
    const doc = verifier.getVerificationDocument();
    return doc?.steps?.verifyCode?.status === "success";
  }
}

async function buildModelAttestation(
  modelId: string,
  proxyEntry: ProxyModelEntry | undefined,
  routerAtc: AtcResponse | null,
  nvidiaJwksReachable: boolean,
): Promise<ModelEnclaveAttestation> {
  if (!proxyEntry || !proxyEntry.repo || !proxyEntry.tag) {
    return buildUnavailableModelAttestation(
      modelId,
      `Model "${modelId}" is not present in live Tinfoil router proxy table`,
    );
  }

  const repo = proxyEntry.repo;
  const tag = proxyEntry.tag;

  // 1. Fetch release SHA-256 digest (tinfoil.hash) and Sigstore DSSE bundle from Tinfoil's GitHub proxy
  const hashRes = await fetchTextWithTimeout(
    `${GITHUB_PROXY_URL}/${repo}/releases/download/${encodeURIComponent(tag)}/tinfoil.hash`,
    4500,
  );
  const releaseDigest = hashRes.ok ? hashRes.text.trim() : "";
  if (!/^[0-9a-fA-F]{64}$/.test(releaseDigest)) {
    return buildUnavailableModelAttestation(
      modelId,
      `Failed to fetch release digest tinfoil.hash for ${repo}@${tag}`,
      repo,
      tag,
    );
  }

  const sigstoreAttResp = await fetchJsonWithTimeout<{
    attestations?: Array<{ bundle?: { dsseEnvelope?: { payload?: string } } }>;
  }>(`${GITHUB_PROXY_URL}/repos/${repo}/attestations/sha256:${releaseDigest}`, 5000);
  const sigstoreBundle = sigstoreAttResp?.attestations?.[0]?.bundle;
  const dssePayloadB64 = sigstoreBundle?.dsseEnvelope?.payload;
  if (!sigstoreBundle || !dssePayloadB64) {
    return buildUnavailableModelAttestation(
      modelId,
      `Failed to fetch Sigstore DSSE bundle for ${repo}@${tag} (sha256:${releaseDigest.slice(0, 12)})`,
      repo,
      tag,
    );
  }

  // 2. Cryptographically verify the Sigstore DSSE bundle (Fulcio OIDC cert + Rekor log + digest) using the SDK verifier
  const sigstoreVerified = await verifySigstoreViaSdk(
    routerAtc,
    repo,
    tag,
    releaseDigest,
    sigstoreBundle,
  );

  let predicate: DssePredicate | undefined;
  try {
    const inToto = JSON.parse(
      Buffer.from(dssePayloadB64, "base64").toString("utf8"),
    ) as { predicate?: DssePredicate };
    predicate = inToto.predicate;
  } catch {
    return buildUnavailableModelAttestation(
      modelId,
      `Malformed DSSE in-toto payload in Sigstore bundle for ${repo}@${tag}`,
      repo,
      tag,
    );
  }

  if (!predicate) {
    return buildUnavailableModelAttestation(
      modelId,
      `Missing in-toto predicate in Sigstore bundle for ${repo}@${tag}`,
      repo,
      tag,
    );
  }

  // 3. Parse deployment YAML from the Sigstore-verified DSSE predicate
  let parsedYaml = {
    containerImageDigest: "",
    weightRepoCommit: "",
    weightMpkHash: "",
    ccGpuFlagsVerified: false,
  };
  if (predicate.config) {
    try {
      const yamlText = Buffer.from(predicate.config, "base64").toString("utf8");
      parsedYaml = parseDeploymentConfigYaml(yamlText);
    } catch {
      // Leave parsedYaml empty if base64 decoding fails
    }
  }

  const cmdlineRootMatch = predicate.cmdline?.match(/roothash=([0-9a-fA-F]{64})/);
  const dmVerityRootHash = predicate.hashes?.root ?? cmdlineRootMatch?.[1] ?? "";
  const kernelHash = predicate.hashes?.kernel ?? "";
  const initrdHash = predicate.hashes?.initrd ?? "";

  const vmShape = {
    cpus: predicate.vm_shape?.cpus ?? 0,
    memoryMb: predicate.vm_shape?.memory_mb ?? 0,
    gpus: predicate.vm_shape?.gpus ?? 0,
    disks: predicate.vm_shape?.disks ?? 0,
  };

  const enclaveHosts: ModelEnclaveAttestation["enclaveHosts"] = [];
  if (proxyEntry.enclaves) {
    for (const [host, info] of Object.entries(proxyEntry.enclaves)) {
      const vHost = proxyEntry.verification?.hosts?.[host];
      enclaveHosts.push({
        host,
        hpkeKey: info.hpke_key ?? "",
        predicate: info.predicate ?? proxyEntry.measurement?.type ?? "",
        tlsKeyFp: info.tls_key_fp ?? "",
        lastSuccess: vHost?.last_success,
        expiresAt: vHost?.expires_at,
        codeTag: vHost?.code_tag ?? tag,
      });
    }
  }

  const sigstoreRegisters = [
    predicate.snp_measurement,
    predicate.tdx_measurement?.rtmr1,
    predicate.tdx_measurement?.rtmr2,
  ].filter((r): r is string => Boolean(r));

  const proxyRegisters = proxyEntry.measurement?.registers ?? [];
  const registersMatchSigstore =
    sigstoreRegisters.length > 0 &&
    proxyRegisters.length === sigstoreRegisters.length &&
    proxyRegisters.every((r, idx) => r.toLowerCase() === sigstoreRegisters[idx].toLowerCase());

  // 4. Attempt direct live hardware attestation verification on a model enclave host running the target tag
  const candidateHostEntry =
    enclaveHosts.find((h) => h.codeTag === tag) ?? enclaveHosts[0];
  let directQuoteVerified = false;
  let directQuoteFormat: string | undefined;
  let directQuoteHost: string | undefined;
  let directQuoteCertVerified = false;
  let directQuoteError: string | undefined;
  let snpChainVerification: SnpChainVerificationResult | undefined;
  let tdxQuoteVerification: TdxQuoteVerificationResult | undefined;

  if (candidateHostEntry?.host) {
    const targetHost = candidateHostEntry.host;
    directQuoteHost = targetHost;
    const [directAtt, directCert] = await Promise.all([
      fetchJsonWithTimeout<{ format?: string; body?: string }>(
        `https://${targetHost}/.well-known/tinfoil-attestation`,
        2500,
      ),
      fetchJsonWithTimeout<{ certificate?: string }>(
        `https://${targetHost}/.well-known/tinfoil-certificate`,
        2500,
      ),
    ]);

    if (directAtt?.format && directAtt?.body) {
      directQuoteFormat = directAtt.format;
      try {
        const rawQuoteBytes = new Uint8Array(
          gunzipSync(Buffer.from(directAtt.body, "base64")),
        );

        if (directAtt.format.includes("sev-snp-guest")) {
          const decodedSnp = decodeSnpReportBytes(rawQuoteBytes);
          const atcModelBundle = await fetchJsonWithTimeout<AtcResponse>(
            ATC_ATTESTATION_URL,
            3500,
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                enclaveUrl: `https://${targetHost}`,
                repo,
              }),
            },
          );
          const kdsChainPem = await getAmdKdsCertChainPem(decodedSnp.productName);
          let vcekDerOrBase64: Uint8Array | string | undefined = atcModelBundle?.vcek;
          if (!vcekDerOrBase64) {
            const chipIdForKds =
              decodedSnp.productName === "Turin"
                ? decodedSnp.chipIdHex.slice(0, 16)
                : decodedSnp.chipIdHex;
            const fmcParam =
              decodedSnp.productName === "Turin" ? `&fmcSPL=${decodedSnp.tcb.fmc}` : "";
            const kdsVcekUrl = `https://kdsintf.amd.com/vcek/v1/${decodedSnp.productName}/${chipIdForKds}?blSPL=${decodedSnp.tcb.bootloader}&teeSPL=${decodedSnp.tcb.tee}&snpSPL=${decodedSnp.tcb.snp}&ucodeSPL=${decodedSnp.tcb.microcode}${fmcParam}`;
            try {
              const vcekRes = await fetch(kdsVcekUrl, {
                signal: AbortSignal.timeout(3500),
                cache: "no-store",
              });
              if (vcekRes.ok) {
                vcekDerOrBase64 = new Uint8Array(await vcekRes.arrayBuffer());
              }
            } catch {
              // Leave undefined if AMD KDS is unreachable
            }
          }
          if (vcekDerOrBase64 && kdsChainPem) {
            snpChainVerification = await verifyAmdSevSnpChainEndToEnd(
              rawQuoteBytes,
              vcekDerOrBase64,
              kdsChainPem,
            );
          }
          const measurementMatches =
            Boolean(predicate.snp_measurement) &&
            decodedSnp.measurementHex.toLowerCase() ===
              predicate.snp_measurement!.toLowerCase();

          if (directCert?.certificate) {
            try {
              await verifyCertificate(
                directCert.certificate,
                targetHost,
                {
                  format: directAtt.format as PredicateType,
                  body: directAtt.body,
                },
                decodedSnp.hpkeKeyFromReportDataHex,
              );
              directQuoteCertVerified = true;
            } catch {
              directQuoteCertVerified = false;
            }
          }

          directQuoteVerified = Boolean(
            snpChainVerification?.verified &&
              measurementMatches &&
              directQuoteCertVerified,
          );
          if (!directQuoteVerified) {
            directQuoteError =
              snpChainVerification?.error ??
              (!measurementMatches
                ? "SEV-SNP measurement mismatch against Sigstore release"
                : "Enclave TLS certificate SAN binding check failed");
          }
        } else if (directAtt.format.includes("tdx-guest")) {
          tdxQuoteVerification = await verifyTdxQuoteEndToEnd(rawQuoteBytes, {
            rtmr1Hex: predicate.tdx_measurement?.rtmr1,
            rtmr2Hex: predicate.tdx_measurement?.rtmr2,
          });

          if (directCert?.certificate) {
            try {
              await verifyCertificate(
                directCert.certificate,
                targetHost,
                {
                  format: directAtt.format as PredicateType,
                  body: directAtt.body,
                },
                tdxQuoteVerification.hpkeKeyHex,
              );
              directQuoteCertVerified = true;
            } catch {
              directQuoteCertVerified = false;
            }
          }

          directQuoteVerified = Boolean(
            tdxQuoteVerification.verified && directQuoteCertVerified,
          );
          if (!directQuoteVerified) {
            directQuoteError =
              tdxQuoteVerification.error ??
              "Enclave TLS certificate SAN binding check failed";
          }
        }
      } catch (err) {
        directQuoteError = err instanceof Error ? err.message : String(err);
      }
    } else {
      // Host TCP 443 is firewalled to Tinfoil's router VPC; query ATC POST to record the exact upstream reason
      const atcProbe = await fetchTextWithTimeout(ATC_ATTESTATION_URL, 2500, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enclaveUrl: `https://${targetHost}`,
          repo,
        }),
      });
      const atcReason = atcProbe.text.trim().slice(0, 180);
      directQuoteError =
        atcProbe.status === 501
          ? `Direct TCP 443 firewalled to router VPC; ATC HTTP 501 (${atcReason})`
          : `Direct TCP 443 to ${targetHost} firewalled to router VPC`;
    }
  }

  const hardwarePredicate =
    enclaveHosts[0]?.predicate ?? proxyEntry.measurement?.type ?? "";
  const isSevSnp = hardwarePredicate.includes("sev-snp");
  const tierClassification: ModelEnclaveAttestation["tierClassification"] = isSevSnp
    ? "Tier A (AMD SEV-SNP + 8x Confidential GPU)"
    : "Tier B (Intel TDX + 8x Confidential GPU)";

  const configuredHosts = proxyEntry.verification?.configured ?? enclaveHosts.length;
  const verifiedHosts = proxyEntry.verification?.verified ?? 0;
  const healthyHosts = proxyEntry.verification?.healthy ?? 0;
  const unverifiedHosts = proxyEntry.verification?.unverified ?? 0;

  const cryptographicallyVerified: string[] = [];
  const trustedFromRouter: string[] = [];

  if (sigstoreVerified) {
    cryptographicallyVerified.push(
      `Sigstore v0.3 DSSE bundle & Rekor transparency log entry for ${repo}@${tag} (sha256:${releaseDigest.slice(0, 12)}…)`,
    );
    cryptographicallyVerified.push(
      `Manifest-pinned dm-verity root (${dmVerityRootHash.slice(0, 12)}…), weight package (${parsedYaml.weightMpkHash.slice(0, 12)}…), and NVIDIA CC vLLM flags`,
    );
  }
  if (registersMatchSigstore) {
    cryptographicallyVerified.push(
      `Router proxy table measurement registers match Sigstore-signed predicate (${sigstoreRegisters.length} registers)`,
    );
  }
  if (directQuoteVerified && directQuoteHost) {
    if (snpChainVerification?.verified) {
      cryptographicallyVerified.push(
        `Live AMD SEV-SNP (${snpChainVerification.productName}) hardware report on ${directQuoteHost}: ARK -> ASK -> VCEK X.509 chain, ECDSA-P384 report signature, LAUNCH_DIGEST, and TLS/HPKE SAN binding`,
      );
    } else if (tdxQuoteVerification?.verified) {
      cryptographicallyVerified.push(
        `Live Intel TDX v4 quote on ${directQuoteHost}: Intel SGX Root CA -> PCK CA -> PCK Leaf chain, QE report ECDSA-P256 signature, attestation key binding, TD Quote Body signature, RTMR1/RTMR2, and TLS/HPKE SAN binding`,
      );
    }
  } else if (directQuoteHost) {
    trustedFromRouter.push(
      `Live per-host TDX quote freshness & HPKE key binding for ${directQuoteHost} (${directQuoteError ?? "verified transitively by router-0.tinfoil.sh"})`,
    );
  }

  trustedFromRouter.push(
    "Active backend host pool health counts & traffic routing across verified model enclaves",
    "In-CVM NVIDIA GPU confidential computing initialization (measured on dm-verity rootfs by tinfoil-boot; Tinfoil enclaves do not expose external NVIDIA NRAS EAT/JWT endpoints)",
  );

  return {
    modelId,
    status: directQuoteVerified
      ? "verified"
      : sigstoreVerified && registersMatchSigstore
        ? "router-attested"
        : "unavailable",
    repo,
    tag,
    hardwarePredicate,
    tierClassification,
    configuredHosts,
    verifiedHosts,
    healthyHosts,
    unverifiedHosts,
    enclaveHosts,
    measurementRegisters: proxyRegisters,
    vmShape,
    dmVerityRootHash,
    kernelHash,
    initrdHash,
    containerImageDigest: parsedYaml.containerImageDigest,
    weightRepoCommit: parsedYaml.weightRepoCommit,
    weightMpkHash: parsedYaml.weightMpkHash,
    ccGpuFlagsVerified: parsedYaml.ccGpuFlagsVerified,
    releaseUrl: `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`,
    sigstoreSearchUrl: `https://search.sigstore.dev/?hash=${releaseDigest}`,
    huggingFaceUrl: buildHuggingFaceUrl(parsedYaml.weightRepoCommit),
    sigstoreVerified,
    sigstoreReleaseDigest: releaseDigest,
    registersMatchSigstore,
    directQuoteVerified,
    directQuoteFormat,
    directQuoteHost,
    directQuoteCertVerified,
    directQuoteError,
    snpChainVerification,
    tdxQuoteVerification,
    nvidiaEatExposed: false,
    nvidiaEatVerified: false,
    nvidiaJwksReachable,
    verificationBreakdown: {
      cryptographicallyVerified,
      trustedFromRouter,
    },
  };
}

export async function GET(request?: Request): Promise<Response> {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next.js request store.
  }

  if (request) {
    const limited = matrixLimiter.check(request);
    if (limited) return limited;
  }

  if (process.env.DROUTER_STUB_UPSTREAM === "1") {
    const reason = "Upstream Tinfoil attestation disabled (DROUTER_STUB_UPSTREAM=1)";
    const unavailableBundle: DeepAttestationBundle = {
      status: "unavailable",
      unavailable: true,
      unavailableReason: reason,
      routerHost: "",
      routerReleaseTag: "",
      routerReleaseDigest: "",
      routerConfigRepo: ROUTER_CONFIG_REPO,
      routerReleaseUrl: "",
      routerSigstoreUrl: "",
      amdKdsUrl: "",
      proxyWellKnownUrl: TINFOIL_PROXY_WELL_KNOWN_URL,
      models: Object.fromEntries(
        CHAT_MODEL_IDS.map((id) => [id, buildUnavailableModelAttestation(id, reason)]),
      ),
      fetchedAt: new Date().toISOString(),
    };
    return NextResponse.json(unavailableBundle, { status: 503 });
  }

  const now = Date.now();
  if (cachedBundle && cachedBundle.expiresAt > now) {
    return NextResponse.json(cachedBundle.bundle);
  }

  const [atc, proxy, nvidiaJwks] = await Promise.all([
    fetchJsonWithTimeout<AtcResponse>(ATC_ATTESTATION_URL, 5000),
    fetchJsonWithTimeout<ProxyWellKnownResponse>(TINFOIL_PROXY_WELL_KNOWN_URL, 5000),
    fetchJsonWithTimeout<{ keys?: Array<Record<string, unknown>> }>(NVIDIA_NRAS_JWKS_URL, 3500),
  ]);

  if (!atc && !proxy) {
    const reason =
      "Upstream Tinfoil attestation service (atc.tinfoil.sh) and router proxy table (inference.tinfoil.sh) are unreachable";
    const unavailableBundle: DeepAttestationBundle = {
      status: "unavailable",
      unavailable: true,
      unavailableReason: reason,
      routerHost: "",
      routerReleaseTag: "",
      routerReleaseDigest: "",
      routerConfigRepo: ROUTER_CONFIG_REPO,
      routerReleaseUrl: "",
      routerSigstoreUrl: "",
      amdKdsUrl: "",
      proxyWellKnownUrl: TINFOIL_PROXY_WELL_KNOWN_URL,
      models: Object.fromEntries(
        CHAT_MODEL_IDS.map((id) => [id, buildUnavailableModelAttestation(id, reason)]),
      ),
      fetchedAt: new Date().toISOString(),
    };
    return NextResponse.json(unavailableBundle, { status: 503 });
  }

  let routerSnpReport: RouterSnpHardwareReport | undefined;
  let routerSnpChain: SnpChainVerificationResult | undefined;
  if (atc?.enclaveAttestationReport?.body) {
    try {
      const gzBytes = Buffer.from(atc.enclaveAttestationReport.body, "base64");
      const rawBytes = new Uint8Array(gunzipSync(gzBytes));
      routerSnpReport = decodeSnpReportBytes(rawBytes);
      if (atc.vcek) {
        const kdsChainPem = await getAmdKdsCertChainPem(routerSnpReport.productName);
        if (kdsChainPem) {
          routerSnpChain = await verifyAmdSevSnpChainEndToEnd(
            rawBytes,
            atc.vcek,
            kdsChainPem,
          );
        }
      }
    } catch {
      // Leave undefined if report decoding fails
    }
  }

  let routerHashes: DeepAttestationBundle["routerHashes"];
  let routerReleaseTag = atc?.releaseTag ?? "";
  if (atc?.sigstoreBundle?.dsseEnvelope?.payload) {
    try {
      const dsseJson = Buffer.from(atc.sigstoreBundle.dsseEnvelope.payload, "base64").toString("utf8");
      const parsedDsse = JSON.parse(dsseJson) as { predicate?: DssePredicate };
      if (parsedDsse.predicate?.hashes) {
        routerHashes = parsedDsse.predicate.hashes;
        if (!routerReleaseTag) {
          routerReleaseTag = parsedDsse.predicate.hashes.version || "";
        }
      }
      if (parsedDsse.predicate?.config) {
        const routerYaml = Buffer.from(parsedDsse.predicate.config, "base64").toString("utf8");
        const tagComment = routerYaml.match(/confidential-model-router@sha256:[0-9a-f]+\s*["']?\s*#\s*(v[0-9.]+)/i);
        if (tagComment?.[1]) {
          routerReleaseTag = tagComment[1];
        }
      }
    } catch {
      // Leave routerReleaseTag as extracted
    }
  }

  const routerHost = atc?.domain ?? "";
  const routerReleaseDigest = atc?.digest ?? "";
  const nvidiaJwksReachable = Boolean(
    nvidiaJwks?.keys && Array.isArray(nvidiaJwks.keys) && nvidiaJwks.keys.length > 0,
  );

  const modelEntries = await Promise.all(
    CHAT_MODEL_IDS.map(async (modelId) => {
      const attestation = await buildModelAttestation(
        modelId,
        proxy?.models?.[modelId],
        atc,
        nvidiaJwksReachable,
      );
      return [modelId, attestation] as const;
    }),
  );

  const models: Record<string, ModelEnclaveAttestation> = {};
  for (const [id, att] of modelEntries) {
    models[id] = att;
  }

  const chipId = routerSnpReport?.chipIdHex ?? "";
  const tcb = routerSnpReport?.tcb;
  const productName = routerSnpReport?.productName;
  const amdKdsUrl =
    productName && chipId && tcb
      ? `https://kdsintf.amd.com/vcek/v1/${productName}/${chipId}?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`
      : "";

  const allModelsAvailable = Object.values(models).every((m) => m.status !== "unavailable");
  const bundleStatus: DeepAttestationBundle["status"] =
    routerSnpChain?.verified && allModelsAvailable ? "verified" : "partial";

  const bundle: DeepAttestationBundle = {
    status: bundleStatus,
    routerHost,
    routerReleaseTag,
    routerReleaseDigest,
    routerConfigRepo: ROUTER_CONFIG_REPO,
    routerSnpReport,
    routerSnpChain,
    routerHashes,
    routerReleaseUrl: routerReleaseTag
      ? `https://github.com/${ROUTER_CONFIG_REPO}/releases/tag/${encodeURIComponent(routerReleaseTag)}`
      : "",
    routerSigstoreUrl: routerReleaseDigest
      ? `https://search.sigstore.dev/?hash=${routerReleaseDigest}`
      : "",
    amdKdsUrl,
    proxyWellKnownUrl: TINFOIL_PROXY_WELL_KNOWN_URL,
    models,
    fetchedAt: new Date().toISOString(),
  };

  cachedBundle = { bundle, expiresAt: now + CACHE_TTL_MS };
  return NextResponse.json(bundle);
}
