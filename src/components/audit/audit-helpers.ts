import type {
  ConsistencyProof,
  InclusionProof,
  SignedTreeHead,
  VerificationLogEvent,
} from "@/lib/transparency/log";
import type {
  DeepAttestationBundle,
  ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import type { HardwareManifest, NodeRecord } from "@/lib/types";

export interface VerifiableClaimRecord {
  id: string;
  title: string;
  claim: string;
  href: string;
  linkLabel: string;
  secondaryHref?: string;
  secondaryLabel?: string;
  liveRecordBadge: string;
  liveSource: boolean;
}

export interface PlainTrustPoint {
  id: string;
  stepNumber: string;
  title: string;
  description: string;
  badge: string;
  href: string;
  buttonLabel: string;
}

export interface TransparencyEntryView {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays: number;
  emergency: boolean;
}

export interface VerifierSubmissionSummaryView {
  verifierFingerprint: string;
  epochHourSec: number;
  overallOk: boolean;
  evidenceHash: string;
  leafIndex: number;
  leafHash: string;
}

export interface TransparencyResponse {
  operatorPublicKey?: string;
  signedTreeHead?: SignedTreeHead;
  anchorExplorerUrl?: string | null;
  persisted?: boolean;
  verificationLog?: {
    root: string;
    treeSize: number;
    events: VerificationLogEvent[];
    inclusionProofs: InclusionProof[];
    consistencyProof: ConsistencyProof;
  };
  consistencyProof?: ConsistencyProof;
  releaseConsistencyProof?: ConsistencyProof;
  distinctVerifierCount?: number;
  totalSubmissions?: number;
  recentSubmissions?: VerifierSubmissionSummaryView[];
  verifications?: {
    distinctVerifierCount: number;
    totalSubmissions: number;
    recentSubmissions: VerifierSubmissionSummaryView[];
  };
  log?: {
    root: string;
    entries: TransparencyEntryView[];
  };
  proofs?: InclusionProof[];
}

export interface RampEvaluationView {
  nodeId: string;
  status: "full" | "ramp" | "suspended";
  restartsIn30d: number;
  dualIdentityDetected: boolean;
  weightBps: number;
  phase: "canary-only" | "linear-ramp" | "steady" | "suspended";
  releaseTag?: string;
  lastChangeKind?: string;
  detail: string;
}

export interface RecordedClaimEventView {
  id: string;
  kind?: string;
  nodeId: string;
  timestamp?: number;
  epochHourSec?: number;
  reasons?: string[];
  slashUsdc?: number;
  bountyUsdc?: number;
  compensationPoolUsdc?: number;
  summary?: string;
  detail?: unknown;
  evidenceHash?: string;
  txHash?: string | null;
  explorerUrl?: string | null;
  onChain?: boolean;
}

export interface MonitoredEnclaveView {
  nodeId: string;
  nodeKind: "tinfoil";
  role: "router" | "model";
  repo: string;
  releaseTag: string;
  releaseDigest: string;
  measurement: string;
  enclaveHost: string;
  ok: boolean;
  attestationChainOk: boolean;
  measurementMatchesRelease: boolean;
  modelProvenanceOk: boolean;
  epochHourSec: number;
}

export interface AccountabilityResponse {
  mongoConfigured?: boolean;
  hasRun?: boolean;
  statusMessage?: string;
  enclaves?: MonitoredEnclaveView[];
  failures?: RecordedClaimEventView[];
  manifests?: HardwareManifest[];
  rampStates: Record<string, RampEvaluationView>;
  recentClaims?: RecordedClaimEventView[];
  forbiddenPrefix?: string;
  registrySource?: "arc" | "fallback";
  registryNodes?: NodeRecord[];
  minStakeUsdc?: string;
  txHash?: string | null;
  explorerUrl?: string | null;
  onChain?: boolean;
}

export interface AuditorRunView {
  model: string;
  passed: boolean;
  verdict:
    | "PASS_GENUINE_FRONTIER_MODEL"
    | "SLASH_MODEL_DOWNGRADE_DETECTED"
    | "CONTINUE_SAMPLING";
  sprtStatistic: number;
  cumulativeSprtStatistic: number;
  upperBoundA: number;
  lowerBoundB: number;
  probesCount: number;
  passedCount: number;
  empiricalPassRate: number;
  meanLatencyMs: number;
  enclaveHost: string;
  at: string;
}

export interface AuditorResponse {
  protocol: string;
  parameters: {
    frontierModel: string;
    baselinePassRateP0: number;
    substitutePassRateP1: number;
    falsePositiveAlpha: number;
    falseNegativeBeta: number;
    maxCallsPerAudit?: number;
    canaryCategories?: { probeId: string; category: string }[];
  };
  mongoConfigured: boolean;
  hasRun: boolean;
  statusMessage: string;
  latestRun: AuditorRunView | null;
  history: AuditorRunView[];
}

export function shortHex(value: unknown, lead = 10, tail = 6): string {
  const s = String(value ?? "");
  if (s.length <= lead + tail + 3) return s;
  return `${s.slice(0, lead)}...${s.slice(-tail)}`;
}

export function formatUnixSec(sec: number | null | undefined): string {
  if (!sec || !Number.isFinite(sec)) return "n/a";
  return new Date(sec * 1000).toISOString().replace("T", " ").slice(0, 19);
}

/**
 * Builds the 5 external verifiable claims with exact records (specific release tag,
 * exact SHA-256 digest, exact AMD chip ID + TCB SPL parameters, live model enclave
 * release, and on-chain Circle Arc registry contract + node ID) from live endpoints.
 */
export function buildVerifiableClaims(params: {
  matrix: DeepAttestationBundle | null;
  accountability: AccountabilityResponse | null;
  transparency: TransparencyResponse | null;
}): VerifiableClaimRecord[] {
  const matrix = params.matrix;
  const acc = params.accountability;
  const trans = params.transparency;

  const routerRepo =
    matrix?.routerConfigRepo ?? "tinfoilsh/confidential-model-router";
  const routerTag = matrix?.routerReleaseTag ?? "v0.0.167";
  const routerReleaseUrl =
    matrix?.routerReleaseUrl ??
    `https://github.com/${routerRepo}/releases/tag/${routerTag}`;

  const kimiModel: ModelEnclaveAttestation | undefined =
    matrix?.models?.["kimi-k3"];
  const kimiRepo = kimiModel?.repo ?? "tinfoilsh/confidential-kimi-k3";
  const kimiTag = kimiModel?.tag ?? "v0.0.15";
  const kimiReleaseUrl =
    kimiModel?.releaseUrl ??
    `https://github.com/${kimiRepo}/releases/tag/${kimiTag}`;

  const routerDigest =
    matrix?.routerReleaseDigest ??
    trans?.verificationLog?.events?.[0]?.releaseDigest ??
    "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e";
  const routerSigstoreUrl =
    matrix?.routerSigstoreUrl ??
    `https://search.sigstore.dev/?hash=${routerDigest}`;

  const kimiDmVerity =
    kimiModel?.dmVerityRootHash ??
    "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b";
  const kimiSigstoreUrl =
    kimiModel?.sigstoreSearchUrl ??
    `https://search.sigstore.dev/?hash=${kimiDmVerity}`;

  const snp = matrix?.routerSnpReport;
  const productName = snp?.productName ?? "Genoa";
  const chipIdHex = snp?.chipIdHex ?? "";
  const tcb = snp?.tcb;
  const amdKdsExactUrl =
    chipIdHex && tcb
      ? `https://kdsintf.amd.com/vcek/v1/${productName}/${chipIdHex}?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`
      : matrix?.amdKdsUrl && matrix.amdKdsUrl.includes("?")
        ? matrix.amdKdsUrl
        : `https://kdsintf.amd.com/vcek/v1/${productName}/cert_chain`;

  const amdKdsChainUrl = `https://kdsintf.amd.com/vcek/v1/${productName}/cert_chain`;

  const proxyUrl =
    matrix?.proxyWellKnownUrl ??
    "https://inference.tinfoil.sh/.well-known/tinfoil-proxy";
  const kimiHost =
    kimiModel?.enclaveHosts?.[0]?.host ??
    "kimi-k3-inf14.tinfoil.containers.tinfoil.dev";
  const kimiWeightUrl =
    kimiModel?.huggingFaceUrl ??
    "https://huggingface.co/moonshotai/Kimi-K3/tree/a590ce090cb049c93a33dfe8c208ec652aa20503";

  const contractAddr = "0xbc8085c2b6fe6e0db05f169925c0b841828f4481";
  const routerNodeOnChain = acc?.registryNodes?.find(
    (n) => n.kind === "tinfoil",
  );
  const latestTx =
    acc?.txHash ?? trans?.signedTreeHead?.anchorTx ?? null;
  const arcPrimaryHref = latestTx
    ? `https://explorer.testnet.arc.io/tx/${latestTx}`
    : acc?.explorerUrl ??
      `https://explorer.testnet.arc.io/address/${contractAddr}`;
  const arcSecondaryHref = `https://testnet.arcscan.app/address/${contractAddr}`;

  return [
    {
      id: "github-release",
      title: "Enclave source and exact release tags (GitHub)",
      claim: `Router release ${routerRepo}@${routerTag} and Kimi K3 enclave release ${kimiRepo}@${kimiTag} that produce the attested boot measurements.`,
      href: routerReleaseUrl,
      linkLabel: `github.com/${routerRepo}/releases/tag/${routerTag}`,
      secondaryHref: kimiReleaseUrl,
      secondaryLabel: `github.com/${kimiRepo}/releases/tag/${kimiTag}`,
      liveRecordBadge: `${routerTag} / ${kimiTag}`,
      liveSource: Boolean(matrix),
    },
    {
      id: "sigstore-rekor",
      title: "Exact build provenance digests (Sigstore Rekor)",
      claim: `Router measurement digest ${shortHex(routerDigest, 12, 8)} and Kimi K3 dm-verity root ${shortHex(kimiDmVerity, 12, 8)} in the public Sigstore Rekor transparency log.`,
      href: routerSigstoreUrl,
      linkLabel: `search.sigstore.dev/?hash=${shortHex(routerDigest, 12, 8)}`,
      secondaryHref: kimiSigstoreUrl,
      secondaryLabel: `search.sigstore.dev/?hash=${shortHex(kimiDmVerity, 12, 8)}`,
      liveRecordBadge: `sha256:${shortHex(routerDigest, 8, 6)}`,
      liveSource: Boolean(matrix),
    },
    {
      id: "amd-kds-vcek",
      title: "Silicon VCEK certificate for live router chip (AMD KDS)",
      claim: chipIdHex
        ? `AMD Key Distribution Service VCEK leaf certificate for ${productName} chip ${shortHex(chipIdHex, 12, 8)} (TCB bl=${tcb?.bootloader ?? 0}, snp=${tcb?.snp ?? 0}, ucode=${tcb?.microcode ?? 0}) on ${matrix?.routerHost ?? "router-0.tinfoil.sh"}.`
        : `AMD Key Distribution Service VCEK certificate chain for ${productName} verifying ${matrix?.routerHost ?? "router-0.tinfoil.sh"}.`,
      href: amdKdsExactUrl,
      linkLabel: chipIdHex
        ? `kdsintf.amd.com/vcek/v1/${productName}/${shortHex(chipIdHex, 10, 6)}`
        : `kdsintf.amd.com/vcek/v1/${productName}/cert_chain`,
      secondaryHref: amdKdsChainUrl,
      secondaryLabel: `kdsintf.amd.com/vcek/v1/${productName}/cert_chain`,
      liveRecordBadge: chipIdHex
        ? `${productName} chip ${shortHex(chipIdHex, 8, 6)}`
        : `${productName} VCEK chain`,
      liveSource: Boolean(chipIdHex),
    },
    {
      id: "tinfoil-proxy-table",
      title: "Live enclave routing table and pinned model weights",
      claim: `Live proxy manifest mapping ${matrix?.routerHost ?? "router-0.tinfoil.sh"} to ${kimiHost} (Intel TDX + NVIDIA CC GPUs, 262,144 max tokens) and pinned weights ${kimiModel?.weightRepoCommit ?? "moonshotai/Kimi-K3@a590ce09"}.`,
      href: proxyUrl,
      linkLabel: "inference.tinfoil.sh/.well-known/tinfoil-proxy",
      secondaryHref: kimiWeightUrl,
      secondaryLabel: "huggingface.co/moonshotai/Kimi-K3/tree/a590ce09...",
      liveRecordBadge: kimiHost,
      liveSource: Boolean(matrix),
    },
    {
      id: "circle-arc-registry",
      title: "On-chain attestation registry (Circle Arc Testnet)",
      claim: routerNodeOnChain
        ? `Contract ${contractAddr} on Circle Arc Testnet (chain 5042002). Node ${shortHex(routerNodeOnChain.id, 10, 6)} staked ${routerNodeOnChain.stake} USDC (status: ${routerNodeOnChain.status}).`
        : `Contract ${contractAddr} on Circle Arc Testnet (chain 5042002) storing node stakes, verification records, and receipt anchors.`,
      href: arcPrimaryHref,
      linkLabel: latestTx
        ? `explorer.testnet.arc.io/tx/${shortHex(latestTx, 10, 6)}`
        : `explorer.testnet.arc.io/address/${shortHex(contractAddr, 10, 6)}`,
      secondaryHref: arcSecondaryHref,
      secondaryLabel: `testnet.arcscan.app/address/${shortHex(contractAddr, 10, 6)}`,
      liveRecordBadge: latestTx
        ? `tx ${shortHex(latestTx, 8, 6)}`
        : `chain 5042002 (${
            acc?.registryNodes?.filter((n) => n.kind === "tinfoil").length || 1
          } active)`,
      liveSource: Boolean(acc?.onChain),
    },
  ];
}

/**
 * Builds the 3 plain-language points for "Why you can trust this" on /audit,
 * each paired with a live external record URL for "Check it yourself".
 */
export function buildPlainTrustPoints(params: {
  matrix: DeepAttestationBundle | null;
  accountability: AccountabilityResponse | null;
  transparency: TransparencyResponse | null;
}): PlainTrustPoint[] {
  const claims = buildVerifiableClaims(params);
  const chipClaim = claims[2];
  const releaseClaim = claims[0];
  const receiptBookClaim = claims[4];

  return [
    {
      id: "factory-seal",
      stepNumber: "1",
      title: "The sealed computer has a real factory seal from the chip maker",
      description:
        "Before your device sends a single word, we run a seal check to make sure the sealed computer is genuine and locked so only it can open your chat.",
      badge: params.matrix ? "Seal checked live" : "Factory seal record",
      href: chipClaim.href,
      buttonLabel: "Check it yourself",
    },
    {
      id: "public-blueprint",
      stepNumber: "2",
      title: "The software inside matches the public blueprint",
      description:
        "The code running inside the sealed computer is open and public. Anyone can open the exact software release to confirm no secret logging was added.",
      badge: params.matrix ? "Public release matched" : "Open software release",
      href: releaseClaim.href,
      buttonLabel: "Check it yourself",
    },
    {
      id: "public-receipt-book",
      stepNumber: "3",
      title: "Every check is written in a public receipt book",
      description:
        "Whenever we run a seal check on the servers, we write a permanent receipt into a public receipt book that nobody can secretly erase.",
      badge: params.accountability?.onChain
        ? "Live public receipt book"
        : "Public receipt book",
      href: receiptBookClaim.href,
      buttonLabel: "Check it yourself",
    },
  ];
}
