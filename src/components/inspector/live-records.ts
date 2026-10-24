import type {
  DeepAttestationBundle,
  ModelEnclaveAttestation,
} from "@/lib/tinfoil/deep-inspect";
import type { NodeRecord, QuorumTicket } from "@/lib/types";

export interface RawAttestationResponse {
  domain?: string;
  digest?: string;
  enclaveAttestationReport?: {
    format?: string;
    body?: string;
  };
  sigstoreBundle?: {
    mediaType?: string;
    verificationMaterial?: {
      tlogEntries?: Array<{
        logIndex?: string;
        integratedTime?: string;
        inclusionProof?: {
          logIndex?: string;
          rootHash?: string;
          treeSize?: string;
        };
      }>;
    };
  };
}

export interface TransparencyLogEntry {
  index: number;
  imageId: string;
  version: string;
  measurement: string;
  approvedAt: number;
  reviewWindowDays: number;
  emergency: boolean;
  builderSignatures: Array<{
    builderId: string;
    publicKey: string;
    signature: string;
  }>;
  reviewerSignatures: Array<{
    reviewerId: string;
    publicKey: string;
    signature: string;
  }>;
}

export interface TransparencyInclusionProof {
  index: number;
  leafHash: string;
  root: string;
  siblings: string[];
}

export interface TransparencySnapshot {
  log?: {
    root: string;
    entries: TransparencyLogEntry[];
  };
  proofs?: TransparencyInclusionProof[];
  verifierSet?: {
    threshold: number;
    total: number;
    verifiers?: Array<{ id: string; publicKeyHex: string }>;
  };
  tickets?: Record<string, QuorumTicket>;
}

export interface RegistrySnapshot {
  source?: "arc" | "fallback";
  address?: string;
  nodes?: NodeRecord[];
  chainId?: number;
  explorer?: string;
}

export interface RekorLookupEntry {
  uuid: string;
  logIndex?: number;
  integratedTime?: number;
  searchUrl: string;
  apiUrl: string;
}

export interface DeploymentAssetLookup {
  repo: string;
  tag: string;
  downloadUrl: string;
  releaseTagUrl: string;
  sha256Digest: string | null;
  rekor: RekorLookupEntry | null;
}

export function buildGitHubReleaseTagUrl(repo: string, tag: string): string {
  return `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`;
}

export function buildGitHubDeploymentJsonUrl(repo: string, tag: string): string {
  return `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/tinfoil-deployment.json`;
}

export function buildGitHubHashAssetUrl(repo: string, tag: string): string {
  return `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/tinfoil.hash`;
}

export function buildAmdKdsVcekUrl(
  productName: string | undefined,
  chipIdHex: string | undefined,
  tcb:
    | {
        bootloader: number;
        tee: number;
        snp: number;
        microcode: number;
      }
    | undefined,
): string | null {
  if (!productName || !chipIdHex || !tcb) return null;
  return `https://kdsintf.amd.com/vcek/v1/${productName}/${chipIdHex}?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`;
}

export function buildArcExplorerAddressUrl(
  explorerBase: string | undefined,
  address: string | undefined,
): string | null {
  if (!address || !address.startsWith("0x")) return null;
  const base = (explorerBase || "https://explorer.testnet.arc.io").replace(
    /\/+$/,
    "",
  );
  return `${base}/address/${address}`;
}

export function buildArcExplorerTxUrl(
  explorerBase: string | undefined,
  txHashOrUrl: string | undefined | null,
): string | null {
  if (!txHashOrUrl) return null;
  if (txHashOrUrl.startsWith("http://") || txHashOrUrl.startsWith("https://")) {
    return txHashOrUrl;
  }
  if (!txHashOrUrl.startsWith("0x")) return null;
  const base = (explorerBase || "https://explorer.testnet.arc.io").replace(
    /\/+$/,
    "",
  );
  return `${base}/tx/${txHashOrUrl}`;
}

export function buildSigstoreSearchByLogIndexUrl(
  logIndex: string | number,
): string {
  return `https://search.sigstore.dev/?logIndex=${encodeURIComponent(String(logIndex))}`;
}

export function buildSigstoreSearchByHashUrl(sha256Hex: string): string {
  const clean = sha256Hex.replace(/^sha256:/, "");
  return `https://search.sigstore.dev/?hash=${encodeURIComponent(clean)}`;
}

export function buildRekorApiEntryByIndexUrl(
  logIndex: string | number,
): string {
  return `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${encodeURIComponent(String(logIndex))}`;
}

export function buildRekorApiEntryByUuidUrl(uuid: string): string {
  return `https://rekor.sigstore.dev/api/v1/log/entries/${encodeURIComponent(uuid)}`;
}

export function extractAttestationRekorEntry(
  raw: RawAttestationResponse | null | undefined,
): {
  logIndex: string;
  integratedTime?: string;
  treeSize?: string;
  rootHash?: string;
  searchUrl: string;
  apiUrl: string;
} | null {
  const entry = raw?.sigstoreBundle?.verificationMaterial?.tlogEntries?.[0];
  const logIndex = entry?.logIndex ?? entry?.inclusionProof?.logIndex;
  if (!logIndex) return null;
  return {
    logIndex,
    integratedTime: entry?.integratedTime,
    treeSize: entry?.inclusionProof?.treeSize,
    rootHash: entry?.inclusionProof?.rootHash,
    searchUrl: buildSigstoreSearchByLogIndexUrl(logIndex),
    apiUrl: buildRekorApiEntryByIndexUrl(logIndex),
  };
}

/**
 * Queries Rekor's public index (`https://rekor.sigstore.dev/api/v1/index/retrieve`)
 * for a SHA-256 artifact digest and resolves the exact Rekor log entry UUID and logIndex.
 */
export async function lookupRekorEntryByDigest(
  sha256Digest: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RekorLookupEntry | null> {
  const cleanHex = sha256Digest.replace(/^sha256:/, "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(cleanHex)) return null;

  try {
    const idxRes = await fetchImpl(
      "https://rekor.sigstore.dev/api/v1/index/retrieve",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash: `sha256:${cleanHex}` }),
      },
    );
    if (!idxRes.ok) return null;
    const uuids = (await idxRes.json()) as unknown;
    if (!Array.isArray(uuids) || uuids.length === 0) return null;
    const uuid = String(uuids[uuids.length - 1] ?? "");
    if (!uuid) return null;

    const apiUrl = buildRekorApiEntryByUuidUrl(uuid);
    let logIndex: number | undefined;
    let integratedTime: number | undefined;

    const entryRes = await fetchImpl(apiUrl, {
      headers: { Accept: "application/json" },
    });
    if (entryRes.ok) {
      const entryData = (await entryRes.json()) as Record<
        string,
        { logIndex?: number; integratedTime?: number }
      >;
      const firstKey = Object.keys(entryData)[0];
      if (firstKey && entryData[firstKey]) {
        logIndex = entryData[firstKey].logIndex;
        integratedTime = entryData[firstKey].integratedTime;
      }
    }

    const searchUrl =
      logIndex !== undefined
        ? buildSigstoreSearchByLogIndexUrl(logIndex)
        : `https://search.sigstore.dev/?uuid=${encodeURIComponent(uuid)}`;

    return {
      uuid,
      logIndex,
      integratedTime,
      searchUrl,
      apiUrl,
    };
  } catch {
    return null;
  }
}

/**
 * Queries GitHub Releases API for the given repo and tag to obtain the exact SHA-256 digest
 * of `tinfoil-deployment.json`, then resolves its Sigstore Rekor entry if obtainable.
 */
export async function resolveModelDeploymentProvenance(
  modelAttestation: Pick<ModelEnclaveAttestation, "repo" | "tag">,
  fetchImpl: typeof fetch = fetch,
): Promise<DeploymentAssetLookup> {
  const { repo, tag } = modelAttestation;
  const releaseTagUrl = buildGitHubReleaseTagUrl(repo, tag);
  const downloadUrl = buildGitHubDeploymentJsonUrl(repo, tag);

  let sha256Digest: string | null = null;
  try {
    const ghUrl = `https://api.github.com/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
    const ghRes = await fetchImpl(ghUrl, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (ghRes.ok) {
      const releaseJson = (await ghRes.json()) as {
        assets?: Array<{ name?: string; digest?: string }>;
      };
      const asset = releaseJson.assets?.find(
        (a) => a.name === "tinfoil-deployment.json",
      );
      if (asset?.digest) {
        sha256Digest = asset.digest.replace(/^sha256:/, "");
      }
    }
  } catch {
    // Ignore GitHub API rate-limit or network error; fall back to null digest
  }

  const rekor = sha256Digest
    ? await lookupRekorEntryByDigest(sha256Digest, fetchImpl)
    : null;

  return {
    repo,
    tag,
    downloadUrl,
    releaseTagUrl,
    sha256Digest,
    rekor,
  };
}

export function resolveActiveRegistryNode(
  node: NodeRecord | null,
  registry: RegistrySnapshot | null,
): NodeRecord | null {
  const nodes = registry?.nodes ?? [];
  if (node) {
    const matched = nodes.find(
      (n) =>
        n.id === node.id ||
        n.endpoint === node.endpoint ||
        (node.kind === "tinfoil" && n.kind === "tinfoil"),
    );
    return matched ?? node;
  }
  return nodes.find((n) => n.kind === "tinfoil") ?? nodes[0] ?? null;
}

export function isDeepAttestationBundle(
  val: unknown,
): val is DeepAttestationBundle {
  return Boolean(
    val &&
      typeof val === "object" &&
      "routerHost" in (val as Record<string, unknown>) &&
      "models" in (val as Record<string, unknown>),
  );
}
