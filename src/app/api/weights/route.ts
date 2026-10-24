import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection, NextResponse } from "next/server";
import {
  BodyTooLargeError,
  createTokenBucketLimiter,
  readBoundedBytes,
} from "@/lib/ratelimit";
import {
  createCustodyProviderKeypair,
  custodyUnwrapWeightKey,
  providerWrapWeightKey,
} from "@/lib/weights/closed-release";
import {
  listModelRegistry,
  OPEN_MODEL_CATALOG,
  proveShardMembership,
  verifyAllLiveModelProvenance,
  verifyLiveModelWeightProvenance,
  verifyShardBeforeLoad,
} from "@/lib/weights/open-shards";

const MAX_WEIGHTS_BODY_BYTES = 8192;

const weightsLimiter = createTokenBucketLimiter({
  name: "weights-route",
  capacity: 60,
  refillPerSec: 2,
});

export async function GET(request?: Request) {
  try {
    await connection();
  } catch {
    // Allow direct invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = weightsLimiter.check(request);
    if (limited) return limited;
  }

  let requestedModel = "kimi-k3";
  let requestedShardIndex = 0;
  if (request?.url) {
    try {
      const url = new URL(request.url);
      const m = url.searchParams.get("model");
      if (m && OPEN_MODEL_CATALOG[m]) {
        requestedModel = m;
      }
      const s = url.searchParams.get("shard");
      if (s !== null) {
        const parsedIdx = Number(s);
        if (Number.isInteger(parsedIdx) && parsedIdx >= 0) {
          requestedShardIndex = parsedIdx;
        }
      }
    } catch {
      // Ignore malformed URL in direct test invocation
    }
  }

  const models = listModelRegistry();
  const sampleModel = OPEN_MODEL_CATALOG[requestedModel] ?? OPEN_MODEL_CATALOG["kimi-k3"];
  const safeShardIndex =
    requestedShardIndex < sampleModel.shardHashes.length ? requestedShardIndex : 0;
  const sampleProof = proveShardMembership(sampleModel.shardHashes, safeShardIndex);
  const verified = verifyShardBeforeLoad(
    sampleProof.shardHash,
    sampleProof,
    sampleModel.merkleRoot,
  );

  const allModelsProvenance = await verifyAllLiveModelProvenance();
  const provenance =
    allModelsProvenance[sampleModel.modelId] ??
    (await verifyLiveModelWeightProvenance(sampleModel.modelId));

  return NextResponse.json({
    models,
    sampleProof: {
      modelId: sampleModel.modelId,
      shardIndex: safeShardIndex,
      verified,
      hfRepo: sampleModel.hfRepo,
      hfCommit: sampleModel.hfCommit,
      ...sampleProof,
    },
    provenance,
    allModelsProvenance,
  });
}

export async function POST(request: Request) {
  const limited = weightsLimiter.check(request);
  if (limited) return limited;

  let body: Record<string, unknown> = {};
  try {
    const rawBytes = await readBoundedBytes(request, MAX_WEIGHTS_BODY_BYTES);
    if (rawBytes.byteLength > 0) {
      const parsed = JSON.parse(new TextDecoder().decode(rawBytes));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      body = parsed as Record<string, unknown>;
    }
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const providerId =
    typeof body.providerId === "string" && body.providerId.trim()
      ? body.providerId.trim().slice(0, 128)
      : "provider-frontier-labs";
  const modelId =
    typeof body.modelId === "string" && body.modelId.trim()
      ? body.modelId.trim().slice(0, 128)
      : "kimi-k3";

  const provenanceModelId = OPEN_MODEL_CATALOG[modelId]?.tinfoilRepo ? modelId : "kimi-k3";
  const provenance = await verifyLiveModelWeightProvenance(provenanceModelId);

  const chipId =
    typeof body.chipId === "string" && body.chipId.trim()
      ? body.chipId.trim().slice(0, 128)
      : (provenance.proxyTable.repo || "tinfoilsh/confidential-kimi-k3");
  const defaultMeasurement =
    provenance.deploymentManifest.snpMeasurement ||
    bytesToHex(sha256(utf8ToBytes("drouter:approved-Rim-measurement:v1")));
  const approvedMeasurement =
    typeof body.approvedMeasurement === "string" && body.approvedMeasurement.length <= 256
      ? body.approvedMeasurement
      : defaultMeasurement;
  const measurement =
    typeof body.measurement === "string" && body.measurement.length <= 256
      ? body.measurement
      : approvedMeasurement;
  const status =
    body.status === "full" || body.status === "ramp" || body.status === "suspended"
      ? body.status
      : "full";
  const quorumSignatures =
    typeof body.quorumSignatures === "number" && Number.isFinite(body.quorumSignatures)
      ? Math.max(0, Math.min(20, Math.floor(body.quorumSignatures)))
      : 5;
  const requiredQuorum =
    typeof body.requiredQuorum === "number" && Number.isFinite(body.requiredQuorum)
      ? Math.max(1, Math.min(20, Math.floor(body.requiredQuorum)))
      : 4;

  // Simulated closed-weight key wrapping (Tinfoil serves open-weight models verified via provenance above)
  const simulatedWeightKeyHex = bytesToHex(
    sha256(utf8ToBytes(`drouter:secret-weight-key:${providerId}:${modelId}`)),
  );

  const custodyKeys = createCustodyProviderKeypair();

  const releaseResult = providerWrapWeightKey({
    providerId,
    modelId,
    weightKeyHex: simulatedWeightKeyHex,
    nodeEvidence: {
      chipId,
      measurement,
      approvedMeasurement,
      status,
      quorumSignatures,
      requiredQuorum,
      custodyX25519Pk: custodyKeys.x25519PublicKey,
      custodyMlkemPk: custodyKeys.mlkemPublicKey,
    },
  });

  if (!releaseResult.released) {
    return NextResponse.json(
      {
        verdict: "REFUSED",
        released: false,
        simulated: true,
        mode: "Simulated",
        reason: releaseResult.reason,
        custodyBindingHash: custodyKeys.bindingHash,
        custodyUnwrapped: false,
        provenance,
      },
      { status: 403 },
    );
  }

  const unwrappedHex = custodyUnwrapWeightKey(releaseResult, custodyKeys);
  const unwrappedMatchesProviderKey = unwrappedHex === simulatedWeightKeyHex;
  const unwrappedKeyCommitment = bytesToHex(sha256(hexToBytes(unwrappedHex)));

  return NextResponse.json({
    verdict: "APPROVED_AND_RELEASED",
    released: true,
    simulated: true,
    mode: "Simulated",
    note: "Simulated: Closed-weight key wrapping runs locally in software using X25519 + ML-KEM-768 + AES-256-GCM + Ed25519. Live Tinfoil models use open weights verified via `provenance`.",
    providerId,
    modelId,
    chipId,
    custodyBindingHash: custodyKeys.bindingHash,
    wrappedBundle: {
      wrappedKeyCiphertextHex: releaseResult.wrappedKeyCiphertextHex,
      nonceHex: releaseResult.nonceHex,
      providerEphemeralX25519Pk: releaseResult.providerEphemeralX25519Pk,
      mlkemCiphertextHex: releaseResult.mlkemCiphertextHex,
      providerSignatureHex: releaseResult.providerSignatureHex,
      providerPublicKeyHex: releaseResult.providerPublicKeyHex,
    },
    custodyModuleConfirmation: {
      unwrappedInsideCustodyModule: unwrappedMatchesProviderKey,
      rawWeightKeyExposedToRouter: false,
      unwrappedKeySha256Commitment: unwrappedKeyCommitment,
      decryptionTarget: "LOCAL_SOFTWARE_KEY_WRAP_MODEL",
      simulated: true,
    },
    provenance,
  });
}
