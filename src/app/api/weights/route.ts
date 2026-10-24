import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection, NextResponse } from "next/server";
import {
  createCustodyProviderKeypair,
  custodyUnwrapWeightKey,
  providerWrapWeightKey,
} from "@/lib/weights/closed-release";
import {
  listModelRegistry,
  OPEN_MODEL_CATALOG,
  proveShardMembership,
  verifyShardBeforeLoad,
} from "@/lib/weights/open-shards";

export async function GET() {
  await connection();

  const models = listModelRegistry();
  const sampleModel = OPEN_MODEL_CATALOG["kimi-k3"];
  const sampleShardIndex = 0;
  const sampleProof = proveShardMembership(sampleModel.shardHashes, sampleShardIndex);
  const verified = verifyShardBeforeLoad(
    sampleProof.shardHash,
    sampleProof,
    sampleModel.merkleRoot
  );

  return NextResponse.json({
    models,
    sampleProof: {
      modelId: sampleModel.modelId,
      shardIndex: sampleShardIndex,
      verified,
      ...sampleProof,
    },
  });
}

export async function POST(request: Request) {
  let body: Record<string, unknown> = {};
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }

  const providerId =
    typeof body.providerId === "string" ? body.providerId : "provider-frontier-labs";
  const modelId =
    typeof body.modelId === "string" ? body.modelId : "frontier-closed-x1";
  const chipId =
    typeof body.chipId === "string" ? body.chipId : "H200-SXM-NV-0042";
  const approvedMeasurement =
    typeof body.approvedMeasurement === "string"
      ? body.approvedMeasurement
      : bytesToHex(sha256(utf8ToBytes("drouter:approved-Rim-measurement:v1")));
  const measurement =
    typeof body.measurement === "string" ? body.measurement : approvedMeasurement;
  const status =
    body.status === "full" || body.status === "ramp" || body.status === "suspended"
      ? body.status
      : "full";
  const quorumSignatures =
    typeof body.quorumSignatures === "number" ? body.quorumSignatures : 5;
  const requiredQuorum =
    typeof body.requiredQuorum === "number" ? body.requiredQuorum : 4;

  // Simulated provider-held master weight key (never exposed outside provider / custody module)
  const simulatedWeightKeyHex = bytesToHex(
    sha256(utf8ToBytes(`drouter:secret-weight-key:${providerId}:${modelId}`))
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
        reason: releaseResult.reason,
        custodyBindingHash: custodyKeys.bindingHash,
        custodyUnwrapped: false,
      },
      { status: 403 }
    );
  }

  // Unwrap inside simulated GPU TEE custody module and confirm integrity via digest without exposing raw key
  const unwrappedHex = custodyUnwrapWeightKey(releaseResult, custodyKeys);
  const unwrappedMatchesProviderKey = unwrappedHex === simulatedWeightKeyHex;
  const unwrappedKeyCommitment = bytesToHex(sha256(hexToBytes(unwrappedHex)));

  return NextResponse.json({
    verdict: "APPROVED_AND_RELEASED",
    released: true,
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
      decryptionTarget: "GPU_VRAM_TEE_ONLY",
    },
  });
}
