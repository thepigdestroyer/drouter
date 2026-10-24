import { connection, NextResponse } from "next/server";
import { createTokenBucketLimiter } from "@/lib/ratelimit";
import {
  listModelRegistry,
  OPEN_MODEL_CATALOG,
  proveShardMembership,
  verifyAllLiveModelProvenance,
  verifyLiveModelWeightProvenance,
  verifyShardBeforeLoad,
} from "@/lib/weights/open-shards";

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
