import { connection } from "next/server";
import { listFrozenBlobSummaries, saveFrozenBlob, type SaveFrozenBlobInput } from "@/lib/freeze/store";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_FREEZE_BODY_BYTES = 262_144; // 256 KB max encrypted freeze blob request
const MAX_CIPHERTEXT_HEX_LEN = 262_144; // 128 KB binary ciphertext

const getLimiter = createTokenBucketLimiter({
  name: "freeze-get",
  capacity: 60,
  refillPerSec: 2,
});

const postLimiter = createTokenBucketLimiter({
  name: "freeze-post",
  capacity: 15,
  refillPerSec: 15 / 60,
});

export async function GET(request?: Request) {
  await connection();
  if (request) {
    const limited = getLimiter.check(request);
    if (limited) return limited;
  }
  const blobs = await listFrozenBlobSummaries();
  return Response.json({ blobs });
}

export async function POST(request: Request) {
  const limited = postLimiter.check(request);
  if (limited) return limited;

  let body: SaveFrozenBlobInput;
  try {
    body = await readBoundedJson<SaveFrozenBlobInput>(request, MAX_FREEZE_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON body" },
      { status: 400 },
    );
  }

  if (
    body &&
    typeof body === "object" &&
    typeof body.ciphertextHex === "string" &&
    body.ciphertextHex.length > MAX_CIPHERTEXT_HEX_LEN
  ) {
    return Response.json(
      { error: `ciphertextHex exceeds maximum allowed size (${MAX_CIPHERTEXT_HEX_LEN / 2} bytes)` },
      { status: 413 },
    );
  }

  if (
    body &&
    typeof body === "object" &&
    typeof body.blobId === "string" &&
    body.blobId.length > 130
  ) {
    return Response.json({ error: "blobId exceeds maximum length" }, { status: 400 });
  }

  try {
    const saved = await saveFrozenBlob(body);
    return Response.json({
      stored: true,
      blobId: saved.blobId,
      byteLength: saved.byteLength,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Invalid freeze blob payload";
    return Response.json({ error: message }, { status: 400 });
  }
}
