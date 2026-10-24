import { connection } from "next/server";
import {
  getFreezeStorageMode,
  listFrozenBlobSummaries,
  saveFrozenBlob,
  type SaveFrozenBlobInput,
} from "@/lib/freeze/store";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

export const MAX_FREEZE_BODY_BYTES = 262_144; // 256 KB max encrypted freeze blob request
export const MAX_CIPHERTEXT_HEX_LEN = 262_144; // 128 KB binary ciphertext

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

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store",
};

export async function GET(request?: Request) {
  try {
    await connection();
  } catch {
    // Allow direct route invocation in unit tests outside Next request storage
  }
  if (request) {
    const limited = getLimiter.check(request, NO_STORE_HEADERS);
    if (limited) return limited;
  }
  // Blob IDs act as unguessable capabilities for read and delete, so they are
  // never listed publicly. Only an aggregate count is returned.
  const activeBlobCount = (await listFrozenBlobSummaries()).length;
  const storage = getFreezeStorageMode();
  return Response.json(
    {
      blobs: [],
      activeBlobCount,
      storageMode: storage.mode,
      persisted: storage.persisted,
      storageLabel: storage.label,
    },
    { headers: NO_STORE_HEADERS },
  );
}

export async function POST(request: Request) {
  const limited = postLimiter.check(request, NO_STORE_HEADERS);
  if (limited) return limited;

  let body: SaveFrozenBlobInput;
  try {
    body = await readBoundedJson<SaveFrozenBlobInput>(request, MAX_FREEZE_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return Response.json({ error: err.message }, { status: 413, headers: NO_STORE_HEADERS });
    }
    return Response.json(
      { error: err instanceof InvalidJsonBodyError ? err.message : "Invalid JSON body" },
      { status: 400, headers: NO_STORE_HEADERS },
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
      { status: 413, headers: NO_STORE_HEADERS },
    );
  }

  if (
    body &&
    typeof body === "object" &&
    typeof body.blobId === "string" &&
    body.blobId.length > 130
  ) {
    return Response.json(
      { error: "blobId exceeds maximum length" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  try {
    const saved = await saveFrozenBlob(body);
    const storage = getFreezeStorageMode();
    return Response.json(
      {
        stored: true,
        blobId: saved.blobId,
        byteLength: saved.byteLength,
        createdAt: saved.createdAt,
        expiresAt: saved.expiresAt,
        storageMode: storage.mode,
        persisted: storage.persisted,
        storageLabel: storage.label,
      },
      { headers: NO_STORE_HEADERS },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Invalid freeze blob payload";
    const status = message.includes("persistence unavailable") ? 503 : 400;
    return Response.json({ error: message }, { status, headers: NO_STORE_HEADERS });
  }
}
