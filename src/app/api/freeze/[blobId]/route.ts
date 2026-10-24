import { connection } from "next/server";
import {
  destroyFrozenBlobVerified,
  getFreezeStorageMode,
  getFrozenBlob,
} from "@/lib/freeze/store";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const BLOB_ID_RE = /^(0x)?[0-9a-fA-F]{2,128}$/;

const blobLimiter = createTokenBucketLimiter({
  name: "freeze-blob-id",
  capacity: 60,
  refillPerSec: 2,
});

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store",
};

export async function GET(
  request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  try {
    await connection();
  } catch {
    // Allow direct route invocation in unit tests outside Next request storage
  }
  const limited = blobLimiter.check(request, NO_STORE_HEADERS);
  if (limited) return limited;

  const { blobId } = await ctx.params;
  if (!BLOB_ID_RE.test(blobId)) {
    return Response.json(
      { error: "Invalid blobId format" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }
  const blob = await getFrozenBlob(blobId);
  if (!blob) {
    return Response.json(
      { error: "Frozen blob not found or expired" },
      { status: 404, headers: NO_STORE_HEADERS },
    );
  }
  const storage = getFreezeStorageMode();
  return Response.json(
    {
      ...blob,
      storageMode: storage.mode,
      persisted: storage.persisted,
    },
    { headers: NO_STORE_HEADERS },
  );
}

export async function DELETE(
  request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  const limited = blobLimiter.check(request, NO_STORE_HEADERS);
  if (limited) return limited;

  const { blobId } = await ctx.params;
  if (!BLOB_ID_RE.test(blobId)) {
    return Response.json(
      { error: "Invalid blobId format" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }
  const res = await destroyFrozenBlobVerified(blobId);
  return Response.json(
    {
      deleted: true,
      removedFromStore: res.deleted,
      verifiedAbsent: res.verifiedAbsent,
    },
    { headers: NO_STORE_HEADERS },
  );
}
