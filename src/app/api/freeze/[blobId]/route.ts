import { connection } from "next/server";
import { deleteFrozenBlob, getFrozenBlob } from "@/lib/freeze/store";
import { createTokenBucketLimiter } from "@/lib/ratelimit";

const BLOB_ID_RE = /^(0x)?[0-9a-fA-F]{2,128}$/;

const blobLimiter = createTokenBucketLimiter({
  name: "freeze-blob-id",
  capacity: 60,
  refillPerSec: 2,
});

export async function GET(
  request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  await connection();
  const limited = blobLimiter.check(request);
  if (limited) return limited;

  const { blobId } = await ctx.params;
  if (!BLOB_ID_RE.test(blobId)) {
    return Response.json({ error: "Invalid blobId format" }, { status: 400 });
  }
  const blob = await getFrozenBlob(blobId);
  if (!blob) {
    return Response.json({ error: "Frozen blob not found" }, { status: 404 });
  }
  return Response.json(blob);
}

export async function DELETE(
  request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  const limited = blobLimiter.check(request);
  if (limited) return limited;

  const { blobId } = await ctx.params;
  if (!BLOB_ID_RE.test(blobId)) {
    return Response.json({ error: "Invalid blobId format" }, { status: 400 });
  }
  await deleteFrozenBlob(blobId);
  return Response.json({ deleted: true });
}
