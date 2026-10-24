import { connection } from "next/server";
import { deleteFrozenBlob, getFrozenBlob } from "@/lib/freeze/store";

export async function GET(
  _request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  await connection();
  const { blobId } = await ctx.params;
  const blob = await getFrozenBlob(blobId);
  if (!blob) {
    return Response.json({ error: "Frozen blob not found" }, { status: 404 });
  }
  return Response.json(blob);
}

export async function DELETE(
  _request: Request,
  ctx: { params: Promise<{ blobId: string }> },
) {
  const { blobId } = await ctx.params;
  await deleteFrozenBlob(blobId);
  return Response.json({ deleted: true });
}
