import { connection } from "next/server";
import { listFrozenBlobSummaries, saveFrozenBlob, type SaveFrozenBlobInput } from "@/lib/freeze/store";

export async function GET() {
  await connection();
  const blobs = await listFrozenBlobSummaries();
  return Response.json({ blobs });
}

export async function POST(request: Request) {
  let body: SaveFrozenBlobInput;
  try {
    body = (await request.json()) as SaveFrozenBlobInput;
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
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
