import { logReceipt, logVerification, mongoConfigured, recentActivity } from "@/lib/db";


const HEX = /^(0x)?[0-9a-fA-F]{1,256}$/;
const CHECK_STATUS = new Set(["pass", "fail", "skip"]);

function str(value: unknown, max = 200): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

/** Public transparency log: recent verifications, receipts and relay totals. */
export async function GET() {
  return Response.json(await recentActivity());
}

/**
 * Accepts only whitelisted, non-sensitive fields. Anything else in the body is dropped, so this
 * endpoint cannot be used to store prompts or outputs.
 */
export async function POST(request: Request) {
  if (!mongoConfigured()) return Response.json({ stored: false, reason: "MongoDB not configured" });
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (body.type === "verification") {
    const nodeId = str(body.nodeId, 80);
    const nodeName = str(body.nodeName, 80);
    const kind = body.kind === "tinfoil" || body.kind === "sim" ? body.kind : null;
    const measurement = str(body.measurement, 300) ?? "";
    const evidenceHash = str(body.evidenceHash, 80);
    const checks = Array.isArray(body.checks)
      ? body.checks
          .filter((c): c is { id: string; status: "pass" | "fail" | "skip" } =>
            typeof c === "object" && c !== null && typeof c.id === "string" && c.id.length <= 8 && CHECK_STATUS.has(c.status),
          )
          .map((c) => ({ id: c.id, status: c.status }))
          .slice(0, 12)
      : [];
    if (!nodeId || !nodeName || !kind || !evidenceHash || !HEX.test(evidenceHash)) {
      return Response.json({ error: "Invalid verification event" }, { status: 400 });
    }
    const stored = await logVerification({
      nodeId,
      nodeName,
      kind,
      ok: body.ok === true,
      checks,
      measurement,
      evidenceHash,
      releaseDigest: str(body.releaseDigest, 100) ?? undefined,
      enclaveHost: str(body.enclaveHost, 100) ?? undefined,
      at: new Date(),
    });
    return Response.json({ stored });
  }

  if (body.type === "receipt") {
    const nodeId = str(body.nodeId, 80);
    const receiptHash = str(body.receiptHash, 80);
    if (!nodeId || !receiptHash || !HEX.test(receiptHash)) {
      return Response.json({ error: "Invalid receipt event" }, { status: 400 });
    }
    const anchorTx = str(body.anchorTx, 80);
    const stored = await logReceipt({
      nodeId,
      receiptHash,
      signatureVerified: body.signatureVerified === true,
      anchorTx: anchorTx && HEX.test(anchorTx) ? anchorTx : null,
      at: new Date(),
    });
    return Response.json({ stored });
  }

  return Response.json({ error: "Unknown event type" }, { status: 400 });
}
