import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { QuorumTicket } from "@/lib/types";
import { canonicalJson, deriveEd25519Key } from "./log";

export const VERIFIER_THRESHOLD = 5;

const VERIFIER_ORGS = [
  { id: "verifier-1", name: "Chaos Labs" },
  { id: "verifier-2", name: "Trail of Bits" },
  { id: "verifier-3", name: "OpenZeppelin" },
  { id: "verifier-4", name: "Spearbit" },
  { id: "verifier-5", name: "Zellic" },
  { id: "verifier-6", name: "Runtime Verification" },
  { id: "verifier-7", name: "Nethermind" },
] as const;

function verifierKey(verifierId: string) {
  return deriveEd25519Key(`transparency/verifier/${verifierId}`);
}

export function ticketSigningPayload(
  ticket: Pick<QuorumTicket, "nodeId" | "chipId" | "nodeIdentityPk" | "epoch" | "status" | "weight">,
): Uint8Array {
  return utf8ToBytes(
    canonicalJson({
      chipId: ticket.chipId,
      epoch: ticket.epoch,
      nodeId: ticket.nodeId,
      nodeIdentityPk: ticket.nodeIdentityPk,
      status: ticket.status,
      weight: ticket.weight,
    }),
  );
}

export function getVerifierSet(): {
  threshold: number;
  total: number;
  verifiers: { id: string; name: string; publicKey: string }[];
} {
  const verifiers = VERIFIER_ORGS.map((org) => ({
    id: org.id,
    name: org.name,
    publicKey: verifierKey(org.id).publicKeyHex,
  }));
  return {
    threshold: VERIFIER_THRESHOLD,
    total: verifiers.length,
    verifiers,
  };
}

export function issueQuorumTicket(params: {
  nodeId: string;
  chipId: string;
  nodeIdentityPk: string;
  epoch?: number;
  status?: "full" | "ramp" | "suspended";
  weight?: number;
  signerCount?: number;
}): QuorumTicket {
  const epoch = params.epoch ?? 1;
  const status = params.status ?? "full";
  const weight =
    params.weight ?? (status === "suspended" ? 0 : status === "ramp" ? 2500 : 10000);
  const signerCount = Math.min(Math.max(params.signerCount ?? VERIFIER_THRESHOLD, 0), VERIFIER_ORGS.length);

  const core = {
    nodeId: params.nodeId,
    chipId: params.chipId,
    nodeIdentityPk: params.nodeIdentityPk,
    epoch,
    status,
    weight,
  };
  const payload = ticketSigningPayload(core);

  const signatures = VERIFIER_ORGS.slice(0, signerCount).map((org) => {
    const key = verifierKey(org.id);
    return {
      verifierId: org.id,
      publicKey: key.publicKeyHex,
      signature: bytesToHex(ed25519.sign(payload, key.secretKey)),
    };
  });

  return {
    ...core,
    signatures,
  };
}

export function verifyQuorumTicket(
  ticket: QuorumTicket,
  k: number = VERIFIER_THRESHOLD,
): {
  ok: boolean;
  validSignatures: number;
  required: number;
  detail: string;
} {
  const required = k;
  const verifierMap = new Map(
    VERIFIER_ORGS.map((org) => [org.id as string, verifierKey(org.id)]),
  );
  const payload = ticketSigningPayload(ticket);

  const seenVerifiers = new Set<string>();
  let allSignaturesValid = true;

  for (const sig of ticket.signatures) {
    const expected = verifierMap.get(sig.verifierId);
    if (!expected || seenVerifiers.has(sig.verifierId)) {
      allSignaturesValid = false;
      continue;
    }
    try {
      if (sig.publicKey.toLowerCase() !== expected.publicKeyHex.toLowerCase()) {
        allSignaturesValid = false;
        continue;
      }
      const sigBytes = hexToBytes(sig.signature);
      if (ed25519.verify(sigBytes, payload, expected.publicKey)) {
        seenVerifiers.add(sig.verifierId);
      } else {
        allSignaturesValid = false;
      }
    } catch {
      allSignaturesValid = false;
    }
  }

  const validSignatures = seenVerifiers.size;
  const reasons: string[] = [];

  if (!allSignaturesValid) {
    reasons.push("ticket contains an invalid, duplicate, or unregistered verifier signature");
  }
  if (validSignatures < required) {
    reasons.push(`insufficient verifier quorum (${validSignatures}/${required})`);
  }
  if (ticket.status === "suspended") {
    reasons.push("node admission ticket status is suspended");
  }
  if (!(ticket.weight > 0)) {
    reasons.push(`node admission weight must be > 0 (got ${ticket.weight})`);
  }

  const ok = reasons.length === 0;
  return {
    ok,
    validSignatures,
    required,
    detail: ok
      ? `Quorum ticket verified (${validSignatures}/${VERIFIER_ORGS.length} verifiers >= ${required}, status=${ticket.status}, weight=${ticket.weight} bps).`
      : reasons.join("; "),
  };
}
