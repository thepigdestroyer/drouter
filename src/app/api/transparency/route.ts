import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { connection } from "next/server";
import {
  deriveEd25519Key,
  getSeedBytes,
  getTransparencyLog,
  proveInclusion,
} from "@/lib/transparency/log";
import { getVerifierSet, issueQuorumTicket } from "@/lib/transparency/quorum";

function deriveNodeChipAndIdentity(nodeId: string): { chipId: string; nodeIdentityPk: string } {
  const seed = getSeedBytes();
  const chipId = bytesToHex(hkdf(sha256, seed, undefined, utf8ToBytes(`sim/chip/${nodeId}`), 64));
  const nodeIdentityPk = deriveEd25519Key(`sim/identity/${nodeId}`).publicKeyHex;
  return { chipId, nodeIdentityPk };
}

export async function GET() {
  await connection();

  const log = getTransparencyLog();
  const proofs = [proveInclusion(0), proveInclusion(1), proveInclusion(2)];
  const verifierSet = getVerifierSet();

  const nodeIds = ["tinfoil-router", "sim-1", "sim-2", "sim-3"] as const;
  const tickets = Object.fromEntries(
    nodeIds.map((nodeId) => {
      const { chipId, nodeIdentityPk } = deriveNodeChipAndIdentity(nodeId);
      return [
        nodeId,
        issueQuorumTicket({
          nodeId,
          chipId,
          nodeIdentityPk,
          epoch: 1,
          status: "full",
          weight: 10000,
          signerCount: 5,
        }),
      ];
    }),
  );

  return Response.json({
    log,
    proofs,
    verifierSet,
    tickets,
  });
}
