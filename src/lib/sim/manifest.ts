import { sha256 } from "@noble/hashes/sha2.js";
import { toHex } from "./bytes";
import { SIM_NODES } from "./constants";
import { SimError } from "./errors";
import { assertSimId, chipId, gpuIds } from "./hardware";
import { canonicalBytes } from "./protocol";
import type { Manifest } from "./types";

export function simNodeSpec(simId: string) {
  assertSimId(simId);
  const spec = SIM_NODES.find((n) => n.id === simId);
  if (!spec) throw new SimError(404, "unknown simulated node");
  return spec;
}

export function buildManifest(simId: string): Manifest {
  const spec = simNodeSpec(simId);
  return {
    simId,
    chipId: toHex(chipId(simId)),
    gpuIds: gpuIds(simId),
    region: spec.region,
    board: "sim-board",
    memory: "sim",
    simulated: true,
  };
}

export function manifestHash(manifest: Manifest): Uint8Array {
  return sha256(canonicalBytes(manifest));
}
