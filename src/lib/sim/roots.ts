import { toHex } from "./bytes";
import { APPROVED_MEASUREMENT, MIN_TCB, SIM_MODEL_ID, SIM_MODEL_ROOT, SIM_NODES } from "./constants";
import { amdRoot, identity, nvidiaRoot } from "./hardware";
import { buildManifest, manifestHash } from "./manifest";
import type { SimRoots } from "./types";

/** The pinned simulated roots and registered node list the browser client trusts. */
export function simRoots(): SimRoots {
  return {
    simulated: true,
    amdRoot: toHex(amdRoot().publicKey),
    nvidiaRoot: toHex(nvidiaRoot().publicKey),
    approvedMeasurement: toHex(APPROVED_MEASUREMENT),
    minTcb: MIN_TCB,
    model: { id: SIM_MODEL_ID, modelRoot: toHex(SIM_MODEL_ROOT) },
    nodes: SIM_NODES.map((spec) => {
      const manifest = buildManifest(spec.id);
      return {
        simId: spec.id,
        simulated: true,
        region: spec.region,
        chipId: manifest.chipId,
        manifestHash: toHex(manifestHash(manifest)),
        gpuIds: manifest.gpuIds,
        identityPublicKey: toHex(identity(spec.id).publicKey),
      };
    }),
  };
}
