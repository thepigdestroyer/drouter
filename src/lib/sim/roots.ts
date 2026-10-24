import { MIN_TCB, SIM_MODEL_ID } from "./constants";
import type { SimRoots } from "./types";

/**
 * Retained only until remaining callers are removed. Returns an empty node list.
 * Delete after UI cleanup.
 */
export function simRoots(): SimRoots {
  return {
    simulated: true,
    amdRoot: "",
    nvidiaRoot: "",
    approvedMeasurement: "",
    minTcb: MIN_TCB,
    model: { id: SIM_MODEL_ID, modelRoot: "" },
    nodes: [],
  };
}
