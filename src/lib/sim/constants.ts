import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { utf8 } from "./bytes";

export const SESSION_LABEL = "drouter/v1/session";
/** Launch-time binding label. Part of the protocol constants; the sim session flow does not use it. */
export const LAUNCH_LABEL = "drouter/v1/launch";

/** REPORT_DATA values starting with this prefix must never be signed by a node. */
export const FORBIDDEN_REPORT_DATA_PREFIX: Uint8Array = sha256(utf8("drouter/forbidden-report-data/v1"));

export interface SimNodeSpec {
  id: string;
  region: string;
}

export const SIM_NODES: readonly SimNodeSpec[] = [
  { id: "sim-1", region: "eu-west" },
  { id: "sim-2", region: "us-east" },
  { id: "sim-3", region: "ap-south" },
];

export const SIM_MODEL_ID = "sim-echo-1";
export const SIM_MODEL_ROOT: Uint8Array = sha256(utf8("sim-echo-1-weights"));

/** sha384("drouter-sim-node-image/v0.1.0"), 48 bytes. */
export const APPROVED_MEASUREMENT: Uint8Array = sha384(utf8("drouter-sim-node-image/v0.1.0"));

export const GPU_FIRMWARE_MEASUREMENT: Uint8Array = sha384(utf8("drouter-sim-gpu-firmware/v0.1.0"));

export const GPUS_PER_NODE = 8;

/** Turin TCB layout components (all must be >= minimum). */
export interface Tcb {
  fmc: number;
  bootloader: number;
  tee: number;
  snp: number;
  microcode: number;
}

export const MIN_TCB: Tcb = { fmc: 1, bootloader: 1, tee: 1, snp: 1, microcode: 1 };
export const SIM_TCB: Tcb = { fmc: 2, bootloader: 3, tee: 1, snp: 4, microcode: 9 };

export const TICKET_IDLE_MS = 30 * 60 * 1000;

/** Bound on session context so a sealed ticket stays small. */
export const MAX_CONTEXT_TOKENS = 16384;
