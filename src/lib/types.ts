export type Hex = `0x${string}`;

/** "tinfoil" nodes are real confidential-compute enclaves; "sim" nodes simulate the hardware evidence. */
export type NodeKind = "tinfoil" | "sim";

export type NodeStatus = "active" | "suspended" | "revoked";

/** A node as recorded in the on-chain registry on Arc. */
export interface NodeRecord {
  id: Hex; // bytes32
  kind: NodeKind;
  name: string;
  /** tinfoil: enclave router host, e.g. "inference.tinfoil.sh"; sim: app path, e.g. "/api/sim/sim-1". */
  endpoint: string;
  /** bytes32 commitment to the approved software measurement. */
  measurement: Hex;
  operator: Hex;
  /** Staked collateral in USDC, as a decimal string. */
  stake: string;
  status: NodeStatus;
  region: string;
  registeredAt: number; // unix seconds
  lastVerifiedAt: number; // unix seconds, 0 if never
  lastVerifiedOk: boolean;
}

/** One line in the client's verification checklist. */
export interface CheckResult {
  id: string;
  label: string;
  status: "pass" | "fail" | "skip";
  detail: string;
}

/** Receipt returned when a session's keys are destroyed. */
export interface PopReceipt {
  nodeId: string;
  sessionIdHash: string; // hex sha256 of the session id
  time: number; // unix seconds
  measurement: string; // hex
  signature: string; // hex
  signerPublicKey: string; // hex
  verified: boolean;
}
