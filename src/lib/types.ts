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

/** Unlinkable blind-signed credit token (Spec §7). */
export interface BlindCreditToken {
  token: string; // hex random 32-byte secret
  signature: string; // hex unblinded RSA signature
  denomination: number; // credits (e.g. 1, 5, 20)
}

/** Plaintext session state encrypted under K_freeze on the client (Spec §Freeze, resume and pop). */
export interface FrozenSessionState {
  modelId: string;
  nodeKind: NodeKind;
  messages: { role: "user" | "assistant"; content: string }[];
  simContextTokens: number;
  createdAt: number;
  turnCount: number;
}

/** Client-held handle returned when freezing a session bubble. */
export interface FreezeReceipt {
  blobId: string;
  freezeSecretHex: string;
  sessionIdHex: string;
  createdAt: number;
}

/** Signed hardware manifest tied to operator stake (Spec §8.1). */
export interface HardwareManifest {
  nodeId: string;
  chipId: string;
  tcb: string;
  gpuIds: string[];
  spdmDevices: string[];
  declared: {
    board: string;
    bmcFirmware: string;
    platformRot: string;
    dimmSlotsTotal: number;
    dimmSlotsPopulated: number;
    dimmSpeedMt: number;
    pcieSlotsPopulated: number;
    region: string;
  };
  timestamp: number;
  signature: string;
  signerPublicKey: string;
}

/** k-of-n verifier admission ticket (Spec §5). */
export interface QuorumTicket {
  nodeId: string;
  chipId: string;
  nodeIdentityPk: string;
  epoch: number;
  status: "full" | "ramp" | "suspended";
  weight: number; // 0..10000 basis points
  signatures: { verifierId: string; publicKey: string; signature: string }[];
}

/** Client-side PII placeholder scrubbing summary. */
export interface ScrubResult {
  scrubbed: string;
  replacements: { placeholder: string; kind: string }[];
}

/** Browser-safe stub when server-only @vercel/sandbox is aliased in client bundles. */
export const Sandbox: {
  create: (...args: unknown[]) => Promise<never>;
} = {
  async create() {
    throw new Error("@vercel/sandbox is server-only");
  },
};

