import type { Tcb } from "./constants";

/** Wire types for the sim node. Every byte string is lowercase hex. */

export interface SignedStatement<T> {
  statement: T;
  signature: string;
}

export interface VcekStatement {
  chipId: string;
  tcb: Tcb;
  vcekPublicKey: string;
  simulated?: boolean;
}

export interface GpuCertStatement {
  gpuIndex: number;
  gpuId: string;
  devicePublicKey: string;
}

export interface GpuReportBody {
  gpuIndex: number;
  gpuId: string;
  ccMode: boolean;
  nonce: string;
  firmwareMeasurement: string;
}

export interface GpuEvidence {
  certificate: SignedStatement<GpuCertStatement>;
  report: GpuReportBody;
  /** Ed25519 over canonical(report) by the GPU device key. */
  signature: string;
}

export interface Manifest {
  simId: string;
  chipId: string;
  gpuIds: string[];
  region: string;
  board: string;
  memory: string;
  simulated?: boolean;
}

export interface EvidenceBundle {
  simId: string;
  simulated: true;
  /** Full 1184-byte SEV-SNP attestation report. */
  report: string;
  vcekCertificate: SignedStatement<VcekStatement>;
  gpus: GpuEvidence[];
  manifest: Manifest;
  manifestHash: string;
  modelId: string;
  modelRoot: string;
  custody: { x25519PublicKey: string; mlkemPublicKey: string };
  identityPublicKey: string;
}

export interface HelloRequest {
  clientNonce: string;
  modelId: string;
}

export interface HelloResponse {
  simulated: true;
  evidence: EvidenceBundle;
  ticket: string;
}

export interface KeyshareRequest {
  ticket: string;
  clientX25519Pk: string;
  mlkemCt: string;
  sealed: string;
}

export interface KeyshareResponse {
  simulated: true;
  ready: string;
  ticket: string;
}

export interface TurnRequest {
  ticket: string;
  turn: number;
  ct: string;
}

export interface TurnResponse {
  simulated: true;
  frames: string[];
  ticket: string;
}

export interface CloseRequest {
  ticket: string;
}

export interface PopReceiptWire {
  simulated?: true;
  nodeId: string;
  sessionIdHash: string;
  time: number;
  measurement: string;
  signature: string;
  signerPublicKey: string;
}

export interface RootsNode {
  simId: string;
  simulated: true;
  region: string;
  chipId: string;
  manifestHash: string;
  gpuIds: string[];
  identityPublicKey: string;
}

export interface SimRoots {
  simulated: true;
  amdRoot: string;
  nvidiaRoot: string;
  approvedMeasurement: string;
  minTcb: Tcb;
  model: { id: string; modelRoot: string };
  nodes: RootsNode[];
}
