import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { HardwareManifest } from "@/lib/types";

export const DEFAULT_SPDM_DEVICES = [
  "spdm://nvidia-hgx-b200/0..7",
  "spdm://connectx-7/0",
  "spdm://nvme-raid/0",
] as const;

export const DEFAULT_MANIFEST_TIMESTAMP = 1760000000;

interface DemoManifestNodeSpec {
  nodeId: string;
  region: string;
  tcb: string;
}

const DEMO_MANIFEST_NODES: readonly DemoManifestNodeSpec[] = [
  { nodeId: "tinfoil-router", region: "us-east", tcb: "fmc:2/bl:3/tee:1/snp:4/ucode:9" },
  { nodeId: "sim-1", region: "eu-west", tcb: "fmc:2/bl:3/tee:1/snp:4/ucode:9" },
  { nodeId: "sim-2", region: "us-east", tcb: "fmc:2/bl:3/tee:1/snp:4/ucode:9" },
  { nodeId: "sim-3", region: "ap-south", tcb: "fmc:2/bl:3/tee:1/snp:4/ucode:9" },
];

function getHardwareSeed(): Uint8Array {
  const raw = process.env.SIM_HARDWARE_SEED || "02".repeat(32);
  const clean = /^[0-9a-fA-F]{64}$/.test(raw) ? raw : "02".repeat(32);
  return hexToBytes(clean);
}

function deriveBytes(info: string, length: number): Uint8Array {
  return hkdf(sha256, getHardwareSeed(), undefined, utf8ToBytes(info), length);
}

export function deriveNodeIdentityKey(nodeId: string): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const secretKey = deriveBytes(`sim/identity/${nodeId}`, 32);
  const publicKey = ed25519.getPublicKey(secretKey);
  return {
    secretKey,
    publicKey,
    publicKeyHex: bytesToHex(publicKey),
  };
}

export function deriveNodeChipId(nodeId: string): string {
  return bytesToHex(deriveBytes(`sim/chip/${nodeId}`, 64));
}

export function deriveNodeGpuIds(nodeId: string, count = 8): string[] {
  return Array.from({ length: count }, (_, idx) => {
    const gpuSecret = deriveBytes(`sim/gpu/${nodeId}/${idx}`, 32);
    const gpuPub = ed25519.getPublicKey(gpuSecret);
    return bytesToHex(sha256(gpuPub).slice(0, 16));
  });
}

function canonicalManifestPayload(
  body: Omit<HardwareManifest, "signature" | "signerPublicKey">,
): Uint8Array {
  const ordered = {
    nodeId: body.nodeId,
    chipId: body.chipId,
    tcb: body.tcb,
    gpuIds: [...body.gpuIds],
    spdmDevices: [...body.spdmDevices],
    declared: {
      board: body.declared.board,
      bmcFirmware: body.declared.bmcFirmware,
      platformRot: body.declared.platformRot,
      dimmSlotsTotal: body.declared.dimmSlotsTotal,
      dimmSlotsPopulated: body.declared.dimmSlotsPopulated,
      dimmSpeedMt: body.declared.dimmSpeedMt,
      pcieSlotsPopulated: body.declared.pcieSlotsPopulated,
      region: body.declared.region,
    },
    timestamp: body.timestamp,
  };
  return utf8ToBytes(JSON.stringify(ordered));
}

export function signManifest(
  body: Omit<HardwareManifest, "signature" | "signerPublicKey">,
  privKey: Uint8Array,
): HardwareManifest {
  const pubKey = ed25519.getPublicKey(privKey);
  const msg = canonicalManifestPayload(body);
  const sig = ed25519.sign(msg, privKey);
  return {
    ...body,
    gpuIds: [...body.gpuIds],
    spdmDevices: [...body.spdmDevices],
    declared: { ...body.declared },
    signature: bytesToHex(sig),
    signerPublicKey: bytesToHex(pubKey),
  };
}

export function verifyManifest(m: HardwareManifest): boolean {
  try {
    const sig = hexToBytes(m.signature);
    const pubKey = hexToBytes(m.signerPublicKey);
    const msg = canonicalManifestPayload(m);
    return ed25519.verify(sig, msg, pubKey);
  } catch {
    return false;
  }
}

export function detectManifestContradiction(
  m: HardwareManifest,
  observed: { chipId?: string; gpuIds?: string[]; region?: string },
): { contradicted: boolean; reasons: string[] } {
  const reasons: string[] = [];

  if (!verifyManifest(m)) {
    reasons.push("Manifest signature verification failed");
  }

  if (observed.chipId !== undefined && observed.chipId !== m.chipId) {
    reasons.push(
      `Attested CPU chipId mismatch: observed ${observed.chipId.slice(0, 16)}... vs manifest ${m.chipId.slice(0, 16)}...`,
    );
  }

  if (observed.gpuIds !== undefined) {
    if (observed.gpuIds.length !== m.gpuIds.length) {
      reasons.push(
        `Attested GPU count mismatch: observed ${observed.gpuIds.length} GPUs vs manifest ${m.gpuIds.length} GPUs`,
      );
    } else {
      const mismatchedIndices: number[] = [];
      for (let i = 0; i < m.gpuIds.length; i++) {
        if (observed.gpuIds[i] !== m.gpuIds[i]) {
          mismatchedIndices.push(i);
        }
      }
      if (mismatchedIndices.length > 0) {
        reasons.push(
          `Attested GPU ID mismatch at slot(s) [${mismatchedIndices.join(", ")}]`,
        );
      }
    }
  }

  if (observed.region !== undefined && observed.region !== m.declared.region) {
    reasons.push(
      `Observed region (${observed.region}) contradicts declared region (${m.declared.region})`,
    );
  }

  return {
    contradicted: reasons.length > 0,
    reasons,
  };
}

export function defaultManifests(): HardwareManifest[] {
  return DEMO_MANIFEST_NODES.map((spec) => {
    const { secretKey } = deriveNodeIdentityKey(spec.nodeId);
    const body: Omit<HardwareManifest, "signature" | "signerPublicKey"> = {
      nodeId: spec.nodeId,
      chipId: deriveNodeChipId(spec.nodeId),
      tcb: spec.tcb,
      gpuIds: deriveNodeGpuIds(spec.nodeId, 8),
      spdmDevices: [...DEFAULT_SPDM_DEVICES],
      declared: {
        board: "AMD-Turin-HGX-8GPU",
        bmcFirmware: "openbmc-2.16-caliptra",
        platformRot: "Caliptra-1.1",
        dimmSlotsTotal: 24,
        dimmSlotsPopulated: 24,
        dimmSpeedMt: 6400,
        pcieSlotsPopulated: 10,
        region: spec.region,
      },
      timestamp: DEFAULT_MANIFEST_TIMESTAMP,
    };
    return signManifest(body, secretKey);
  });
}

export function getManifestForNode(nodeId: string): HardwareManifest | undefined {
  return defaultManifests().find((m) => m.nodeId === nodeId);
}
