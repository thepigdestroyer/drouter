import { toHex, utf8 } from "./bytes";

/**
 * Synthetic 16-byte ASCII prefix ("sim-chip-0000000" -> 73696d2d636869702d30303030303030 in hex)
 * kept only so legacy synthetic chip IDs can be detected and rejected.
 * Delete after UI cleanup.
 */
export const SYNTHETIC_CHIP_ID_PREFIX_TEXT = "sim-chip-0000000";
export const SYNTHETIC_CHIP_ID_PREFIX_BYTES: Uint8Array = utf8(SYNTHETIC_CHIP_ID_PREFIX_TEXT);
export const SYNTHETIC_CHIP_ID_HEX_PREFIX = toHex(SYNTHETIC_CHIP_ID_PREFIX_BYTES);

export function assertSimId(simId: string): never {
  throw new Error(
    `Simulated practice node "${simId}" has been removed from production; use attested Tinfoil enclaves.`,
  );
}
