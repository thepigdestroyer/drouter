/**
 * Shared plain-language copy helpers and jargon sanitizers (`src/lib/plain-copy.ts`).
 *
 * Ensures unexpanded views use plain vocabulary with zero forbidden technical jargon
 * and zero em/en dashes.
 */

/**
 * Forbidden technical terms that must never appear in default (unexpanded) views.
 */
export const FORBIDDEN_PLAIN_VIEW_TERMS: readonly string[] = [
  "attestation",
  "attested",
  "enclave",
  "TEE",
  "SEV-SNP",
  "SNP",
  "TDX",
  "HPKE",
  "RFC",
  "Merkle",
  "nullifier",
  "RSA",
  "quorum",
  "Sigstore",
  "Rekor",
  "VCEK",
  "CKKS",
  "FHE",
  "homomorphic",
  "dm-verity",
  "measurement",
  "ciphertext",
  "hash",
  "digest",
  "ECDSA",
  "X25519",
  "PII",
  "OHTTP",
  "SPRT",
  "Arc testnet",
  "relay hop",
  "bucket bytes",
] as const;

/**
 * Replaces user-visible "dRouter" with "deRoute" and converts technical terms
 * into the approved plain vocabulary for any dynamic text shown outside TechDetails.
 */
export function sanitizeJargonToPlainWords(input: string): string {
  if (!input) return "";
  const out = input
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\bdRouter\b/g, "deRoute")
    .replace(/\bover\s+server-resolved\s+handle\s+\$INPUT\s*/gi, "")
    .replace(/\$INPUT\b/g, "your task")
    .replace(/\$RESULT_\d+\b/g, "the result")
    .replace(/\bArc\s+testnet\b/gi, "public receipt book")
    .replace(/\bCircle\s+Arc\b/gi, "public receipt book")
    .replace(/\brelay\s+hops?\b/gi, "routing steps")
    .replace(/\bbucket\s+bytes\b/gi, "standard message size")
    .replace(/\bhomomorphic(?:ally)?\b/gi, "reversible")
    .replace(/\bdm-verity\b/gi, "disk seal")
    .replace(/\bSEV-SNP\b/gi, "hardware lock")
    .replace(/\bSNP\b/gi, "hardware lock")
    .replace(/\bTDX\b/gi, "hardware lock")
    .replace(/\bVCEK\b/gi, "chip key")
    .replace(/\bHPKE\b/gi, "sealed lock")
    .replace(/\bOHTTP\b/gi, "blind relay")
    .replace(/\bSPRT\b/gi, "spot check")
    .replace(/\bCKKS\b/gi, "locked math")
    .replace(/\bFHE\b/gi, "locked math")
    .replace(/\bECDSA\b/gi, "digital signature")
    .replace(/\bX25519\b/gi, "key exchange")
    .replace(/\bRSA\b/gi, "blind signature")
    .replace(/\bPII\b/gi, "personal details")
    .replace(/\bRFC\s*\d+\b/gi, "standard rule")
    .replace(/\bRFC\b/gi, "standard rule")
    .replace(/\bMerkle\b/gi, "receipt tree")
    .replace(/\bnullifiers?\b/gi, "used-token record")
    .replace(/\bquorum\b/gi, "group of independent checkers")
    .replace(/\bSigstore\b/gi, "public software log")
    .replace(/\bRekor\b/gi, "public software log")
    .replace(/\battestations?\b/gi, "seal check")
    .replace(/\battested\b/gi, "seal-checked")
    .replace(/\benclaves?\b/gi, "sealed computer")
    .replace(/\bTEEs?\b/gi, "sealed computer")
    .replace(/\bmeasurements?\b/gi, "seal fingerprint")
    .replace(/\bciphertexts?\b/gi, "locked message")
    .replace(/\bhashes\b/gi, "fingerprints")
    .replace(/\bhash\b/gi, "fingerprint")
    .replace(/\bdigests?\b/gi, "summary code")
    .replace(/\bsimulated\b/gi, "preview")
    .replace(/\bsimulation\b/gi, "preview");

  return out.replace(/\s+/g, " ").trim();
}

/**
 * Checks whether a plain-view string contains any forbidden technical term.
 */
export function findForbiddenPlainTerms(text: string): string[] {
  const found: string[] = [];
  for (const term of FORBIDDEN_PLAIN_VIEW_TERMS) {
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\b`, "i");
    if (re.test(text)) {
      found.push(term);
    }
  }
  return found;
}

export const PLAIN_ATLAS_PRESET_QUERIES: readonly {
  label: string;
  query: string;
}[] = [
  {
    label: "How two sealed computers protect you",
    query: "Tinfoil confidential GPU model router",
  },
  {
    label: "Stopping memory wire tapping",
    query: "DDR5 memory bus interposer probe mitigation",
  },
  {
    label: "Anonymous tokens for payment",
    query: "blind signature credits double-spend",
  },
  {
    label: "Guarding against voltage tampering",
    query: "VoltPillager voltage fault injection",
  },
] as const;

export function resolveEffectiveAtlasQuery(rawQuery: string): string {
  const trimmed = rawQuery.trim();
  const matchedPreset = PLAIN_ATLAS_PRESET_QUERIES.find(
    (p) => p.label.toLowerCase() === trimmed.toLowerCase(),
  );
  return matchedPreset ? matchedPreset.query : trimmed;
}

export interface PlainDocOverride {
  title: string;
  categoryLabel: string;
  summary: string;
}

const PLAIN_DOC_OVERRIDES: Record<string, PlainDocOverride> = {
  "provider-tinfoil": {
    title: "Tinfoil: Sealed computers for private AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Tinfoil runs open AI models inside locked hardware so nobody outside can read your prompts or answers. Before your device sends a message, it checks the hardware seal and locks the message so only the sealed computer can open it.",
  },
  "provider-phala-redpill": {
    title: "Phala Cloud / Redpill: Sealed GPU computers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Runs open AI models on locked server chips and graphics cards. Publishes a gateway seal check, though its connection from the gateway to individual worker computers is not yet fully verified end-to-end.",
  },
  "provider-near-ai-cloud": {
    title: "NEAR AI Cloud: Sealed AI cloud servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Offers AI models hosted on locked server hardware. Requires an account key to inspect its seal check report, and independent checks note that some worker routes are not yet fully verified.",
  },
  "provider-venice-ai": {
    title: "Venice.ai: Locked chat mode",
    categoryLabel: "Sealed computer provider",
    summary:
      "Provides a locked mode for selected AI models running on sealed hardware. Independent checks found that some worker routes and hardware proofs are still incomplete.",
  },
  "provider-prem-ai": {
    title: "Prem AI: Sealed AI servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Locks messages on your device before sending them to sealed servers. Its default verifier rules leave some software fingerprints unpinned unless configured manually.",
  },
  "provider-ppq-ai": {
    title: "PPQ.AI: Pay-per-question private AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Routes private AI questions to Tinfoil sealed computers without a monthly subscription. To keep your message locked all the way from your device to the sealed computer, you must use its local privacy proxy.",
  },
  "provider-confidential-ai": {
    title: "Confidential AI: Locked cloud servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "Runs AI models inside locked servers with a secure tunnel that ends inside the locked hardware. Its graphics card seal checks are still marked as raw and unverified.",
  },
  "provider-chutes-bittensor": {
    title: "Chutes: Decentralized AI servers",
    categoryLabel: "Sealed computer provider",
    summary:
      "A marketplace of community-run locked AI servers. While individual servers publish hardware seal checks, the main gateway can see messages before passing them along.",
  },
  "provider-privatemode-cosmian": {
    title: "Privatemode (Edgeless Systems): European sealed AI",
    categoryLabel: "Sealed computer provider",
    summary:
      "Hosted in Europe on locked servers that pass 13 out of 13 hardware seal checks. Requires the Privatemode app or helper tool on your device to lock messages end-to-end.",
  },
  "provider-nanogpt": {
    title: "NanoGPT: Pay-per-prompt AI storefront",
    categoryLabel: "Sealed computer provider",
    summary:
      "Offers pay-per-prompt access to AI models on locked servers. However, its gateway unlocks messages outside the sealed computer, and several models failed independent hardware seal checks.",
  },
  "advisory-tee-fail-ddr5": {
    title: "Memory wire tapping attack and how deRoute blocks it",
    categoryLabel: "Hardware safety note",
    summary:
      "Researchers showed that someone with physical access to a server can clip a probe onto memory wires and watch repeated patterns. deRoute checks for repeated patterns in memory and hides your personal details on your device before anything is sent.",
  },
  "advisory-ddrop": {
    title: "Memory write-dropping attack (DDRop) and safety checks",
    categoryLabel: "Hardware safety note",
    summary:
      "Researchers showed an attacker touching server memory wires can block new memory writes so old data stays behind. deRoute runs hardware seal checks and hides your personal details on your device before trusting a sealed computer.",
  },
  "advisory-cipherleaks": {
    title: "Memory pattern leaks (Cipherleaks & BadRAM) and fixes",
    categoryLabel: "Hardware safety note",
    summary:
      "Older server firmware leaked secret key patterns through memory updates or fake memory chips. deRoute checks that servers run updated firmware and never sends your raw personal details off your device.",
  },
  "advisory-voltpillager": {
    title: "Power voltage tampering (VoltPillager) and multi-layer protection",
    categoryLabel: "Hardware safety note",
    summary:
      "An attacker with physical access to a server motherboard can jolt its power wires to cause calculation errors. Because physical tampering is possible on a single machine, deRoute combines device-side detail hiding, independent seal checkers, and the public receipt book.",
  },
  "arch-vmpl0-inner-monitor": {
    title:
      "How deRoute uses anonymous tokens, detail hiding, and the public receipt book",
    categoryLabel: "How deRoute works",
    summary:
      "deRoute separates payment from your identity using prepaid anonymous tokens that cannot be traced back to you. Before your message leaves your device, deRoute hides your personal details and pads every message to a standard size, then records verification receipts in the public receipt book.",
  },
  "arch-two-hop-gpu-custody": {
    title: "How deRoute checks two sealed computers in a row",
    categoryLabel: "How deRoute works",
    summary:
      "Your message passes through an open-source sealed router computer that checks the second sealed AI computer running the graphics cards. Your device checks the seal on both computers and locks your message so only the sealed computer can open it.",
  },
};

export function formatPlainAtlasResult(item: {
  docId: string;
  title: string;
  category: string;
  summary: string;
  provider?: string;
}): PlainDocOverride {
  const known = PLAIN_DOC_OVERRIDES[item.docId];
  if (known) {
    return known;
  }

  if (item.docId.startsWith("provider-")) {
    const cleanName = sanitizeJargonToPlainWords(
      item.title.split("-")[0]?.trim() || item.provider || "Provider",
    );
    return {
      title: `${cleanName}: Sealed computer for private AI`,
      categoryLabel: "Sealed computer provider",
      summary: sanitizeJargonToPlainWords(item.summary),
    };
  }

  const categoryLabel =
    item.category === "provider"
      ? "Sealed computer provider"
      : item.category === "advisory"
        ? "Hardware safety note"
        : "How deRoute works";

  return {
    title: sanitizeJargonToPlainWords(item.title),
    categoryLabel,
    summary: sanitizeJargonToPlainWords(item.summary),
  };
}
