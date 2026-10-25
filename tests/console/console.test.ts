import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  lockVault,
  subscribeVaultSession,
  unlockVaultWithPassphrase,
  updateVaultPayload,
  getCurrentVaultSession,
} from "@/lib/auth/vault";
import {
  clearStoredCredits,
  storeCreditTokens,
  storedCreditBalance,
} from "@/lib/credits/client";
import {
  rulesetFingerprint,
  setFilterFingerprintVerifyOptionsForTests,
} from "@/lib/privacy/fingerprint";
import { createMechanicalSession } from "@/lib/privacy/mechanical";
import { MECHANICAL_RULESET } from "@/lib/privacy/mechanical-ruleset";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import {
  prepareHistoricalTurnText,
  prepareOutboundTurn,
  previewDraftPrivacy,
  rebuildMechanicalSessionFromMessages,
  restoreUnspentCreditHeader,
} from "@/components/console/send-pipeline";
import { exportSessionProof } from "@/components/console/proof-exporter";
import {
  CONSOLE_EXAMPLE_PROMPTS,
  CONSOLE_HIDE_MARKER_HINT,
  describeModel,
  formatHiddenDetailsSummary,
  FRIENDLY_MODELS,
} from "@/components/console";
import {
  friendlyFailureReason,
  friendlyRuntimeError,
} from "@/components/visual-trust-dashboard";
import {
  formatRedactionKindLabel,
  friendlyCreditFlowError,
  PrivacyBar,
} from "@/components/privacy-bar";
import {
  openSession,
  pickNode,
  registryAndQuorumCheck,
  type RegistryNodeRecord,
  type RegistryResponse,
} from "@/components/session";
import type { CheckResult } from "@/lib/types";

const SAMPLE_NODE: RegistryNodeRecord = {
  id: "0x2696913aef54b88e8338ba4a362549e7c70465faa781aaa12240d20a247df29a",
  key: "tinfoil-router",
  kind: "tinfoil",
  name: "Tinfoil confidential router",
  endpoint: "inference.tinfoil.sh",
  measurement:
    "0x0cdd9e7ac27b90dcb58c7b0be92ff23b1b1092908be240a23ebbf45fb3732da0",
  operator: "0x7a5cCE3386c4D572A9C2891103250fA878838cfB",
  stake: "0.01",
  status: "active",
  region: "us",
  registeredAt: 1792851417,
  lastVerifiedAt: 1792852705,
  lastVerifiedOk: true,
};

const ALL_PASS_CHECKS: CheckResult[] = [
  { id: "C1", label: "Hardware signature chain", status: "pass", detail: "OK" },
  { id: "C2", label: "Approved software", status: "pass", detail: "OK" },
  { id: "C3", label: "HPKE key bound", status: "pass", detail: "OK" },
  { id: "C4", label: "Running code = released", status: "pass", detail: "OK" },
  { id: "C5", label: "Confidential GPUs", status: "pass", detail: "OK" },
  { id: "C6", label: "Registry admission", status: "pass", detail: "OK" },
  { id: "C7", label: "Pinned model", status: "pass", detail: "OK" },
];

describe("console send pipeline (I1 + I2 + I3)", () => {
  beforeEach(() => {
    clearStoredCredits();
    lockVault();
    setFilterFingerprintVerifyOptionsForTests({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: rulesetFingerprint(MECHANICAL_RULESET),
        anchorTx: `0x${"ab".repeat(32)}`,
      },
    });
  });

  afterEach(() => {
    setFilterFingerprintVerifyOptionsForTests(null);
    clearStoredCredits();
    lockVault();
    vi.restoreAllMocks();
  });

  it("wires preparePrompt with getActiveCustomScrubTerms and restores streamed replies", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: ["Project Helios", "Dana Reyes"],
      createdAt: 1700000000000,
    });

    const scrubber = createSessionScrubber();
    const raw =
      "Email dana.reyes@example.com about Project Helios for Dana Reyes using key sk-prod987654321.";
    const turn = await prepareOutboundTurn(raw, {
      scrubEnabled: true,
      normalizeStyle: true,
      scrubber,
    });

    expect(turn.outboundText).not.toContain("dana.reyes@example.com");
    expect(turn.outboundText).not.toContain("Project Helios");
    expect(turn.outboundText).not.toContain("Dana Reyes");
    expect(turn.outboundText).not.toContain("sk-prod987654321");

    expect(turn.report.redactions.length).toBeGreaterThanOrEqual(4);
    expect(turn.report.customTermsCount).toBe(2);
    expect(turn.report.bucketBytes).toBeGreaterThanOrEqual(4096);
    expect(turn.report.riskBefore).toBeGreaterThan(turn.report.riskAfter);
    expect(turn.creditHeader).toBeNull();
    expect(turn.report.creditAttached).toBe(false);

    // Simulate streamed model response containing placeholders
    const emailPlaceholder = turn.report.redactions.find(
      (r) => r.kind === "EMAIL",
    )?.placeholder;
    const entityPlaceholders = turn.report.redactions.filter(
      (r) => r.kind === "ENTITY",
    );
    expect(emailPlaceholder).toBeDefined();
    expect(entityPlaceholders.length).toBe(2);

    const modelStreamed = `Sent update on ${entityPlaceholders[0].placeholder} to ${entityPlaceholders[1].placeholder} at ${emailPlaceholder}.`;
    const restored = turn.restore(modelStreamed);
    expect(restored).toContain("Project Helios");
    expect(restored).toContain("Dana Reyes");
    expect(restored).toContain("dana.reyes@example.com");
  });

  it("attaches x-drouter-credit from takeCreditHeader when a token is stored and decrements balance", async () => {
    storeCreditTokens([
      {
        token: "aa".repeat(32),
        signature: "bb".repeat(64),
        denomination: 1,
      },
      {
        token: "cc".repeat(32),
        signature: "dd".repeat(64),
        denomination: 1,
      },
    ]);
    expect(storedCreditBalance()).toBe(2);

    const turn = await prepareOutboundTurn("Hello enclave", {
      scrubEnabled: true,
    });

    expect(turn.creditHeader).toBeTruthy();
    expect(turn.report.creditAttached).toBe(true);
    expect(turn.report.creditNullifier).toMatch(/^[0-9a-f]{64}$/);
    expect(turn.creditBalanceAfter).toBe(1);
    expect(storedCreditBalance()).toBe(1);
  });

  it("computes live draft preview via preparePrompt without spending credits", () => {
    storeCreditTokens([
      {
        token: "11".repeat(32),
        signature: "22".repeat(64),
        denomination: 1,
      },
    ]);
    const preview = previewDraftPrivacy(
      "Contact dana.reyes@example.com with colour preferences",
      { scrubEnabled: true, normalizeStyle: true },
    );
    expect(preview.prepared.outboundText).toContain("[EMAIL_1]");
    expect(preview.prepared.outboundText).toContain("color");
    expect(preview.prepared.report.styleChanges).toBeGreaterThanOrEqual(1);
    expect(storedCreditBalance()).toBe(1);
  });

  it("never bypasses preparePrompt even if scrubEnabled is false and prepares resumed historical turns", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: ["Secret Project Alpha"],
      createdAt: 1700000000000,
    });

    const scrubber = createSessionScrubber();
    const turn = await prepareOutboundTurn(
      "Discuss Secret Project Alpha with dana.reyes@example.com about colour",
      { scrubEnabled: false, normalizeStyle: true, scrubber },
    );
    expect(turn.outboundText).not.toContain("Secret Project Alpha");
    expect(turn.outboundText).not.toContain("dana.reyes@example.com");
    expect(turn.outboundText).toContain("color");

    const historical = prepareHistoricalTurnText(
      "Earlier note on Secret Project Alpha at 415-555-0199",
      { normalizeStyle: true, scrubber },
    );
    expect(historical).not.toContain("Secret Project Alpha");
    expect(historical).not.toContain("415-555-0199");
  });

  it("restores unspent credit header back to local wallet if turn fails before streaming", async () => {
    storeCreditTokens([
      {
        token: "ee".repeat(32),
        signature: "ff".repeat(64),
        denomination: 1,
      },
    ]);
    expect(storedCreditBalance()).toBe(1);

    const turn = await prepareOutboundTurn("Hello", { scrubEnabled: true });
    expect(turn.creditHeader).toBeTruthy();
    expect(storedCreditBalance()).toBe(0);

    const refundedBalance = restoreUnspentCreditHeader(turn.creditHeader);
    expect(refundedBalance).toBe(1);
    expect(storedCreditBalance()).toBe(1);
  });

  it("uses the fingerprinted mechanical filter across all three chat send-pipeline call sites with session-stable placeholders and restores repeated/reordered placeholders", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: ["Project Helios"],
      createdAt: 1700000000000,
    });

    const session = createMechanicalSession();

    // 1. Live draft preview uses mechanical filter (hides names, dates, money amounts, custom words)
    const draft = previewDraftPrivacy(
      "Send $125,000.00 to Elena Rostova on 2026-10-25 for Project Helios.",
      { session },
    );
    expect(draft.prepared.outboundText).not.toContain("Elena Rostova");
    expect(draft.prepared.outboundText).not.toContain("2026-10-25");
    expect(draft.prepared.outboundText).not.toContain("$125,000.00");
    expect(draft.prepared.outboundText).not.toContain("Project Helios");
    expect(draft.prepared.outboundText).toBe(
      "Send [DIGITS_1] to [NAME_1] on [DATE_1] for [ENTITY_1].",
    );

    // 2. Turn 1 outbound preparation reuses the same session placeholders
    const turn1Raw =
      "Send $125,000.00 to Elena Rostova on 2026-10-25 for Project Helios.";
    const turn1 = await prepareOutboundTurn(turn1Raw, { session });
    expect(turn1.outboundText).toBe(
      "Send [DIGITS_1] to [NAME_1] on [DATE_1] for [ENTITY_1].",
    );

    // 3. Turn 2 introduces a second name and a second amount alongside Elena Rostova
    const turn2Raw =
      "Ask Marcus Vance and Elena Rostova whether the $125,000.00 wire or the $50,000.00 hold applies on 2026-10-25.";
    const turn2 = await prepareOutboundTurn(turn2Raw, { session });
    expect(turn2.outboundText).toBe(
      "Ask [NAME_2] and [NAME_1] whether the [DIGITS_1] wire or the [DIGITS_2] hold applies on [DATE_1].",
    );

    // 4. Re-preparing historical Turn 1 produces identical placeholders ([NAME_1], not [NAME_3])
    const historicalTurn1 = prepareHistoricalTurnText(turn1Raw, { session });
    expect(historicalTurn1).toBe(turn1.outboundText);

    // 5. Restoring model output with repeated and reordered placeholders puts every original back
    const modelReply =
      "Confirmed for [ENTITY_1]: [NAME_2] notified [NAME_1] on [DATE_1] that [DIGITS_2] and [DIGITS_1] were cleared by [NAME_2] and [NAME_1].";
    expect(turn2.restore(modelReply)).toBe(
      "Confirmed for Project Helios: Marcus Vance notified Elena Rostova on 2026-10-25 that $50,000.00 and $125,000.00 were cleared by Marcus Vance and Elena Rostova.",
    );
  });

  it("ensures live draft preview equals the sent text across turns 1 to 3 without mutating the live session on intermediate keystrokes", async () => {
    const session = createMechanicalSession();

    // Turn 1: simulate intermediate keystrokes in previewDraftPrivacy before sending
    previewDraftPrivacy("Meet Partial Name and ££temp secret££", { session });
    expect(session.entries()).toHaveLength(0);

    const turn1Draft =
      "Meet Elena Rostova about ££Project Falcon££ on 2026-10-25.";
    const preview1 = previewDraftPrivacy(turn1Draft, { session });
    const sent1 = await prepareOutboundTurn(turn1Draft, { session });
    expect(preview1.prepared.outboundText).toBe(sent1.outboundText);
    expect(sent1.outboundText).toBe(
      "Meet [NAME_1] about [MARKED_1] on [DATE_1].",
    );

    // Turn 2: simulate intermediate keystrokes, then preview and send
    previewDraftPrivacy("Ask Someone Else at 10.99.88.77", { session });
    const turn2Draft =
      "Ask Marcus Vance and Elena Rostova if ££Project Falcon££ or ££Backup Plan££ is ready.";
    const preview2 = previewDraftPrivacy(turn2Draft, { session });
    const sent2 = await prepareOutboundTurn(turn2Draft, { session });
    expect(preview2.prepared.outboundText).toBe(sent2.outboundText);
    expect(sent2.outboundText).toBe(
      "Ask [NAME_2] and [NAME_1] if [MARKED_1] or [MARKED_2] is ready.",
    );

    // Turn 3: third turn with new and repeated items + PrivacyBar markup check
    const turn3Draft =
      "Email Clara Oswald and Marcus Vance at clara@example.com regarding ££Backup Plan££ and ££Phase Three££.";
    const preview3 = previewDraftPrivacy(turn3Draft, { session });

    const barHtml = renderToStaticMarkup(
      React.createElement(PrivacyBar, {
        scrubEnabled: true,
        onToggleScrub: () => {},
        draftText: turn3Draft,
        session,
        creditBalance: 5,
        onMintCredits: async () => {},
      }),
    );
    expect(barHtml).toContain(preview3.prepared.outboundText);
    expect(barHtml).toContain("[MARKED_2] (marked by you)");
    expect(barHtml).toContain("[MARKED_3] (marked by you)");

    const sent3 = await prepareOutboundTurn(turn3Draft, { session });
    expect(preview3.prepared.outboundText).toBe(sent3.outboundText);
    expect(sent3.outboundText).toBe(
      "Email [NAME_3] and [NAME_2] at [EMAIL_1] regarding [MARKED_2] and [MARKED_3].",
    );
  });

  it("clears the mechanical session on sign-out / vault lock and rebuilds session consistently on resume", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    const session = createMechanicalSession();

    const unsub = subscribeVaultSession(() => {
      if (!getCurrentVaultSession()) {
        session.clear();
      }
    });

    try {
      const turn1 = await prepareOutboundTurn(
        "Contact Elena Rostova about ££Project Falcon££.",
        { session },
      );
      expect(turn1.outboundText).toBe("Contact [NAME_1] about [MARKED_1].");
      expect(session.entries().length).toBe(2);

      // Sign-out / lockVault triggers subscribeVaultSession and clears the session
      lockVault();
      expect(session.entries()).toEqual([]);

      // After sign-out, a new person starts at [NAME_1]
      const afterSignOut = await prepareOutboundTurn(
        "Contact Marcus Vance.",
        { session },
      );
      expect(afterSignOut.outboundText).toBe("Contact [NAME_1].");

      // Resume consistency: rebuilding session from restored conversation messages
      const restoredMessages = [
        {
          role: "user" as const,
          content: "Meet Elena Rostova on 2026-10-25 for ££Project Falcon££.",
        },
        {
          role: "assistant" as const,
          content: "Scheduled Elena Rostova on 2026-10-25 for Project Falcon.",
        },
      ];
      rebuildMechanicalSessionFromMessages(restoredMessages, { session });

      // Next turn after resume reuses [NAME_1] and [MARKED_1] from Turn 1, assigns [NAME_2] to Marcus Vance, and restores Turn 1 placeholders
      const resumedTurn2 = await prepareOutboundTurn(
        "Add Marcus Vance and Elena Rostova to ££Project Falcon££.",
        { session },
      );
      expect(resumedTurn2.outboundText).toBe(
        "Add [NAME_2] and [NAME_1] to [MARKED_1].",
      );
      expect(
        resumedTurn2.restore(
          "Confirmed [NAME_1] and [NAME_2] on [DATE_1] for [MARKED_1].",
        ),
      ).toBe(
        "Confirmed Elena Rostova and Marcus Vance on 2026-10-25 for Project Falcon.",
      );
    } finally {
      unsub();
    }
  });

  it("hides every sensitive item in CONSOLE_EXAMPLE_PROMPTS (non-technical and technical examples) and labels MARKED spans as 'marked by you'", () => {
    expect(CONSOLE_HIDE_MARKER_HINT).toBe(
      "Wrap anything in ££ like ££this££ to hide it.",
    );
    expect(formatRedactionKindLabel("MARKED")).toBe("marked by you");
    expect(formatRedactionKindLabel("SECRET")).toBe("SECRET");

    const nonTech = CONSOLE_EXAMPLE_PROMPTS.find(
      (e) => e.id === "non-technical",
    );
    const tech = CONSOLE_EXAMPLE_PROMPTS.find((e) => e.id === "technical");
    expect(nonTech).toBeDefined();
    expect(tech).toBeDefined();

    for (const example of [nonTech!, tech!]) {
      const preview = previewDraftPrivacy(example.prompt);
      for (const sensitive of example.sensitiveItems) {
        expect(
          preview.prepared.outboundText,
          `Example ${example.id} must hide ${sensitive}`,
        ).not.toContain(sensitive);
      }
      expect(
        preview.prepared.report.redactions.some((r) => r.kind === "MARKED"),
      ).toBe(true);
      // Restore puts back the text without ££ markers
      const expectedRestored = example.prompt.replace(/££/g, "");
      expect(preview.prepared.restore(preview.prepared.outboundText)).toBe(
        expectedRestored,
      );
    }
  });
});

describe("plain-language console helpers and jargon-free defaults", () => {
  const BANNED_JARGON = [
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
  ];

  it("formats hidden details summary in plain words", () => {
    expect(formatHiddenDetailsSummary(0)).toBe("0 personal details hidden");
    expect(formatHiddenDetailsSummary(1)).toBe("1 personal detail hidden");
    expect(formatHiddenDetailsSummary(2)).toBe("2 personal details hidden");
  });

  it("describes every model in plain words without banned jargon", () => {
    for (const model of Object.values(FRIENDLY_MODELS)) {
      const combined = `${model.name} ${model.summary}`;
      for (const word of BANNED_JARGON) {
        expect(combined.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
    const fallback = describeModel("custom-model");
    expect(fallback.summary).toContain("sealed computer");
  });

  it("produces plain-language failure reasons free of banned jargon", () => {
    const reasons = [
      friendlyFailureReason("Could not load registry", []),
      friendlyFailureReason(null, [
        { id: "C1", label: "Hardware", status: "fail", detail: "bad VCEK" },
      ]),
      friendlyFailureReason(null, [
        { id: "C2", label: "Software", status: "fail", detail: "bad digest" },
      ]),
      friendlyFailureReason(null, [
        { id: "C3", label: "Key", status: "fail", detail: "bad HPKE" },
      ]),
      friendlyFailureReason(null, [
        { id: "C5", label: "GPU", status: "fail", detail: "bad GPU" },
      ]),
      friendlyFailureReason(null, [
        { id: "C6", label: "Registry", status: "fail", detail: "suspended" },
      ]),
    ];

    for (const text of reasons) {
      for (const word of BANNED_JARGON) {
        expect(text.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
  });

  it("produces plain-language runtime and credit errors free of banned jargon", () => {
    const messages = [
      friendlyRuntimeError(
        "Not verified: C3 (HPKE key) failed: enclave digest mismatch",
      ),
      friendlyRuntimeError("Free daily allowance exhausted (402): /api/credits/invoice"),
      friendlyCreditFlowError(
        "No confirmed USDC Transfer log found on Arc testnet for RSA blind claim",
      ),
      friendlyCreditFlowError("Invoice has expired (410)"),
      friendlyCreditFlowError("Invoice has already been claimed (409)"),
    ];
    for (const text of messages) {
      for (const word of BANNED_JARGON) {
        expect(text.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
  });
});

describe("honest registry & quorum checks and failure handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("never invents quorum numbers when /api/transparency lacks verifierSet or ticket", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })),
    );

    const registry: RegistryResponse = {
      source: "arc",
      nodes: [SAMPLE_NODE],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    const c6 = await registryAndQuorumCheck(SAMPLE_NODE, registry);
    expect(c6.id).toBe("C6");
    expect(c6.detail).toContain("quorum ticket unavailable");
    expect(c6.detail).not.toContain("5/7");
  });

  it("marks C6 as fail when node is suspended or stake is below minStake", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("error", { status: 503 })),
    );

    const suspendedNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      status: "suspended",
      stake: "0",
    };
    const registry: RegistryResponse = {
      source: "arc",
      minStake: "0.01",
      nodes: [suspendedNode],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    const c6 = await registryAndQuorumCheck(suspendedNode, registry);
    expect(c6.status).toBe("fail");
    expect(c6.detail).toContain("suspended");
  });

  it("picks model-specific real Tinfoil nodes from /api/registry and rejects simulated nodes", () => {
    const kimiNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      id: "0x37c6b00064a5e5043631e41357f5500152a68198204c336745d6ba7fa0a0bb61",
      key: "tinfoil-kimi-k3",
      modelId: "kimi-k3",
      name: "Tinfoil Kimi K3 enclave",
    };
    const glmNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      id: "0x43c1bcad64147bb5f79acd628765525e02dcb7876bd5682742a5a663f49d88cd",
      key: "tinfoil-glm-5-3",
      modelId: "glm-5-3",
      name: "Tinfoil GLM-5.3 enclave",
    };

    const chosenGlm = pickNode(
      [SAMPLE_NODE, kimiNode, glmNode],
      "tinfoil",
      "glm-5-3",
    );
    expect(chosenGlm?.key).toBe("tinfoil-glm-5-3");
    expect(pickNode([SAMPLE_NODE, kimiNode, glmNode], "sim")).toBeNull();
  });

  it("blocks session opening on non-tinfoil nodes without calling /api/sim", async () => {
    const fetchSpy = vi.fn(
      async (input: RequestInfo | URL) => {
        void input;
        return new Response("error", { status: 503 });
      },
    );
    vi.stubGlobal("fetch", fetchSpy);

    const legacySimNode: RegistryNodeRecord = {
      ...SAMPLE_NODE,
      kind: "sim",
      name: "Simulated node 1",
      endpoint: "/api/sim/sim-1",
      status: "suspended",
      stake: "0",
    };
    const registry: RegistryResponse = {
      source: "arc",
      minStake: "0.01",
      nodes: [legacySimNode],
      chainId: 5042002,
      explorer: "https://explorer.testnet.arc.io",
    };

    await expect(
      openSession(legacySimNode, registry, () => {}, "kimi-k3"),
    ).rejects.toThrow();

    for (const call of fetchSpy.mock.calls) {
      expect(String(call[0])).not.toContain("/api/sim");
    }
  });
});

describe("forensics proof export action", () => {
  beforeEach(() => {
    lockVault();
  });

  afterEach(() => {
    lockVault();
  });

  it("builds and offline-verifies a valid forensic proof bundle from session state", () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);

    const exported = exportSessionProof(
      {
        node: SAMPLE_NODE,
        model: "kimi-k3",
        checks: ALL_PASS_CHECKS,
        evidence: {
          "Enclave host": "router-0.tinfoil.sh",
          "Enclave fingerprint": SAMPLE_NODE.measurement,
          "Chip ID": "f901a2b3...9912ab01",
        },
        verifyAnchorUrl:
          "https://explorer.testnet.arc.io/tx/0x" + "ab".repeat(32),
      },
      { triggerDownload: false },
    );

    expect(exported.verification.valid).toBe(true);
    expect(exported.verification.digestMatches).toBe(true);
    expect(exported.verification.clientSignatureValid).toBe(true);
    expect(exported.verification.allChecksPassed).toBe(true);
    expect(exported.verification.originVerified).toBe(true);
    expect(exported.bundle.arcAnchorTx).toBe("0x" + "ab".repeat(32));
    expect(exported.filename).toMatch(/\.drouter-proof\.json$/);
  });
});
