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
  applyVaultSignOutReset,
  executeSendTurn,
  prepareHistoricalTurnText,
  prepareHistoryForWire,
  prepareOutboundTurn,
  previewDraftPrivacy,
  rebuildMechanicalSessionFromMessages,
  reserveAssistantLiteralPlaceholders,
  restoreUnspentCreditHeader,
  stripWireContentFromMessages,
} from "@/components/console/send-pipeline";
import { exportSessionProof } from "@/components/console/proof-exporter";
import {
  CONSOLE_EXAMPLE_PROMPTS,
  CONSOLE_HIDE_MARKER_HINT,
  ConsoleMessageItem,
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
  type ChatMessage,
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

describe("resending earlier messages", () => {
  it("never resends an AI reply with hidden details put back; it is filtered again first", () => {
    const session = createMechanicalSession();
    const prompt =
      "Write a polite reply to Dana Reyes at dana.reyes@example.com about rescheduling our call to 2026-10-30 and keeping my number 415-555-0199 and ££our merger offer££ private.";
    const sent = prepareHistoricalTurnText(prompt, { session });
    for (const original of ["Dana", "dana.reyes@example.com", "2026-10-30", "415-555-0199", "merger", "££"]) {
      expect(sent).not.toContain(original);
    }

    const shownReply =
      "**To:** dana.reyes@example.com\nDear Dana Reyes, can we move our call to 2026-10-30? Please keep 415-555-0199 and our merger offer private.";
    const history = prepareHistoryForWire(
      [
        { role: "user", content: prompt, wireContent: sent },
        // A resumed reply that lost its original wire text.
        { role: "assistant", content: shownReply },
      ],
      { session },
    );

    expect(history[0].wireContent).toBe(sent);
    const resent = history[1].wireContent ?? "";
    for (const original of ["Dana", "dana.reyes@example.com", "2026-10-30", "415-555-0199", "merger"]) {
      expect(resent).not.toContain(original);
    }
    expect(resent).toContain("[EMAIL_1]");
    expect(resent).toContain("[MARKED_1]");
    expect(session.restore(resent)).toContain("dana.reyes@example.com");
  });

  it("turn 1 ££Project Falcon££, AI reply repeats it, turn 2 sends history and new text with no Project Falcon anywhere in the wire (C5)", async () => {
    const session = createMechanicalSession();

    // Turn 1: user hides ££Project Falcon££; AI reply repeats it on the wire
    const turn1 = await executeSendTurn({
      text: "Please review ££Project Falcon££ with Dana Reyes before Friday.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send(wireHistory) {
          expect(JSON.stringify(wireHistory)).not.toContain("Project Falcon");
          expect(JSON.stringify(wireHistory)).not.toContain("Dana Reyes");
          yield "Confirmed: Project Falcon is ready for [NAME_1] on Friday.";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    expect(turn1.restoredReply).toBe(
      "Confirmed: Project Falcon is ready for Dana Reyes on Friday.",
    );

    // Turn 2: user mentions Project Falcon WITHOUT ££ markers; both history and new text are sent
    let turn2WirePayload = "";
    const turn2 = await executeSendTurn({
      text: "Can we move Project Falcon and project falcon launch notes to Monday?",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send(wireHistory) {
          turn2WirePayload = JSON.stringify(wireHistory);
          yield "Moved [MARKED_1] launch notes to Monday for [NAME_1].";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;
    expect(turn2WirePayload.toLowerCase()).not.toContain("project falcon");
    expect(turn2WirePayload.toLowerCase()).not.toContain("dana reyes");
    expect(turn2.wireHistory[0].content).toBe(
      "Please review [MARKED_1] with [NAME_1] before Friday.",
    );
    expect(turn2.wireHistory[1].content).toBe(
      "Confirmed: [MARKED_1] is ready for [NAME_1] on Friday.",
    );
    expect(turn2.wireHistory[2].content).toBe(
      "Can we move [MARKED_1] and [MARKED_1] launch notes to Monday?",
    );
  });

  it("prepares outbound turn BEFORE history and passes existing wireContent through rehideKnownValues so newly marked ££ phrases in Turn 2 are hidden in Turn 1 history (C5)", async () => {
    const session = createMechanicalSession();

    // Turn 1: user mentions "our merger offer" unmarked
    const turn1 = await executeSendTurn({
      text: "Draft a short note about our merger offer.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Here is the draft note about our merger offer.";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;

    // Turn 2: user now wraps ££our merger offer££ in markers
    const turn2 = await executeSendTurn({
      text: "Revise ££our merger offer££ to be more concise.",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Revised [MARKED_1].";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;
    expect(
      JSON.stringify(turn2.wireHistory).toLowerCase(),
    ).not.toContain("our merger offer");
    expect(turn2.wireHistory[0].content).toBe(
      "Draft a short note about [MARKED_1].",
    );
    expect(turn2.wireHistory[1].content).toBe(
      "Here is the draft note about [MARKED_1].",
    );
    expect(turn2.wireHistory[2].content).toBe(
      "Revise [MARKED_1] to be more concise.",
    );
  });

  it("strips wireContent when freezing/saving and rebuilds session from both user and assistant messages (normalizeStyle false on assistant) on resume (C5 + I4 + M1)", async () => {
    const session1 = createMechanicalSession();
    const turn1 = await executeSendTurn({
      text: "Check ££Project Falcon££ status.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session1,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Status for [MARKED_1]: contact Dana Reyes at dana.reyes@example.com, don't delay.";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;

    // Freeze: strip wireContent and privacyReport
    const frozenMessages = stripWireContentFromMessages(turn1.messages);
    expect(frozenMessages).toHaveLength(2);
    expect("wireContent" in frozenMessages[0]).toBe(false);
    expect("wireContent" in frozenMessages[1]).toBe(false);
    expect("privacyReport" in frozenMessages[0]).toBe(false);

    // Resume into a fresh session: rebuildMechanicalSessionFromMessages scans both user and assistant (I4)
    const resumedSession = createMechanicalSession();
    rebuildMechanicalSessionFromMessages(frozenMessages, {
      normalizeStyle: true,
      session: resumedSession,
    });

    // Assistant's Dana Reyes and dana.reyes@example.com are immediately in the rebuilt session
    const entries = resumedSession.entries();
    expect(entries.some((e) => e.original === "Project Falcon" && e.placeholder === "[MARKED_1]")).toBe(true);
    expect(entries.some((e) => e.original === "Dana Reyes" && e.placeholder === "[NAME_1]")).toBe(true);
    expect(entries.some((e) => e.original === "dana.reyes@example.com" && e.placeholder === "[EMAIL_1]")).toBe(true);

    // Send Turn 2 after resume
    const turn2 = await executeSendTurn({
      text: "Ask Marcus Vance and Dana Reyes about Project Falcon at bob@example.com.",
      messages: frozenMessages,
      model: "kimi-k3",
      mechanicalSession: resumedSession,
      scrubEnabled: true,
      normalizeStyle: true,
      activeSession: {
        async *send() {
          yield "Asked [NAME_2] and [NAME_1] about [MARKED_1] at [EMAIL_2].";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;
    const allWire = JSON.stringify(turn2.wireHistory);
    expect(allWire).not.toContain("Project Falcon");
    expect(allWire).not.toContain("Dana Reyes");
    expect(allWire).not.toContain("Marcus Vance");
    expect(allWire).not.toContain("dana.reyes@example.com");
    expect(allWire).not.toContain("bob@example.com");
    // Assistant message in wireHistory was NOT style-normalized ("don't" stays "don't", not "do not")
    expect(turn2.wireHistory[1].content).toContain("don't");
    // Email from Turn 2 got [EMAIL_2], not colliding with assistant's [EMAIL_1] from Turn 1
    expect(turn2.wireHistory[2].content).toContain("[EMAIL_2]");

    // M1: Resumed user message has wireContent !== content and no privacyReport, yet renders "Show exactly what was sent"
    const resumedUserMsgAfterPrepare = turn2.messages[0];
    expect(resumedUserMsgAfterPrepare.privacyReport).toBeUndefined();
    expect(resumedUserMsgAfterPrepare.wireContent).toBe("Check [MARKED_1] status.");
    const itemHtml = renderToStaticMarkup(
      React.createElement(ConsoleMessageItem, {
        message: resumedUserMsgAfterPrepare,
        modelName: "Kimi K3",
        isStreamingLast: false,
      }),
    );
    expect(itemHtml).toContain('data-testid="message-sent-text"');
    expect(itemHtml).toContain("Show exactly what was sent");
    expect(itemHtml).toContain("Check [MARKED_1] status.");
  });

  it("clears both chat messages and mechanical session on vault sign-out / lock (C4)", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    const session = createMechanicalSession();
    let messagesState: ChatMessage[] = [
      {
        role: "user",
        content: "Email dana.reyes@example.com about ££Project Falcon££.",
        wireContent: "Email [EMAIL_1] about [MARKED_1].",
      },
      {
        role: "assistant",
        content: "Will email dana.reyes@example.com about Project Falcon.",
        wireContent: "Will email [EMAIL_1] about [MARKED_1].",
      },
    ];
    await prepareOutboundTurn(messagesState[0].content, { session });
    expect(session.entries().length).toBeGreaterThanOrEqual(2);

    const unsub = subscribeVaultSession(() => {
      if (!getCurrentVaultSession()) {
        applyVaultSignOutReset({
          session,
          setMessages: (next) => {
            messagesState = next;
          },
        });
      }
    });

    try {
      lockVault();
      expect(messagesState).toEqual([]);
      expect(session.entries()).toEqual([]);
    } finally {
      unsub();
    }
  });

  it("clones the mechanical session before preparing a turn and restores the clone if send fails before the first token (M2)", async () => {
    storeCreditTokens([
      {
        token: "ab".repeat(32),
        signature: "cd".repeat(64),
        denomination: 1,
      },
    ]);
    let session = createMechanicalSession();

    // Turn 1 succeeds
    const turn1 = await executeSendTurn({
      text: "Hello Elena Rostova.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Hello [NAME_1].";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    session = turn1.mechanicalSession;
    expect(session.entries()).toEqual([
      { placeholder: "[NAME_1]", kind: "NAME", original: "Elena Rostova" },
    ]);

    // Turn 2 fails before yielding any token
    const failedTurn2 = await executeSendTurn({
      text: "Contact Marcus Vance at marcus@example.com for ££Project Titan££.",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          throw new Error("Connection reset before first token");
          yield "";
        },
      },
    });
    expect(failedTurn2.ok).toBe(false);
    if (failedTurn2.ok) return;
    expect(failedTurn2.failedBeforeFirstToken).toBe(true);
    expect(failedTurn2.messages).toEqual(turn1.messages);
    expect(failedTurn2.restoredInput).toBe(
      "Contact Marcus Vance at marcus@example.com for ££Project Titan££.",
    );

    // Restore rolled-back session clone
    session = failedTurn2.mechanicalSession;
    expect(session.entries()).toEqual([
      { placeholder: "[NAME_1]", kind: "NAME", original: "Elena Rostova" },
    ]);

    // Subsequent retry with a different name gets [NAME_2] (not [NAME_3])
    const retryTurn2 = await executeSendTurn({
      text: "Contact Clara Oswald.",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Contacted [NAME_2].";
        },
      },
    });
    expect(retryTurn2.ok).toBe(true);
    if (!retryTurn2.ok) return;
    expect(retryTurn2.wireHistory[2].content).toBe("Contact [NAME_2].");
    expect(retryTurn2.restoredReply).toBe("Contacted Clara Oswald.");
  });

  it("reserves literal [KIND_N] tokens in completed assistant replies that are not session placeholders (M3)", async () => {
    const session = createMechanicalSession();

    // Turn 1: no names or emails redacted yet, but assistant explains placeholders using literal [NAME_1] and [EMAIL_1]
    const turn1 = await executeSendTurn({
      text: "How does your privacy filter work?",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Names become [NAME_1] and emails become [EMAIL_1] before leaving your browser.";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    expect(turn1.reservedLiterals).toEqual(["[NAME_1]", "[EMAIL_1]"]);
    expect(session.entries()).toEqual([]);

    // Turn 2: user mentions a real name and email; session skips [NAME_1] and [EMAIL_1] and assigns [NAME_2] and [EMAIL_2]
    const turn2 = await executeSendTurn({
      text: "Email Dana Reyes at dana.reyes@example.com.",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Sent to [NAME_2] at [EMAIL_2] (example placeholder [NAME_1] stays untouched).";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;
    expect(turn2.wireHistory[2].content).toBe("Email [NAME_2] at [EMAIL_2].");
    expect(turn2.restoredReply).toBe(
      "Sent to Dana Reyes at dana.reyes@example.com (example placeholder [NAME_1] stays untouched).",
    );

    // Direct helper verification as well
    const extraReserved = reserveAssistantLiteralPlaceholders(
      "Another literal [IP_4] beside known [NAME_2].",
      session,
    );
    expect(extraReserved).toEqual(["[IP_4]"]);
  });

  it("hides a custom term added mid-conversation in resent Turn 1 history even when Turn 2 does not mention it, and updates wireContent for 'Show exactly what was sent' (R2-M1 #1)", async () => {
    unlockVaultWithPassphrase("abandon ability able about above absent", false);
    updateVaultPayload({
      customScrubTerms: [],
      createdAt: 1700000000000,
    });

    const session = createMechanicalSession();

    // Turn 1: live chat, user mentions "codename zephyr" before adding it as a custom scrub term
    const turn1 = await executeSendTurn({
      text: "We are reviewing codename zephyr with Dana Reyes today.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send(wireHistory) {
          expect(wireHistory[0].content).toBe(
            "We are reviewing codename zephyr with [NAME_1] today.",
          );
          yield "Here are notes on codename zephyr for [NAME_1].";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    expect(turn1.messages[0].wireContent).toBe(
      "We are reviewing codename zephyr with [NAME_1] today.",
    );

    // Mid-conversation: user adds "codename zephyr" to their vault custom scrub terms without freezing/resuming
    updateVaultPayload({
      customScrubTerms: ["codename zephyr"],
      createdAt: 1700000000000,
    });

    // Turn 2: user prompt does NOT mention "codename zephyr"
    const streamedSnapshots: string[] = [];
    const turn2 = await executeSendTurn({
      text: "What are the next steps for Dana Reyes?",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      onStreamDelta: ({ restoredReply }) => {
        streamedSnapshots.push(restoredReply);
      },
      activeSession: {
        async *send(wireHistory) {
          expect(JSON.stringify(wireHistory).toLowerCase()).not.toContain(
            "codename zephyr",
          );
          yield "Next steps for [NAME_1] on ";
          yield "[ENTITY_1] are ready.";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;

    // Resent Turn 1 user message and assistant reply both have "codename zephyr" hidden as [ENTITY_1]
    expect(turn2.wireHistory[0].content).toBe(
      "We are reviewing [ENTITY_1] with [NAME_1] today.",
    );
    expect(turn2.wireHistory[1].content).toBe(
      "Here are notes on [ENTITY_1] for [NAME_1].",
    );
    expect(turn2.wireHistory[2].content).toBe(
      "What are the next steps for [NAME_1]?",
    );

    // Earlier message's wireContent is updated so "Show exactly what was sent" stays accurate
    expect(turn2.messages[0].wireContent).toBe(
      "We are reviewing [ENTITY_1] with [NAME_1] today.",
    );
    const turn1Html = renderToStaticMarkup(
      React.createElement(ConsoleMessageItem, {
        message: turn2.messages[0],
        modelName: "Kimi K3",
        isStreamingLast: false,
      }),
    );
    expect(turn1Html).toContain("Show exactly what was sent");
    expect(turn1Html).toContain(
      "We are reviewing [ENTITY_1] with [NAME_1] today.",
    );
    expect(turn1Html).not.toContain(
      "We are reviewing codename zephyr with [NAME_1] today.",
    );

    // Streaming display and final restored reply are unaffected and restore [ENTITY_1]
    expect(streamedSnapshots).toEqual([
      "Next steps for Dana Reyes on ",
      "Next steps for Dana Reyes on codename zephyr are ready.",
    ]);
    expect(turn2.restoredReply).toBe(
      "Next steps for Dana Reyes on codename zephyr are ready.",
    );
  });

  it("hides a new email invented by the AI in its Turn 1 reply when resending in Turn 2, and restores it in Turn 2's reply (R2-M1 #2)", async () => {
    const session = createMechanicalSession();

    // Turn 1: user sends an email; AI reply invents a brand-new email (support@acme-internal.org) on the wire
    const turn1 = await executeSendTurn({
      text: "Write to dana.reyes@example.com about the schedule.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Reply to [EMAIL_1] or escalate to support@acme-internal.org.";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    expect(turn1.restoredReply).toBe(
      "Reply to dana.reyes@example.com or escalate to support@acme-internal.org.",
    );

    // Turn 2: user asks a follow-up without typing the email; resending Turn 1's AI reply hides support@acme-internal.org as [EMAIL_2]
    const turn2 = await executeSendTurn({
      text: "Should I copy that escalation address too?",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send(wireHistory) {
          expect(JSON.stringify(wireHistory)).not.toContain(
            "dana.reyes@example.com",
          );
          expect(JSON.stringify(wireHistory)).not.toContain(
            "support@acme-internal.org",
          );
          yield "Yes, copy [EMAIL_2] along with [EMAIL_1].";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;

    expect(turn2.wireHistory[0].content).toBe(
      "Write to [EMAIL_1] about the schedule.",
    );
    expect(turn2.wireHistory[1].content).toBe(
      "Reply to [EMAIL_1] or escalate to [EMAIL_2].",
    );
    expect(turn2.messages[1].wireContent).toBe(
      "Reply to [EMAIL_1] or escalate to [EMAIL_2].",
    );
    expect(turn2.restoredReply).toBe(
      "Yes, copy support@acme-internal.org along with dana.reyes@example.com.",
    );
  });

  it("keeps placeholders for earlier values identical across multiple live turns when rebuilding wire history from content (R2-M1 #3)", async () => {
    const session = createMechanicalSession();

    const turn1 = await executeSendTurn({
      text: "Contact Elena Rostova at elena@example.com about ££Project Horizon££ on 2026-10-25.",
      messages: [],
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Noted [NAME_1] ([EMAIL_1]) for [MARKED_1] on [DATE_1].";
        },
      },
    });
    expect(turn1.ok).toBe(true);
    if (!turn1.ok) return;
    const turn1UserWire = turn1.wireHistory[0].content;
    expect(turn1UserWire).toBe(
      "Contact [NAME_1] at [EMAIL_1] about [MARKED_1] on [DATE_1].",
    );

    const turn2 = await executeSendTurn({
      text: "Add Marcus Vance at marcus@example.com to ££Backup Plan££.",
      messages: turn1.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Added [NAME_2] ([EMAIL_2]) to [MARKED_2] alongside [NAME_1] on [MARKED_1].";
        },
      },
    });
    expect(turn2.ok).toBe(true);
    if (!turn2.ok) return;

    const turn3 = await executeSendTurn({
      text: "Confirm both with Elena Rostova and Marcus Vance.",
      messages: turn2.messages,
      model: "kimi-k3",
      mechanicalSession: session,
      scrubEnabled: true,
      activeSession: {
        async *send() {
          yield "Confirmed with [NAME_1] and [NAME_2] for [MARKED_1] and [MARKED_2].";
        },
      },
    });
    expect(turn3.ok).toBe(true);
    if (!turn3.ok) return;

    // Turn 1 and Turn 2 placeholders in Turn 3's wireHistory are identical to when they were first sent
    expect(turn3.wireHistory[0].content).toBe(turn1UserWire);
    expect(turn3.wireHistory[1].content).toBe(
      "Noted [NAME_1] ([EMAIL_1]) for [MARKED_1] on [DATE_1].",
    );
    expect(turn3.wireHistory[2].content).toBe(
      "Add [NAME_2] at [EMAIL_2] to [MARKED_2].",
    );
    expect(turn3.wireHistory[3].content).toBe(
      "Added [NAME_2] ([EMAIL_2]) to [MARKED_2] alongside [NAME_1] on [MARKED_1].",
    );
    expect(turn3.wireHistory[4].content).toBe(
      "Confirm both with [NAME_1] and [NAME_2].",
    );
  });
});
