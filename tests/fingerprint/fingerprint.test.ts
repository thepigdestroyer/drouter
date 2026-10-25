import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FilterFingerprintBadge,
  renderFilterFingerprintSummaryText,
} from "@/components/privacy/filter-fingerprint-badge";
import {
  FilterFingerprintMismatchError,
  prepareOutboundTurn,
} from "@/components/console/send-pipeline";
import {
  checkArcTransactionReceipt,
  computeFilterAnchorReceiptHash,
  evaluateLocalFilterFingerprint,
  getPublishedFilterFingerprint,
  rulesetFingerprint,
  setFilterFingerprintStatusForTests,
  setFilterFingerprintVerifyOptionsForTests,
  verifyFilterFingerprint,
} from "@/lib/privacy/fingerprint";
import {
  MECHANICAL_RULESET,
  type MechanicalRuleset,
} from "@/lib/privacy/mechanical-ruleset";
import { runPublishFilterFingerprint } from "../../scripts/publish-filter-fingerprint.mjs";

const ROOT = resolve(__dirname, "../..");

function cloneRuleset(): MechanicalRuleset {
  return JSON.parse(JSON.stringify(MECHANICAL_RULESET)) as MechanicalRuleset;
}

afterEach(() => {
  setFilterFingerprintStatusForTests(null);
  setFilterFingerprintVerifyOptionsForTests(null);
  vi.restoreAllMocks();
});

describe("E2: rulesetFingerprint stability and sensitivity", () => {
  it("computes a stable 0x-prefixed 32-byte sha256 fingerprint over canonicalJson(MECHANICAL_RULESET)", () => {
    const fp1 = rulesetFingerprint();
    const fp2 = rulesetFingerprint(cloneRuleset());

    expect(fp1).toMatch(/^0x[0-9a-f]{64}$/);
    expect(fp1).toBe(fp2);

    const anchorHash = computeFilterAnchorReceiptHash(
      MECHANICAL_RULESET.version,
      fp1,
    );
    expect(anchorHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("changes the fingerprint whenever any rule in MECHANICAL_RULESET changes (version, regex source/flags, threshold, wordlist, homoglyph)", () => {
    const baseline = rulesetFingerprint();

    // 1. Version change
    const vChanged = cloneRuleset();
    vChanged.version = "1.0.1";
    expect(rulesetFingerprint(vChanged)).not.toBe(baseline);

    // 2. Regex source change
    const regexSourceChanged = cloneRuleset();
    (
      regexSourceChanged.patterns.email as Array<{
        source: string;
        flags: string;
      }>
    )[0].source += "x";
    expect(rulesetFingerprint(regexSourceChanged)).not.toBe(baseline);

    // 3. Regex flags change
    const regexFlagsChanged = cloneRuleset();
    (
      regexFlagsChanged.patterns.email as Array<{
        source: string;
        flags: string;
      }>
    )[0].flags = "gi";
    expect(rulesetFingerprint(regexFlagsChanged)).not.toBe(baseline);

    // 4. Entropy threshold change
    const thresholdChanged = cloneRuleset();
    thresholdChanged.entropyRules.hexMinEntropy = 2.85;
    expect(rulesetFingerprint(thresholdChanged)).not.toBe(baseline);

    // 5. Numeric validation threshold change
    const phoneDigitsChanged = cloneRuleset();
    phoneDigitsChanged.thresholds.phoneMinDigits = 9;
    expect(rulesetFingerprint(phoneDigitsChanged)).not.toBe(baseline);

    // 6. Word list change
    const wordListChanged = cloneRuleset();
    (wordListChanged.wordLists.technicalSingleWords as string[]).push(
      "hypervisor",
    );
    expect(rulesetFingerprint(wordListChanged)).not.toBe(baseline);

    // 7. Homoglyph map change
    const homoglyphChanged = cloneRuleset();
    (homoglyphChanged.unicodeNormalization.homoglyphMap as Record<
      string,
      string
    >)["\u0430"] = "A";
    expect(rulesetFingerprint(homoglyphChanged)).not.toBe(baseline);

    // 8. Zero-width code unit list change
    const zwChanged = cloneRuleset();
    (zwChanged.unicodeNormalization.zeroWidthCodeUnits as number[]).push(
      0x200a,
    );
    expect(rulesetFingerprint(zwChanged)).not.toBe(baseline);
  });
});

describe("E2: static check that mechanical.ts has no rule constants outside MECHANICAL_RULESET", () => {
  it("contains no regex literals, no hardcoded pattern strings, no word-list sets, and no magic rule thresholds in mechanical.ts", () => {
    const mechanicalPath = resolve(ROOT, "src/lib/privacy/mechanical.ts");
    const source = readFileSync(mechanicalPath, "utf8");

    // Strip comments before checking for regex literals or rule constants
    const withoutBlockComments = source.replace(/\/\*[\s\S]*?\*\//g, "");
    const withoutComments = withoutBlockComments.replace(/\/\/.*$/gm, "");

    // 1. No regex literals `/.../flags` anywhere in mechanical.ts
    const regexLiteralMatches = withoutComments.match(
      /(?:^|[=(\[,:;!&|?])\s*\/(?![/*])(?:\\.|[^/\\\r\n])+\/[gimsuy]*/gm,
    );
    expect(regexLiteralMatches).toBeNull();

    // 2. Only `compileRuleSpec` may call `new RegExp(...)`
    const newRegExpMatches = withoutComments.match(/new\s+RegExp\s*\(/g) ?? [];
    expect(newRegExpMatches).toHaveLength(1);

    // 3. No rule constant identifiers left in mechanical.ts
    const forbiddenRuleConstNames = [
      "SECRET_PATTERNS",
      "EMAIL_PATTERNS",
      "URL_PATTERNS",
      "ACCT_PATTERNS",
      "IP_PATTERNS",
      "ADDRESS_PATTERNS",
      "DATE_PATTERNS",
      "PHONE_PATTERNS",
      "HOMOGLYPH_MAP",
      "ZERO_WIDTH_CODE_UNITS",
      "IBAN_COUNTRY_CODES",
      "SENTENCE_STARTER_NON_NAMES",
      "TECHNICAL_TITLE_CASE_ALLOWLIST",
      "TECHNICAL_SINGLE_WORDS",
    ];
    for (const name of forbiddenRuleConstNames) {
      expect(withoutComments).not.toContain(name);
    }

    // 4. Imports MECHANICAL_RULESET from ./mechanical-ruleset
    expect(withoutComments).toContain('from "./mechanical-ruleset"');
    expect(withoutComments).toContain("MECHANICAL_RULESET");
  });
});

describe("E2: FilterFingerprintBadge states and send blocking", () => {
  it("handles State 1 (not yet published): renders plain message without orange alert and allows sending", async () => {
    const published = getPublishedFilterFingerprint();
    expect(published.version).toBe(MECHANICAL_RULESET.version);
    expect(published.fingerprint).toBeNull();
    expect(published.anchorTx).toBeNull();

    const status = await verifyFilterFingerprint({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: null,
        anchorTx: null,
      },
    });

    expect(status.state).toBe("not-published");
    expect(status.blockingSend).toBe(false);
    expect(status.plainSummary).toBe(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: not yet published`,
    );
    expect(renderFilterFingerprintSummaryText(status)).toBe(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: not yet published`,
    );

    const html = renderToStaticMarkup(
      React.createElement(FilterFingerprintBadge, { status }),
    );
    expect(html).toContain(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: not yet published`,
    );
    expect(html).not.toContain("filter-fingerprint-mismatch-alert");

    // Sending proceeds normally when unpublished
    const turn = await prepareOutboundTurn("Hello dana.reyes@example.com", {
      publishedFingerprintOverride: {
        version: MECHANICAL_RULESET.version,
        fingerprint: null,
        anchorTx: null,
      },
    });
    expect(turn.outboundText).toContain("[EMAIL_1]");
  });

  it("handles State 2 (published & matching + confirmed Arc receipt): verifies via eth_getTransactionReceipt and shows tx link inside TechDetails", async () => {
    const fp = rulesetFingerprint();
    const txHash = `0x${"ab".repeat(32)}`;
    const mockFetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        method?: string;
        params?: string[];
      };
      expect(body.method).toBe("eth_getTransactionReceipt");
      expect(body.params).toEqual([txHash]);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            transactionHash: txHash,
            status: "0x1",
            blockNumber: "0x1234",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const status = await verifyFilterFingerprint({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: fp,
        anchorTx: txHash,
      },
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(status.state).toBe("match");
    expect(status.arcReceiptVerified).toBe(true);
    expect(status.blockingSend).toBe(false);
    expect(status.plainSummary).toBe(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: matches the published version`,
    );
    expect(status.anchorUrl).toBe(`https://explorer.testnet.arc.io/tx/${txHash}`);

    // Closed TechDetails by default hides jargon and tx link
    const closedHtml = renderToStaticMarkup(
      React.createElement(FilterFingerprintBadge, { status }),
    );
    expect(closedHtml).toContain(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: matches the published version`,
    );
    expect(closedHtml).not.toContain("filter-fingerprint-mismatch-alert");
    expect(closedHtml).not.toContain("filter-fingerprint-tx-link");

    // Expanded TechDetails shows the Arc explorer tx link and fingerprint digests
    const openHtml = renderToStaticMarkup(
      React.createElement(FilterFingerprintBadge, {
        status,
        defaultOpenTechDetails: true,
      }),
    );
    expect(openHtml).toContain("filter-fingerprint-tx-link");
    expect(openHtml).toContain(`https://explorer.testnet.arc.io/tx/${txHash}`);
    expect(openHtml).toContain(fp);
  });

  it("handles State 3 (mismatch): renders orange alert and blocks prepareOutboundTurn from sending", async () => {
    const tamperedFingerprint = `0x${"ff".repeat(32)}`;
    const status = evaluateLocalFilterFingerprint({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: tamperedFingerprint,
        anchorTx: `0x${"cd".repeat(32)}`,
      },
    });

    expect(status.state).toBe("mismatch");
    expect(status.blockingSend).toBe(true);
    expect(status.blockReason).toContain("does not match the published version");

    const html = renderToStaticMarkup(
      React.createElement(FilterFingerprintBadge, { status }),
    );
    expect(html).toContain("filter-fingerprint-mismatch-alert");
    expect(html).toContain("border-accent");
    expect(html).toContain(
      `Personal-detail filter v${MECHANICAL_RULESET.version}: does not match the published version`,
    );

    // Send pipeline throws FilterFingerprintMismatchError when fingerprint mismatches
    await expect(
      prepareOutboundTurn("Hello world", {
        publishedFingerprintOverride: {
          version: MECHANICAL_RULESET.version,
          fingerprint: tamperedFingerprint,
          anchorTx: `0x${"cd".repeat(32)}`,
        },
      }),
    ).rejects.toThrow(FilterFingerprintMismatchError);
  });

  it("handles State 4 (Arc receipt missing or reverted): marks state as receipt-missing without falsely claiming receipt confirmation", async () => {
    const fp = rulesetFingerprint();
    const txHash = `0x${"ef".repeat(32)}`;
    const mockNullReceiptFetch = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: null,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const receiptCheck = await checkArcTransactionReceipt(txHash, {
      fetchImpl: mockNullReceiptFetch as unknown as typeof fetch,
    });
    expect(receiptCheck.exists).toBe(false);
    expect(receiptCheck.succeeded).toBe(false);

    const status = await verifyFilterFingerprint({
      published: {
        version: MECHANICAL_RULESET.version,
        fingerprint: fp,
        anchorTx: txHash,
      },
      fetchImpl: mockNullReceiptFetch as unknown as typeof fetch,
    });

    expect(status.state).toBe("receipt-missing");
    expect(status.arcReceiptVerified).toBe(false);
    expect(status.blockingSend).toBe(false);
    expect(renderFilterFingerprintSummaryText(status)).toContain(
      "public receipt pending",
    );
  });
});

describe("E2: scripts/publish-filter-fingerprint.mjs safety", () => {
  it("computes the exact fingerprint and refuses to anchor or overwrite published-fingerprint.json without --confirm", async () => {
    const beforeFile = readFileSync(
      resolve(ROOT, "src/lib/privacy/published-fingerprint.json"),
      "utf8",
    );
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const res = await runPublishFilterFingerprint([]);

    expect(res.ok).toBe(false);
    expect(res.confirmed).toBe(false);
    expect(res.version).toBe(MECHANICAL_RULESET.version);
    expect(res.fingerprint).toBe(rulesetFingerprint());
    expect(res.anchorReceiptHash).toBe(
      computeFilterAnchorReceiptHash(
        MECHANICAL_RULESET.version,
        rulesetFingerprint(),
      ),
    );
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining("without --confirm"),
    );

    const afterFile = readFileSync(
      resolve(ROOT, "src/lib/privacy/published-fingerprint.json"),
      "utf8",
    );
    expect(afterFile).toBe(beforeFile);
    logSpy.mockRestore();
    errSpy.mockRestore();
  });

  it("keeps all W6-C UI and library files free of em dashes (—) and keeps default badge view free of banned jargon", () => {
    const ownedFiles = [
      "src/lib/privacy/mechanical.ts",
      "src/lib/privacy/mechanical-ruleset.ts",
      "src/lib/privacy/fingerprint.ts",
      "src/lib/privacy/published-fingerprint.json",
      "src/components/privacy/filter-fingerprint-badge.tsx",
      "src/components/console.tsx",
      "src/components/console/send-pipeline.ts",
      "scripts/publish-filter-fingerprint.mjs",
    ];
    for (const rel of ownedFiles) {
      const content = readFileSync(resolve(ROOT, rel), "utf8");
      expect(content, `${rel} must not contain em dash`).not.toContain("—");
    }

    const bannedJargon = [
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

    const states = [
      evaluateLocalFilterFingerprint({
        published: { version: "1.0.0", fingerprint: null, anchorTx: null },
      }),
      evaluateLocalFilterFingerprint({
        published: {
          version: "1.0.0",
          fingerprint: rulesetFingerprint(),
          anchorTx: `0x${"ab".repeat(32)}`,
        },
      }),
      evaluateLocalFilterFingerprint({
        published: {
          version: "1.0.0",
          fingerprint: `0x${"ff".repeat(32)}`,
          anchorTx: `0x${"ab".repeat(32)}`,
        },
      }),
    ];

    for (const st of states) {
      const html = renderToStaticMarkup(
        React.createElement(FilterFingerprintBadge, { status: st }),
      );
      for (const word of bannedJargon) {
        expect(html.toLowerCase()).not.toContain(word.toLowerCase());
      }
    }
  });
});
