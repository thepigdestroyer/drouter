import { describe, expect, it } from "vitest";
import {
  createSessionScrubber,
  isValidIbanMod97,
  isValidLuhn,
} from "@/lib/privacy/scrubber";
import {
  bucketForTokens,
  estimateTokens,
  minimizeHistory,
} from "@/lib/privacy/padding";

// Runtime builders so no secret-looking literal is committed to the repository
function joinParts(...parts: string[]): string {
  return parts.join("");
}

function buildLuhnCard(prefixDigits: string, totalLength = 16): string {
  const body = prefixDigits.padEnd(totalLength - 1, "4");
  let sum = 0;
  let shouldDouble = true; // rightmost payload digit is doubled when computing check digit
  for (let i = body.length - 1; i >= 0; i--) {
    let d = body.charCodeAt(i) - 48;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  return `${body}${checkDigit}`;
}

const AWS_STS_FIXTURE = joinParts("ASIA", "IOSFODNN7EXAMPLE");

describe("Subsystem 5: Client-Side Privacy Guard", () => {
  describe("SessionScrubber (reversible PII & secret placeholder substitution)", () => {
    it("replaces emails, API keys (tk_..., sk-...), phone numbers, IPv4s, 0x addresses, and custom terms with numbered placeholders", () => {
      const scrubber = createSessionScrubber(["Project Nightfall", "Acme Bio"]);
      const tkKey = joinParts("tk", "_live_", "9876543210abcdef");
      const skKey = joinParts("sk", "-proj-", "abcdef1234567890");

      const prompt = [
        "Contact alice@acme.com or bob@example.org.",
        `Keys: ${tkKey} and ${skKey}.`,
        "Call +1 (415) 555-0199 or +44 20 7946 0958.",
        "Server IP is 192.168.10.42.",
        "Payout wallet: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.",
        "Confidential context for Project Nightfall at Acme Bio.",
      ].join(" ");

      const { scrubbed, replacements } = scrubber.scrub(prompt);

      expect(scrubbed).not.toContain("alice@acme.com");
      expect(scrubbed).not.toContain("bob@example.org");
      expect(scrubbed).not.toContain(tkKey);
      expect(scrubbed).not.toContain(skKey);
      expect(scrubbed).not.toContain("415");
      expect(scrubbed).not.toContain("7946 0958");
      expect(scrubbed).not.toContain("192.168.10.42");
      expect(scrubbed).not.toContain("0x71C7656EC7ab88b098defB751B7401B5f6d8976F");
      expect(scrubbed).not.toContain("Project Nightfall");
      expect(scrubbed).not.toContain("Acme Bio");

      expect(scrubbed).toContain("[EMAIL_1]");
      expect(scrubbed).toContain("[EMAIL_2]");
      expect(scrubbed).toContain("[SECRET_1]");
      expect(scrubbed).toContain("[SECRET_2]");
      expect(scrubbed).toContain("[PHONE_1]");
      expect(scrubbed).toContain("[PHONE_2]");
      expect(scrubbed).toContain("[IP_1]");
      expect(scrubbed).toContain("[ACCT_1]");
      expect(scrubbed).toContain("[ENTITY_1]");
      expect(scrubbed).toContain("[ENTITY_2]");

      expect(replacements.length).toBe(10);

      const entries = scrubber.entries();
      const emailEntry = entries.find((e) => e.placeholder === "[EMAIL_1]");
      expect(emailEntry).toBeDefined();
      expect(emailEntry?.preview).toBe("al***@acme.com");
    });

    it("maps repeated occurrences of the same email across turns to the same [EMAIL_1]", () => {
      const scrubber = createSessionScrubber();

      const turn1 = scrubber.scrub("Please email alice@acme.com with the summary.");
      const turn2 = scrubber.scrub("Forward a copy to alice@acme.com and charlie@acme.com.");
      const turn3 = scrubber.scrub("Confirming ALICE@acme.com received the report.");

      expect(turn1.scrubbed).toBe("Please email [EMAIL_1] with the summary.");
      expect(turn2.scrubbed).toBe("Forward a copy to [EMAIL_1] and [EMAIL_2].");
      expect(turn3.scrubbed).toBe("Confirming [EMAIL_1] received the report.");
      expect(scrubber.entries().filter((e) => e.kind === "EMAIL")).toHaveLength(2);
    });

    it("accurately restores all placeholders in model replies", () => {
      const scrubber = createSessionScrubber(["Dr. Evelyn Vance"]);
      scrubber.addCustomTerm("Horizon Clinic");
      const tkToken = joinParts("tk", "_secret_token_", "998877");

      const userPrompt =
        `Send results for Dr. Evelyn Vance at Horizon Clinic to evelyn@horizon.org (IP 10.24.0.9, wallet 0x1234567890abcdef1234567890abcdef12345678, phone +1-212-555-0147, token ${tkToken}).`;
      const { scrubbed } = scrubber.scrub(userPrompt);

      expect(scrubbed).toBe(
        "Send results for [ENTITY_1] at [ENTITY_2] to [EMAIL_1] (IP [IP_1], wallet [ACCT_1], phone [PHONE_1], token [SECRET_1]).",
      );

      const modelReply =
        "I have prepared the summary for [ENTITY_1] at [ENTITY_2]. It will be sent to [EMAIL_1] from host [IP_1], billed to [ACCT_1], and verified via SMS to [PHONE_1] using key [SECRET_1].";

      const restored = scrubber.restore(modelReply);
      expect(restored).toBe(
        `I have prepared the summary for Dr. Evelyn Vance at Horizon Clinic. It will be sent to evelyn@horizon.org from host 10.24.0.9, billed to 0x1234567890abcdef1234567890abcdef12345678, and verified via SMS to +1-212-555-0147 using key ${tkToken}.`,
      );

      scrubber.clear();
      expect(scrubber.entries()).toHaveLength(0);
    });

    it("blocks bypasses (zero-width chars, Cyrillic/fullwidth homoglyphs, split keys, base64-wrapped keys, JWTs, PEM keys, SSNs, NHS/NI numbers) and prevents literal [EMAIL_1] collision", () => {
      const scrubber = createSessionScrubber(["Project Nightfall"]);

      // 1. Literal placeholder [EMAIL_1] already in user prompt alongside real email
      const collisionInput =
        "The doc mentions literal [EMAIL_1] and real contact dana.reyes+audit@sub.acme.co.uk.";
      const { scrubbed: collisionScrubbed } = scrubber.scrub(collisionInput);
      expect(collisionScrubbed).toBe(
        "The doc mentions literal [EMAIL_1] and real contact [EMAIL_2].",
      );
      expect(scrubber.restore(collisionScrubbed)).toBe(collisionInput);

      // 2. If a later turn contains literal [EMAIL_2] (which is now in byPlaceholder), it is protected and restored back to literal [EMAIL_2]
      const turn2Input = "Why did the parser emit literal [EMAIL_2] in the log?";
      const { scrubbed: turn2Scrubbed } = scrubber.scrub(turn2Input);
      expect(turn2Scrubbed).not.toContain("[EMAIL_2]");
      expect(scrubber.restore(turn2Scrubbed)).toBe(turn2Input);

      // 3. Adversarial bypasses: zero-width spaces, Cyrillic homoglyphs, split key, base64 key, JWT, PEM, SSN, UK NI, NHS
      scrubber.clear();
      const rawWrappedKey = joinParts("sk", "-proj-", "secretBase64WrappedKey123456");
      const b64Key = Buffer.from(rawWrappedKey).toString("base64");
      const jwt = [
        Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"),
        Buffer.from('{"sub":"1234567890","name":"Dana"}').toString("base64url"),
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      ].join(".");
      const pemHeader = joinParts("-----BEGIN ", "EC PRIVATE KEY-----");
      const pemFooter = joinParts("-----END ", "EC PRIVATE KEY-----");
      const pem = `${pemHeader}\nMHcCAQEEIJTc7910abcdef1234567890==\n${pemFooter}`;
      const splitKey = joinParts("sk", "-proj-abcd\n", "efgh12345678");
      const ssn = ["123", "45", "6789"].join("-");

      const bypassPrompt = [
        `Zero-width email: al\u200Bice@ac\u200Cme.com`,
        `Homoglyph email: \u0430lice@\u0430cme.com`,
        `Homoglyph entity: \u0420roject Nightf\u0430ll`,
        `Split key: ${splitKey}`,
        `Base64 key: ${b64Key}`,
        `JWT: ${jwt}`,
        `PEM: ${pem}`,
        `SSN: ${ssn}`,
        `UK NI: QQ 12 34 56 C`,
        `NHS: NHS 485 777 3456`,
        `AWS: ${AWS_STS_FIXTURE}`,
      ].join(" | ");

      const { scrubbed: bypassScrubbed } = scrubber.scrub(bypassPrompt);
      expect(bypassScrubbed).not.toContain("acme.com");
      expect(bypassScrubbed).not.toContain("Nightf");
      expect(bypassScrubbed).not.toContain("efgh12345678");
      expect(bypassScrubbed).not.toContain(b64Key);
      expect(bypassScrubbed).not.toContain(jwt.slice(0, 10));
      expect(bypassScrubbed).not.toContain("EC PRIVATE KEY");
      expect(bypassScrubbed).not.toContain(ssn);
      expect(bypassScrubbed).not.toContain("QQ 12 34 56 C");
      expect(bypassScrubbed).not.toContain("485 777 3456");
      expect(bypassScrubbed).not.toContain(AWS_STS_FIXTURE);

      // Both zero-width and homoglyph variants of alice@acme.com canonicalize to [EMAIL_1]
      expect(scrubber.entries().filter((e) => e.kind === "EMAIL")).toHaveLength(1);
    });

    it("scrubs API keys across all major providers (OpenAI, Anthropic, Google, AWS, GitHub, Stripe, Slack, Tinfoil) built at runtime", () => {
      const scrubber = createSessionScrubber();

      const providerKeys: Record<string, string> = {
        openaiProj: joinParts("sk", "-proj-", "9a8b7c6d5e4f3g2h1i0j"),
        openaiSvc: joinParts("sk", "-svcacct-", "AbCdEfGhIjKlMnOpQrSt12"),
        anthropic: joinParts("sk", "-ant-api03-", "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876"),
        googleApi: joinParts("AIza", "SyDaNaReYeS0123456789AbCdEfGhIjKlMnOp"),
        googleOauth: joinParts("ya29", ".", "a0AfH6SMBx9876543210_synthetic_token"),
        googleClient: joinParts("GOCSPX", "-", "9876543210AbCdEfGhIjKlMn"),
        awsAkia: joinParts("AKIA", "IOSFODNN7EXAMPLE"),
        awsSecret: joinParts("aws_secret_access_key", " = ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        githubPat: joinParts("ghp", "_", "1234567890abcdefghijklmnopqrstuvwxyzAB"),
        githubFine: joinParts("github_pat", "_", "11ABCDEFG0123456789_abcdefghijklmnopqrstuv"),
        stripeLive: joinParts("sk", "_live_", "51H8xYzAbCdEfGhIjKlMnOpQr"),
        stripeRestricted: joinParts("rk", "_live_", "99AbCdEfGhIjKlMnOpQrStUv"),
        stripeWebhook: joinParts("whsec", "_", "abcdef0123456789abcdef0123456789"),
        slackBot: joinParts("xoxb", "-", "123456789012-345678901234-AbCdEfGhIjKlMnOpQrStUvWx"),
        slackApp: joinParts("xapp", "-1-", "A0123456789-9876543210123-abcdef0123456789"),
        slackWebhook: joinParts(
          "https://hooks.slack.com/services/",
          "T01234567/B89012345/aBcDeFgHiJkLmNoPqRsTuVwX",
        ),
        tinfoilTk: joinParts("tk", "_live_", "drouterEnclaveKey0123456789"),
        tinfoilTf: joinParts("tf", "_live_", "confidentialGpuKey987654321"),
      };

      const prompt = Object.entries(providerKeys)
        .map(([name, val]) => `${name}: ${val}`)
        .join(" | ");

      const { scrubbed } = scrubber.scrub(prompt);

      for (const [, secretVal] of Object.entries(providerKeys)) {
        expect(scrubbed).not.toContain(secretVal);
      }
      expect(scrubber.restore(scrubbed)).toBe(prompt);
    });

    it("scrubs Luhn-valid credit cards (Visa, Mastercard, Amex 4-6-5, Diners 4-6-4, contiguous & spaced) while ignoring non-Luhn numbers", () => {
      const scrubber = createSessionScrubber();

      const visaRaw = buildLuhnCard("453201511283036", 16);
      const visaSpaced = `${visaRaw.slice(0, 4)} ${visaRaw.slice(4, 8)} ${visaRaw.slice(8, 12)} ${visaRaw.slice(12)}`;
      const mcRaw = buildLuhnCard("542523343010990", 16);
      const mcDashed = `${mcRaw.slice(0, 4)}-${mcRaw.slice(4, 8)}-${mcRaw.slice(8, 12)}-${mcRaw.slice(12)}`;
      const amexRaw = buildLuhnCard("37828224631000", 15);
      const amexGrouped = `${amexRaw.slice(0, 4)} ${amexRaw.slice(4, 10)} ${amexRaw.slice(10)}`;
      const dinersRaw = buildLuhnCard("3852000002323", 14);
      const dinersGrouped = `${dinersRaw.slice(0, 4)}-${dinersRaw.slice(4, 10)}-${dinersRaw.slice(10)}`;

      // Flip last digit of visaRaw to make an invalid Luhn number
      const badLastDigit = (Number(visaRaw.slice(-1)) + 1) % 10;
      const invalidLuhnNumber = `${visaRaw.slice(0, -1)}${badLastDigit}`;

      expect(isValidLuhn(visaSpaced)).toBe(true);
      expect(isValidLuhn(mcDashed)).toBe(true);
      expect(isValidLuhn(amexGrouped)).toBe(true);
      expect(isValidLuhn(dinersGrouped)).toBe(true);
      expect(isValidLuhn(invalidLuhnNumber)).toBe(false);

      const prompt = `Cards: ${visaSpaced}, ${mcDashed}, ${amexGrouped}, ${dinersGrouped}. Non-card build ID: ${invalidLuhnNumber}.`;
      const { scrubbed } = scrubber.scrub(prompt);

      expect(scrubbed).not.toContain(visaSpaced);
      expect(scrubbed).not.toContain(mcDashed);
      expect(scrubbed).not.toContain(amexGrouped);
      expect(scrubbed).not.toContain(dinersGrouped);
      expect(scrubbed).toContain(invalidLuhnNumber);
      expect(scrubber.restore(scrubbed)).toBe(prompt);
    });

    it("scrubs realistic addresses, dates of birth, UK postcodes, passport numbers, IBANs, and international phone numbers", () => {
      const scrubber = createSessionScrubber();

      const ukIban = ["GB29", "NWBK", "6016", "1331", "9268", "19"].join(" ");
      const deIban = ["DE89", "3704", "0044", "0532", "0130", "00"].join("");
      const frIban = ["fr76", "3000", "6000", "0112", "3456", "7890", "189"].join(" ");

      expect(isValidIbanMod97(ukIban)).toBe(true);
      expect(isValidIbanMod97(deIban)).toBe(true);
      expect(isValidIbanMod97(frIban)).toBe(true);

      const items = {
        usAddress: "742 Evergreen Terrace, Apt 2B, Springfield, IL 62704",
        ukAddress: "221B Baker Street, London",
        poBox: "P.O. Box 48219",
        ukPostcode1: "SW1A 1AA",
        ukPostcode2: "EC1A 1BB",
        ukPostcode3: "M1 1AE",
        ukPostcode4: "GIR 0AA",
        dobLabeled: "DOB: 1988-11-23",
        dobSlash: "14/07/1992",
        dobWritten: "March 15, 1984",
        passportLabeled: "Passport #543210987",
        passportUsNextGen: "A87654321",
        passportEu: "AB7654321",
        passportMrz: "P<GBRREYES<<DANA<<<<<<<<<<<<<<<<<<<<<<<<<<<",
        ukIban,
        deIban,
        frIban,
        phoneUsExt: "+1 (415) 555-0199 ext. 402",
        phoneUkTrunk: "+44 (0) 20 7946 0958",
        phoneUkMobile: "07911 123456",
        phoneFrPairs: "+33 1 42 68 55 00",
        phoneFrDots: "06.12.34.56.78",
        phoneDeSlash: "030 / 12345678",
      };

      const prompt = Object.entries(items)
        .map(([k, v]) => `${k}=[${v}]`)
        .join(" ; ");

      const { scrubbed } = scrubber.scrub(prompt);

      expect(scrubbed).not.toContain("742 Evergreen Terrace");
      expect(scrubbed).not.toContain("221B Baker Street");
      expect(scrubbed).not.toContain("Box 48219");
      expect(scrubbed).not.toContain("SW1A 1AA");
      expect(scrubbed).not.toContain("EC1A 1BB");
      expect(scrubbed).not.toContain("M1 1AE");
      expect(scrubbed).not.toContain("GIR 0AA");
      expect(scrubbed).not.toContain("1988-11-23");
      expect(scrubbed).not.toContain("14/07/1992");
      expect(scrubbed).not.toContain("March 15, 1984");
      expect(scrubbed).not.toContain("543210987");
      expect(scrubbed).not.toContain("A87654321");
      expect(scrubbed).not.toContain("AB7654321");
      expect(scrubbed).not.toContain("P<GBRREYES");
      expect(scrubbed).not.toContain("NWBK");
      expect(scrubbed).not.toContain("37040044");
      expect(scrubbed).not.toContain("3000 6000");
      expect(scrubbed).not.toContain("555-0199");
      expect(scrubbed).not.toContain("7946 0958");
      expect(scrubbed).not.toContain("07911 123456");
      expect(scrubbed).not.toContain("42 68 55 00");
      expect(scrubbed).not.toContain("06.12.34.56.78");
      expect(scrubbed).not.toContain("12345678");

      expect(scrubber.restore(scrubbed)).toBe(prompt);
    });
  });

  describe("Upload Bucket Padding & Token Estimation (Spec §6)", () => {
    it("estimates tokens using UTF-8 byte / 4 heuristic with min 1 for non-empty text", () => {
      expect(estimateTokens("")).toBe(0);
      expect(estimateTokens("hi")).toBe(1);
      expect(estimateTokens("12345678")).toBe(2);
    });

    it("computes power-of-two 1024-token buckets and 50 ms frame cadence", () => {
      const b50 = bucketForTokens(50);
      expect(b50.bucketTokens).toBe(1024);
      expect(b50.exponent).toBe(0);
      expect(b50.padTokens).toBe(974);
      expect(b50.frameCadenceMs).toBe(50);

      const b1024 = bucketForTokens(1024);
      expect(b1024.bucketTokens).toBe(1024);
      expect(b1024.exponent).toBe(0);
      expect(b1024.padTokens).toBe(0);
      expect(b1024.overheadPct).toBe(0);

      const b1025 = bucketForTokens(1025);
      expect(b1025.bucketTokens).toBe(2048);
      expect(b1025.exponent).toBe(1);
      expect(b1025.padTokens).toBe(1023);

      const b5000 = bucketForTokens(5000);
      expect(b5000.bucketTokens).toBe(8192);
      expect(b5000.exponent).toBe(3);
      expect(b5000.padTokens).toBe(3192);
      expect(b5000.frameCadenceMs).toBe(50);
    });

    it("pads and unpads payloads across exact bucket boundaries (0B, 1B, 4091B, 4092B, 4093B, 1MB) without leaking length inside the bucket", async () => {
      const { padPayloadToBucket, unpadPayloadFromBucket } = await import(
        "@/lib/privacy/padding"
      );

      // 0B and 1B and 4092B (4092 + 4B prefix = 4096B = 1024 tokens) must all produce identical 4096-byte buffers
      const p0 = padPayloadToBucket("");
      const p1 = padPayloadToBucket("a");
      const p4091 = padPayloadToBucket("b".repeat(4091));
      const p4092 = padPayloadToBucket("c".repeat(4092));
      const p4093 = padPayloadToBucket("d".repeat(4093));

      expect(p0.bucketBytes).toBe(4096);
      expect(p1.bucketBytes).toBe(4096);
      expect(p4091.bucketBytes).toBe(4096);
      expect(p4092.bucketBytes).toBe(4096);
      expect(p4093.bucketBytes).toBe(8192);

      expect(unpadPayloadFromBucket(p0.paddedBytes)).toBe("");
      expect(unpadPayloadFromBucket(p1.paddedBytes)).toBe("a");
      expect(unpadPayloadFromBucket(p4091.paddedBytes)).toBe("b".repeat(4091));
      expect(unpadPayloadFromBucket(p4092.paddedBytes)).toBe("c".repeat(4092));
      expect(unpadPayloadFromBucket(p4093.paddedBytes)).toBe("d".repeat(4093));
    });
  });

  describe("Local Context Minimizer", () => {
    it("respects maxTokensBudget, preserves chronological order, and prioritizes turns sharing keywords with query", () => {
      const messages: { role: "user" | "assistant"; content: string; id: number }[] = [
        {
          id: 0,
          role: "user",
          content: "System boot: initialize workspace session.",
        },
        {
          id: 1,
          role: "assistant",
          content: "Unrelated discussion about CSS flexbox button padding and colors.",
        },
        {
          id: 2,
          role: "user",
          content: "We configured the PostgreSQL migration schema and index partitioning.",
        },
        {
          id: 3,
          role: "assistant",
          content: "Unrelated discussion about coffee machines and office plants.",
        },
        {
          id: 4,
          role: "user",
          content: "The PostgreSQL migration failed on the partitioning step.",
        },
        {
          id: 5,
          role: "assistant",
          content: "Let me inspect the latest logs for you.",
        },
        {
          id: 6,
          role: "user",
          content: "How do we fix the PostgreSQL migration partitioning error?",
        },
      ];

      // Calculate token budget that fits pinned messages (0, 5, 6) + 2 middle messages (2 and 4)
      const pinnedTokens =
        estimateTokens(messages[0].content) +
        estimateTokens(messages[5].content) +
        estimateTokens(messages[6].content);
      const relevantMiddleTokens =
        estimateTokens(messages[2].content) + estimateTokens(messages[4].content);
      const budget = pinnedTokens + relevantMiddleTokens;

      const result = minimizeHistory(
        messages,
        "PostgreSQL migration partitioning schema",
        budget,
      );

      expect(result.tokensAfter).toBeLessThanOrEqual(budget);
      expect(result.tokensBefore).toBeGreaterThan(result.tokensAfter);
      expect(result.droppedCount).toBe(2);

      const selectedIds = result.selected.map((m) => m.id);
      // Preserves chronological order and keeps first (0), relevant middle (2, 4), and last two (5, 6)
      expect(selectedIds).toEqual([0, 2, 4, 5, 6]);
    });
  });
});
