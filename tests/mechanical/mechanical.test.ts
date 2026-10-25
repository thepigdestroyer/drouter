import { afterEach, describe, expect, it, vi } from "vitest";
import {
  computeShannonEntropy,
  createMechanicalSession,
  isHighEntropyToken,
  mechanicalRedact,
} from "@/lib/privacy/mechanical";
import {
  attestedPiiFilter,
  clearAttestedPiiFilterCacheForTests,
  setAttestedPiiFilterClientForTests,
  type AttestedPiiSecureClientLike,
} from "@/lib/privacy/attested-filter";

function joinParts(...parts: string[]): string {
  return parts.join("");
}

function buildLuhnCard(prefixDigits: string, totalLength = 16): string {
  const body = prefixDigits.padEnd(totalLength - 1, "4");
  let sum = 0;
  let shouldDouble = true;
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

function interleaveWith(str: string, sep: string): string {
  return Array.from(str).join(sep);
}

function toFullwidthAscii(str: string): string {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 0x21 && code <= 0x7e) {
      out += String.fromCharCode(code + 0xfee0);
    } else {
      out += str[i];
    }
  }
  return out;
}

function toMathBoldAscii(str: string): string {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      out += String.fromCodePoint(0x1d400 + (code - 65));
    } else if (code >= 97 && code <= 122) {
      out += String.fromCodePoint(0x1d41a + (code - 97));
    } else if (code >= 48 && code <= 57) {
      out += String.fromCodePoint(0x1d7ce + (code - 48));
    } else {
      out += str[i];
    }
  }
  return out;
}

afterEach(() => {
  setAttestedPiiFilterClientForTests(null);
  clearAttestedPiiFilterCacheForTests();
});

describe("D3: Deterministic Fail-Closed Mechanical Redaction Filter (mechanicalRedact)", () => {
  it("redacts runtime-constructed names (multi-word, titled, hyphenated, apostrophe, nobiliary particles, labeled) and restores identically", () => {
    const firstNames = ["Elena", "Marcus", "Jean-Luc", "Mary-Jane", "Liam"];
    const lastNames = ["Rostova", "Vance", "Picard", "Watson", "O'Connor"];
    const fullName1 = `${firstNames[0]} ${lastNames[0]}`;
    const fullName2 = joinParts("Dr. ", firstNames[1], " ", lastNames[1], ", MD");
    const fullName3 = `${firstNames[2]} ${lastNames[2]}`;
    const fullName4 = `${firstNames[3]} ${lastNames[3]}`;
    const fullName5 = joinParts("Prof. ", firstNames[4], " ", lastNames[4]);
    const nobleName = ["Johannes", "van", "der", "Waals"].join(" ");
    const labeledSingleName = ["Patient: ", "Katarina"].join("");

    const input = [
      `Please contact ${fullName1} and ${fullName2} regarding the chart.`,
      `Forwarded by ${fullName3}, ${fullName4}, and ${fullName5}.`,
      `Reviewed with ${nobleName}.`,
      `${labeledSingleName} arrived at the clinic.`,
    ].join(" ");

    const res = mechanicalRedact(input);

    expect(res.text).not.toContain(fullName1);
    expect(res.text).not.toContain("Elena");
    expect(res.text).not.toContain("Rostova");
    expect(res.text).not.toContain("Marcus");
    expect(res.text).not.toContain("Vance");
    expect(res.text).not.toContain("Jean-Luc");
    expect(res.text).not.toContain("Mary-Jane");
    expect(res.text).not.toContain("O'Connor");
    expect(res.text).not.toContain("Waals");
    expect(res.text).not.toContain("Katarina");

    // Sentence-starter "Please" and "Reviewed" must remain intact outside the placeholder
    expect(res.text).toContain("Please contact [NAME_1]");
    expect(res.redactions.filter((r) => r.kind === "NAME").length).toBeGreaterThanOrEqual(7);
    expect(res.restore(res.text)).toBe(input);
  });

  it("redacts any token with 4+ consecutive digits, comma-grouped numbers, phones, SSNs, and Luhn cards", () => {
    const fourDigits = ["4", "8", "2", "9"].join("");
    const prefixedToken = joinParts("cohort-", "984120", "-v2");
    const currencyAmount = joinParts("$", "185,400.00");
    const ssn = ["412", "58", "9034"].join("-");
    const card = buildLuhnCard("453298172635491", 16);
    const phone = ["+1", "(415)", "555-0184"].join(" ");
    const localPhone = ["555", "867", "5309"].slice(1).join("-");

    const input = [
      `Pin code ${fourDigits}, identifier ${prefixedToken}, grant ${currencyAmount}.`,
      `SSN ${ssn}, card ${card}, phone ${phone}, local ${localPhone}.`,
    ].join(" ");

    const res = mechanicalRedact(input);

    expect(res.text).not.toContain(fourDigits);
    expect(res.text).not.toContain("984120");
    expect(res.text).not.toContain("185,400");
    expect(res.text).not.toContain(ssn);
    expect(res.text).not.toContain(card);
    expect(res.text).not.toContain("555-0184");
    expect(res.text).not.toContain(localPhone);

    const kinds = new Set(res.redactions.map((r) => r.kind));
    expect(kinds.has("DIGITS")).toBe(true);
    expect(kinds.has("ACCT")).toBe(true);
    expect(kinds.has("PHONE")).toBe(true);
    expect(res.restore(res.text)).toBe(input);
  });

  it("redacts street addresses, PO boxes, UK postcodes, and ZIP+4 codes built at runtime", () => {
    const street1 = ["742", "Evergreen", "Terrace,", "Apt", "4B,", "Springfield,", "IL", "62704"].join(" ");
    const street2 = ["221B", "Baker", "Street"].join(" ");
    const streetLower = ["88", "maple", "boulevard", "suite", "12"].join(" ");
    const poBox = ["P.O.", "Box", "49102"].join(" ");
    const ukPostcode = ["SW1A", "2AA"].join(" ");

    const input = `Ship to ${street1} or ${street2} or ${streetLower} or ${poBox} (${ukPostcode}).`;
    const res = mechanicalRedact(input);

    expect(res.text).not.toContain("Evergreen Terrace");
    expect(res.text).not.toContain("Baker Street");
    expect(res.text).not.toContain("maple boulevard");
    expect(res.text).not.toContain("Box 49102");
    expect(res.text).not.toContain("SW1A 2AA");
    expect(res.redactions.some((r) => r.kind === "ADDRESS")).toBe(true);
    expect(res.restore(res.text)).toBe(input);
  });

  it("redacts URLs and bare domains with paths/ports while preserving trailing sentence punctuation", () => {
    const httpsUrl = joinParts("https://", "portal.northvale-health", ".org/patient/record?id=42");
    const wwwUrl = joinParts("www.", "clinical-trial-tracker", ".io/intake");
    const bareDomain = joinParts("internal.biobank", ".co.uk:8443/export");
    const wsUrl = joinParts("wss://", "stream.enclave-node", ".dev/v1/events");

    const input = `Check ${httpsUrl}, ${wwwUrl}; ${bareDomain}. Also ${wsUrl}!`;
    const res = mechanicalRedact(input);

    expect(res.text).not.toContain("northvale-health");
    expect(res.text).not.toContain("clinical-trial-tracker");
    expect(res.text).not.toContain("internal.biobank");
    expect(res.text).not.toContain("stream.enclave-node");

    // Trailing punctuation (, ; . !) is preserved outside the placeholders
    expect(res.text).toBe("Check [URL_1], [URL_2]; [URL_3]. Also [URL_4]!");
    expect(res.restore(res.text)).toBe(input);
  });

  it("redacts dates across ISO-8601, slash/dot/hyphen, 2-digit year, and written month formats", () => {
    const isoDate = ["2026", "10", "24"].join("-");
    const isoTimestamp = `${["2026", "04", "15"].join("-")}T14:32:10Z`;
    const slashDate = ["14", "07", "1992"].join("/");
    const dotDate = ["03", "11", "2024"].join(".");
    const shortYearDate = ["09", "28", "89"].join("/");
    const monthNameDate1 = ["March", "15th,", "1984"].join(" ");
    const monthNameDate2 = ["24", "October", "2026"].join(" ");
    const labeledDob = joinParts("DOB: ", "1979-02-19");

    const input = [
      `Dates: ${isoDate}, ${isoTimestamp}, ${slashDate}, ${dotDate},`,
      `${shortYearDate}, ${monthNameDate1}, ${monthNameDate2}, ${labeledDob}.`,
    ].join(" ");

    const res = mechanicalRedact(input);

    expect(res.text).not.toContain(isoDate);
    expect(res.text).not.toContain("14:32:10Z");
    expect(res.text).not.toContain(slashDate);
    expect(res.text).not.toContain(dotDate);
    expect(res.text).not.toContain(shortYearDate);
    expect(res.text).not.toContain("March 15th");
    expect(res.text).not.toContain("24 October");
    expect(res.text).not.toContain("1979-02-19");
    expect(res.redactions.filter((r) => r.kind === "DATE")).toHaveLength(8);
    expect(res.restore(res.text)).toBe(input);
  });

  it("redacts known secrets AND unlabeled high-entropy tokens via Shannon entropy threshold", () => {
    const openAiKey = joinParts("sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz123456");
    const dbUrl = joinParts("postgres://", "admin:s3cr3tP@ssw0rd@db.internal:5432/prod");
    const labeledPass = joinParts("password=", "CorrectHorse#91!");
    // Unlabeled high-entropy tokens (no known prefix, no 4 consecutive digits)
    const unlabeledAlnum = joinParts("xK9m", "Q2pL", "8vR4", "nZ7w", "Y1bC");
    const unlabeledHex = joinParts("dead", "beef", "cafe", "babe", "f00d", "a1b2");
    const unlabeledConsonant = joinParts("xqkzv", "jwmpl", "rbynd", "fghts");

    expect(computeShannonEntropy(unlabeledAlnum)).toBeGreaterThan(3.75);
    expect(isHighEntropyToken(unlabeledAlnum)).toBe(true);
    expect(isHighEntropyToken(unlabeledHex)).toBe(true);
    expect(isHighEntropyToken(unlabeledConsonant)).toBe(true);

    // Ordinary long English words must NOT be flagged as high-entropy
    expect(isHighEntropyToken("confidentiality")).toBe(false);
    expect(isHighEntropyToken("internationalization")).toBe(false);
    expect(isHighEntropyToken("cryptographically")).toBe(false);
    expect(isHighEntropyToken("microarchitecture")).toBe(false);

    const input = `Keys: ${openAiKey} | ${dbUrl} | ${labeledPass} | ${unlabeledAlnum} | ${unlabeledHex} | ${unlabeledConsonant}`;
    const res = mechanicalRedact(input);

    expect(res.text).not.toContain(openAiKey);
    expect(res.text).not.toContain("s3cr3tP");
    expect(res.text).not.toContain("CorrectHorse");
    expect(res.text).not.toContain(unlabeledAlnum);
    expect(res.text).not.toContain(unlabeledHex);
    expect(res.text).not.toContain(unlabeledConsonant);
    expect(res.restore(res.text)).toBe(input);
  });

  it("defeats adversarial Unicode tricks, zero-width characters, bidi overrides, fullwidth/math symbols, and split tokens", () => {
    // 1. Zero-width characters inside name, email, URL, and digits
    const zwName = joinParts("Al\u200Bex", " ", "Riv\u200Cera");
    const zwEmail = joinParts("al\u200Bex.riv\u200Dera", "@", "ac\uFEFFme.org");
    const zwDigits = joinParts("98", "\u200B", "41", "\u2060", "20");
    const zwUrl = joinParts("https://", "sec\u200Bret.ac\u00ADme.com/path");

    // 2. Bidi override & variation selector injection
    const bidiSecret = joinParts("sk-proj-", "\u202E", "AbCdEfGh12345678", "\u202C");
    const vsName = joinParts("Da\uFE01na", " ", "Rey\uFE02es");

    // 3. Cyrillic / Greek homoglyphs + precomposed & combining diacritics
    const cyrillicName = "\u0410lex \u0420ostov"; // Cyrillic A and P
    const accentedName = "Jos\u0065\u0301 Garc\u00EDa"; // Combining acute + precomposed í
    const fullwidthDigits = toFullwidthAscii("482910");
    const mathBoldName = toMathBoldAscii("Clara Vance");
    const mathBoldDigits = toMathBoldAscii("739201");

    // 4. Split tokens (spaced API key, spaced digits, obfuscated email, char-by-char split name)
    const splitApiKey = joinParts("sk-proj-", "abcd12 ", "efgh34 ", "ijkl56");
    const charSplitKey = interleaveWith(joinParts("sk-proj-", "ab12cd34"), " ");
    const splitDigits = ["4", "8", "2", "9", "1", "0"].join(" ");
    const splitEmail = ["dana.reyes", "[at]", "northvale", "[dot]", "org"].join(" ");
    const charSplitName = interleaveWith("JaneDoe", " ");

    const adversarialInput = [
      `ZW: ${zwName} | ${zwEmail} | ${zwDigits} | ${zwUrl}`,
      `Bidi/VS: ${bidiSecret} | ${vsName}`,
      `Unicode: ${cyrillicName} | ${accentedName} | ${fullwidthDigits} | ${mathBoldName} | ${mathBoldDigits}`,
      `Split: ${splitApiKey} | ${charSplitKey} | ${splitDigits} | ${splitEmail} | ${charSplitName}`,
    ].join("\n");

    const res = mechanicalRedact(adversarialInput);

    expect(res.text).not.toContain("Riv\u200Cera");
    expect(res.text).not.toContain("ac\uFEFFme.org");
    expect(res.text).not.toContain(zwDigits);
    expect(res.text).not.toContain("ac\u00ADme.com");
    expect(res.text).not.toContain("AbCdEfGh12345678");
    expect(res.text).not.toContain("Rey\uFE02es");
    expect(res.text).not.toContain(cyrillicName);
    expect(res.text).not.toContain("Garc\u00EDa");
    expect(res.text).not.toContain(fullwidthDigits);
    expect(res.text).not.toContain(mathBoldName);
    expect(res.text).not.toContain(mathBoldDigits);
    expect(res.text).not.toContain("efgh34");
    expect(res.text).not.toContain(charSplitKey);
    expect(res.text).not.toContain(splitDigits);
    expect(res.text).not.toContain("northvale");
    expect(res.text).not.toContain(charSplitName);

    // Every single adversarial span restores byte-for-byte to the exact original string
    expect(res.restore(res.text)).toBe(adversarialInput);
  });

  it("measures false-positive behaviour on ordinary sentences (0 redactions on plain prose; expected fail-closed redactions on capitalized multi-word nouns and 4-digit numbers)", () => {
    const ordinaryCleanSentences = [
      "The quick brown fox jumps over the lazy dog near the river bank.",
      "We need to summarize the quarterly financial report and check the latency metrics before deployment.",
      "Please verify that the database connection pool closes idle sockets after thirty seconds.",
      "Enclave memory encryption protects confidential workloads against physical interposer probes.",
      "In Python, lists are mutable and dictionaries preserve insertion order.",
      "However, the system remained stable throughout the entire load test.",
    ];

    for (const sentence of ordinaryCleanSentences) {
      const res = mechanicalRedact(sentence);
      expect(res.redactions).toEqual([]);
      expect(res.text).toBe(sentence);
      expect(res.restore(res.text)).toBe(sentence);
    }

    // Ordinary sentences with capitalized multi-word proper nouns or 4-digit numbers
    // intentionally trigger fail-closed redaction (by design of D3):
    const failClosedOrdinary = [
      {
        sentence: "The Golden Gate Bridge opened in 1937 and spans the strait.",
        expectedKinds: ["NAME", "DIGITS"],
      },
      {
        sentence: "Our local development server listens on port 8080 by default.",
        expectedKinds: ["DIGITS"],
      },
      {
        sentence: "We travelled to New York City for the autumn conference.",
        expectedKinds: ["NAME"],
      },
    ];

    for (const item of failClosedOrdinary) {
      const res = mechanicalRedact(item.sentence);
      expect(res.redactions.map((r) => r.kind)).toEqual(item.expectedKinds);
      expect(res.restore(res.text)).toBe(item.sentence);
    }
  });

  it("maintains session-stable placeholders across multi-turn chats via createMechanicalSession and restores repeated/reordered placeholders", () => {
    const session = createMechanicalSession(["Project Helios"]);

    const turn1Input =
      "Meet Elena Rostova on 2026-10-25 about the $185,400.00 grant for Project Helios.";
    const turn1 = mechanicalRedact(turn1Input, { session });

    expect(turn1.text).toBe(
      "Meet [NAME_1] on [DATE_1] about the [DIGITS_1] grant for [ENTITY_1].",
    );

    const turn2Input =
      "Ask Marcus Vance and Elena Rostova if the $185,400.00 transfer or the $92,000.00 reserve is ready for Project Helios.";
    const turn2 = mechanicalRedact(turn2Input, {
      session,
      customTerms: ["Northvale Vault"],
    });

    // Elena Rostova keeps [NAME_1]; Marcus Vance gets [NAME_2] and never collides with [NAME_1]
    expect(turn2.text).toBe(
      "Ask [NAME_2] and [NAME_1] if the [DIGITS_1] transfer or the [DIGITS_2] reserve is ready for [ENTITY_1].",
    );

    // Re-preparing historical turn 1 produces the exact same placeholders
    const turn1Reprepared = mechanicalRedact(turn1Input, { session });
    expect(turn1Reprepared.text).toBe(turn1.text);

    // Turn 3 has no new redactions in the user message, but model reply repeats and reorders placeholders from turns 1 & 2
    const turn3 = mechanicalRedact("Who approved the transfer first?", {
      session,
    });
    expect(turn3.redactions).toEqual([]);

    const modelReply =
      "On [DATE_1], [NAME_2] told [NAME_1] that [NAME_2] and [NAME_1] approved [DIGITS_2] and [DIGITS_1] for [ENTITY_1].";
    expect(turn3.restore(modelReply)).toBe(
      "On 2026-10-25, Marcus Vance told Elena Rostova that Marcus Vance and Elena Rostova approved $92,000.00 and $185,400.00 for Project Helios.",
    );

    // Clearing the session resets counters while keeping initial custom terms
    session.clear();
    expect(session.entries()).toEqual([]);
    const afterClear = session.redact(
      "Follow up with Marcus Vance on Project Helios.",
    );
    expect(afterClear.text).toBe("Follow up with [NAME_1] on [ENTITY_1].");
  });

  it("handles explicit ££...££ markers first: closed, unclosed (fail-closed), empty ££££, multi-line, next to money (£125,000), inside code, and repeated across turns", () => {
    const session = createMechanicalSession();

    // 1. Closed marker, empty ££££ marker, and adjacent £125,000 money amount
    const turn1Input =
      "Budget £125,000 for ££Project Falcon££££££ with ££internal codename alpha££.";
    const turn1 = session.redact(turn1Input);
    expect(turn1.text).toBe("Budget [DIGITS_1] for [MARKED_1] with [MARKED_2].");
    expect(turn1.redactions).toEqual([
      { kind: "DIGITS", placeholder: "[DIGITS_1]" },
      { kind: "MARKED", placeholder: "[MARKED_1]" },
      { kind: "MARKED", placeholder: "[MARKED_2]" },
    ]);
    // Restore puts back only the inner text without ££ markers
    expect(turn1.restore(turn1.text)).toBe(
      "Budget £125,000 for Project Falcon with internal codename alpha.",
    );

    // 2. Marked span runs FIRST before every other rule (so emails/keys inside ££...££ become one [MARKED_N] placeholder, never split)
    const innerEmailAndKey = joinParts(
      "owner dana.reyes@example.com with ",
      "sk",
      "_live_",
      "51HxYz9876543210",
    );
    const priorityRes = session.redact(`Config: ££${innerEmailAndKey}££.`);
    expect(priorityRes.text).toBe("Config: [MARKED_3].");
    expect(priorityRes.redactions).toEqual([
      { kind: "MARKED", placeholder: "[MARKED_3]" },
    ]);
    expect(priorityRes.restore(priorityRes.text)).toBe(
      `Config: ${innerEmailAndKey}.`,
    );

    // 3. Multi-line marked span and inside a code snippet
    const codeSnippet = [
      "```ts",
      'const endpoint = "££https://staging-01.secret-cluster.internal:8443/v2££";',
      "const note = `££line one of secret",
      "line two of secret££`;",
      "```",
    ].join("\n");
    const codeRes = session.redact(codeSnippet);
    expect(codeRes.text).not.toContain("staging-01");
    expect(codeRes.text).not.toContain("line one of secret");
    expect(codeRes.text).not.toContain("line two of secret");
    expect(codeRes.text).toContain('const endpoint = "[MARKED_4]";');
    expect(codeRes.text).toContain("const note = `[MARKED_5]`;");
    expect(codeRes.restore(codeRes.text)).toBe(
      [
        "```ts",
        'const endpoint = "https://staging-01.secret-cluster.internal:8443/v2";',
        "const note = `line one of secret",
        "line two of secret`;",
        "```",
      ].join("\n"),
    );

    // 4. Repeated across turns (including case/Unicode variations) reuses [MARKED_1]
    const turn2 = session.redact(
      "Confirm ££project falcon££ and ££Pro\u200Bject Falcon££ launch.",
    );
    expect(turn2.text).toBe("Confirm [MARKED_1] and [MARKED_1] launch.");
    expect(turn2.restore("Status for [MARKED_1]: ready.")).toBe(
      "Status for Project Falcon: ready.",
    );

    // 5. Fail closed: an opening ££ with no closing ££ hides everything from the marker to the end of the message
    const unclosedInput =
      "Public intro before marker ££everything after this opening marker is hidden\nincluding line two and 10.42.7.19";
    const unclosedRes = session.redact(unclosedInput);
    expect(unclosedRes.text).toBe("Public intro before marker [MARKED_6]");
    expect(unclosedRes.text).not.toContain("everything after");
    expect(unclosedRes.text).not.toContain("10.42.7.19");
    expect(unclosedRes.restore(unclosedRes.text)).toBe(
      "Public intro before marker everything after this opening marker is hidden\nincluding line two and 10.42.7.19",
    );
  });

  it("maintains case-folded and Unicode-normalized canonical key stability across turns and escapes colliding literal placeholders", () => {
    const session = createMechanicalSession();

    const t1 = session.redact(
      "Contact Dana.Reyes@Example.com and Elena Rostova at https://Portal.Acme.Internal/login.",
    );
    expect(t1.text).toBe("Contact [EMAIL_1] and [NAME_1] at [URL_1].");

    // Turn 2 uses different case, zero-width characters, and Cyrillic homoglyphs for the same items
    const t2 = session.redact(
      "Follow up with dana.reyes@example.com, El\u200Bena R\u043Estov\u0430, and https://portal.acme.internal/login.",
    );
    expect(t2.text).toBe("Follow up with [EMAIL_1], [NAME_1], and [URL_1].");

    // Literal placeholder collision in Turn 3: typing literal [NAME_1] when [NAME_1] is already allocated
    const t3 = session.redact(
      "Why did the log print literal [NAME_1] for Elena Rostova?",
    );
    // The first [NAME_1] is a literal collision so it gets escaped to [ENTITY_1]; the real Elena Rostova still gets [NAME_1]
    expect(t3.text).toBe("Why did the log print literal [ENTITY_1] for [NAME_1]?");
    expect(t3.restore(t3.text)).toBe(
      "Why did the log print literal [NAME_1] for Elena Rostova?",
    );
  });

  it("hides technical details (API keys, valid IPv4s, IPv6s, MAC addresses, internal hostnames, and user file paths) while preserving version numbers and clean code snippets", () => {
    const apiKey = joinParts("sk", "_live_", "51HxYz9876543210fictional");
    const ghToken = joinParts("ghp", "_", "1234567890abcdefghijklmnopqrstuvwxyzAB");
    const ipv4 = "10.42.7.19";
    const ipv4Port = "192.168.1.250:8080";
    const ipv6Full = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    const ipv6Compressed = "fe80::1ff:fe23:4567:890a";
    const ipv6Trailing = "2001:db8::";
    const macColon = "00:1A:2B:3C:4D:5E";
    const macHyphen = "02-42-AC-11-00-02";
    const macCisco = "001a.2b3c.4d5e";
    const hostInternal = "billing.int.acme.internal";
    const hostLocal = "redis-cache.local";
    const hostCorp = "gitlab.eng.acme.corp";
    const hostLan = "nas-01.lan";
    const hostIntranet = "hr-portal.acme.intranet";
    const hostCloud = "ip-10-42-7-19.ec2.internal";
    const pathMac = "/Users/dana/acme/deploy.log";
    const pathLinux = "/home/dana_reyes/.ssh/id_rsa";
    const pathWin = "C:\\Users\\dana\\AppData\\Local\\temp.txt";

    const techInput = [
      `Keys: ${apiKey}, ${ghToken}.`,
      `IPs: ${ipv4}, ${ipv4Port}, ${ipv6Full}, ${ipv6Compressed}, ${ipv6Trailing}.`,
      `MACs: ${macColon}, ${macHyphen}, ${macCisco}.`,
      `Hosts: ${hostInternal}, ${hostLocal}, ${hostCorp}, ${hostLan}, ${hostIntranet}, ${hostCloud}.`,
      `Paths: ${pathMac}, ${pathLinux}, ${pathWin}.`,
    ].join(" ");

    const res = mechanicalRedact(techInput);

    for (const item of [
      apiKey,
      ghToken,
      ipv4,
      ipv4Port,
      ipv6Full,
      ipv6Compressed,
      ipv6Trailing,
      macColon,
      macHyphen,
      macCisco,
      hostInternal,
      hostLocal,
      hostCorp,
      hostLan,
      hostIntranet,
      hostCloud,
      pathMac,
      pathLinux,
      pathWin,
      "/Users/dana",
      "/home/dana_reyes",
      "C:\\Users\\dana",
      "deploy.log",
      "temp.txt",
    ]) {
      expect(res.text).not.toContain(item);
    }
    expect(res.restore(res.text)).toBe(techInput);

    // Version strings like 1.2.3 or v2.4.10 and ordinary code snippets must remain untouched (0 false positives)
    const cleanCodeAndVersions = [
      "Upgrade package from v1.2.3 to 2.4.10 before running the build.",
      "function add(a: number, b: number): number { return a + b; }",
      "const items = array.filter((x) => x.active).map((x) => x.label);",
      "import { useState, useEffect } from 'react';",
    ];
    for (const snippet of cleanCodeAndVersions) {
      const cleanRes = mechanicalRedact(snippet);
      expect(cleanRes.redactions).toEqual([]);
      expect(cleanRes.text).toBe(snippet);
    }
  });
});

describe("D4: Attested Enclave PII Filter (attestedPiiFilter)", () => {
  it("calls Tinfoil's pii-filter enclave via SecureClient when verified and returns verified: true", async () => {
    const mockFetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { text?: string };
      return new Response(
        JSON.stringify({
          schema_version: 1,
          summary: {
            output_mode: "typed",
            span_count: 2,
            by_label: { private_person: 1, private_phone: 1 },
            decoded_mismatch: false,
          },
          text: body.text,
          detected_spans: [
            {
              label: "private_person",
              start: 5,
              end: 16,
              text: "Alex Rivera",
              placeholder: "<PRIVATE_PERSON>",
            },
            {
              label: "private_phone",
              start: 20,
              end: 32,
              text: "555-867-5309",
              placeholder: "<PRIVATE_PHONE>",
            },
          ],
          redacted_text: "Call <PRIVATE_PERSON> at <PRIVATE_PHONE>",
          warning: null,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const mockClient: AttestedPiiSecureClientLike = {
      ready: vi.fn(async () => {}),
      getVerificationDocument: () => ({
        securityVerified: true,
        enclaveHost: "pii-filter.tinfoil.sh",
        releaseTag: "v0.3.3",
      }),
      fetch: mockFetch,
    };

    setAttestedPiiFilterClientForTests(mockClient);

    const res = await attestedPiiFilter("Call Alex Rivera at 555-867-5309");
    expect(res).toEqual({
      text: "Call <PRIVATE_PERSON> at <PRIVATE_PHONE>",
      redactionCount: 2,
      model: "pii-filter",
      verified: true,
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("refuses to send raw text and falls back to mechanicalRedact with verified: false if enclave attestation is not securityVerified", async () => {
    const spyFetch = vi.fn();
    const unverifiedClient: AttestedPiiSecureClientLike = {
      ready: vi.fn(async () => {}),
      getVerificationDocument: () => ({
        securityVerified: false,
        enclaveHost: "pii-filter.tinfoil.sh",
      }),
      fetch: spyFetch,
    };

    setAttestedPiiFilterClientForTests(unverifiedClient);

    const sample = "Contact Alex Rivera at alex.rivera@example.org or 555-867-5309.";
    const res = await attestedPiiFilter(sample);

    expect(spyFetch).not.toHaveBeenCalled();
    expect(res.verified).toBe(false);
    expect(res.model).toBe("pii-filter");
    expect(res.text).not.toContain("Alex Rivera");
    expect(res.text).not.toContain("alex.rivera@example.org");
    expect(res.text).not.toContain("555-867-5309");
    expect(res.redactionCount).toBe(3);
  });

  it("falls back cleanly to mechanicalRedact with verified: false when TINFOIL_API_KEY is missing or HTTP fails", async () => {
    const prevKey = process.env.TINFOIL_API_KEY;
    try {
      delete process.env.TINFOIL_API_KEY;
      const sample = "Email Dana Reyes at dana.reyes@example.org on 2026-10-24.";
      const noKeyRes = await attestedPiiFilter(sample);
      expect(noKeyRes.verified).toBe(false);
      expect(noKeyRes.model).toBe("pii-filter");
      expect(noKeyRes.text).not.toContain("Dana Reyes");
      expect(noKeyRes.text).not.toContain("dana.reyes@example.org");
      expect(noKeyRes.text).not.toContain("2026-10-24");
      expect(noKeyRes.redactionCount).toBe(3);
    } finally {
      if (prevKey !== undefined) {
        process.env.TINFOIL_API_KEY = prevKey;
      }
    }
  });

  it(
    "verifies and calls Tinfoil's live pii-filter enclave end-to-end when TINFOIL_API_KEY is set",
    async () => {
      const apiKey = process.env.TINFOIL_API_KEY?.trim();
      if (!apiKey || process.env.DROUTER_STUB_UPSTREAM === "1") {
        return;
      }

      const syntheticInput =
        "Please reach out to Jordan Taylor at jordan.taylor@example.org or 415-555-0192.";
      const liveRes = await attestedPiiFilter(syntheticInput);

      expect(liveRes.verified).toBe(true);
      expect(liveRes.model).toBe("pii-filter");
      expect(liveRes.redactionCount).toBeGreaterThanOrEqual(2);
      expect(liveRes.text).not.toContain("Jordan Taylor");
      expect(liveRes.text).not.toContain("jordan.taylor@example.org");
      expect(liveRes.text).toContain("<PRIVATE_");
    },
    25_000,
  );
});
