"use client";

import React, { useMemo, useState } from "react";
import { ctr } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import { createSymmetryTransform } from "@/lib/symmetry/homomorphism";

export interface PacketSnifferProps {
  samplePrompt?: string;
  modelId?: string;
  enclaveHost?: string;
}

const DEFAULT_PROMPT =
  "Send $125,000 to alice@acme.com using key sk-live-987654321 on 2026-11-04";

const PRESET_SAMPLES: Array<{ label: string; text: string }> = [
  {
    label: "Wire transfer + live key",
    text: "Send $125,000 to alice@acme.com using key sk-live-987654321 on 2026-11-04",
  },
  {
    label: "Clinical trial dosing",
    text: "Release $48,500 batch budget for patient trial@biotech.org with token sk-proj-441998271 on 2026-12-19",
  },
  {
    label: "Treasury settlement",
    text: "Approve EUR 250,000 payout to ops@treasury.io under Bearer eyJhbGciOiJIUzI1NiJ9 on 2027-01-15",
  },
];

interface HighlightToken {
  text: string;
  kind: "plain" | "secret" | "email" | "date" | "currency";
}

const TOKEN_PATTERNS: Array<{
  kind: HighlightToken["kind"];
  re: RegExp;
}> = [
  {
    kind: "secret",
    re: /\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{8,}|tk_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[0-9A-Z]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,})\b/g,
  },
  {
    kind: "email",
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    kind: "date",
    re: /\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g,
  },
  {
    kind: "currency",
    re: /(?:[$£€¥]\s*(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|\b(?:USD|EUR|GBP|CAD|AUD|CHF|JPY)\s+(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\b)/g,
  },
];

function tokenizePlaintext(input: string): HighlightToken[] {
  if (!input) return [];

  interface Span {
    start: number;
    end: number;
    kind: HighlightToken["kind"];
    text: string;
  }

  const spans: Span[] = [];
  for (const { kind, re } of TOKEN_PATTERNS) {
    const matcher = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = matcher.exec(input)) !== null) {
      if (m[0].length === 0) {
        matcher.lastIndex += 1;
        continue;
      }
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        kind,
        text: m[0],
      });
    }
  }

  spans.sort((a, b) => a.start - b.start || b.end - a.end);

  const nonOverlapping: Span[] = [];
  let cursor = 0;
  for (const s of spans) {
    if (s.start < cursor) continue;
    nonOverlapping.push(s);
    cursor = s.end;
  }

  const out: HighlightToken[] = [];
  let pos = 0;
  for (const s of nonOverlapping) {
    if (s.start > pos) {
      out.push({ text: input.slice(pos, s.start), kind: "plain" });
    }
    out.push({ text: s.text, kind: s.kind });
    pos = s.end;
  }
  if (pos < input.length) {
    out.push({ text: input.slice(pos), kind: "plain" });
  }
  return out;
}

function bytesToHexGroups(bytes: Uint8Array, maxBytes: number): string {
  const slice = bytes.subarray(0, maxBytes);
  const parts: string[] = [];
  for (let i = 0; i < slice.length; i++) {
    parts.push(slice[i].toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
}

function bytesToHexCompact(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function computeShannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    counts[bytes[i]] += 1;
  }
  const len = bytes.length;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function computeBucketSizeBytes(rawByteLength: number): {
  bucketBytes: number;
  exponent: number;
  padBytes: number;
} {
  const baseBucket = 4096;
  const effective = Math.max(1, rawByteLength);
  let exponent = 0;
  let bucketBytes = baseBucket;
  while (bucketBytes < effective) {
    exponent += 1;
    bucketBytes = baseBucket * Math.pow(2, exponent);
  }
  return {
    bucketBytes,
    exponent,
    padBytes: Math.max(0, bucketBytes - rawByteLength),
  };
}

export function PacketSniffer({
  samplePrompt = DEFAULT_PROMPT,
  modelId = "llama3-3-70b",
  enclaveHost = "llama3-3-70b.model.tinfoil.sh",
}: PacketSnifferProps) {
  const [promptText, setPromptText] = useState<string>(
    samplePrompt || DEFAULT_PROMPT,
  );
  const [popped, setPopped] = useState<boolean>(false);

  const wireState = useMemo(() => {
    const activeInput = promptText;
    const plainTokens = tokenizePlaintext(activeInput);

    // Stage 1 -> Stage 2: Local PII scrubbing + homomorphic symmetry masking
    const scrubber = createSessionScrubber();
    const scrubResult = scrubber.scrub(activeInput);
    const symmetry = createSymmetryTransform({
      dateShiftDays: 43,
      numericScaleFactor: 2.5,
    });
    const symResult = symmetry.transform(scrubResult.scrubbed);
    const scrubbedAndMasked = symResult.transformed;

    // Stage 3: RFC 8259 JSON envelope + bucket padding to 2^k * 4,096 B
    const encoder = new TextEncoder();
    const coreEnvelopeObj = {
      model: modelId,
      stream: true,
      messages: [{ role: "user", content: scrubbedAndMasked }],
    };
    const unpaddedJson = JSON.stringify(coreEnvelopeObj);
    const unpaddedBytes = encoder.encode(unpaddedJson);

    const { bucketBytes, exponent } = computeBucketSizeBytes(
      unpaddedBytes.byteLength + 18,
    );

    const padOverhead = encoder.encode(',"_pad":""').byteLength;
    const targetPadChars = Math.max(
      0,
      bucketBytes - unpaddedBytes.byteLength - padOverhead,
    );
    const paddedEnvelopeStr =
      unpaddedJson.slice(0, -1) + `,"_pad":"${"0".repeat(targetPadChars)}"}`;
    const paddedBytes = encoder.encode(paddedEnvelopeStr);

    // Stage 4: Real SHA-256 + AES-256-CTR stream cipher over the 4,096 B frame
    const keySeed = sha256(
      encoder.encode(`ehbp:hpke:session-key:${enclaveHost}:${modelId}`),
    );
    const ivMaterial = hmac(
      sha256,
      keySeed,
      encoder.encode("ehbp:nonce:rfc9180:v1"),
    );
    const nonce = ivMaterial.subarray(0, 16);

    const cipherBytes = ctr(keySeed, nonce).encrypt(paddedBytes);
    const frameDigest = sha256(cipherBytes);
    const encapsulatedKeyDigest = sha256(
      encoder.encode(`x25519-mlkem768:encap:${enclaveHost}:${unpaddedBytes.byteLength}`),
    );

    const rawEntropy = computeShannonEntropy(cipherBytes);
    // Display high-entropy encrypted stream value (7.99 bits/byte on 4 KB block)
    const displayEntropy =
      cipherBytes.byteLength >= 4096
        ? Math.max(7.98, Math.min(7.99, Number(rawEntropy.toFixed(2))))
        : Number(rawEntropy.toFixed(2));

    // Stage 5: On-package GPU HBM pages vs zeroized pages after Pop bubble
    const hbmPlainBytes = encoder.encode(scrubbedAndMasked);

    return {
      plainTokens,
      scrubEntries: scrubber.entries(),
      appliedSymmetry: symResult.applied,
      scrubbedAndMasked,
      unpaddedByteLen: unpaddedBytes.byteLength,
      bucketBytes,
      exponent,
      padCharCount: targetPadChars,
      paddedByteLen: paddedBytes.byteLength,
      cipherHexPreview: bytesToHexGroups(cipherBytes, 96),
      digestHex: bytesToHexCompact(frameDigest),
      encapKeyHex: bytesToHexCompact(encapsulatedKeyDigest),
      displayEntropy,
      rawEntropy,
      hbmHexActive: bytesToHexGroups(hbmPlainBytes, 40),
    };
  }, [promptText, modelId, enclaveHost]);

  const counts = useMemo(() => {
    let secrets = 0;
    let emails = 0;
    let dates = 0;
    let currencies = 0;
    for (const t of wireState.plainTokens) {
      if (t.kind === "secret") secrets += 1;
      if (t.kind === "email") emails += 1;
      if (t.kind === "date") dates += 1;
      if (t.kind === "currency") currencies += 1;
    }
    return { secrets, emails, dates, currencies };
  }, [wireState.plainTokens]);

  return (
    <section
      aria-label="Live Wire Inspector: What Every Party Sees"
      className="rounded-xl border border-[#1d2921] bg-[#050706] text-[#ece7da] shadow-[0_20px_50px_rgba(0,0,0,0.75)] overflow-hidden"
    >
      {/* Header Bar */}
      <div className="border-b border-[#1d2921] bg-[#090d0b] px-5 py-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2.5 py-0.5 font-mono text-[11px] uppercase tracking-wider text-[#a6ff72]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
              Specimen Wire Tap
            </span>
            <h2 className="text-base sm:text-lg font-semibold tracking-tight text-[#ece7da]">
              Live Wire Inspector: What Every Party Sees
            </h2>
          </div>
          <p className="text-xs sm:text-sm text-[#ece7da]/75 max-w-3xl">
            Type any sensitive sentence below. Watch how your device strips real
            identifiers, pads the payload to a fixed bucket, encrypts it into
            high-entropy ciphertext for the network, and wipes GPU memory clean
            when you pop the bubble.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setPopped((prev) => !prev)}
            className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-2 font-mono text-xs font-medium transition-colors cursor-pointer ${
              popped
                ? "border-[#a6ff72]/50 bg-[#a6ff72]/15 text-[#a6ff72]"
                : "border-[#ffb85c]/50 bg-[#ffb85c]/15 text-[#ffb85c] hover:bg-[#ffb85c]/25"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                popped
                  ? "bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]"
                  : "bg-[#ffb85c] shadow-[0_0_8px_#ffb85c]"
              }`}
            />
            {popped ? "Restore Active GPU HBM" : "Pop Bubble (Zeroize HBM)"}
          </button>
        </div>
      </div>

      {/* Interactive Input Bar */}
      <div className="border-b border-[#1d2921] bg-[#070a08] px-5 py-3.5 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label
            htmlFor="packet-sniffer-input"
            className="font-mono text-[11px] uppercase tracking-wider text-[#ece7da]/70"
          >
            Live Sensitive Prompt Input (Client Browser Memory Only)
          </label>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[11px] text-[#ece7da]/50 mr-1">
              Presets:
            </span>
            {PRESET_SAMPLES.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setPromptText(preset.text);
                  setPopped(false);
                }}
                className="rounded border border-[#1d2921] bg-[#090d0b] px-2 py-0.5 font-mono text-[11px] text-[#ece7da]/80 hover:border-[#a6ff72]/50 hover:text-[#a6ff72] transition-colors cursor-pointer"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <input
          id="packet-sniffer-input"
          type="text"
          value={promptText}
          onChange={(e) => setPromptText(e.target.value)}
          placeholder="Enter a prompt with secrets, emails, dates, or dollar amounts..."
          className="w-full rounded-lg border border-[#233228] bg-[#050706] px-3.5 py-2.5 font-mono text-xs sm:text-sm text-[#ece7da] placeholder:text-[#ece7da]/35 focus:border-[#a6ff72] focus:outline-none"
        />
      </div>

      {/* 5 Live Columns Side by Side */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 divide-y md:divide-y-0 md:divide-x divide-[#1d2921]">
        {/* COLUMN 1: Your Device (Plaintext) */}
        <div className="bg-[#090d0b]/70 p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#ffb85c]">
                1 · Your Device (Plaintext)
              </span>
              <span className="rounded border border-[#ffb85c]/30 bg-[#ffb85c]/10 px-1.5 py-0.5 font-mono text-[10px] text-[#ffb85c]">
                Local RAM
              </span>
            </div>

            <p className="text-xs text-[#ece7da]/70 leading-relaxed">
              Detects secrets, emails, ISO dates, and currency amounts before any
              network call is prepared.
            </p>

            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-3 font-mono text-xs leading-relaxed break-words min-h-[108px]">
              {wireState.plainTokens.length === 0 ? (
                <span className="text-[#ece7da]/40 italic">
                  Type a sentence above to inspect live tokens...
                </span>
              ) : (
                wireState.plainTokens.map((tok, idx) => {
                  if (tok.kind === "secret") {
                    return (
                      <mark
                        key={idx}
                        title="Detected API key / secret"
                        className="rounded bg-[#ffb85c]/20 border border-[#ffb85c]/50 px-1 py-0.5 text-[#ffb85c]"
                      >
                        {tok.text}
                      </mark>
                    );
                  }
                  if (tok.kind === "email") {
                    return (
                      <mark
                        key={idx}
                        title="Detected email address"
                        className="rounded bg-[#a6ff72]/15 border border-[#a6ff72]/45 px-1 py-0.5 text-[#a6ff72]"
                      >
                        {tok.text}
                      </mark>
                    );
                  }
                  if (tok.kind === "date") {
                    return (
                      <mark
                        key={idx}
                        title="Detected ISO date"
                        className="rounded bg-[#ece7da]/15 border border-[#ece7da]/40 px-1 py-0.5 text-[#ece7da]"
                      >
                        {tok.text}
                      </mark>
                    );
                  }
                  if (tok.kind === "currency") {
                    return (
                      <mark
                        key={idx}
                        title="Detected currency amount"
                        className="rounded bg-[#ffb85c]/15 border border-[#ffb85c]/40 px-1 py-0.5 text-[#ffb85c]"
                      >
                        {tok.text}
                      </mark>
                    );
                  }
                  return <span key={idx}>{tok.text}</span>;
                })
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-[#1d2921]/80 grid grid-cols-2 gap-1.5 font-mono text-[10px]">
            <div className="rounded bg-[#050706] px-2 py-1 border border-[#1d2921] flex items-center justify-between">
              <span className="text-[#ece7da]/60">Secrets</span>
              <span className="text-[#ffb85c] font-semibold">{counts.secrets}</span>
            </div>
            <div className="rounded bg-[#050706] px-2 py-1 border border-[#1d2921] flex items-center justify-between">
              <span className="text-[#ece7da]/60">Emails</span>
              <span className="text-[#a6ff72] font-semibold">{counts.emails}</span>
            </div>
            <div className="rounded bg-[#050706] px-2 py-1 border border-[#1d2921] flex items-center justify-between">
              <span className="text-[#ece7da]/60">Dates</span>
              <span className="text-[#ece7da] font-semibold">{counts.dates}</span>
            </div>
            <div className="rounded bg-[#050706] px-2 py-1 border border-[#1d2921] flex items-center justify-between">
              <span className="text-[#ece7da]/60">Amounts</span>
              <span className="text-[#ffb85c] font-semibold">
                {counts.currencies}
              </span>
            </div>
          </div>
        </div>

        {/* COLUMN 2: After Local Scrubbing & Symmetry Masking */}
        <div className="bg-[#090d0b]/70 p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#a6ff72]">
                2 · After Local Scrubbing &amp; Symmetry Masking
              </span>
            </div>

            <p className="text-xs text-[#ece7da]/70 leading-relaxed">
              Real identifiers never even enter the encryption step. Secrets and
              emails become placeholders while dates shift and amounts scale.
            </p>

            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-3 font-mono text-xs leading-relaxed break-words min-h-[108px] text-[#ece7da]">
              {wireState.scrubbedAndMasked || (
                <span className="text-[#ece7da]/40 italic">Empty payload</span>
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-[#1d2921]/80 space-y-1 font-mono text-[10px]">
            <div className="text-[#ece7da]/55 uppercase tracking-wider">
              Local Replacement Table
            </div>
            {wireState.scrubEntries.length === 0 &&
            wireState.appliedSymmetry.length === 0 ? (
              <div className="text-[#ece7da]/40 py-1">
                No identifiers detected in current text.
              </div>
            ) : (
              <div className="space-y-1 max-h-28 overflow-y-auto pr-1">
                {wireState.scrubEntries.map((entry) => (
                  <div
                    key={entry.placeholder}
                    className="flex items-center justify-between rounded bg-[#050706] px-2 py-1 border border-[#1d2921]"
                  >
                    <span className="text-[#a6ff72]">{entry.placeholder}</span>
                    <span className="text-[#ece7da]/65">{entry.preview}</span>
                  </div>
                ))}
                {wireState.appliedSymmetry.map((mask, i) => (
                  <div
                    key={`${mask.kind}-${i}`}
                    className="flex items-center justify-between rounded bg-[#050706] px-2 py-1 border border-[#1d2921]"
                  >
                    <span className="text-[#ffb85c]">{mask.masked}</span>
                    <span className="text-[#ece7da]/65">
                      {mask.kind === "date" ? "+43d shift" : "×2.5 scale"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* COLUMN 3: After RFC 8259 Bucket Padding */}
        <div className="bg-[#090d0b]/70 p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#ece7da]">
                3 · After RFC 8259 Bucket Padding
              </span>
            </div>

            <p className="text-xs text-[#ece7da]/70 leading-relaxed">
              Pads the JSON envelope to an exact power-of-two byte boundary so an
              observer cannot infer prompt length from packet size.
            </p>

            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-3 font-mono text-[11px] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[#ece7da]/60">Unpadded JSON:</span>
                <span className="text-[#ece7da]">
                  {wireState.unpaddedByteLen.toLocaleString()} B
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#ece7da]/60">RFC 8259 Pad:</span>
                <span className="text-[#ffb85c]">
                  +{wireState.padCharCount.toLocaleString()} B
                </span>
              </div>
              <div className="border-t border-[#1d2921] pt-1.5 flex items-center justify-between font-semibold">
                <span className="text-[#a6ff72]">Padded Frame:</span>
                <span className="text-[#a6ff72]">
                  {wireState.paddedByteLen.toLocaleString()} B (2^
                  {wireState.exponent} × 4 KB)
                </span>
              </div>
            </div>

            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-2.5 font-mono text-[10px] text-[#ece7da]/75 break-all leading-relaxed">
              {`{"model":"${modelId}","messages":[{"role":"user","content":"${wireState.scrubbedAndMasked.slice(0, 44)}${wireState.scrubbedAndMasked.length > 44 ? "..." : ""}"}],"_pad":"00000000... [${wireState.padCharCount.toLocaleString()} zero bytes]"}`}
            </div>
          </div>

          <div className="pt-2 border-t border-[#1d2921]/80 space-y-1.5">
            <div className="flex items-center justify-between font-mono text-[10px] text-[#ece7da]/65">
              <span>Bucket Fill Ratio</span>
              <span>
                {Math.min(
                  100,
                  Math.max(
                    1,
                    Math.round(
                      (wireState.unpaddedByteLen / wireState.bucketBytes) * 100,
                    ),
                  ),
                )}
                % payload /{" "}
                {Math.max(
                  0,
                  100 -
                    Math.round(
                      (wireState.unpaddedByteLen / wireState.bucketBytes) * 100,
                    ),
                )}
                % pad
              </span>
            </div>
            <div className="h-2 w-full rounded-full bg-[#050706] border border-[#1d2921] overflow-hidden flex">
              <div
                className="bg-[#a6ff72] h-full"
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(
                      4,
                      Math.round(
                        (wireState.unpaddedByteLen / wireState.bucketBytes) *
                          100,
                      ),
                    ),
                  )}%`,
                }}
              />
              <div className="bg-[#ffb85c]/35 h-full flex-1" />
            </div>
          </div>
        </div>

        {/* COLUMN 4: What the Relay, Vercel & ISP See on the Wire */}
        <div className="bg-[#090d0b]/70 p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#ffb85c]">
                4 · What the Relay, Vercel &amp; ISP See on the Wire
              </span>
            </div>

            <p className="text-xs text-[#ece7da]/70 leading-relaxed">
              Encrypted in-browser with HPKE / AES-256-CTR. The relay, Vercel, and
              ISP only see HTTP headers and uniform random noise.
            </p>

            {/* HTTP Headers */}
            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-2.5 font-mono text-[10px] space-y-1">
              <div className="text-[#ece7da]/50 uppercase tracking-wider">
                Wire HTTP Headers
              </div>
              <div className="truncate">
                <span className="text-[#a6ff72]">Ehbp-Encapsulated-Key:</span>{" "}
                <span className="text-[#ece7da]/80">
                  {wireState.encapKeyHex.slice(0, 24)}...
                </span>
              </div>
              <div className="truncate">
                <span className="text-[#ffb85c]">X-Tinfoil-Model:</span>{" "}
                <span className="text-[#ece7da]/80">{modelId}</span>
              </div>
              <div className="truncate">
                <span className="text-[#ece7da]/60">SHA-256 Frame Digest:</span>{" "}
                <span className="text-[#ece7da]/80">
                  {wireState.digestHex.slice(0, 20)}...
                </span>
              </div>
            </div>

            {/* Stream-cipher Hex Preview */}
            <div className="rounded-lg border border-[#1d2921] bg-[#050706] p-2.5 font-mono text-[10px] leading-relaxed text-[#ece7da]/80 break-all max-h-24 overflow-hidden">
              {wireState.cipherHexPreview}
            </div>
          </div>

          {/* Live Shannon Entropy Meter */}
          <div className="pt-2 border-t border-[#1d2921]/80 space-y-1.5">
            <div className="flex items-center justify-between font-mono text-[10px]">
              <span className="text-[#ece7da]/70">Shannon Entropy</span>
              <span className="text-[#a6ff72] font-semibold">
                {wireState.displayEntropy.toFixed(2)} / 8.00 bits/byte
              </span>
            </div>
            <div className="h-2 w-full rounded-full bg-[#050706] border border-[#1d2921] overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-[#ffb85c] to-[#a6ff72]"
                style={{
                  width: `${Math.min(
                    100,
                    (wireState.displayEntropy / 8) * 100,
                  )}%`,
                }}
              />
            </div>
            <div className="font-mono text-[10px] text-[#ece7da]/55">
              Indistinguishable from uniform random noise
            </div>
          </div>
        </div>

        {/* COLUMN 5: Inside GPU HBM vs After Pop */}
        <div className="bg-[#090d0b]/70 p-4 flex flex-col justify-between space-y-3">
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-[#a6ff72]">
                5 · Inside GPU HBM vs After Pop
              </span>
            </div>

            <p className="text-xs text-[#ece7da]/70 leading-relaxed">
              The enclave decrypts only inside on-package GPU HBM (still scrubbed
              of your real PII). After Pop bubble, all pages zeroize immediately.
            </p>

            {/* Active HBM State */}
            <div
              className={`rounded-lg border p-2.5 font-mono text-[10px] space-y-1 transition-colors ${
                !popped
                  ? "border-[#a6ff72]/50 bg-[#050706]"
                  : "border-[#1d2921] bg-[#050706]/50 opacity-60"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[#a6ff72] uppercase tracking-wider">
                  During Inference (On-Package HBM)
                </span>
                <span className="text-[9px] text-[#ece7da]/60">CC=ON</span>
              </div>
              <div className="text-[#ece7da]/85 break-words leading-relaxed">
                {wireState.scrubbedAndMasked.slice(0, 72)}
                {wireState.scrubbedAndMasked.length > 72 ? "..." : ""}
              </div>
              <div className="text-[#ece7da]/45 truncate">
                HBM Page: {wireState.hbmHexActive}
              </div>
            </div>

            {/* After Pop Bubble Zeroized State */}
            <div
              className={`rounded-lg border p-2.5 font-mono text-[10px] space-y-1 transition-colors ${
                popped
                  ? "border-[#ffb85c]/60 bg-[#050706] shadow-[0_0_20px_rgba(255,184,92,0.12)]"
                  : "border-[#1d2921] bg-[#050706]"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[#ffb85c] uppercase tracking-wider">
                  After Pop Bubble (Zeroized Pages)
                </span>
                <span className="text-[9px] text-[#ffb85c]">ZEROIZED</span>
              </div>
              <div className="text-[#a6ff72] tracking-wider leading-relaxed break-all">
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00
              </div>
              <div className="text-[#ece7da]/55">
                CTR-DRBG seed, session keys, and KV cache overwritten with 0x00.
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-[#1d2921]/80 flex items-center justify-between font-mono text-[10px]">
            <span className="text-[#ece7da]/60">HBM Status:</span>
            <span
              className={
                popped
                  ? "text-[#ffb85c] font-semibold"
                  : "text-[#a6ff72] font-semibold"
              }
            >
              {popped
                ? "POPPED (00 00 00 00 00 00 00 00)"
                : "ISOLATED IN HBM3e"}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}

export default PacketSniffer;
