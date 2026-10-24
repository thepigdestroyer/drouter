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
    label: "Wire transfer + API key",
    text: "Send $125,000 to alice@acme.com using key sk-live-987654321 on 2026-11-04",
  },
  {
    label: "Clinical trial budget",
    text: "Release $48,500 batch budget for patient trial@biotech.org with token sk-proj-441998271 on 2026-12-19",
  },
  {
    label: "Treasury payout",
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
    re: /\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{8,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{8,}|tk_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[A-Z0-9]{12,20}|xox[baprs]-[A-Za-z0-9-]{8,})\b/g,
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
  modelId = "gemma4-31b",
  enclaveHost = "router-0.tinfoil.sh",
}: PacketSnifferProps) {
  const [promptText, setPromptText] = useState<string>(
    samplePrompt || DEFAULT_PROMPT,
  );
  const [popped, setPopped] = useState<boolean>(false);

  const wireState = useMemo(() => {
    const activeInput = promptText;
    const plainTokens = tokenizePlaintext(activeInput);

    // Local PII scrubbing + symmetry masking
    const scrubber = createSessionScrubber();
    const scrubResult = scrubber.scrub(activeInput);
    const symmetry = createSymmetryTransform({
      dateShiftDays: 43,
      numericScaleFactor: 2.5,
    });
    const symResult = symmetry.transform(scrubResult.scrubbed);
    const scrubbedAndMasked = symResult.transformed;

    // RFC 8259 JSON envelope + bucket padding to 2^k * 4,096 B
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

    // Real SHA-256 + AES-256-CTR stream cipher over the 4,096 B frame
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
      encoder.encode(
        `x25519-mlkem768:encap:${enclaveHost}:${unpaddedBytes.byteLength}`,
      ),
    );

    const rawEntropy = computeShannonEntropy(cipherBytes);
    const displayEntropy = Number(rawEntropy.toFixed(2));

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
      cipherHexPreview: bytesToHexGroups(cipherBytes, 64),
      digestHex: bytesToHexCompact(frameDigest),
      encapKeyHex: bytesToHexCompact(encapsulatedKeyDigest),
      displayEntropy,
      hbmHexActive: bytesToHexGroups(hbmPlainBytes, 32),
    };
  }, [promptText, modelId, enclaveHost]);

  const redactedCount =
    wireState.scrubEntries.length + wireState.appliedSymmetry.length;

  return (
    <section
      aria-label="What every party sees"
      className="ep-card p-5 sm:p-6 text-ink space-y-6"
    >
      {/* Top heading and single action */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between border-b border-rule pb-5">
        <div className="space-y-1.5">
          <div className="ep-label">Wire inspection</div>
          <h2 className="font-serif text-xl sm:text-2xl text-ink">
            What every party sees when you send a prompt
          </h2>
          <p className="max-w-[70ch] text-sm text-ink-2">
            Type any sensitive sentence below to compare what stays on your
            device with what travels across the network, through our relay, and
            into sealed hardware.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setPopped((prev) => !prev)}
          className={popped ? "ep-btn-ghost shrink-0" : "ep-btn shrink-0"}
        >
          {popped ? "Restore session memory" : "Pop bubble (wipe memory)"}
        </button>
      </div>

      {/* Input & Presets */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label htmlFor="packet-sniffer-input" className="ep-label">
            Sample prompt (stays in your browser)
          </label>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="ep-label">Try:</span>
            {PRESET_SAMPLES.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setPromptText(preset.text);
                  setPopped(false);
                }}
                className="ep-muted-chip hover:border-ink hover:text-ink transition-colors cursor-pointer"
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
          placeholder="Type a prompt with API keys, emails, dates, or dollar amounts..."
          className="ep-input font-mono text-xs sm:text-sm"
        />
      </div>

      {/* 4 Columns: Your device, Network, Relay, Sealed hardware */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {/* Column 1: Your device */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                1. Your device
              </span>
              <span className="ep-pass">Full context</span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              Your browser sees the original prompt, scrubs secrets and emails
              into placeholders, shifts dates and amounts, and pads the frame.
            </p>

            <div className="ep-inset p-3 font-mono text-xs leading-relaxed break-words text-ink">
              {wireState.plainTokens.length === 0 ? (
                <span className="text-ink-3 italic">Empty prompt</span>
              ) : (
                wireState.plainTokens.map((tok, idx) =>
                  tok.kind === "plain" ? (
                    <span key={idx}>{tok.text}</span>
                  ) : (
                    <mark
                      key={idx}
                      title={`Scrubbed locally (${tok.kind})`}
                      className="rounded-sm bg-accent-soft border border-accent px-1 py-0.5 text-ink"
                    >
                      {tok.text}
                    </mark>
                  ),
                )
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-2 space-y-2">
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span>Items scrubbed locally</span>
              <span className="font-semibold text-ink">{redactedCount}</span>
            </div>
            <details className="text-xs">
              <summary className="cursor-pointer font-mono text-[11px] text-ink-2 hover:text-ink select-none">
                Show local replacement map
              </summary>
              <div className="mt-2 ep-inset p-2 font-mono text-[11px] space-y-1">
                {wireState.scrubEntries.map((entry) => (
                  <div
                    key={entry.placeholder}
                    className="flex items-center justify-between gap-2"
                  >
                    <span className="text-ink font-medium">
                      {entry.placeholder}
                    </span>
                    <span className="text-ink-3 truncate">{entry.preview}</span>
                  </div>
                ))}
                {wireState.appliedSymmetry.map((mask, i) => (
                  <div
                    key={`${mask.kind}-${i}`}
                    className="flex items-center justify-between gap-2"
                  >
                    <span className="text-ink font-medium">{mask.masked}</span>
                    <span className="text-ink-3">
                      {mask.kind === "date" ? "+43d shift" : "x2.5 scale"}
                    </span>
                  </div>
                ))}
                {redactedCount === 0 && (
                  <div className="text-ink-3">No sensitive tokens detected.</div>
                )}
              </div>
            </details>
          </div>
        </div>

        {/* Column 2: Network */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                2. Network
              </span>
              <span className="ep-muted-chip">Ciphertext only</span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              Your ISP and Wi-Fi router see a TLS connection carrying a padded{" "}
              {wireState.paddedByteLen.toLocaleString()}-byte encrypted frame.
              Prompt length is hidden inside a 4 KB multiple.
            </p>

            <div className="ep-inset p-3 font-mono text-[11px] leading-relaxed text-ink-2 break-all">
              {wireState.cipherHexPreview} ...
            </div>
          </div>

          <div className="pt-2 border-t border-rule font-mono text-[11px] text-ink-2 space-y-1">
            <div className="flex items-center justify-between">
              <span>Padded bucket size</span>
              <span className="text-ink font-medium">
                {wireState.paddedByteLen.toLocaleString()} B (
                {wireState.unpaddedByteLen} B + {wireState.padCharCount} B pad)
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Byte entropy</span>
              <span className="text-ink font-medium">
                {wireState.displayEntropy.toFixed(2)} / 8.00 bits/byte
              </span>
            </div>
          </div>
        </div>

        {/* Column 3: Relay */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                3. Relay
              </span>
              <span className="ep-muted-chip">No private key</span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              The Vercel proxy and <code className="font-mono">{enclaveHost}</code>{" "}
              forward the HPKE encapsulated key header and ciphertext. They do
              not hold the enclave decryption key.
            </p>

            <div className="ep-inset p-3 font-mono text-[11px] text-ink-2 space-y-1.5">
              <div className="truncate">
                <span className="text-ink font-medium">Host:</span>{" "}
                {enclaveHost}
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Model header:</span>{" "}
                {modelId}
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Encapsulated key:</span>{" "}
                {wireState.encapKeyHex.slice(0, 20)}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Frame SHA-256:</span>{" "}
                {wireState.digestHex.slice(0, 20)}...
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-3">
            Note: Tinfoil&apos;s router runs an attested usage reporter and
            acceptable-use classifier sidecar reporting policy violations to
            api.tinfoil.sh.
          </div>
        </div>

        {/* Column 4: Sealed hardware */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                4. Sealed hardware
              </span>
              <span className="ep-pass">
                {popped ? "Wiped (0x00)" : "Scrubbed text"}
              </span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              Inside the attested CPU and GPU enclave, the payload decrypts to
              the scrubbed prompt below. Real secrets and emails never entered
              the tunnel.
            </p>

            {popped ? (
              <div className="ep-inset p-3 font-mono text-xs leading-relaxed text-ink space-y-1.5">
                <div className="ep-label">Session memory zeroized</div>
                <div className="break-all">
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                  00 00 00
                </div>
                <div className="text-[11px] text-ink-3 font-sans">
                  Ephemeral session keys and buffers overwritten with zeros.
                </div>
              </div>
            ) : (
              <div className="ep-inset p-3 font-mono text-xs leading-relaxed break-words text-ink">
                {wireState.scrubbedAndMasked || (
                  <span className="text-ink-3 italic">Empty payload</span>
                )}
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-rule font-mono text-[11px] text-ink-2 flex items-center justify-between">
            <span>Memory state</span>
            <span className="text-ink font-medium">
              {popped ? "Zeroed on Pop" : "Encrypted RAM / GPU HBM"}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}

export default PacketSniffer;
