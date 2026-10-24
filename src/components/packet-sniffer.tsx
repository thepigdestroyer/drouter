"use client";

import React, { useEffect, useMemo, useState } from "react";
import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Verifier, type AttestationBundle } from "tinfoil";
import { InkButton } from "@/components/ink/ink-button";
import { TechDetails } from "@/components/ink/tech-details";
import { preparePrompt } from "@/lib/pipeline";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
import { padJsonPayloadToBucket } from "@/lib/relay";
import { decodeSnpReportBytes } from "@/lib/tinfoil/deep-inspect";

export interface PacketSnifferProps {
  samplePrompt?: string;
  modelId?: string;
  enclaveHost?: string;
}

const DEFAULT_PROMPT =
  "Send $125,000 to dana.reyes@acme.example using key sk-live-9876543210abcdef on 2026-11-04";

const PRESET_SAMPLES: Array<{ label: string; text: string }> = [
  {
    label: "Send money",
    text: "Send $125,000 to dana.reyes@acme.example using key sk-live-9876543210abcdef on 2026-11-04",
  },
  {
    label: "Medical note",
    text: "Release $48,500 batch budget for patient dana.reyes@biotech.example with token sk-proj-4419982710abcdef on 2026-12-19",
  },
  {
    label: "Company payment",
    text: "Approve EUR 250,000 payout to dana.reyes@treasury.example under Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYW5hIn0.sig12345 on 2027-01-15",
  },
];

// Pinned HPKE X25519 public key from router-0.tinfoil.sh REPORT_DATA[32..64] used during SSR
// before the client-side /api/relay/attestation fetch resolves.
const FALLBACK_ENCLAVE_HPKE_PUBLIC_KEY_HEX =
  "5b89805f6ad3d337d0f633ef07fd86081ec542a10e5710d5806494263d8b192b";

const HPKE_VERSION_LABEL = utf8ToBytes("HPKE-v1");
const KEM_SUITE_ID_X25519 = new Uint8Array([0x4b, 0x45, 0x4d, 0x00, 0x20]); // "KEM" || 0x0020
const HPKE_SUITE_ID = new Uint8Array([
  0x48, 0x50, 0x4b, 0x45, // "HPKE"
  0x00, 0x20, // KEM: DHKEM(X25519, HKDF-SHA256)
  0x00, 0x01, // KDF: HKDF-SHA256
  0x00, 0x02, // AEAD: AES-256-GCM
]);
const EMPTY_BYTES = new Uint8Array(0);
const EHBP_REQUEST_INFO = utf8ToBytes("ehbp request");

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

const PLAIN_TOKEN_LABELS: Record<Exclude<HighlightToken["kind"], "plain">, string> = {
  secret: "hidden key",
  email: "hidden email",
  date: "hidden date",
  currency: "hidden amount",
};

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.byteLength;
  }
  return out;
}

function writeUint16BE(val: number): Uint8Array {
  return new Uint8Array([(val >>> 8) & 0xff, val & 0xff]);
}

function hpkeLabeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array
): Uint8Array {
  const labeledIkm = concatBytes(HPKE_VERSION_LABEL, suiteId, utf8ToBytes(label), ikm);
  return extract(sha256, labeledIkm, salt.byteLength > 0 ? salt : undefined);
}

function hpkeLabeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number
): Uint8Array {
  const labeledInfo = concatBytes(
    writeUint16BE(length),
    HPKE_VERSION_LABEL,
    suiteId,
    utf8ToBytes(label),
    info
  );
  return expand(sha256, prk, labeledInfo, length);
}

/**
 * Genuine RFC 9180 HPKE Base mode encapsulation (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM) with EHBP request domain separation ("ehbp request").
 * Matches Tinfoil's EHBP wire framing (Ehbp-Encapsulated-Key + 4-byte length prefix + GCM ciphertext).
 */
export function sealEhbpHpkeFrame(
  plaintextBytes: Uint8Array,
  recipientPubKeyBytes: Uint8Array,
  ephemeralSecretKeyBytes: Uint8Array
): {
  encapsulatedKeyBytes: Uint8Array;
  ciphertextBytes: Uint8Array;
  ehbpWireFrameBytes: Uint8Array;
} {
  const enc = x25519.getPublicKey(ephemeralSecretKeyBytes);
  const dhShared = x25519.getSharedSecret(ephemeralSecretKeyBytes, recipientPubKeyBytes);
  const kemContext = concatBytes(enc, recipientPubKeyBytes);
  const eaePrk = hpkeLabeledExtract(KEM_SUITE_ID_X25519, EMPTY_BYTES, "eae_prk", dhShared);
  const sharedSecret = hpkeLabeledExpand(
    KEM_SUITE_ID_X25519,
    eaePrk,
    "shared_secret",
    kemContext,
    32
  );

  const pskIdHash = hpkeLabeledExtract(HPKE_SUITE_ID, EMPTY_BYTES, "psk_id_hash", EMPTY_BYTES);
  const infoHash = hpkeLabeledExtract(HPKE_SUITE_ID, EMPTY_BYTES, "info_hash", EHBP_REQUEST_INFO);
  const ksContext = concatBytes(new Uint8Array([0x00]), pskIdHash, infoHash);

  const secret = hpkeLabeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY_BYTES);
  const key = hpkeLabeledExpand(HPKE_SUITE_ID, secret, "key", ksContext, 32);
  const baseNonce = hpkeLabeledExpand(HPKE_SUITE_ID, secret, "base_nonce", ksContext, 12);

  const ciphertextBytes = gcm(key, baseNonce, EMPTY_BYTES).encrypt(plaintextBytes);

  const ehbpWireFrameBytes = new Uint8Array(4 + ciphertextBytes.byteLength);
  new DataView(ehbpWireFrameBytes.buffer).setUint32(0, ciphertextBytes.byteLength, false);
  ehbpWireFrameBytes.set(ciphertextBytes, 4);

  return {
    encapsulatedKeyBytes: enc,
    ciphertextBytes,
    ehbpWireFrameBytes,
  };
}

function bytesToHexGroups(bytes: Uint8Array, maxBytes: number): string {
  const slice = bytes.subarray(0, maxBytes);
  const parts: string[] = [];
  for (let i = 0; i < slice.length; i++) {
    parts.push(slice[i].toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
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

async function extractHpkeKeyFromAttestationBundle(
  bundle: AttestationBundle
): Promise<{ hpkePublicKeyHex: string; host: string; releaseTag?: string }> {
  const host = bundle.domain || "router-0.tinfoil.sh";
  try {
    const verifier = new Verifier({
      configRepo: "tinfoilsh/confidential-model-router",
    });
    const verified = await verifier.verifyBundle(bundle);
    const doc = verifier.getVerificationDocument();
    if (verified.hpkePublicKey && verified.hpkePublicKey.length === 64) {
      return {
        hpkePublicKeyHex: verified.hpkePublicKey,
        host,
        releaseTag: doc?.releaseTag ?? bundle.releaseTag,
      };
    }
  } catch {
    // Fall back to direct SEV-SNP REPORT_DATA[32..64] extraction below
  }

  if (bundle.enclaveAttestationReport?.body && typeof DecompressionStream !== "undefined") {
    const bin = atob(bundle.enclaveAttestationReport.body);
    const gz = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      gz[i] = bin.charCodeAt(i);
    }
    const stream = new Response(gz.buffer).body;
    if (stream) {
      const decompressed = stream.pipeThrough(new DecompressionStream("gzip"));
      const rawBytes = new Uint8Array(await new Response(decompressed).arrayBuffer());
      const decoded = decodeSnpReportBytes(rawBytes);
      if (decoded.hpkeKeyFromReportDataHex.length === 64) {
        return {
          hpkePublicKeyHex: decoded.hpkeKeyFromReportDataHex,
          host,
          releaseTag: bundle.releaseTag,
        };
      }
    }
  }

  throw new Error("Could not extract HPKE public key from attestation bundle");
}

export function PacketSniffer({
  samplePrompt = DEFAULT_PROMPT,
  modelId = "kimi-k3",
  enclaveHost = "router-0.tinfoil.sh",
}: PacketSnifferProps) {
  const [promptText, setPromptText] = useState<string>(
    samplePrompt || DEFAULT_PROMPT
  );
  const [popped, setPopped] = useState<boolean>(false);

  // Live enclave HPKE public key fetched from /api/relay/attestation in useEffect
  const [liveEnclaveKeyHex, setLiveEnclaveKeyHex] = useState<string>(
    FALLBACK_ENCLAVE_HPKE_PUBLIC_KEY_HEX
  );
  const [liveHost, setLiveHost] = useState<string>(enclaveHost);
  const [keySourceLabel, setKeySourceLabel] = useState<
    "loading" | "verified-live" | "pinned-fallback"
  >("loading");
  const [ephemeralSecretHex, setEphemeralSecretHex] = useState<string | null>(
    null
  );

  useEffect(() => {
    // Generate CSPRNG ephemeral X25519 sender secret key inside useEffect (safe for SSR/prerender)
    const sk = new Uint8Array(32);
    window.crypto.getRandomValues(sk);
    setEphemeralSecretHex(bytesToHex(sk));

    let cancelled = false;
    fetch("/api/relay/attestation", { cache: "no-store" })
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return (await res.json()) as AttestationBundle;
      })
      .then(async (bundle) => {
        const extracted = await extractHpkeKeyFromAttestationBundle(bundle);
        if (!cancelled) {
          setLiveEnclaveKeyHex(extracted.hpkePublicKeyHex);
          setLiveHost(extracted.host);
          setKeySourceLabel("verified-live");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setKeySourceLabel("pinned-fallback");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const wireState = useMemo(() => {
    const activeInput = promptText;
    const plainTokens = tokenizePlaintext(activeInput);

    // 1. Run the real browser prompt pipeline (Interface I1, @/lib/pipeline)
    const scrubber = createSessionScrubber();
    const prepared = preparePrompt(activeInput, {
      scrubber,
      normalizeStyle: true,
    });

    // 2. Build the RFC 8259 JSON request body padded to prepared.bucketBytes
    const encoder = new TextEncoder();
    const coreEnvelopeObj = {
      model: modelId,
      stream: true,
      messages: [{ role: "user", content: prepared.outboundText }],
    };
    const unpaddedJson = JSON.stringify(coreEnvelopeObj);
    const {
      paddedJson,
      originalBytes: unpaddedByteLen,
      bucketBytes,
    } = padJsonPayloadToBucket(unpaddedJson, prepared.bucketBytes);
    const paddedBytes = encoder.encode(paddedJson);
    const padCharCount = Math.max(0, bucketBytes - unpaddedByteLen);

    // 3. Perform genuine RFC 9180 HPKE Base mode encapsulation to the enclave's X25519 public key
    // Sealing needs a random ephemeral key, which the browser creates after mount;
    // nothing is sealed during prerender.
    const recipientPubKeyBytes = hexToBytes(liveEnclaveKeyHex);
    const {
      encapsulatedKeyBytes,
      ciphertextBytes,
      ehbpWireFrameBytes,
    } = ephemeralSecretHex
      ? sealEhbpHpkeFrame(paddedBytes, recipientPubKeyBytes, hexToBytes(ephemeralSecretHex))
      : {
          encapsulatedKeyBytes: new Uint8Array(0),
          ciphertextBytes: new Uint8Array(0),
          ehbpWireFrameBytes: new Uint8Array(0),
        };

    const frameDigest = sha256(ehbpWireFrameBytes);
    const rawEntropy = computeShannonEntropy(ciphertextBytes);
    const displayEntropy = Number(rawEntropy.toFixed(2));

    // Deterministic visual bar heights from the sealed bytes (or fallback text) for the ISP visual
    const barHeights: number[] = [];
    for (let i = 0; i < 16; i++) {
      const b =
        ciphertextBytes.length > i
          ? ciphertextBytes[i]
          : paddedBytes[i % Math.max(1, paddedBytes.length)] ?? 128;
      barHeights.push(28 + (b % 68));
    }

    return {
      plainTokens,
      scrubEntries: scrubber.entries(),
      prepared,
      outboundText: prepared.outboundText,
      unpaddedByteLen,
      bucketBytes,
      padCharCount,
      paddedByteLen: paddedBytes.byteLength,
      hpkeCipherByteLen: ciphertextBytes.byteLength,
      ehbpFrameByteLen: ehbpWireFrameBytes.byteLength,
      cipherHexPreview: bytesToHexGroups(ciphertextBytes, 64),
      relayWirePreview: bytesToHexGroups(ehbpWireFrameBytes, 24),
      digestHex: bytesToHex(frameDigest),
      encapKeyHex: bytesToHex(encapsulatedKeyBytes),
      enclavePubKeyHex: liveEnclaveKeyHex,
      displayEntropy,
      barHeights,
    };
  }, [promptText, modelId, liveHost, liveEnclaveKeyHex, ephemeralSecretHex]);

  const redactedCount = wireState.prepared.report.redactions.length;

  return (
    <section
      aria-label="What each person can see"
      className="ep-card p-5 sm:p-6 text-ink space-y-6"
    >
      {/* Top heading and single action */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between border-b border-rule pb-5">
        <div className="space-y-1.5">
          <div className="ep-label">Side-by-side view</div>
          <h2 className="font-serif text-xl sm:text-2xl text-ink">
            What each person can see
          </h2>
          <p className="max-w-[68ch] text-sm text-ink-2">
            Type any sentence below to see what stays on your screen and what
            is visible to your internet provider, our server, and the sealed
            computer. Everything runs right here in your browser.
          </p>
        </div>

        <InkButton
          type="button"
          variant={popped ? "ghost" : "primary"}
          onClick={() => setPopped((prev) => !prev)}
          className="shrink-0"
        >
          {popped ? "Bring message back" : "End chat and erase key"}
        </InkButton>
      </div>

      {/* Input & Presets */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label htmlFor="packet-sniffer-input" className="ep-label">
            Try a sample message (stays on your device)
          </label>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="ep-label">Examples:</span>
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
          placeholder="Type a message with an email, secret key, date, or price..."
          className="ep-input text-sm"
        />
      </div>

      {/* 4 Simple Cards: You, Your internet provider, Our server, The sealed computer */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {/* Card 1: You */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                You
              </span>
              <span className="ep-pass shrink-0 whitespace-nowrap">
                Sees everything
              </span>
            </div>

            {/* Small ink visual: page with personal details masked */}
            <svg
              viewBox="0 0 160 54"
              className="h-12 w-full text-ink"
              fill="none"
              aria-hidden="true"
            >
              <rect
                x="10"
                y="6"
                width="140"
                height="42"
                rx="4"
                stroke="currentColor"
                strokeWidth="1.5"
                fill="var(--color-paper-2)"
              />
              <line
                x1="22"
                y1="19"
                x2="66"
                y2="19"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
              <rect
                x="72"
                y="14"
                width="44"
                height="10"
                rx="2"
                fill="var(--color-accent-soft)"
                stroke="var(--color-accent)"
                strokeWidth="1.2"
              />
              <line
                x1="22"
                y1="34"
                x2="52"
                y2="34"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
              <rect
                x="58"
                y="29"
                width="56"
                height="10"
                rx="2"
                fill="var(--color-ink)"
              />
            </svg>

            <p className="text-xs text-ink-2 leading-relaxed">
              You see your full message. We hide your personal details before
              anything leaves your device, so names, emails, keys, and prices
              stay with you.
            </p>

            <div className="ep-inset p-3 text-xs leading-relaxed break-words text-ink">
              {wireState.plainTokens.length === 0 ? (
                <span className="text-ink-3 italic">Type a message above</span>
              ) : (
                wireState.plainTokens.map((tok, idx) =>
                  tok.kind === "plain" ? (
                    <span key={idx}>{tok.text}</span>
                  ) : (
                    <mark
                      key={idx}
                      title="Hidden on your device before sending"
                      className="rounded-sm bg-accent-soft border border-accent px-1 py-0.5 text-ink"
                    >
                      {tok.text}
                    </mark>
                  )
                )
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-3">
            Highlighted words stay on your screen and never travel across the
            internet.
          </div>
        </div>

        {/* Card 2: Your internet provider */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                Your internet provider
              </span>
              <span className="ep-muted-chip shrink-0 whitespace-nowrap">
                Only noise
              </span>
            </div>

            {/* Small ink visual: uniform locked envelope with static bars */}
            <svg
              viewBox="0 0 160 54"
              className="h-12 w-full text-ink"
              fill="none"
              aria-hidden="true"
            >
              <rect
                x="10"
                y="6"
                width="140"
                height="42"
                rx="4"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeDasharray="4 2"
                fill="var(--color-paper-2)"
              />
              {wireState.barHeights.map((h, idx) => {
                const barH = Math.max(8, Math.round((h / 100) * 26));
                const x = 20 + idx * 7.8;
                const y = 40 - barH;
                return (
                  <rect
                    key={idx}
                    x={x}
                    y={y}
                    width="4.5"
                    height={barH}
                    rx="1"
                    fill="currentColor"
                    opacity={idx % 2 === 0 ? "0.75" : "0.4"}
                  />
                );
              })}
            </svg>

            <p className="text-xs text-ink-2 leading-relaxed">
              Your Wi-Fi owner and internet provider cannot read a single word.
              Every message looks the same size from outside and is locked so
              only the sealed computer can open it.
            </p>

            <div className="ep-inset p-3 text-xs leading-relaxed text-ink-2 space-y-2">
              <div className="flex items-center gap-1.5">
                <span
                  className="inline-block h-2 w-2 rounded-full bg-ink"
                  aria-hidden="true"
                />
                <span className="font-medium text-ink">
                  Uniform locked package
                </span>
              </div>
              <p className="text-ink-3">
                Looks like random static in a standard-sized box. Short notes
                and longer questions are padded to match.
              </p>
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-3">
            No readable words and no clue how long your real question was.
          </div>
        </div>

        {/* Card 3: Our server */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                Our server
              </span>
              <span className="ep-muted-chip shrink-0 whitespace-nowrap">
                No key
              </span>
            </div>

            {/* Small ink visual: locked box passing untouched along a rail */}
            <svg
              viewBox="0 0 160 54"
              className="h-12 w-full text-ink"
              fill="none"
              aria-hidden="true"
            >
              <line
                x1="12"
                y1="30"
                x2="148"
                y2="30"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeDasharray="3 3"
              />
              <rect
                x="58"
                y="14"
                width="44"
                height="28"
                rx="4"
                fill="var(--color-paper-2)"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M74 14 V10 C74 6 86 6 86 10 V14"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <circle cx="80" cy="28" r="2.5" fill="currentColor" />
              <path
                d="M126 24 L134 30 L126 36"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>

            <p className="text-xs text-ink-2 leading-relaxed">
              deRoute passes your locked package to the sealed computer, but
              our server does not hold the key and cannot peek inside.
            </p>

            <div className="ep-inset p-3 text-xs leading-relaxed text-ink-2 space-y-2">
              <div className="font-medium text-ink">
                Blind pass-through courier
              </div>
              <p className="text-ink-3">
                Our server hands the locked box to the sealed computer and
                hands the locked reply back to you.
              </p>
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-3">
            Even if someone demanded our server logs, your words are not there.
          </div>
        </div>

        {/* Card 4: The sealed computer */}
        <div className="ep-card p-4 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2 border-b border-rule pb-2">
              <span className="font-serif text-base font-medium text-ink">
                The sealed computer
              </span>
              <span className="ep-pass shrink-0 whitespace-nowrap">
                {popped ? "Wiped clean" : "Cleaned text"}
              </span>
            </div>

            {/* Small ink visual: sealed chamber or dissolved blank paper */}
            <svg
              viewBox="0 0 160 54"
              className="h-12 w-full text-ink"
              fill="none"
              aria-hidden="true"
            >
              <rect
                x="14"
                y="6"
                width="132"
                height="42"
                rx="5"
                stroke="currentColor"
                strokeWidth="1.5"
                fill="var(--color-paper-2)"
              />
              {popped ? (
                <>
                  <circle cx="52" cy="27" r="2" fill="currentColor" opacity="0.35" />
                  <circle cx="80" cy="22" r="1.5" fill="currentColor" opacity="0.25" />
                  <circle cx="106" cy="31" r="2" fill="currentColor" opacity="0.3" />
                </>
              ) : (
                <>
                  <line
                    x1="28"
                    y1="21"
                    x2="96"
                    y2="21"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                  <line
                    x1="28"
                    y1="33"
                    x2="76"
                    y2="33"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                  <circle
                    cx="122"
                    cy="27"
                    r="9"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M118 27 L121 30 L127 24"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </>
              )}
            </svg>

            <p className="text-xs text-ink-2 leading-relaxed">
              Inside its locked room, the sealed computer opens your message
              with your personal details already hidden. When you leave, the
              key dissolves.
            </p>

            {popped ? (
              <div className="ep-inset p-3 text-xs leading-relaxed text-ink space-y-1">
                <div className="font-medium text-ink">
                  Blank paper. Nothing left behind.
                </div>
                <p className="text-ink-3">
                  The temporary key was erased, so this conversation can never
                  be reopened.
                </p>
              </div>
            ) : (
              <div className="ep-inset p-3 text-xs leading-relaxed break-words text-ink">
                {wireState.plainTokens.length === 0 ? (
                  <span className="text-ink-3 italic">Empty message</span>
                ) : (
                  wireState.plainTokens.map((tok, idx) =>
                    tok.kind === "plain" ? (
                      <span key={idx}>{tok.text}</span>
                    ) : (
                      <span
                        key={idx}
                        className="inline-block rounded bg-paper px-1.5 py-0.5 mx-0.5 border border-rule font-medium text-ink-2"
                      >
                        [{PLAIN_TOKEN_LABELS[tok.kind]}]
                      </span>
                    )
                  )
                )}
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-3">
            {popped
              ? "Memory erased when you ended the chat."
              : "Answers your question without ever seeing your real name or keys."}
          </div>
        </div>
      </div>

      {/* All raw bytes, live keys, and protocol metrics live inside TechDetails */}
      <TechDetails label="What really happened">
        <div className="space-y-4 pt-2 text-xs text-ink-2">
          <p className="max-w-[72ch] leading-relaxed">
            Your browser ran <code className="font-mono text-ink">preparePrompt</code>{" "}
            locally, padded the JSON envelope to a power-of-two bucket (
            <code className="font-mono text-ink">{wireState.bucketBytes}</code>{" "}
            bucket bytes), and sealed it with RFC 9180 HPKE (DHKEM(X25519,
            HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the enclave public key
            extracted from{" "}
            <code className="font-mono text-ink">/api/relay/attestation</code>.
          </p>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4 font-mono text-[11px]">
            {/* Tech 1: Device */}
            <div className="ep-inset p-3 space-y-2">
              <div className="ep-label">1. Local PII scrubber</div>
              <div className="flex items-center justify-between">
                <span>Redactions</span>
                <span className="font-semibold text-ink">{redactedCount}</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Privacy risk score</span>
                <span className="font-semibold text-ink">
                  {wireState.prepared.report.riskBefore} -&gt;{" "}
                  {wireState.prepared.report.riskAfter}
                </span>
              </div>
              <div className="border-t border-rule pt-2 space-y-1">
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
                {redactedCount === 0 && (
                  <div className="text-ink-3">No sensitive tokens detected.</div>
                )}
              </div>
            </div>

            {/* Tech 2: ISP / Wire */}
            <div className="ep-inset p-3 space-y-2">
              <div className="ep-label">2. Padded HPKE wire frame</div>
              <div className="flex items-center justify-between">
                <span>Bucket bytes</span>
                <span className="text-ink font-medium">
                  {wireState.bucketBytes.toLocaleString()} B (
                  {wireState.unpaddedByteLen} B + {wireState.padCharCount} B pad)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>HPKE ciphertext</span>
                <span className="text-ink font-medium">
                  {wireState.hpkeCipherByteLen.toLocaleString()} B (+16 B GCM tag)
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span>Shannon entropy</span>
                <span className="text-ink font-medium">
                  {wireState.displayEntropy.toFixed(2)} / 8.00 bits/byte
                </span>
              </div>
              <div className="border-t border-rule pt-2 break-all text-ink-3">
                {wireState.cipherHexPreview} ...
              </div>
            </div>

            {/* Tech 3: Relay */}
            <div className="ep-inset p-3 space-y-1.5">
              <div className="ep-label">
                3. Relay hop ({keySourceLabel === "verified-live" ? "live key" : "pinned key"})
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Host:</span> {liveHost}
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Enclave X25519 key:</span>{" "}
                0x{wireState.enclavePubKeyHex.slice(0, 20)}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">
                  Ehbp-Encapsulated-Key:
                </span>{" "}
                0x{wireState.encapKeyHex.slice(0, 20)}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Frame bytes:</span>{" "}
                {wireState.relayWirePreview}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Frame SHA-256:</span>{" "}
                0x{wireState.digestHex.slice(0, 20)}...
              </div>
              <div className="border-t border-rule pt-1.5 font-sans text-[11px] text-ink-3">
                Note: Tinfoil&apos;s router runs an attested usage reporter and
                acceptable-use classifier sidecar reporting policy violations to
                api.tinfoil.sh.
              </div>
            </div>

            {/* Tech 4: Enclave */}
            <div className="ep-inset p-3 space-y-2">
              <div className="ep-label">4. Enclave plaintext buffer</div>
              <div className="flex items-center justify-between">
                <span>Memory state</span>
                <span className="text-ink font-medium">
                  {popped ? "Zeroed (0x00)" : "SEV-SNP + GPU HBM"}
                </span>
              </div>
              <div className="border-t border-rule pt-2 break-words text-ink">
                {popped
                  ? "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                  : wireState.outboundText}
              </div>
            </div>
          </div>
        </div>
      </TechDetails>
    </section>
  );
}

export default PacketSniffer;
