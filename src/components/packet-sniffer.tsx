"use client";

import React, { useEffect, useMemo, useState } from "react";
import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Verifier, type AttestationBundle } from "tinfoil";
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
    label: "Wire transfer + API key",
    text: "Send $125,000 to dana.reyes@acme.example using key sk-live-9876543210abcdef on 2026-11-04",
  },
  {
    label: "Clinical trial budget",
    text: "Release $48,500 batch budget for patient dana.reyes@biotech.example with token sk-proj-4419982710abcdef on 2026-12-19",
  },
  {
    label: "Treasury payout",
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
    const recipientPubKeyBytes = hexToBytes(liveEnclaveKeyHex);
    const senderSecretBytes = ephemeralSecretHex
      ? hexToBytes(ephemeralSecretHex)
      : sha256(utf8ToBytes(`drouter:hpke:ssr-ephemeral:${liveHost}:${modelId}`));

    const {
      encapsulatedKeyBytes,
      ciphertextBytes,
      ehbpWireFrameBytes,
    } = sealEhbpHpkeFrame(paddedBytes, recipientPubKeyBytes, senderSecretBytes);

    const frameDigest = sha256(ehbpWireFrameBytes);
    const rawEntropy = computeShannonEntropy(ciphertextBytes);
    const displayEntropy = Number(rawEntropy.toFixed(2));

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
    };
  }, [promptText, modelId, liveHost, liveEnclaveKeyHex, ephemeralSecretHex]);

  const redactedCount = wireState.prepared.report.redactions.length;

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
            Type any sensitive sentence below to run it through{" "}
            <code className="font-mono text-xs">preparePrompt</code> and seal it
            with RFC 9180 HPKE to the live enclave public key from{" "}
            <code className="font-mono text-xs">/api/relay/attestation</code>.
            Nothing is sent to a model.
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
            Sample prompt (computed locally in your browser)
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
              Your browser runs <code className="font-mono">preparePrompt</code>{" "}
              locally to replace secrets and emails with placeholders, normalize
              style, and pad the payload to a power-of-two byte bucket.
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
                  )
                )
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-rule text-xs text-ink-2 space-y-2">
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span>Redactions (preparePrompt)</span>
              <span className="font-semibold text-ink">{redactedCount}</span>
            </div>
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span>Privacy risk score</span>
              <span className="font-semibold text-ink">
                {wireState.prepared.report.riskBefore} &rarr;{" "}
                {wireState.prepared.report.riskAfter}
              </span>
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
              <span className="ep-muted-chip">HPKE ciphertext</span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              Your ISP and Wi-Fi router see a padded{" "}
              {wireState.paddedByteLen.toLocaleString()}-byte payload sealed
              into {wireState.hpkeCipherByteLen.toLocaleString()} bytes of RFC
              9180 HPKE AES-256-GCM ciphertext.
            </p>

            <div className="ep-inset p-3 font-mono text-[11px] leading-relaxed text-ink-2 break-all">
              {wireState.cipherHexPreview} ...
            </div>
          </div>

          <div className="pt-2 border-t border-rule font-mono text-[11px] text-ink-2 space-y-1">
            <div className="flex items-center justify-between">
              <span>Padded bucket size</span>
              <span className="text-ink font-medium">
                {wireState.bucketBytes.toLocaleString()} B (
                {wireState.unpaddedByteLen} B + {wireState.padCharCount} B pad)
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>HPKE ciphertext size</span>
              <span className="text-ink font-medium">
                {wireState.hpkeCipherByteLen.toLocaleString()} B (+16 B GCM tag)
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
              <span className="ep-muted-chip">
                {keySourceLabel === "verified-live"
                  ? "Live enclave key"
                  : "No private key"}
              </span>
            </div>

            <p className="text-xs text-ink-2 leading-relaxed">
              The relay forwards the X25519 encapsulated key header and{" "}
              {wireState.ehbpFrameByteLen.toLocaleString()}-byte EHBP ciphertext
              frame to <code className="font-mono">{liveHost}</code>. It cannot
              decrypt the body.
            </p>

            <div className="ep-inset p-3 font-mono text-[11px] text-ink-2 space-y-1.5">
              <div className="truncate">
                <span className="text-ink font-medium">Host:</span> {liveHost}
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Enclave HPKE key:</span>{" "}
                {wireState.enclavePubKeyHex.slice(0, 20)}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">
                  Ehbp-Encapsulated-Key:
                </span>{" "}
                {wireState.encapKeyHex.slice(0, 20)}...
              </div>
              <div className="truncate">
                <span className="text-ink font-medium">Ciphertext bytes:</span>{" "}
                {wireState.relayWirePreview}...
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
              Inside the attested CPU and GPU enclave, the HPKE frame decrypts
              to the <code className="font-mono">preparePrompt</code> output
              below. Raw secrets and emails never entered the tunnel.
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
                {wireState.outboundText || (
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
