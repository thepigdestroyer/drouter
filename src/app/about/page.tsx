"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  CONFIDENTIAL_PROVIDERS,
  SPEC_V2_ROADMAP,
  filterProviders,
  type DrouterIntegrationStatus,
} from "@/lib/providers/catalog";

const QUICK_MODEL_FILTERS = [
  { label: "All Models", query: "" },
  { label: "Kimi K3", query: "Kimi" },
  { label: "DeepSeek", query: "DeepSeek" },
  { label: "GLM", query: "GLM" },
  { label: "Llama", query: "Llama" },
  { label: "Qwen", query: "Qwen" },
] as const;

function statusBadge(status: DrouterIntegrationStatus) {
  switch (status) {
    case "live-integrated":
      return {
        label: "LIVE INTEGRATED IN DROUTER",
        bg: "rgba(166, 255, 114, 0.12)",
        border: "rgba(166, 255, 114, 0.45)",
        color: "#a6ff72",
      };
    case "compatible-openai-e2ee":
      return {
        label: "COMPATIBLE E2EE ENCLAVE",
        bg: "rgba(255, 184, 92, 0.12)",
        border: "rgba(255, 184, 92, 0.42)",
        color: "#ffb85c",
      };
    case "gateway-tee-only":
      return {
        label: "GATEWAY TEE ONLY",
        bg: "rgba(236, 231, 218, 0.06)",
        border: "rgba(236, 231, 218, 0.22)",
        color: "#b7b1a3",
      };
  }
}

export default function AboutArchitecturePage() {
  const [modelQuery, setModelQuery] = useState("");
  const [requireE2ee, setRequireE2ee] = useState(false);
  const [requirePqc, setRequirePqc] = useState(false);

  const filteredProviders = useMemo(
    () =>
      filterProviders({
        modelQuery,
        requireE2ee,
        requirePqc,
      }),
    [modelQuery, requireE2ee, requirePqc],
  );

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#050706",
        color: "#ece7da",
      }}
      className="selection:bg-[#a6ff72]/20 selection:text-[#a6ff72]"
    >
      <main className="mx-auto flex max-w-7xl flex-col gap-12 px-4 py-8 md:px-8">
        {/* Top Specimen Header */}
        <header
          style={{ borderColor: "rgba(236, 231, 218, 0.14)" }}
          className="flex flex-wrap items-end justify-between gap-4 border-b pb-6"
        >
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-[#a6ff72]">
              <span>SPECIMEN CABINET // DROUTER ARCHITECTURE &amp; FIELD DIRECTORY</span>
              <span
                style={{
                  borderColor: "rgba(166, 255, 114, 0.35)",
                  backgroundColor: "rgba(166, 255, 114, 0.08)",
                }}
                className="rounded border px-2 py-0.5 text-[10px]"
              >
                REV 2026.10
              </span>
            </div>
            <h1 className="font-serif text-3xl italic tracking-tight text-[#ece7da] md:text-4xl">
              Verifiable Confidential Inference at Frontier Scale
            </h1>
            <p className="max-w-3xl text-sm leading-relaxed text-[#ece7da]/75">
              Why pure cryptographic multiparty schemes hit a physics wall on trillion-parameter
              models, how the four-pillar enclave architecture closes the gap today, and how every
              live confidential provider in 2026 stacks up under attestation inspection.
            </p>
          </div>

          <nav className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <Link
              href="/"
              style={{
                borderColor: "rgba(166, 255, 114, 0.4)",
                backgroundColor: "rgba(166, 255, 114, 0.08)",
                color: "#a6ff72",
              }}
              className="rounded border px-3 py-1.5 transition hover:bg-[#a6ff72]/20"
            >
              ← Live Enclave Console
            </Link>
            <Link
              href="/audit"
              style={{
                borderColor: "rgba(236, 231, 218, 0.2)",
                color: "#ece7da",
              }}
              className="rounded border px-3 py-1.5 transition hover:border-[#ffb85c] hover:text-[#ffb85c]"
            >
              Audit &amp; Quorum Lab
            </Link>
            <Link
              href="/network"
              style={{
                borderColor: "rgba(236, 231, 218, 0.2)",
                color: "#ece7da",
              }}
              className="rounded border px-3 py-1.5 transition hover:border-[#ffb85c] hover:text-[#ffb85c]"
            >
              Arc Network Registry
            </Link>
          </nav>
        </header>

        {/* SECTION 01: WHY WE BUILT DROUTER */}
        <section className="space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="space-y-1">
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#a6ff72]">
                01 · WHY WE BUILT DROUTER
              </span>
              <h2 className="font-serif text-2xl italic text-[#ece7da]">
                From Pure FHE Idealism to the Nested-Enclave GPU Bubble
              </h2>
            </div>
            <span className="font-mono text-xs text-[#ffb85c]">
              2.3B SOFTMAX EXPONENTIALS / TOKEN @ 1M CONTEXT
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(236, 231, 218, 0.14)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#ffb85c]">STAGE I · THE FHE &amp; 3PC WALL</span>
                <span className="text-[#ece7da]/50">MATH VS. SILICON</span>
              </div>
              <h3 className="font-serif text-lg italic text-[#ece7da]">
                Why Pure Cryptography Stalls on 3T Models
              </h3>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                We started with the textbook dream: run frontier inference inside Fully Homomorphic
                Encryption (FHE) or 3-party Multi-Party Computation (3PC) so no hardware vendor ever
                requires trust. Then we modeled a single autoregressive token on a 2.8T-parameter
                MoE model at a 1,000,000-token context window.
              </p>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                Attention over 1M tokens across 128 layers and 18,432 heads demands roughly{" "}
                <span className="font-mono text-[#ffb85c]">2.3 billion softmax exponentials</span>{" "}
                and non-linear RMSNorm divisions per generated token. In FHE, each non-linear gate
                triggers programmable bootstrapping; in 3PC, each layer requires cross-WAN beaver
                triple rounds. Latency balloons from 25 milliseconds per token to over 40 minutes.
              </p>
            </div>

            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(166, 255, 114, 0.28)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#a6ff72]">STAGE II · NESTED-ENCLAVE GPU BUBBLE</span>
                <span className="text-[#a6ff72]">NATIVE HBM SPEED</span>
              </div>
              <h3 className="font-serif text-lg italic text-[#ece7da]">
                Hardware Memory Encryption + VMPL0 Isolation
              </h3>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                To serve real models like <span className="font-mono text-[#ece7da]">Kimi K3</span>,{" "}
                <span className="font-mono text-[#ece7da]">GLM-5.3</span>, and{" "}
                <span className="font-mono text-[#ece7da]">DeepSeek V4.1</span> at interactive
                streaming speeds, weights and KV-caches must live in HBM3e inside an{" "}
                <span className="font-mono text-[#a6ff72]">8x B200 / H200 / H100 CC</span> GPU
                bubble paired with an AMD SEV-SNP or Intel TDX host enclave.
              </p>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                Instead of trusting a cloud operator, the browser encrypts every HTTP payload with
                RFC 9180 HPKE directly to the enclave&apos;s attested public key. An inner VMPL0
                monitor enforces zero disk writes, deterministic HBM zeroization after every turn,
                and strict egress whitelisting.
              </p>
            </div>

            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(236, 231, 218, 0.14)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#ffb85c]">STAGE III · ASHI TIER C HYBRID</span>
                <span className="text-[#ece7da]/50">CRYPTOGRAPHIC DETERRENCE</span>
              </div>
              <h3 className="font-serif text-lg italic text-[#ece7da]">
                Defence-in-Depth When Silicon Alone Is Not Enough
              </h3>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                Hardware enclaves are extraordinarily fast, but physical side channels and supply
                chain bugs are non-zero risks over a multi-year horizon. That is why dRouter wraps
                the hardware bubble in the{" "}
                <span className="font-mono text-[#a6ff72]">ASHI Tier C</span> protocol.
              </p>
              <p className="text-xs leading-relaxed text-[#ece7da]/75">
                Every node posts slashable USDC collateral on Circle Arc, answers indistinguishable
                canary honeytoken probes, requires a 5-of-7 independent verifier quorum before
                joining routing, and exposes a self-liquidating key-compromise bounty if its signing
                key ever leaks outside the enclave.
              </p>
            </div>
          </div>
        </section>

        {/* SECTION 02: THE FOUR-PILLAR ARCHITECTURE */}
        <section className="space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="space-y-1">
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#a6ff72]">
                02 · THE FOUR-PILLAR ARCHITECTURE
              </span>
              <h2 className="font-serif text-2xl italic text-[#ece7da]">
                Encryption, Anonymity, Verification, and Accountability
              </h2>
            </div>
            <span className="font-mono text-xs text-[#ece7da]/60">
              END-TO-END PROTOCOL INVARIANTS (SPEC §1 TO §8)
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {/* Pillar 1 */}
            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(166, 255, 114, 0.25)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase tracking-wider text-[#a6ff72]">
                  PILLAR I · ENCRYPTION
                </span>
                <span className="rounded border border-[#a6ff72]/30 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                  RFC 9180 HPKE + HBM CUSTODY
                </span>
              </div>
              <h3 className="font-serif text-xl italic text-[#ece7da]">
                Client-to-Enclave HPKE &amp; Zero-Plaintext Freeze
              </h3>
              <ul className="space-y-1.5 text-xs leading-relaxed text-[#ece7da]/80">
                <li>
                  <span className="font-mono text-[#a6ff72]">01.</span> Prompts are sealed in the
                  browser using HPKE Encrypted HTTP Body (EHBP) with hybrid X25519 + ML-KEM-768
                  post-quantum key encapsulation.
                </li>
                <li>
                  <span className="font-mono text-[#a6ff72]">02.</span> Weights and active KV-caches
                  remain inside encrypted CPU RAM and 8x GPU HBM3e arenas governed by deterministic
                  VMPL0 zeroization after each turn.
                </li>
                <li>
                  <span className="font-mono text-[#a6ff72]">03.</span> Multi-turn continuity uses a
                  browser-held <span className="font-mono text-[#ffb85c]">K_freeze</span> AES-256-GCM
                  key so encrypted session blobs can be stored without any server ever possessing the
                  decryption key.
                </li>
              </ul>
            </div>

            {/* Pillar 2 */}
            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(255, 184, 92, 0.25)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase tracking-wider text-[#ffb85c]">
                  PILLAR II · ANONYMITY
                </span>
                <span className="rounded border border-[#ffb85c]/30 bg-[#ffb85c]/10 px-2 py-0.5 font-mono text-[10px] text-[#ffb85c]">
                  BLIND RSA + OBLIVIOUS RELAY
                </span>
              </div>
              <h3 className="font-serif text-xl italic text-[#ece7da]">
                Unlinkable Payments &amp; Metadata Stripping
              </h3>
              <ul className="space-y-1.5 text-xs leading-relaxed text-[#ece7da]/80">
                <li>
                  <span className="font-mono text-[#ffb85c]">01.</span> Oblivious relays strip caller
                  IP addresses, TLS fingerprints, and timing bursts while padding encrypted frames to
                  fixed bucket boundaries.
                </li>
                <li>
                  <span className="font-mono text-[#ffb85c]">02.</span> Inference is paid with
                  Chaumian RSA Blind Credits: the mint signs a blinded token at purchase time and
                  cannot link wallet identity to the unblinded nullifier spent at inference time.
                </li>
                <li>
                  <span className="font-mono text-[#ffb85c]">03.</span> Zero application telemetry:
                  relays record only aggregate byte counters, never prompts, completions, or user
                  identifiers.
                </li>
              </ul>
            </div>

            {/* Pillar 3 */}
            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(166, 255, 114, 0.25)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase tracking-wider text-[#a6ff72]">
                  PILLAR III · VERIFICATION
                </span>
                <span className="rounded border border-[#a6ff72]/30 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-[10px] text-[#a6ff72]">
                  2-HOP TEE + 5-OF-7 QUORUM
                </span>
              </div>
              <h3 className="font-serif text-xl italic text-[#ece7da]">
                Silicon Roots of Trust &amp; Reproducible Log Proofs
              </h3>
              <ul className="space-y-1.5 text-xs leading-relaxed text-[#ece7da]/80">
                <li>
                  <span className="font-mono text-[#a6ff72]">01.</span> Full 2-hop attestation
                  inspects both the AMD SEV-SNP router enclave and the downstream Intel TDX / SEV-SNP
                  model enclave plus all 8 NVIDIA GPU CC SPDM tokens.
                </li>
                <li>
                  <span className="font-mono text-[#a6ff72]">02.</span> Enclave measurements must
                  match reproducible container digests anchored in Sigstore Rekor and the dRouter
                  Merkle Software Transparency Log.
                </li>
                <li>
                  <span className="font-mono text-[#a6ff72]">03.</span> Before a browser dispatches a
                  single byte, it verifies a 5-of-7 independent verifier quorum ticket and binds the
                  enclave&apos;s ephemeral key to the TLS transcript.
                </li>
              </ul>
            </div>

            {/* Pillar 4 */}
            <div
              style={{
                backgroundColor: "#0a0e0c",
                borderColor: "rgba(255, 184, 92, 0.25)",
              }}
              className="rounded-lg border p-5 space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase tracking-wider text-[#ffb85c]">
                  PILLAR IV · ACCOUNTABILITY
                </span>
                <span className="rounded border border-[#ffb85c]/30 bg-[#ffb85c]/10 px-2 py-0.5 font-mono text-[10px] text-[#ffb85c]">
                  CIRCLE ARC SLASHING + BOUNTIES
                </span>
              </div>
              <h3 className="font-serif text-xl italic text-[#ece7da]">
                Economic Skin in the Game &amp; Canary Traps
              </h3>
              <ul className="space-y-1.5 text-xs leading-relaxed text-[#ece7da]/80">
                <li>
                  <span className="font-mono text-[#ffb85c]">01.</span> Every enclave operator locks
                  USDC stake inside the Circle Arc registry contract and undergoes a mandatory
                  canary-only ramp after any restart.
                </li>
                <li>
                  <span className="font-mono text-[#ffb85c]">02.</span> Continuous canary honeytoken
                  sessions inject indistinguishable decoy credentials; any exfiltration triggers
                  deterministic on-chain slashing.
                </li>
                <li>
                  <span className="font-mono text-[#ffb85c]">03.</span> The Forbidden-Prefix
                  Key-Compromise Bounty lets anyone holding a leaked enclave signing key sign a
                  reserved prefix and claim an instant USDC reward on Arc.
                </li>
              </ul>
            </div>
          </div>
        </section>

        {/* SECTION 03: FRONTIER CONFIDENTIAL PROVIDER DIRECTORY */}
        <section className="space-y-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="space-y-1">
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#a6ff72]">
                03 · FRONTIER CONFIDENTIAL PROVIDER DIRECTORY (2026)
              </span>
              <h2 className="font-serif text-2xl italic text-[#ece7da]">
                All 10 Confidential Inference Providers Compared
              </h2>
              <p className="max-w-3xl text-xs text-[#ece7da]/70">
                Sourced from live attestation endpoints and{" "}
                <span className="font-mono text-[#ece7da]">confidentialinference.net</span>. Filter
                by model family, end-to-end enclave encryption vs. gateway termination, or hybrid
                post-quantum support.
              </p>
            </div>
            <div className="font-mono text-xs text-[#a6ff72]">
              SHOWING {filteredProviders.length} OF {CONFIDENTIAL_PROVIDERS.length} PROVIDERS
            </div>
          </div>

          {/* Interactive Filter Controls */}
          <div
            style={{
              backgroundColor: "#0a0e0c",
              borderColor: "rgba(236, 231, 218, 0.16)",
            }}
            className="flex flex-col gap-4 rounded-lg border p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              {/* Quick Model Family Pills */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="mr-1 font-mono text-[11px] uppercase tracking-wider text-[#ece7da]/60">
                  Model Filter:
                </span>
                {QUICK_MODEL_FILTERS.map((item) => {
                  const active =
                    modelQuery.trim().toLowerCase() === item.query.toLowerCase();
                  return (
                    <button
                      key={item.label}
                      type="button"
                      onClick={() => setModelQuery(item.query)}
                      style={{
                        borderColor: active
                          ? "#a6ff72"
                          : "rgba(236, 231, 218, 0.18)",
                        backgroundColor: active
                          ? "rgba(166, 255, 114, 0.14)"
                          : "rgba(236, 231, 218, 0.03)",
                        color: active ? "#a6ff72" : "#ece7da",
                      }}
                      className="rounded border px-2.5 py-1 font-mono text-xs transition hover:border-[#a6ff72]/60"
                    >
                      {item.label}
                    </button>
                  );
                })}
              </div>

              {/* Search Input */}
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={modelQuery}
                  onChange={(e) => setModelQuery(e.target.value)}
                  placeholder="Search model, provider, or TEE..."
                  style={{
                    backgroundColor: "#050706",
                    borderColor: "rgba(236, 231, 218, 0.22)",
                    color: "#ece7da",
                  }}
                  className="w-64 rounded border px-3 py-1.5 font-mono text-xs placeholder:text-[#ece7da]/40 focus:border-[#a6ff72] focus:outline-none"
                />
                {(modelQuery || requireE2ee || requirePqc) && (
                  <button
                    type="button"
                    onClick={() => {
                      setModelQuery("");
                      setRequireE2ee(false);
                      setRequirePqc(false);
                    }}
                    className="font-mono text-xs text-[#ffb85c] underline"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {/* Boolean Checkboxes */}
            <div className="flex flex-wrap items-center gap-6 border-t border-[#ece7da]/10 pt-3 font-mono text-xs">
              <label className="flex cursor-pointer items-center gap-2 text-[#ece7da]/85">
                <input
                  type="checkbox"
                  checked={requireE2ee}
                  onChange={(e) => setRequireE2ee(e.target.checked)}
                  className="accent-[#a6ff72]"
                />
                <span>Require Client-to-Enclave E2EE (exclude Gateway-only TLS)</span>
              </label>

              <label className="flex cursor-pointer items-center gap-2 text-[#ece7da]/85">
                <input
                  type="checkbox"
                  checked={requirePqc}
                  onChange={(e) => setRequirePqc(e.target.checked)}
                  className="accent-[#ffb85c]"
                />
                <span>Require Hybrid PQC Key Encapsulation (X25519 + ML-KEM-768)</span>
              </label>
            </div>
          </div>

          {/* Provider Cards Grid */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {filteredProviders.map((provider, idx) => {
              const badge = statusBadge(provider.statusInDrouter);
              return (
                <article
                  key={provider.id}
                  style={{
                    backgroundColor: "#0a0e0c",
                    borderColor:
                      provider.statusInDrouter === "live-integrated"
                        ? "rgba(166, 255, 114, 0.45)"
                        : "rgba(236, 231, 218, 0.14)",
                  }}
                  className="flex flex-col justify-between rounded-lg border p-5 space-y-4"
                >
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-[#ece7da]/45">
                            #{String(idx + 1).padStart(2, "0")}
                          </span>
                          <h3 className="font-serif text-xl italic text-[#ece7da]">
                            {provider.name}
                          </h3>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[11px] text-[#ece7da]/65">
                          <span>Input: {provider.inputUsdPerM}</span>
                          <span>·</span>
                          <span>{provider.channelSecurity}</span>
                        </div>
                      </div>

                      <span
                        style={{
                          backgroundColor: badge.bg,
                          borderColor: badge.border,
                          color: badge.color,
                        }}
                        className="rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
                      >
                        {badge.label}
                      </span>
                    </div>

                    {/* Hardware & Attestation Matrix */}
                    <div
                      style={{
                        backgroundColor: "#050706",
                        borderColor: "rgba(236, 231, 218, 0.1)",
                      }}
                      className="grid grid-cols-2 gap-2 rounded border p-3 font-mono text-[11px]"
                    >
                      <div>
                        <div className="text-[#ece7da]/45">CPU TEE</div>
                        <div className="text-[#ece7da]">{provider.cpuTee}</div>
                      </div>
                      <div>
                        <div className="text-[#ece7da]/45">GPU TEE</div>
                        <div className="text-[#ece7da]">{provider.gpuTee}</div>
                      </div>
                      <div>
                        <div className="text-[#ece7da]/45">ATTESTATION VERDICT</div>
                        <div className="text-[#a6ff72]">{provider.attestationVerdict}</div>
                      </div>
                      <div>
                        <div className="text-[#ece7da]/45">HYBRID PQC</div>
                        <div
                          className={
                            provider.pqcHybrid ? "text-[#a6ff72]" : "text-[#ece7da]/60"
                          }
                        >
                          {provider.pqcHybrid ? "Enabled (ML-KEM Hybrid)" : "Classical ECDH/TLS"}
                        </div>
                      </div>
                    </div>

                    {/* Frontier Models */}
                    <div className="space-y-1.5">
                      <div className="font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/50">
                        Frontier Models ({provider.frontierModels.length} highlighted)
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {provider.frontierModels.map((model) => (
                          <span
                            key={model}
                            style={{
                              backgroundColor: "rgba(236, 231, 218, 0.05)",
                              borderColor: "rgba(236, 231, 218, 0.16)",
                            }}
                            className="rounded border px-2 py-0.5 font-mono text-[11px] text-[#ece7da]/90"
                          >
                            {model}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Plain-English Trust Notes */}
                    <p className="text-xs leading-relaxed text-[#ece7da]/75">
                      {provider.trustNotes}
                    </p>
                  </div>

                  {/* External Links */}
                  <div className="flex items-center justify-between border-t border-[#ece7da]/10 pt-3 font-mono text-xs">
                    <a
                      href={provider.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[#a6ff72] hover:underline"
                    >
                      Provider Site ↗
                    </a>
                    <a
                      href={provider.docsUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[#ffb85c] hover:underline"
                    >
                      Live Attestation Docs ↗
                    </a>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        {/* SECTION 04: WHERE THE SPEC GOES NEXT (V2 ROADMAP) */}
        <section className="space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div className="space-y-1">
              <span className="font-mono text-xs uppercase tracking-[0.2em] text-[#ffb85c]">
                04 · WHERE THE SPEC GOES NEXT (V2 ROADMAP)
              </span>
              <h2 className="font-serif text-2xl italic text-[#ece7da]">
                Five Engineering Frontiers Beyond Spec v1
              </h2>
            </div>
            <span className="font-mono text-xs text-[#ece7da]/60">
              OPEN RESEARCH &amp; SILICON ROADMAP
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {SPEC_V2_ROADMAP.map((item) => (
              <div
                key={item.id}
                style={{
                  backgroundColor: "#0a0e0c",
                  borderColor: "rgba(236, 231, 218, 0.14)",
                }}
                className="rounded-lg border p-5 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="rounded border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2 py-0.5 font-mono text-xs text-[#a6ff72]">
                      V2.{item.number}
                    </span>
                    <h3 className="font-serif text-xl italic text-[#ece7da]">
                      {item.title}
                    </h3>
                  </div>
                  <span className="font-mono text-xs text-[#ffb85c]">
                    {item.tierTarget}
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-4 pt-1 md:grid-cols-3">
                  <div className="space-y-1">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/50">
                      Bottleneck Solved
                    </div>
                    <p className="text-xs leading-relaxed text-[#ece7da]/80">
                      {item.bottleneckSolved}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[#a6ff72]">
                      Architectural Mechanism
                    </div>
                    <p className="text-xs leading-relaxed text-[#ece7da]/80">
                      {item.mechanism}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[#ffb85c]">
                      Verification Artifact
                    </div>
                    <p className="text-xs leading-relaxed text-[#ece7da]/80">
                      {item.verificationArtifact}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
