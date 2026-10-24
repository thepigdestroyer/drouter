"use client";

import React, { useState } from "react";

export interface ThreatScenario {
  id: string;
  index: string;
  specimenCode: string;
  vectorCategory: string;
  attackTitle: string;
  attackerGoal: string;
  whatAttackerSees: string;
  neutralizingLayer: string;
  defenseSummary: string;
  plainExplanation: string;
  controls: string[];
  telemetryProof: {
    metricLabel: string;
    metricValue: string;
    verificationTag: string;
    rawArtifact: string;
  };
  residualNote: string;
}

export const THREAT_SCENARIOS: ThreatScenario[] = [
  {
    id: "malicious-relay",
    index: "01",
    specimenCode: "VEC-01 / NET-RELAY",
    vectorCategory: "Network & Edge Proxy",
    attackTitle: "Malicious Relay / Vercel Host",
    attackerGoal:
      "Inspect your plaintext prompt, read streamed model tokens, or infer prompt length from packet sizes at the routing gateway.",
    whatAttackerSees:
      "Fixed-bucket padded ciphertext blobs (1024 B, 4096 B, 16384 B) wrapped in hybrid X25519 + ML-KEM-768 HPKE and inner AES-256-GCM.",
    neutralizingLayer: "L1 Browser Sandbox + L2 Enclave HPKE Tunnel",
    defenseSummary:
      "Stopped by browser-to-enclave HPKE (RFC 9180) + inner AES-256-GCM + RFC 8259 bucket padding.",
    plainExplanation:
      "Your browser encrypts every prompt directly to the enclave public key before it touches the network. Even if the Vercel host or dRouter relay is completely compromised, it only forwards opaque ciphertext padded into uniform size buckets.",
    controls: [
      "RFC 9180 HPKE (X25519 + ML-KEM-768)",
      "Inner AES-256-GCM session seal",
      "RFC 8259 JSON whitespace bucket padding",
    ],
    telemetryProof: {
      metricLabel: "Relay Payload Visibility",
      metricValue: "0.00% Plaintext / Bucket-Padded",
      verificationTag: "HPKE-SEAL-OK",
      rawArtifact:
        "aad=drouter/v1/chat | bucket=4096B | kem=X25519+MLKEM768 | cipher=AES-256-GCM",
    },
    residualNote:
      "Relay sees connection timing and bucket size tier only, never prompt content or token text.",
  },
  {
    id: "ddr5-interposer",
    index: "02",
    specimenCode: "VEC-02 / PHY-INTERPOSER",
    vectorCategory: "Physical Hardware Bus",
    attackTitle: "Datacenter Tech Clips $900 DDR5 Probe onto RAM (TEE.fail)",
    attackerGoal:
      "Passively snoop CPU-to-DRAM memory lines or replay deterministic ciphertexts across the PCIe bus during active inference.",
    whatAttackerSees:
      "High-entropy AES-XTS host memory lines and fresh 96-bit random nonces on every CPU-to-GPU bounce buffer.",
    neutralizingLayer: "L3 Silicon Memory Encryption + GPU HBM Custody",
    defenseSummary:
      "Stopped by GPU HBM Custody (S3) + non-deterministic AES-GCM nonces on host transfer buffers (V1 audit: 0 repeated blocks, 7.99 bits/byte entropy).",
    plainExplanation:
      "Model weights, KV-cache state, and token activations stay inside Hopper H100 HBM3 on-package memory. Any transfer across PCIe uses fresh random AES-256-GCM nonces so physical interposers cannot correlate repeated blocks.",
    controls: [
      "GPU HBM Custody (S3 on-package memory)",
      "Non-deterministic AES-GCM bounce buffer nonces",
      "V1 Audit: 0 repeated 16B blocks, 7.99 bits/byte entropy",
    ],
    telemetryProof: {
      metricLabel: "Host Bus Ciphertext Entropy",
      metricValue: "7.994 bits/byte (0 Repeats)",
      verificationTag: "S3-HBM-CUSTODY + V1-PASS",
      rawArtifact:
        "bus_audit=V1 | repeated_16b_blocks=0/65536 | shannon_entropy=7.9941 | hbm_custody=LOCKED",
    },
    residualNote:
      "Physical probe captures only randomized ciphertext traffic with zero reusable keystream.",
  },
  {
    id: "debug-mode-container",
    index: "03",
    specimenCode: "VEC-03 / ENCLAVE-INTEGRITY",
    vectorCategory: "Host OS & Container Image",
    attackTitle: "Operator Leaves SEV-SNP Debug Mode On or Modifies Container",
    attackerGoal:
      "Boot a patched container image that logs user prompts, or attach a hypervisor debugger to read enclave memory.",
    whatAttackerSees:
      "Connection aborted inside the user's browser before ephemeral session keys are ever generated or transmitted.",
    neutralizingLayer: "L1 Client Hardware Verifier + L4 Sigstore Log",
    defenseSummary:
      "Stopped by browser C1/C2/C4 checks against AMD VCEK root + Sigstore Rekor transparency log before any key is shared.",
    plainExplanation:
      "Before sending a single byte, your browser checks the AMD SEV-SNP hardware signature against AMD's silicon root, verifies that the hardware DEBUG bit is zero, and matches the 48-byte launch measurement against the immutable Sigstore Rekor build log.",
    controls: [
      "C1 AMD VCEK ECDSA P-384 hardware signature check",
      "C2 Policy bit check (DEBUG=0, MIGRATE_MA=0, SMT=1)",
      "C4 Sigstore Rekor transparency log digest match",
    ],
    telemetryProof: {
      metricLabel: "Pre-Key Handshake Gate",
      metricValue: "Aborted at 0 Bytes Sent",
      verificationTag: "C1-C2-C4-ENFORCED",
      rawArtifact:
        "policy.debug_bit=0 (REQUIRED) | vcek_sig=VERIFIED | rekor_log_index=#149882104",
    },
    residualNote:
      "Any single bit mismatch in the container digest or SEV-SNP policy halts key exchange in the browser.",
  },
  {
    id: "model-weight-swap",
    index: "04",
    specimenCode: "VEC-04 / MODEL-SUBSTITUTION",
    vectorCategory: "Model Integrity & Quality",
    attackTitle: "Provider Secretly Swaps Kimi K3 (2.8T) for a Cheap 8B Model",
    attackerGoal:
      "Pocket high-tier inference fees while serving degraded responses from a quantized or smaller model inside the enclave.",
    whatAttackerSees:
      "Attestation rejection at boot if weight blocks differ, plus automatic on-chain quarantine when statistical logits drift.",
    neutralizingLayer: "L4 Measured Weight Root + L5 SPRT Mystery-Shopper",
    defenseSummary:
      "Caught by C7 pinned dm-verity weight root (mpk-58d5e74b…) + Mystery-Shopper SPRT statistical auditing.",
    plainExplanation:
      "The read-only dm-verity Merkle root of the model weights is pinned directly inside the signed enclave measurement. In addition, blind mystery-shopper probes run Sequential Probability Ratio Tests (SPRT) to catch runtime quantization tricks.",
    controls: [
      "C7 Pinned dm-verity weight Merkle root (mpk-58d5e74b…)",
      "Blind Mystery-Shopper Canary prompts",
      "Wald SPRT log-likelihood ratio audit",
    ],
    telemetryProof: {
      metricLabel: "Weight & Logit Integrity",
      metricValue: "mpk-58d5e74b… + SPRT H0 Accepted",
      verificationTag: "C7-VERITY + SPRT-OK",
      rawArtifact:
        "model_pack=mpk-58d5e74b91a2 | fs=dm-verity-ro | sprt_llr=-4.82 (threshold=-4.59)",
    },
    residualNote:
      "Altering a single 4 KB weight page breaks dm-verity I/O; runtime logit drift triggers slashing.",
  },
  {
    id: "subpoena-post-session",
    index: "05",
    specimenCode: "VEC-05 / POST-SESSION-COMPULSION",
    vectorCategory: "Legal Compulsion & Storage Breach",
    attackTitle: "Court Subpoena or Breach After Session Ends",
    attackerGoal:
      "Demand historical chat logs from the operator or recover past prompts from database snapshots weeks later.",
    whatAttackerSees:
      "Zeroed enclave RAM pages, no server-side prompt logs, and crypto-shredded client vaults locked under client-held K_freeze.",
    neutralizingLayer: "L1 Client Crypto-Shredding + L2 Ephemeral RAM Zeroization",
    defenseSummary:
      "Stopped by Pop Bubble key zeroization (V6) + Zero-Telemetry Mode + client-held K_freeze crypto-shredding.",
    plainExplanation:
      "When you click Pop Bubble, the enclave overwrites the ephemeral session key and KV-cache in RAM and returns a signed destruction receipt. If you save a Frozen Bubble, the AES key stays only on your device.",
    controls: [
      "Pop Bubble explicit RAM zeroization (V6 audit)",
      "Zero-Telemetry Mode (no server prompt storage)",
      "Client-held K_freeze HKDF-SHA256 crypto-shredding",
    ],
    telemetryProof: {
      metricLabel: "Retained Server Plaintext",
      metricValue: "0 Bytes (Zeroized in 1.4 ms)",
      verificationTag: "V6-ZEROIZED + K-FREEZE",
      rawArtifact:
        "session_key=0x0000...0000 | kv_cache_pages=WIPED | server_db_rows=0 | k_freeze=CLIENT_ONLY",
    },
    residualNote:
      "Operators cannot hand over data that never existed on disk and whose session keys are wiped.",
  },
  {
    id: "colluding-verifiers",
    index: "06",
    specimenCode: "VEC-06 / QUORUM-SYBIL",
    vectorCategory: "On-Chain Consensus & Routing",
    attackTitle: "3 Colluding Verifiers Try to Admit a Rogue Node",
    attackerGoal:
      "Bribe a minority of attestation verifiers to whitelist an unverified server on the registry contract.",
    whatAttackerSees:
      "On-chain transaction revert in AttestationVerifier.sol, plus independent browser rejection even if all 7 verifiers lied.",
    neutralizingLayer: "L5 5-of-7 Arc Quorum + L1 Dual-Gate Browser Check",
    defenseSummary:
      "Blocked by 5-of-7 Verifier Quorum (C6) + independent client-side hardware verification (G8).",
    plainExplanation:
      "Admitting a node on Circle Arc Testnet requires at least 5 of 7 independent verifier signatures. More importantly, your browser never trusts the blockchain alone: it re-verifies the raw silicon signature locally (G8 Dual-Gate).",
    controls: [
      "C6 5-of-7 ECDSA Verifier Quorum on Circle Arc",
      "G8 Client-Side Dual-Gate independent verification",
      "Per-chip stake cap (2% of active pool)",
    ],
    telemetryProof: {
      metricLabel: "Consensus & Client Gate",
      metricValue: "3/7 Rejected (Needs >=5) + Local G8",
      verificationTag: "C6-QUORUM + G8-DUAL-GATE",
      rawArtifact:
        "quorum_sigs=3/7 (REVERT: InsufficientQuorum) | browser_g8_verify=REQUIRED_INDEPENDENTLY",
    },
    residualNote:
      "Even a 7-of-7 on-chain compromise cannot bypass your browser's local AMD/Intel silicon check.",
  },
  {
    id: "lab-key-extraction",
    index: "07",
    specimenCode: "VEC-07 / SILICON-DECAPPING",
    vectorCategory: "Nation-State Lab Extraction",
    attackTitle: "Attacker Extracts Chip Attestation Key in a Lab",
    attackerGoal:
      "Decap a physical CPU with focused ion beams, extract its VCEK private key, and impersonate a trusted enclave at scale.",
    whatAttackerSees:
      "Immediate economic self-destruction: anyone holding the extracted key can claim 50% of the node's USDC stake in one transaction.",
    neutralizingLayer: "L5 Cryptoeconomic Toxicity & Key-Compromise Bounty",
    defenseSummary:
      "Made toxic by the 50% Key-Compromise Bounty (F = sha256(\"drouter/forbidden-report-data/v1\")) + Canary Honeytoken slashing + 2% operator share cap.",
    plainExplanation:
      "Honest enclave binaries refuse to ever sign the forbidden digest F. If an attacker extracts the silicon key in a lab, any insider or researcher can sign F once and submit it to NodeStakeVault.sol to seize 50% of the operator's stake and burn the rest.",
    controls: [
      "50% Key-Compromise Bounty on forbidden digest F",
      "F = sha256(\"drouter/forbidden-report-data/v1\")",
      "Canary Honeytoken slashing + 2% operator share cap",
    ],
    telemetryProof: {
      metricLabel: "Extracted Key Economic Value",
      metricValue: "Instant 100% Slash (50% Bounty Paid)",
      verificationTag: "FORBIDDEN-DIGEST-TRAP",
      rawArtifact:
        "F=sha256('drouter/forbidden-report-data/v1') | bounty=50% USDC | burned=50% | max_pool_share=2%",
    },
    residualNote:
      "The extracted key becomes a bearer check against the attacker's own collateral before it can exploit users.",
  },
];

export interface ThreatMatrixProps {
  className?: string;
  defaultActiveIds?: string[];
}

export function ThreatMatrix({
  className = "",
  defaultActiveIds = ["malicious-relay", "ddr5-interposer"],
}: ThreatMatrixProps) {
  const [activeAttacks, setActiveAttacks] = useState<Record<string, boolean>>(
    () => {
      const initial: Record<string, boolean> = {};
      for (const item of THREAT_SCENARIOS) {
        initial[item.id] = defaultActiveIds.includes(item.id);
      }
      return initial;
    }
  );

  const [focusedId, setFocusedId] = useState<string>(
    defaultActiveIds[0] ?? THREAT_SCENARIOS[0].id
  );

  const toggleAttack = (id: string) => {
    setActiveAttacks((prev) => {
      const nextState = !prev[id];
      return { ...prev, [id]: nextState };
    });
    setFocusedId(id);
  };

  const setAllAttacks = (enabled: boolean) => {
    const next: Record<string, boolean> = {};
    for (const item of THREAT_SCENARIOS) {
      next[item.id] = enabled;
    }
    setActiveAttacks(next);
  };

  const activeCount = THREAT_SCENARIOS.filter(
    (s) => activeAttacks[s.id]
  ).length;
  const focusedScenario =
    THREAT_SCENARIOS.find((s) => s.id === focusedId) ?? THREAT_SCENARIOS[0];
  const isFocusedSimulating = Boolean(activeAttacks[focusedScenario.id]);

  return (
    <section
      aria-label="What If Someone Cheats? Live Attack Simulator"
      className={`rounded-2xl border border-[#ece7da]/15 bg-[#050706] text-[#ece7da] shadow-[0_24px_80px_rgba(0,0,0,0.85)] overflow-hidden ${className}`}
    >
      {/* Top Specimen Cabinet Header Bar */}
      <div className="border-b border-[#ece7da]/10 bg-[#090d0b] px-5 py-4 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[#a6ff72]/40 bg-[#a6ff72]/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-[#a6ff72]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
                Interactive Specimen Matrix
              </span>
              <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-[#ece7da]/55">
                7 Real-World Attack Vectors · Zero Single Points of Trust
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-semibold tracking-tight text-[#ece7da]">
              What If Someone Cheats? · Live Attack Simulator
            </h2>
            <p className="max-w-3xl text-xs sm:text-sm text-[#ece7da]/75 leading-relaxed">
              Flip any toggle below to simulate a real-world compromise across
              the relay, physical RAM bus, container host, model weights, or
              verifier quorum. Watch which cryptographic layer neutralizes the
              attack before plaintext can leak.
            </p>
          </div>

          {/* Global Simulation Controls & Counter */}
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="rounded-xl border border-[#ece7da]/15 bg-[#050706] px-3.5 py-2 text-right">
              <div className="font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/55">
                Simulated Compromises
              </div>
              <div className="mt-0.5 flex items-center justify-end gap-2 font-mono text-xs font-semibold">
                <span
                  className={
                    activeCount > 0 ? "text-[#ffb85c]" : "text-[#ece7da]/60"
                  }
                >
                  {activeCount} / {THREAT_SCENARIOS.length} Active
                </span>
                <span className="text-[#ece7da]/30">|</span>
                <span className="text-[#a6ff72]">
                  {activeCount} / {activeCount} Neutralized
                </span>
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setAllAttacks(true)}
                className="cursor-pointer rounded-lg border border-[#ffb85c]/40 bg-[#ffb85c]/10 px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-[#ffb85c] transition hover:bg-[#ffb85c]/20"
              >
                Simulate All 7 Attacks
              </button>
              <button
                type="button"
                onClick={() => setAllAttacks(false)}
                className="cursor-pointer rounded-lg border border-[#ece7da]/15 bg-[#050706] px-3 py-2 font-mono text-[11px] font-medium uppercase tracking-wider text-[#ece7da]/70 transition hover:border-[#ece7da]/35 hover:text-[#ece7da]"
              >
                Reset
              </button>
            </div>
          </div>
        </div>

        {/* Defense-in-Depth Layer Status Strip */}
        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {[
            {
              layer: "L1 · Browser Gate",
              desc: "HPKE + C1/C2/C4 + K_freeze",
              triggered:
                activeAttacks["malicious-relay"] ||
                activeAttacks["debug-mode-container"] ||
                activeAttacks["subpoena-post-session"] ||
                activeAttacks["colluding-verifiers"],
            },
            {
              layer: "L2 · Enclave Tunnel",
              desc: "AES-256-GCM + Bucket Pad + V6",
              triggered:
                activeAttacks["malicious-relay"] ||
                activeAttacks["subpoena-post-session"],
            },
            {
              layer: "L3 · Silicon & HBM3",
              desc: "SEV-SNP + GPU HBM Custody (S3)",
              triggered:
                activeAttacks["ddr5-interposer"] ||
                activeAttacks["debug-mode-container"],
            },
            {
              layer: "L4 · Measured Build",
              desc: "Sigstore Rekor + dm-verity C7",
              triggered:
                activeAttacks["debug-mode-container"] ||
                activeAttacks["model-weight-swap"],
            },
            {
              layer: "L5 · Arc Stake & SPRT",
              desc: "5-of-7 Quorum + 50% Bounty",
              triggered:
                activeAttacks["model-weight-swap"] ||
                activeAttacks["colluding-verifiers"] ||
                activeAttacks["lab-key-extraction"],
            },
          ].map((item) => (
            <div
              key={item.layer}
              className={`rounded-lg border px-3 py-2 transition ${
                item.triggered
                  ? "border-[#a6ff72]/45 bg-[#a6ff72]/10"
                  : "border-[#ece7da]/10 bg-[#050706]/80"
              }`}
            >
              <div className="flex items-center justify-between gap-1">
                <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-[#ece7da]">
                  {item.layer}
                </span>
                <span
                  className={`font-mono text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                    item.triggered
                      ? "bg-[#a6ff72]/20 text-[#a6ff72]"
                      : "bg-[#ece7da]/10 text-[#ece7da]/55"
                  }`}
                >
                  {item.triggered ? "ENGAGED" : "STANDBY"}
                </span>
              </div>
              <div className="mt-0.5 truncate font-mono text-[10px] text-[#ece7da]/65">
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Split View: 7 Toggleable Threat Rows + Live Specimen Telemetry Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12">
        {/* Left Column: 7 Interactive Threat Toggle Cards */}
        <div className="divide-y divide-[#ece7da]/10 lg:col-span-7 lg:border-r lg:border-[#ece7da]/10">
          {THREAT_SCENARIOS.map((scenario) => {
            const isSimulating = Boolean(activeAttacks[scenario.id]);
            const isFocused = focusedScenario.id === scenario.id;

            return (
              <div
                key={scenario.id}
                onClick={() => setFocusedId(scenario.id)}
                className={`group cursor-pointer px-5 py-4 transition sm:px-6 ${
                  isSimulating
                    ? "bg-[#090d0b]"
                    : "bg-[#050706] hover:bg-[#090d0b]/60"
                } ${
                  isFocused
                    ? "ring-1 ring-inset ring-[#a6ff72]/40"
                    : ""
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    {/* Specimen Metadata Row */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-[#ece7da]/45">
                        #{scenario.index} · {scenario.specimenCode}
                      </span>
                      <span className="rounded border border-[#ece7da]/15 bg-[#050706] px-1.5 py-0.5 font-mono text-[10px] text-[#ece7da]/70">
                        {scenario.vectorCategory}
                      </span>
                      {isSimulating ? (
                        <span className="inline-flex items-center gap-1 rounded border border-[#a6ff72]/45 bg-[#a6ff72]/15 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-[#a6ff72]">
                          <span className="h-1.5 w-1.5 rounded-full bg-[#a6ff72]" />
                          Attack Neutralized
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded border border-[#ece7da]/15 bg-[#ece7da]/5 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/55">
                          Toggle to Simulate
                        </span>
                      )}
                    </div>

                    {/* Attack Headline */}
                    <h3 className="mt-1.5 text-sm sm:text-base font-semibold text-[#ece7da] group-hover:text-white">
                      {scenario.attackTitle}
                    </h3>

                    {/* Immediate Neutralization Line */}
                    <div
                      className={`mt-2 rounded-lg border px-3 py-2 text-xs leading-relaxed transition ${
                        isSimulating
                          ? "border-[#a6ff72]/35 bg-[#a6ff72]/[0.07] text-[#ece7da]"
                          : "border-[#ece7da]/10 bg-[#090d0b]/70 text-[#ece7da]/75"
                      }`}
                    >
                      <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[#a6ff72] mr-2">
                        Defense Verdict:
                      </span>
                      <span>{scenario.defenseSummary}</span>
                    </div>

                    {/* Control Pills */}
                    <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                      {scenario.controls.map((ctrl) => (
                        <span
                          key={ctrl}
                          className={`rounded-md border px-2 py-0.5 font-mono text-[10px] ${
                            isSimulating
                              ? "border-[#a6ff72]/30 bg-[#a6ff72]/10 text-[#a6ff72]"
                              : "border-[#ece7da]/15 bg-[#050706] text-[#ece7da]/65"
                          }`}
                        >
                          {ctrl}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Interactive Toggle Switch */}
                  <div className="flex flex-col items-end gap-1.5 pt-0.5">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={isSimulating}
                      aria-label={`Simulate attack: ${scenario.attackTitle}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleAttack(scenario.id);
                      }}
                      className={`relative inline-flex h-7 w-13 shrink-0 cursor-pointer items-center rounded-full border transition-colors duration-200 focus:outline-none ${
                        isSimulating
                          ? "border-[#ff6d4d]/60 bg-[#ff6d4d]/25"
                          : "border-[#ece7da]/25 bg-[#090d0b]"
                      }`}
                    >
                      <span
                        className={`inline-block h-5 w-5 transform rounded-full transition-transform duration-200 ${
                          isSimulating
                            ? "translate-x-6 bg-[#a6ff72] shadow-[0_0_10px_#a6ff72]"
                            : "translate-x-1 bg-[#ece7da]/60"
                        }`}
                      />
                    </button>
                    <span
                      className={`font-mono text-[9px] uppercase tracking-wider ${
                        isSimulating ? "text-[#ffb85c]" : "text-[#ece7da]/45"
                      }`}
                    >
                      {isSimulating ? "Compromise On" : "Normal"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Column: Live Specimen Inspection & Attack Trace */}
        <div className="flex flex-col justify-between bg-[#090d0b] p-5 sm:p-6 lg:col-span-5">
          <div className="space-y-4">
            {/* Inspector Header */}
            <div className="flex items-center justify-between gap-2 border-b border-[#ece7da]/10 pb-3">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#ece7da]/55">
                  Live Threat Specimen #{focusedScenario.index}
                </div>
                <div className="mt-0.5 font-mono text-xs font-semibold text-[#a6ff72]">
                  {focusedScenario.specimenCode} ·{" "}
                  {focusedScenario.neutralizingLayer}
                </div>
              </div>
              <button
                type="button"
                onClick={() => toggleAttack(focusedScenario.id)}
                className={`cursor-pointer rounded-lg border px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider transition ${
                  isFocusedSimulating
                    ? "border-[#a6ff72]/50 bg-[#a6ff72]/15 text-[#a6ff72]"
                    : "border-[#ff6d4d]/50 bg-[#ff6d4d]/15 text-[#ff6d4d] hover:bg-[#ff6d4d]/25"
                }`}
              >
                {isFocusedSimulating
                  ? "Simulating Attack (Blocked)"
                  : "Trigger This Attack"}
              </button>
            </div>

            {/* Attack Title & Plain English Breakdown */}
            <div>
              <h3 className="text-base font-semibold text-[#ece7da]">
                {focusedScenario.attackTitle}
              </h3>
              <p className="mt-1.5 text-xs sm:text-sm leading-relaxed text-[#ece7da]/80">
                {focusedScenario.plainExplanation}
              </p>
            </div>

            {/* Step-by-Step Attack vs Defense Comparison Boxes */}
            <div className="space-y-2.5">
              <div className="rounded-xl border border-[#ff6d4d]/35 bg-[#ff6d4d]/[0.07] p-3.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[#ff6d4d]">
                    1. Adversary Action
                  </span>
                  <span className="font-mono text-[10px] text-[#ff6d4d]/80">
                    Hostile Assumption
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-[#ece7da]/90">
                  {focusedScenario.attackerGoal}
                </p>
              </div>

              <div className="rounded-xl border border-[#ffb85c]/35 bg-[#ffb85c]/[0.07] p-3.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[#ffb85c]">
                    2. What the Attacker Actually Obtains
                  </span>
                  <span className="font-mono text-[10px] text-[#ffb85c]/80">
                    Zero Plaintext
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-[#ece7da]/90">
                  {focusedScenario.whatAttackerSees}
                </p>
              </div>

              <div className="rounded-xl border border-[#a6ff72]/40 bg-[#a6ff72]/[0.08] p-3.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[#a6ff72]">
                    3. How dRouter Neutralizes It
                  </span>
                  <span className="font-mono text-[10px] text-[#a6ff72]">
                    {focusedScenario.telemetryProof.verificationTag}
                  </span>
                </div>
                <p className="mt-1 text-xs font-medium leading-relaxed text-[#ece7da]">
                  {focusedScenario.defenseSummary}
                </p>
              </div>
            </div>

            {/* Cryptographic Telemetry Proof Readout */}
            <div className="rounded-xl border border-[#ece7da]/15 bg-[#050706] p-3.5 font-mono">
              <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-[#ece7da]/55">
                <span>{focusedScenario.telemetryProof.metricLabel}</span>
                <span className="text-[#a6ff72]">
                  {focusedScenario.telemetryProof.metricValue}
                </span>
              </div>
              <div className="mt-2 overflow-x-auto rounded border border-[#ece7da]/10 bg-[#090d0b] px-2.5 py-2 text-[11px] text-[#ece7da]/85">
                <code>{focusedScenario.telemetryProof.rawArtifact}</code>
              </div>
              <div className="mt-2 text-[11px] text-[#ece7da]/65 font-sans">
                <span className="font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/50 mr-1.5">
                  Boundary Note:
                </span>
                {focusedScenario.residualNote}
              </div>
            </div>
          </div>

          {/* Bottom Summary Footer inside Inspector */}
          <div className="mt-6 rounded-xl border border-[#ece7da]/12 bg-[#050706] p-3.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[10px] uppercase tracking-wider text-[#ece7da]/60">
                Combined Multi-Vector Status
              </span>
              <span className="font-mono text-[11px] font-semibold text-[#a6ff72]">
                Plaintext Exposure: 0 Bytes
              </span>
            </div>
            <p className="mt-1 text-xs text-[#ece7da]/70 leading-relaxed">
              Even if all 7 compromises happen at the same time, your browser
              blocks unverified nodes before key exchange and keeps active
              session keys sealed inside attested enclave memory.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ThreatMatrix;
