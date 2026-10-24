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
    specimenCode: "NET-RELAY",
    vectorCategory: "Network and proxy",
    attackTitle: "The web host or relay tries to read your prompt",
    attackerGoal:
      "Read your plaintext prompt, inspect streamed tokens, or guess prompt length from packet sizes at the gateway.",
    whatAttackerSees:
      "Fixed-bucket padded ciphertext blobs (4,096 B multiples) encrypted to the enclave public key.",
    neutralizingLayer: "Browser local scrubbing + HPKE tunnel",
    defenseSummary:
      "Your browser scrubs identifiers locally and encrypts the padded request directly to the enclave key.",
    plainExplanation:
      "Your browser strips sensitive tokens and encrypts every prompt before it leaves your device. Even if our Vercel host is compromised, it only forwards padded ciphertext.",
    controls: [
      "RFC 9180 HPKE encryption",
      "Local PII and secret scrubbing",
      "4,096-byte bucket padding",
    ],
    telemetryProof: {
      metricLabel: "Relay payload visibility",
      metricValue: "0 bytes plaintext (bucket-padded)",
      verificationTag: "HPKE-SEAL-OK",
      rawArtifact:
        "aad=drouter/v1/chat | bucket=4096B | cipher=AES-256-GCM",
    },
    residualNote:
      "The relay sees connection timing and bucket size tier only, never prompt text.",
  },
  {
    id: "ddr5-interposer",
    index: "02",
    specimenCode: "PHY-INTERPOSER",
    vectorCategory: "Physical hardware bus",
    attackTitle: "A technician clips a hardware probe onto server RAM",
    attackerGoal:
      "Snoop CPU-to-DRAM memory lines or replay deterministic ciphertexts across the PCIe bus during inference.",
    whatAttackerSees:
      "Encrypted host memory lines and fresh random nonces on every CPU-to-GPU bounce buffer.",
    neutralizingLayer: "CPU memory encryption + GPU HBM custody",
    defenseSummary:
      "Active model weights and KV caches stay in GPU HBM, and host transfer buffers use fresh random AES-GCM nonces.",
    plainExplanation:
      "AMD SEV-SNP and Intel TDX encrypt host RAM in silicon, while NVIDIA confidential computing keeps active weights in on-package GPU memory and encrypts PCIe transfers with fresh nonces.",
    controls: [
      "AMD SEV-SNP / Intel TDX memory encryption",
      "NVIDIA GPU HBM custody",
      "Fresh random nonces on bounce buffers",
    ],
    telemetryProof: {
      metricLabel: "Host bus ciphertext entropy",
      metricValue: "7.99 bits/byte (0 repeated 16B blocks)",
      verificationTag: "V1-BUS-AUDIT-PASS",
      rawArtifact:
        "bus_audit=V1 | repeated_16b_blocks=0 | shannon_entropy=7.99",
    },
    residualNote:
      "A physical RAM probe captures only randomized ciphertext with no repeated blocks.",
  },
  {
    id: "debug-mode-container",
    index: "03",
    specimenCode: "ENCLAVE-INTEGRITY",
    vectorCategory: "Host OS and container image",
    attackTitle: "An operator enables debug mode or runs a modified container",
    attackerGoal:
      "Boot a modified container image that logs user prompts, or attach a debugger to read enclave memory.",
    whatAttackerSees:
      "The client aborts the connection before generating or sending any session key.",
    neutralizingLayer: "Hardware quote check + Sigstore Rekor log",
    defenseSummary:
      "We verify the hardware signature, confirm the debug bit is off, and match the build digest against Sigstore Rekor.",
    plainExplanation:
      "Before sending your prompt, the verifier checks the AMD SEV-SNP or Intel TDX hardware quote against the vendor root, confirms debug mode is disabled, and matches the launch measurement against the public Sigstore Rekor build log.",
    controls: [
      "Vendor silicon root signature check",
      "Guest policy check (debug disabled)",
      "Sigstore Rekor transparency log match",
    ],
    telemetryProof: {
      metricLabel: "Pre-key handshake gate",
      metricValue: "Aborted at 0 bytes sent on mismatch",
      verificationTag: "QUOTE-AND-REKOR-OK",
      rawArtifact:
        "policy.debug=0 | hardware_sig=VERIFIED | rekor_log=MATCHED",
    },
    residualNote:
      "Any mismatch in the container digest or hardware policy stops key exchange.",
  },
  {
    id: "model-weight-swap",
    index: "04",
    specimenCode: "MODEL-SUBSTITUTION",
    vectorCategory: "Model integrity",
    attackTitle: "A provider swaps a large model for a cheaper smaller model",
    attackerGoal:
      "Charge for a frontier model while serving answers from a smaller or heavily quantized model.",
    whatAttackerSees:
      "Boot measurement mismatch if the container image changes, plus statistical canary failure under audit.",
    neutralizingLayer: "Measured container digest + canary prompts",
    defenseSummary:
      "The model serving container is pinned in the attestation measurement, and canary prompts test response quality.",
    plainExplanation:
      "The enclave measurement pins the container image and model configuration, and simulated mystery-shopper probes check for statistical drift.",
    controls: [
      "Measured container rootfs digest",
      "Simulated mystery-shopper canary probes",
      "Sequential probability ratio check",
    ],
    telemetryProof: {
      metricLabel: "Model image and canary check",
      metricValue: "Measurement matched + canary accepted",
      verificationTag: "IMAGE-PINNED",
      rawArtifact:
        "image_digest=PINNED | canary_audit=PASS",
    },
    residualNote:
      "Changing the container image alters the hardware measurement reported at boot.",
  },
  {
    id: "subpoena-post-session",
    index: "05",
    specimenCode: "POST-SESSION-DATA",
    vectorCategory: "Post-session storage",
    attackTitle: "Database breach or compulsion after your session ends",
    attackerGoal:
      "Recover historical prompts from server disks or database snapshots after a session finishes.",
    whatAttackerSees:
      "Wiped session keys and, if you froze a session, only AES-256-GCM ciphertext whose key stays on your device.",
    neutralizingLayer: "Client-held keys + session memory wipe",
    defenseSummary:
      "Popping a bubble wipes ephemeral session keys in RAM, and frozen session blobs store only client-encrypted ciphertext.",
    plainExplanation:
      "dRouter does not log plaintext prompts. When you pop a session bubble, ephemeral keys are zeroed. If you freeze a session to resume later, the decryption key stays in your browser.",
    controls: [
      "Pop bubble session key zeroization",
      "Client-held freeze key (AES-256-GCM)",
      "Server rejects plaintext freeze uploads",
    ],
    telemetryProof: {
      metricLabel: "Retained server plaintext",
      metricValue: "0 bytes stored on dRouter server",
      verificationTag: "CIPHERTEXT-ONLY",
      rawArtifact:
        "session_key=ZEROED | freeze_store=AES_256_GCM_CIPHERTEXT_ONLY",
    },
    residualNote:
      "Note: Tinfoil's upstream router runs an attested acceptable-use classifier sidecar that reports policy violations to api.tinfoil.sh.",
  },
  {
    id: "colluding-verifiers",
    index: "06",
    specimenCode: "QUORUM-SYBIL",
    vectorCategory: "Verifier quorum",
    attackTitle: "A minority of verifiers collude to approve a bad node",
    attackerGoal:
      "Bribe 3 verifiers into signing a routing ticket for an unverified server.",
    whatAttackerSees:
      "Quorum check rejects tickets with fewer than 5 of 7 signatures, and the client still checks the raw hardware quote.",
    neutralizingLayer: "5-of-7 quorum + direct quote verification",
    defenseSummary:
      "Routing tickets require at least 5 of 7 verifier signatures, and the client independently verifies the hardware quote.",
    plainExplanation:
      "Admitting a node to the simulated routing table requires 5 of 7 independent verifier signatures, and direct hardware quote verification provides a second check.",
    controls: [
      "5-of-7 Ed25519 verifier quorum threshold",
      "Independent hardware quote verification",
      "Arc Testnet registry anchor",
    ],
    telemetryProof: {
      metricLabel: "Quorum threshold check",
      metricValue: "3/7 rejected (requires 5/7)",
      verificationTag: "QUORUM-ENFORCED",
      rawArtifact:
        "quorum_sigs=3/7 (REJECTED) | threshold=5/7",
    },
    residualNote:
      "Simulated quorum tickets are verified in our transparency and accountability modules.",
  },
  {
    id: "lab-key-extraction",
    index: "07",
    specimenCode: "KEY-EXTRACTION",
    vectorCategory: "Physical key extraction",
    attackTitle: "An attacker extracts a node signing key in a lab",
    attackerGoal:
      "Extract a node's attestation key to sign fake reports and impersonate an honest enclave.",
    whatAttackerSees:
      "Anyone with the extracted key can sign a forbidden prefix to claim a 50% slash bounty against the node's stake (Simulated).",
    neutralizingLayer: "Forbidden-prefix key bounty (Simulated)",
    defenseSummary:
      "Honest enclaves never sign the forbidden prefix F, so any signature over F proves key extraction and slashes the node.",
    plainExplanation:
      "In our accountability simulation, honest enclaves refuse to sign REPORT_DATA starting with F = sha256('drouter/forbidden-report-data/v1'). Signing F serves as a cryptographic proof of key compromise.",
    controls: [
      "Forbidden report_data prefix F",
      "50% key-compromise bounty simulation",
      "Canary honeytoken commitment simulation",
    ],
    telemetryProof: {
      metricLabel: "Compromised key penalty",
      metricValue: "100% stake slash (50% reporter bounty, Simulated)",
      verificationTag: "BOUNTY-TRAP-SIM",
      rawArtifact:
        "F=sha256('drouter/forbidden-report-data/v1') | slash=100% | mode=SIMULATED",
    },
    residualNote:
      "Slashing and bounty claims are simulated against sim-1, sim-2, and sim-3.",
  },
];

export interface ThreatMatrixProps {
  className?: string;
  defaultActiveIds?: string[];
}

export function ThreatMatrix({
  className = "",
  defaultActiveIds = ["malicious-relay"],
}: ThreatMatrixProps) {
  const [activeAttacks, setActiveAttacks] = useState<Record<string, boolean>>(
    () => {
      const initial: Record<string, boolean> = {};
      for (const item of THREAT_SCENARIOS) {
        initial[item.id] = defaultActiveIds.includes(item.id);
      }
      return initial;
    },
  );

  const toggleAttack = (id: string) => {
    setActiveAttacks((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const setAllAttacks = (enabled: boolean) => {
    const next: Record<string, boolean> = {};
    for (const item of THREAT_SCENARIOS) {
      next[item.id] = enabled;
    }
    setActiveAttacks(next);
  };

  const activeCount = THREAT_SCENARIOS.filter(
    (s) => activeAttacks[s.id],
  ).length;

  return (
    <section
      aria-label="What if someone cheats?"
      className={`ep-card p-5 sm:p-6 text-ink space-y-5 ${className}`}
    >
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between border-b border-rule pb-4">
        <div className="space-y-1">
          <div className="ep-label">Threat scenarios</div>
          <h2 className="font-serif text-xl sm:text-2xl text-ink">
            Seven ways an operator or attacker could try to cheat
          </h2>
          <p className="max-w-[70ch] text-sm text-ink-2">
            Select any scenario below to see what the attacker gets and which
            technical check blocks the leak.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <span className="ep-muted-chip">
            {activeCount} of {THREAT_SCENARIOS.length} selected
          </span>
          <button
            type="button"
            onClick={() => setAllAttacks(true)}
            className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
          >
            Select all
          </button>
          <button
            type="button"
            onClick={() => setAllAttacks(false)}
            className="ep-btn-ghost text-xs py-1.5 px-3 cursor-pointer"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Scenario rows */}
      <div className="divide-y divide-rule">
        {THREAT_SCENARIOS.map((scenario) => {
          const isSimulating = Boolean(activeAttacks[scenario.id]);

          return (
            <div key={scenario.id} className="py-4 first:pt-0 last:pb-0 space-y-3">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="space-y-1 max-w-[70ch]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="ep-label">
                      {scenario.index}. {scenario.vectorCategory}
                    </span>
                    <span className="ep-pass">{scenario.neutralizingLayer}</span>
                  </div>
                  <h3 className="font-serif text-base sm:text-lg font-medium text-ink">
                    {scenario.attackTitle}
                  </h3>
                  <p className="text-sm text-ink-2">
                    {scenario.defenseSummary}
                  </p>
                </div>

                <button
                  type="button"
                  aria-pressed={isSimulating}
                  onClick={() => toggleAttack(scenario.id)}
                  className={
                    isSimulating
                      ? "ep-btn text-xs py-1.5 px-3 shrink-0 self-start cursor-pointer"
                      : "ep-btn-ghost text-xs py-1.5 px-3 shrink-0 self-start cursor-pointer"
                  }
                >
                  {isSimulating ? "Hide breakdown" : "Inspect scenario"}
                </button>
              </div>

              {isSimulating && (
                <div className="ep-inset p-4 space-y-3 text-sm">
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                    <div>
                      <div className="ep-label">Attacker goal</div>
                      <p className="mt-1 text-xs text-ink-2 leading-relaxed">
                        {scenario.attackerGoal}
                      </p>
                    </div>
                    <div>
                      <div className="ep-label">What the attacker gets</div>
                      <p className="mt-1 text-xs text-ink-2 leading-relaxed">
                        {scenario.whatAttackerSees}
                      </p>
                    </div>
                    <div>
                      <div className="ep-label">How it is stopped</div>
                      <p className="mt-1 text-xs text-ink leading-relaxed">
                        {scenario.plainExplanation}
                      </p>
                    </div>
                  </div>

                  <details className="text-xs text-ink-3 border-t border-rule pt-2.5">
                    <summary className="cursor-pointer font-mono text-ink-2 hover:text-ink select-none">
                      Show technical controls and boundary notes
                    </summary>
                    <div className="mt-2 space-y-2 font-mono text-xs text-ink-2">
                      <div>
                        <span className="text-ink font-medium">Controls:</span>{" "}
                        {scenario.controls.join(" | ")}
                      </div>
                      <div>
                        <span className="text-ink font-medium">
                          {scenario.telemetryProof.metricLabel}:
                        </span>{" "}
                        {scenario.telemetryProof.metricValue} (
                        {scenario.telemetryProof.rawArtifact})
                      </div>
                      <div className="font-sans text-ink-3">
                        <span className="font-mono text-ink-2">
                          Boundary note:
                        </span>{" "}
                        {scenario.residualNote}
                      </div>
                    </div>
                  </details>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default ThreatMatrix;
