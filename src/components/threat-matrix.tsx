"use client";

import React, { useState } from "react";
import { TechDetails } from "@/components/ink/tech-details";

export interface ThreatDefenseTestRef {
  filePath: string;
  testName: string;
  githubUrl: string;
  codePath?: string;
  codeUrl?: string;
}

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
  defenseTests: ThreatDefenseTestRef[];
  telemetryProof: {
    metricLabel: string;
    metricValue: string;
    verificationTag: string;
    rawArtifact: string;
  };
  residualNote: string;
}

export interface VillainScenario {
  id: string;
  label: string;
  shortTag: string;
  whatTheyTry: string;
  whatStopsThem: string;
  scenarioIds: string[];
}

export const GITHUB_BLOB_BASE =
  "https://github.com/thepigdestroyer/drouter/blob/main";

export function githubBlobUrl(repoRelativePath: string): string {
  const clean = repoRelativePath.replace(/^\/+/, "");
  return `${GITHUB_BLOB_BASE}/${clean}`;
}

export const THREAT_VILLAINS: VillainScenario[] = [
  {
    id: "nosy-server-owner",
    label: "A nosy server owner",
    shortTag: "Middleman server",
    whatTheyTry:
      "They try to read your message as it passes through their web server or peek inside the computer while it works.",
    whatStopsThem:
      "We hide your personal details before anything leaves your device, make every message look the same size from outside, and lock your words so only the sealed computer can open them.",
    scenarioIds: ["malicious-relay", "debug-mode-container"],
  },
  {
    id: "hacker-with-probe",
    label: "A hacker with a probe",
    shortTag: "Physical wiretap",
    whatTheyTry:
      "They walk into the data center and clip a wire onto the memory chips or try to reboot or change a server without telling anyone.",
    whatStopsThem:
      "The computer scrambles its memory in hardware with a fresh lock on every step, and our hourly monitor checks every sealed computer and writes any unannounced change or failure into the public receipt book.",
    scenarioIds: ["ddr5-interposer", "continuous-enclave-monitor"],
  },
  {
    id: "fake-server",
    label: "A fake server",
    shortTag: "Impostor or cheap brain",
    whatTheyTry:
      "They pretend to be a real sealed computer, swap the smart AI brain for a cheaper one, or try to erase a bad check from the log.",
    whatStopsThem:
      "Your browser runs a seal check before sending a single word, our secret shopper sends surprise test questions to catch any brain swap, and every check is locked into a public receipt book.",
    scenarioIds: ["model-weight-swap", "transparency-log-tampering"],
  },
  {
    id: "leaky-company",
    label: "A leaky company",
    shortTag: "Database leak later",
    whatTheyTry:
      "Someone demands old chat logs from the company database or breaks into storage weeks after you finish talking.",
    whatStopsThem:
      "deRoute never saves your plain messages, wipes the temporary chat key when you finish, and keeps the only unlock key on your own device if you pause and lock a chat for later.",
    scenarioIds: ["subpoena-post-session"],
  },
];

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
    defenseTests: [
      {
        filePath: "tests/privacy/privacy.test.ts",
        testName:
          "pads and unpads payloads across exact bucket boundaries (0B, 1B, 4091B, 4092B, 4093B, 1MB) without leaking length inside the bucket",
        githubUrl: githubBlobUrl("tests/privacy/privacy.test.ts"),
        codePath: "src/lib/privacy/padding.ts",
        codeUrl: githubBlobUrl("src/lib/privacy/padding.ts"),
      },
      {
        filePath: "tests/tinfoil/tinfoil.test.ts",
        testName:
          "padJsonPayloadToBucket pads a 180-byte JSON payload to 4,096 B and a 5,000-byte payload to 8,192 B while preserving JSON.parse equivalence",
        githubUrl: githubBlobUrl("tests/tinfoil/tinfoil.test.ts"),
        codePath: "src/lib/relay.ts",
        codeUrl: githubBlobUrl("src/lib/relay.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "Relay payload framing",
      metricValue: "Padded to 4,096-byte power-of-two buckets before encryption",
      verificationTag: "HPKE-SEAL-OK",
      rawArtifact:
        "aad=drouter/v1/chat | min_bucket=4096B | cipher=AES-256-GCM",
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
    defenseTests: [
      {
        filePath: "tests/tinfoil/tinfoil.test.ts",
        testName:
          "verifyModelEnclaveStatus passes when hosts are verified and GPUs are in CC mode, and fails on unverified hosts, 0 GPUs, or unavailable status",
        githubUrl: githubBlobUrl("tests/tinfoil/tinfoil.test.ts"),
        codePath: "src/lib/tinfoil/deep-inspect.ts",
        codeUrl: githubBlobUrl("src/lib/tinfoil/deep-inspect.ts"),
      },
      {
        filePath: "tests/custody/custody.test.ts",
        testName:
          "overwrites internal key/counter/derived Uint8Array buffers with 0x00 and throws after zeroize()",
        githubUrl: githubBlobUrl("tests/custody/custody.test.ts"),
        codePath: "src/lib/custody/index.ts",
        codeUrl: githubBlobUrl("src/lib/custody/index.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "Confidential GPU flags",
      metricValue: "8x NVIDIA CC GPUs with VLLM_DISABLE_UVA=1 and SYMM_MEM=0",
      verificationTag: "CC-GPU-VERIFIED",
      rawArtifact:
        "VLLM_DISABLE_UVA=1 | VLLM_ALLREDUCE_USE_SYMM_MEM=0 | cc_gpus=8",
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
    defenseTests: [
      {
        filePath: "tests/tinfoil/tinfoil.test.ts",
        testName:
          "decodeSnpReportBytes accurately parses a 1,184-byte binary SNP report",
        githubUrl: githubBlobUrl("tests/tinfoil/tinfoil.test.ts"),
        codePath: "src/lib/tinfoil/deep-inspect.ts",
        codeUrl: githubBlobUrl("src/lib/tinfoil/deep-inspect.ts"),
      },
      {
        filePath: "tests/monitor/monitor.test.ts",
        testName:
          "refuses to forward prompts when enclave attestation verification fails",
        githubUrl: githubBlobUrl("tests/monitor/monitor.test.ts"),
        codePath: "scripts/drouter-proxy.mjs",
        codeUrl: githubBlobUrl("scripts/drouter-proxy.mjs"),
      },
    ],
    telemetryProof: {
      metricLabel: "Pre-key handshake gate",
      metricValue: "Connection aborted before key exchange on quote or digest mismatch",
      verificationTag: "QUOTE-AND-REKOR-OK",
      rawArtifact:
        "policy.debugAllowed=false | hardware_sig=VERIFIED | rekor_log=MATCHED",
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
      "Boot measurement mismatch if the container image changes, plus sequential probability ratio test (SPRT) failure under canary audit.",
    neutralizingLayer: "Measured container digest + SPRT canary audit",
    defenseSummary:
      "The model serving container and weight package are pinned in the attestation measurement, and canary prompts test response quality.",
    plainExplanation:
      "The enclave measurement pins the container image and model weight package (mpk), and mystery-shopper canary probes score exact answers, JSON structure, echoed model ID, and token counts under Wald's SPRT.",
    controls: [
      "Measured container rootfs digest and weight mpk",
      "Mystery-shopper canary probes (5 deterministic signals)",
      "Wald Sequential Probability Ratio Test (SPRT)",
    ],
    defenseTests: [
      {
        filePath: "tests/auditor/auditor.test.ts",
        testName:
          "scores canary responses with exact-answer, JSON format, model echo, token counts, and latency signals",
        githubUrl: githubBlobUrl("tests/auditor/auditor.test.ts"),
        codePath: "src/lib/auditor/canary.ts",
        codeUrl: githubBlobUrl("src/lib/auditor/canary.ts"),
      },
      {
        filePath: "tests/tinfoil/tinfoil.test.ts",
        testName:
          "parseDeploymentConfigYaml extracts weightRepoCommit, weightMpkHash, containerImageDigest, and ccGpuFlagsVerified from Kimi K3 YAML",
        githubUrl: githubBlobUrl("tests/tinfoil/tinfoil.test.ts"),
        codePath: "src/lib/tinfoil/deep-inspect.ts",
        codeUrl: githubBlobUrl("src/lib/tinfoil/deep-inspect.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "Model image and SPRT canary check",
      metricValue: "Pinned container digest + SPRT bounds (p0=0.90, p1=0.45)",
      verificationTag: "IMAGE-PINNED",
      rawArtifact:
        "image_digest=PINNED | sprt_alpha=0.001 | sprt_beta=0.01",
    },
    residualNote:
      "Changing the container image or weight package alters the hardware measurement reported at boot.",
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
      "deRoute does not log plaintext prompts. When you pop a session bubble, ephemeral keys are zeroed. If you freeze a session to resume later, the decryption key stays in your browser.",
    controls: [
      "Pop bubble session key zeroization",
      "Client-held freeze key (AES-256-GCM)",
      "Server rejects plaintext freeze uploads",
    ],
    defenseTests: [
      {
        filePath: "tests/freeze/freeze.test.ts",
        testName:
          "server store rejects any payload containing freezeSecretHex, plaintext messages, prompts, or IP metadata, and caps blob size",
        githubUrl: githubBlobUrl("tests/freeze/freeze.test.ts"),
        codePath: "src/lib/freeze/store.ts",
        codeUrl: githubBlobUrl("src/lib/freeze/store.ts"),
      },
      {
        filePath: "tests/custody/custody.test.ts",
        testName:
          "overwrites internal key/counter/derived Uint8Array buffers with 0x00 and throws after zeroize()",
        githubUrl: githubBlobUrl("tests/custody/custody.test.ts"),
        codePath: "src/lib/custody/index.ts",
        codeUrl: githubBlobUrl("src/lib/custody/index.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "Server freeze store schema",
      metricValue: "Rejects freezeSecretHex and plaintext messages on upload",
      verificationTag: "CIPHERTEXT-ONLY",
      rawArtifact:
        "session_key=ZEROED | freeze_store=AES_256_GCM_CIPHERTEXT_ONLY",
    },
    residualNote:
      "Note: Tinfoil's upstream router runs an attested acceptable-use classifier sidecar that reports policy violations to api.tinfoil.sh.",
  },
  {
    id: "transparency-log-tampering",
    index: "06",
    specimenCode: "LOG-INTEGRITY",
    vectorCategory: "Transparency log and quote verification",
    attackTitle: "An operator tries to forge a seal check or rewrite the receipt book",
    attackerGoal:
      "Serve an unverified server quote or secretly delete a failed verification entry from the transparency log.",
    whatAttackerSees:
      "End-to-end AMD SEV-SNP / Intel TDX signature checks and RFC 6962 Merkle consistency proofs reject any tampered quote or altered log history.",
    neutralizingLayer: "Direct quote check + RFC 6962 Merkle proofs",
    defenseSummary:
      "Clients verify AMD SEV-SNP and Intel TDX quotes directly against hardware roots, and verify RFC 6962 Merkle inclusion and consistency proofs signed by the operator key.",
    plainExplanation:
      "Clients and independent verifiers check the AMD KDS VCEK chain and Intel TDX PCK chain directly, while every verification event is appended to an RFC 6962 SHA-256 Merkle tree whose Signed Tree Head is anchored on Circle Arc Testnet.",
    controls: [
      "Direct AMD SEV-SNP and Intel TDX quote verification",
      "RFC 6962 Merkle inclusion and consistency proofs",
      "Ed25519 Signed Tree Head anchored on Circle Arc Testnet",
    ],
    defenseTests: [
      {
        filePath: "tests/transparency/transparency.test.ts",
        testName:
          "matches official RFC 6962 / Certificate Transparency SHA-256 Merkle tree test vectors",
        githubUrl: githubBlobUrl("tests/transparency/transparency.test.ts"),
        codePath: "src/lib/transparency/log.ts",
        codeUrl: githubBlobUrl("src/lib/transparency/log.ts"),
      },
      {
        filePath: "tests/tinfoil/tinfoil.test.ts",
        testName:
          "cryptographically verifies live router AMD SEV-SNP (Genoa), model AMD SEV-SNP (Turin), and model Intel TDX v4 quotes end-to-end",
        githubUrl: githubBlobUrl("tests/tinfoil/tinfoil.test.ts"),
        codePath: "src/lib/tinfoil/deep-inspect.ts",
        codeUrl: githubBlobUrl("src/lib/tinfoil/deep-inspect.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "RFC 6962 Merkle & hardware quote check",
      metricValue: "SHA-256 inclusion + consistency proofs + Ed25519 STH verified",
      verificationTag: "MERKLE-STH-OK",
      rawArtifact:
        "tree=RFC6962-SHA256 | sth_sig=Ed25519 | chain=AMD-KDS+INTEL-PCK",
    },
    residualNote:
      "Tree heads are signed by the operator Ed25519 key and anchored on Circle Arc Testnet so split views or history rewrites are detectable.",
  },
  {
    id: "continuous-enclave-monitor",
    index: "07",
    specimenCode: "CONTINUOUS-MONITOR",
    vectorCategory: "Continuous monitoring and on-chain failure logging",
    attackTitle: "An enclave fails attestation or changes code without a signed release",
    attackerGoal:
      "Serve requests from an unverified host, tamper with the enclave report, or deploy an unannounced binary change.",
    whatAttackerSees:
      "Continuous hourly monitoring detects any attestation failure or unannounced measurement change, suspends traffic weight, and records the failure evidence hash on Circle Arc Testnet.",
    neutralizingLayer: "Continuous enclave monitor + Arc registry",
    defenseSummary:
      "Continuous monitoring verifies every live Tinfoil enclave against AMD KDS, Intel TDX, Sigstore Rekor, and Hugging Face commits, recording any failure on Circle Arc Testnet.",
    plainExplanation:
      "Every hour, the continuous monitor checks the router and all model enclaves end to end, tracks release upgrades and host restarts, and writes any verification failure with its evidence hash to the Circle Arc Testnet DRouterRegistry contract.",
    controls: [
      "Continuous enclave attestation and provenance check",
      "Release change and unannounced restart ramp control",
      "On-chain failure evidence recording on Circle Arc Testnet",
    ],
    defenseTests: [
      {
        filePath: "tests/accountability/accountability.test.ts",
        testName:
          "records verification failures on Arc with evidence hashes when attestation, weight provenance, or SPRT auditor fails (capped at <= 3 Arc tx)",
        githubUrl: githubBlobUrl("tests/accountability/accountability.test.ts"),
        codePath: "src/lib/accountability/monitor.ts",
        codeUrl: githubBlobUrl("src/lib/accountability/monitor.ts"),
      },
      {
        filePath: "tests/arc/registry.test.ts",
        testName:
          "executes recordVerification and anchorReceipt via mocked viem wallet client",
        githubUrl: githubBlobUrl("tests/arc/registry.test.ts"),
        codePath: "src/lib/arc/registry.ts",
        codeUrl: githubBlobUrl("src/lib/arc/registry.ts"),
      },
    ],
    telemetryProof: {
      metricLabel: "Continuous monitor and on-chain failure log",
      metricValue: "Hourly verification of router + model enclaves with on-chain evidence hashes",
      verificationTag: "MONITOR-AND-ARC-VERIFIED",
      rawArtifact:
        "cron=/api/cron/monitor | contract=DRouterRegistry",
    },
    residualNote:
      "Verification failure evidence hashes and receipt roots are recorded on the Circle Arc Testnet DRouterRegistry contract.",
  },
];

export interface ThreatMatrixProps {
  className?: string;
  defaultActiveIds?: string[];
}

export function ThreatMatrix({ className = "" }: ThreatMatrixProps) {
  const [selectedVillainId, setSelectedVillainId] = useState<string>(
    THREAT_VILLAINS[0].id,
  );

  const selectedVillain =
    THREAT_VILLAINS.find((v) => v.id === selectedVillainId) ??
    THREAT_VILLAINS[0];

  const matchingScenarios = THREAT_SCENARIOS.filter((s) =>
    selectedVillain.scenarioIds.includes(s.id),
  );

  return (
    <section
      aria-label="What if someone cheats?"
      className={`ep-card p-5 sm:p-6 text-ink space-y-6 ${className}`}
    >
      <div className="space-y-1.5 border-b border-rule pb-4">
        <div className="ep-label">Interactive check</div>
        <h2 className="font-serif text-xl sm:text-2xl text-ink">
          What if someone cheats?
        </h2>
        <p className="max-w-[65ch] text-sm text-ink-2">
          Pick a villain below to see what they would try to do and what stops
          them.
        </p>
      </div>

      {/* Villain picker buttons */}
      <div
        role="group"
        aria-label="Pick a villain"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
      >
        {THREAT_VILLAINS.map((villain) => {
          const isSelected = villain.id === selectedVillain.id;
          return (
            <button
              key={villain.id}
              type="button"
              aria-pressed={isSelected}
              onClick={() => setSelectedVillainId(villain.id)}
              className={`text-left p-4 rounded border transition-colors cursor-pointer ${
                isSelected
                  ? "bg-ink text-paper border-ink"
                  : "bg-paper hover:bg-paper-2 text-ink border-rule"
              }`}
            >
              <div
                className={`font-mono text-[11px] uppercase tracking-wider ${
                  isSelected ? "text-paper/80" : "text-ink-3"
                }`}
              >
                {villain.shortTag}
              </div>
              <div className="mt-1 font-serif text-base font-medium">
                {villain.label}
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected villain plain explanation */}
      <div className="ep-inset p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule pb-3">
          <h3 className="font-serif text-lg font-medium text-ink">
            {selectedVillain.label}
          </h3>
          <span className="ep-pass">Stopped before any leak</span>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="ep-card p-4 space-y-1.5">
            <div className="ep-label">What they would try</div>
            <p className="text-sm sm:text-base text-ink leading-relaxed">
              {selectedVillain.whatTheyTry}
            </p>
          </div>
          <div className="ep-card p-4 space-y-1.5">
            <div className="ep-label">What stops them</div>
            <p className="text-sm sm:text-base text-ink leading-relaxed">
              {selectedVillain.whatStopsThem}
            </p>
          </div>
        </div>

        <TechDetails label="Show technical details">
          <div className="space-y-6 pt-2 text-xs">
            <div className="space-y-3">
              <div className="ep-label">
                Technical defenses for {selectedVillain.label.toLowerCase()}
              </div>
              {matchingScenarios.map((scenario) => (
                <div
                  key={scenario.id}
                  className="ep-card p-4 space-y-3 text-ink-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-serif text-sm font-medium text-ink">
                      {scenario.index}. {scenario.attackTitle}
                    </span>
                    <span className="ep-pass">{scenario.neutralizingLayer}</span>
                  </div>
                  <p className="leading-relaxed">{scenario.plainExplanation}</p>
                  <div className="font-mono text-[11px] text-ink-3">
                    Controls: {scenario.controls.join(" | ")}
                  </div>
                  <div className="font-mono text-[11px] text-ink-3">
                    {scenario.telemetryProof.metricLabel}:{" "}
                    {scenario.telemetryProof.metricValue} (
                    {scenario.telemetryProof.rawArtifact})
                  </div>
                  <div className="space-y-1.5 pt-1">
                    <div className="ep-label">Repository tests and files</div>
                    <ul className="space-y-1.5">
                      {scenario.defenseTests.map((t) => (
                        <li
                          key={`${t.filePath}:${t.testName}`}
                          className="flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1 bg-paper-2 p-2 rounded border border-rule font-mono text-[11px]"
                        >
                          <div className="min-w-0">
                            <div className="text-ink">
                              it(&quot;{t.testName}&quot;)
                            </div>
                            <div className="text-ink-3 break-all">
                              {t.filePath}
                              {t.codePath ? ` -> ${t.codePath}` : ""}
                            </div>
                          </div>
                          <div className="flex flex-wrap items-center gap-3 shrink-0">
                            <a
                              href={t.githubUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="ep-link"
                            >
                              {t.filePath} -&gt;
                            </a>
                            {t.codePath && t.codeUrl && (
                              <a
                                href={t.codeUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="ep-link"
                              >
                                {t.codePath} -&gt;
                              </a>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="text-[11px] text-ink-3">
                    Boundary note: {scenario.residualNote}
                  </div>
                </div>
              ))}
            </div>

            <div className="space-y-2 border-t border-rule pt-4">
              <div className="ep-label">
                Complete 7-scenario threat matrix and test index
              </div>
              <div className="space-y-2">
                {THREAT_SCENARIOS.map((scenario) => (
                  <div
                    key={scenario.id}
                    className="ep-card p-3 space-y-1.5 text-[11px]"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium text-ink">
                        {scenario.index}. {scenario.attackTitle} (
                        {scenario.specimenCode})
                      </span>
                      <span className="font-mono text-ink-3">
                        {scenario.neutralizingLayer}
                      </span>
                    </div>
                    <p className="text-ink-2">{scenario.defenseSummary}</p>
                    <div className="flex flex-wrap gap-3 font-mono">
                      {scenario.defenseTests.map((t) => (
                        <a
                          key={`${scenario.id}:${t.filePath}:${t.testName}`}
                          href={t.githubUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="ep-link"
                        >
                          {t.filePath} -&gt;
                        </a>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </TechDetails>
      </div>
    </section>
  );
}

export default ThreatMatrix;
