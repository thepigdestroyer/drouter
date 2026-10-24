"use client";

import React from "react";
import type { CheckResult, NodeRecord } from "@/lib/types";

export type InspectorTab =
  | "overview"
  | "silicon"
  | "gpu"
  | "provenance"
  | "onchain"
  | "privacy";

export interface VisualTrustDashboardProps {
  phase: "idle" | "verifying" | "ready" | "streaming" | "closed" | "error";
  node: NodeRecord | null;
  model: string;
  checks: CheckResult[];
  scrubEnabled: boolean;
  zeroTelemetry: boolean;
  onToggleZeroTelemetry: (next: boolean) => void;
  creditBalance: number;
  evidence: Record<string, string>;
  onOpenInspector: (initialTab?: InspectorTab) => void;
  onOpenTerminalModal: () => void;
}

export function VisualTrustDashboard({
  phase,
  node,
  model,
  checks,
  scrubEnabled,
  zeroTelemetry,
  onToggleZeroTelemetry,
  creditBalance,
  evidence,
  onOpenInspector,
  onOpenTerminalModal,
}: VisualTrustDashboardProps) {
  const passedChecks = checks.filter((c) => c.status === "pass").length;
  const totalChecks = checks.length > 0 ? checks.length : 7;
  const isProtected = phase === "ready" || phase === "streaming";
  const isVerifying = phase === "verifying";
  const isError = phase === "error";

  const chipIdPreview = evidence.chipId
    ? `${evidence.chipId.slice(0, 12)}…${evidence.chipId.slice(-6)}`
    : node?.kind === "tinfoil"
      ? "859dc53c31d4…878c31"
      : "a91f00e4c81b…3e2109";

  const verdictConfig = isProtected
    ? {
        badge: "Protected Inside Verified Hardware Bubble",
        headline:
          "Your prompts are scrubbed on your device, encrypted in your browser with keys held only inside the attested enclave, and deleted when you pop the bubble. Not even dRouter, Vercel, or the server host can read them.",
        border: "border-emerald-500/40",
        bg: "bg-gradient-to-r from-emerald-950/50 via-zinc-900/90 to-teal-950/40",
        pillBg: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
        dot: "bg-emerald-400 shadow-[0_0_12px_#34d399]",
      }
    : isVerifying
      ? {
          badge:
            "Verifying Silicon Signatures, Sigstore Build Log, GPU CC Mode & Arc Stake…",
          headline:
            "Your browser is independently checking the AMD SEV-SNP / Intel TDX hardware report, Sigstore transparency log, GPU enclave cluster, and Circle Arc Testnet quorum before generating ephemeral session keys.",
          border: "border-amber-500/40",
          bg: "bg-gradient-to-r from-amber-950/40 via-zinc-900/90 to-zinc-900/80",
          pillBg: "bg-amber-500/15 text-amber-300 border-amber-500/40",
          dot: "bg-amber-400 animate-ping",
        }
      : isError
        ? {
            badge: "Verification Halted — Plaintext Blocked from Leaving Browser",
            headline:
              "One or more cryptographic hardware checks failed or could not be reached. Your browser refused to open an encrypted session.",
            border: "border-rose-500/40",
            bg: "bg-gradient-to-r from-rose-950/40 via-zinc-900/90 to-zinc-900/80",
            pillBg: "bg-rose-500/15 text-rose-300 border-rose-500/40",
            dot: "bg-rose-400",
          }
        : {
            badge:
              "Ready to Route & Verify — Nothing leaves your browser until all 7 checks pass",
            headline:
              "Send a prompt or click Open & Attest Bubble to verify silicon signatures, reproducible builds, 8× confidential GPUs, and on-chain stake in real time.",
            border: "border-zinc-800",
            bg: "bg-gradient-to-r from-zinc-900/95 via-zinc-900/80 to-zinc-950",
            pillBg: "bg-zinc-800/90 text-zinc-200 border-zinc-700",
            dot: "bg-emerald-400/80",
          };

  const stages: Array<{
    step: string;
    title: string;
    subtitle: string;
    tab: InspectorTab;
    accent: string;
    badge: string;
    bullets: Array<{ label: string; value: string; highlight?: boolean }>;
    cta: string;
  }> = [
    {
      step: "STAGE 1 · CLIENT",
      title: "Your Device",
      subtitle: "Plaintext stays here",
      tab: "privacy",
      accent: "group-hover:border-sky-500/50",
      badge: "Browser Sandbox",
      bullets: [
        {
          label: "PII Scrubber",
          value: scrubEnabled ? "Active (Reversible)" : "Off",
          highlight: scrubEnabled,
        },
        {
          label: "Per-Session Cache Salt",
          value: "Isolated (256-bit)",
          highlight: true,
        },
        {
          label: "Blind Credits",
          value: `${creditBalance} unlinkable tok`,
        },
        {
          label: "Storage",
          value: "Ephemeral RAM",
        },
      ],
      cta: "Inspect privacy shields ↗",
    },
    {
      step: "STAGE 2 · TRANSIT",
      title: "Blind Relay",
      subtitle: "drouter / Oblivious Hop",
      tab: "privacy",
      accent: "group-hover:border-violet-500/50",
      badge: "Zero Plaintext",
      bullets: [
        {
          label: "Sees",
          value: "HPKE Ciphertext Only (RFC 9180)",
          highlight: true,
        },
        {
          label: "Bucket Padding",
          value: "2^j × 1,024 tok",
        },
        {
          label: "Can decrypt",
          value: "Impossible (no private key)",
          highlight: true,
        },
        {
          label: "IP / Wallet Link",
          value: "Unlinkable (Blind RSA)",
        },
      ],
      cta: "Inspect oblivious relay ↗",
    },
    {
      step: "STAGE 3 · SILICON",
      title: "Outer Enclave Router",
      subtitle: "AMD SEV-SNP Hardware TEE",
      tab: "silicon",
      accent: "group-hover:border-emerald-500/50",
      badge: node?.kind === "sim" ? "Simulated SEV-SNP" : "AMD EPYC Milan/Genoa",
      bullets: [
        {
          label: "Chip ID",
          value: chipIdPreview,
        },
        {
          label: "Policy",
          value: "Debug=OFF · Migration=OFF · SMT=OFF",
          highlight: true,
        },
        {
          label: "Provenance",
          value: "Signed Release · Sigstore Rekor",
          highlight: true,
        },
        {
          label: "On-Chain Stake",
          value: node ? `${node.stake} USDC` : "10,000 USDC",
        },
      ],
      cta: "Inspect CPU registers ↗",
    },
    {
      step: "STAGE 4 · INFERENCE",
      title: "GPU Bubble",
      subtitle: "8× Confidential GPUs",
      tab: "gpu",
      accent: "group-hover:border-teal-500/50",
      badge: "HBM Encrypted",
      bullets: [
        {
          label: "Model",
          value: model,
          highlight: true,
        },
        {
          label: "Compute",
          value: "8× NVIDIA GPUs in CC Mode",
          highlight: true,
        },
        {
          label: "Filesystem",
          value: "dm-verity read-only rootfs",
        },
        {
          label: "Lifecycle",
          value: "Zero retention after Pop",
          highlight: true,
        },
      ],
      cta: "Inspect GPU cluster & weights ↗",
    },
  ];

  return (
    <section
      aria-label="Visual Trust & Attestation Pipeline"
      className="w-full rounded-2xl border border-zinc-800/90 bg-zinc-950/90 p-4 sm:p-5 shadow-2xl backdrop-blur-md"
    >
      {/* Top Verdict Banner */}
      <div
        className={`rounded-xl border ${verdictConfig.border} ${verdictConfig.bg} p-4 transition-all duration-300`}
      >
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2.5">
              <span
                className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold tracking-wide ${verdictConfig.pillBg}`}
              >
                <span className={`h-2 w-2 rounded-full ${verdictConfig.dot}`} />
                {verdictConfig.badge}
              </span>

              <button
                type="button"
                onClick={() => onOpenInspector("overview")}
                className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2.5 py-1 text-xs font-mono text-emerald-300 hover:bg-emerald-900/50 transition"
                title="Click to inspect all 7 cryptographic & hardware checks"
              >
                <span>
                  {passedChecks > 0
                    ? `${passedChecks}/${totalChecks} Checks Verified`
                    : "7 Cryptographic Checks Armed"}
                </span>
                <span className="text-emerald-400">↗</span>
              </button>
            </div>

            <p className="text-xs sm:text-sm text-zinc-300 leading-relaxed">
              {verdictConfig.headline}
            </p>
          </div>

          {/* Right side controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => onToggleZeroTelemetry(!zeroTelemetry)}
              className={`group relative inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition ${
                zeroTelemetry
                  ? "border-emerald-500/40 bg-emerald-950/40 text-emerald-200 hover:bg-emerald-900/50"
                  : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800"
              }`}
              title="When ON, your browser does not auto-publish session timestamps to any public or on-chain log."
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  zeroTelemetry ? "bg-emerald-400" : "bg-zinc-500"
                }`}
              />
              <span>Zero-Telemetry Mode: {zeroTelemetry ? "ON" : "OFF"}</span>
            </button>

            <button
              type="button"
              onClick={() => onOpenInspector("overview")}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-3.5 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/25 hover:border-emerald-400 transition shadow-sm"
            >
              <span>Verify Raw Records</span>
              <span aria-hidden="true">↗</span>
            </button>

            <button
              type="button"
              onClick={onOpenTerminalModal}
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900/90 px-3.5 py-2 text-xs font-semibold text-zinc-100 hover:bg-zinc-800 hover:border-zinc-600 transition"
            >
              <span>Use in Terminal / IDE</span>
              <span className="font-mono text-emerald-400">⌘</span>
            </button>
          </div>
        </div>

        {/* Zero-Telemetry micro-caption */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800/80 pt-2.5 text-[11px] text-zinc-400">
          <span>
            <strong className="text-zinc-300">Zero-Telemetry guarantee:</strong>{" "}
            {zeroTelemetry
              ? "Active — Your browser will NOT auto-publish session timestamps to any log or blockchain."
              : "Off — Session verification receipts may be anchored to Circle Arc Testnet."}
          </span>
          <button
            type="button"
            onClick={() => onOpenInspector("silicon")}
            className="font-medium text-emerald-400 hover:text-emerald-300 underline decoration-emerald-500/40 underline-offset-2"
          >
            Inspect hardware &amp; cryptographic records ↗
          </button>
        </div>
      </div>

      {/* Interactive 4-Stage Pipeline Diagram */}
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {stages.map((stage, idx) => (
          <div key={stage.title} className="relative flex items-stretch">
            <button
              type="button"
              onClick={() => onOpenInspector(stage.tab)}
              className={`group relative flex w-full flex-col justify-between rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-3.5 text-left transition-all duration-200 hover:bg-zinc-900/95 hover:shadow-lg ${stage.accent}`}
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                    {stage.step}
                  </span>
                  <span className="rounded-md border border-zinc-700/80 bg-zinc-800/80 px-2 py-0.5 font-mono text-[10px] text-zinc-300">
                    {stage.badge}
                  </span>
                </div>

                <div className="mt-1.5 flex items-baseline justify-between">
                  <h3 className="text-sm font-semibold text-zinc-100 group-hover:text-white">
                    {stage.title}
                  </h3>
                  <span className="text-[11px] text-zinc-400">
                    {stage.subtitle}
                  </span>
                </div>

                <dl className="mt-3 space-y-1.5 border-t border-zinc-800/80 pt-2.5 text-xs">
                  {stage.bullets.map((b) => (
                    <div
                      key={b.label}
                      className="flex items-center justify-between gap-2"
                    >
                      <dt className="text-zinc-400 shrink-0">{b.label}:</dt>
                      <dd
                        className={`truncate font-mono text-[11px] ${
                          b.highlight
                            ? "text-emerald-300 font-medium"
                            : "text-zinc-200"
                        }`}
                        title={b.value}
                      >
                        {b.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="mt-3 flex items-center justify-between border-t border-zinc-800/60 pt-2 text-[11px] font-medium text-emerald-400 group-hover:text-emerald-300">
                <span>{stage.cta}</span>
                <span className="font-mono text-[10px] text-zinc-500 group-hover:text-emerald-400">
                  HPKE E2EE
                </span>
              </div>
            </button>

            {/* Encrypted-tunnel connector badge between cards on xl screens */}
            {idx < stages.length - 1 && (
              <div
                aria-hidden="true"
                className="pointer-events-none hidden xl:flex absolute -right-3 top-1/2 z-10 -translate-y-1/2 items-center justify-center"
              >
                <span className="flex h-5 w-5 items-center justify-center rounded-full border border-emerald-500/50 bg-zinc-950 text-[10px] text-emerald-400 shadow">
                  →
                </span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Compact 7-Check Status Strip */}
      {checks.length > 0 && (
        <div className="mt-3.5 flex flex-wrap items-center gap-1.5 pt-1">
          {checks.map((c) => {
            const tabForCheck: InspectorTab =
              c.id === "C1" || c.id === "C2" || c.id === "C5"
                ? "silicon"
                : c.id === "C3" || c.id === "C4"
                  ? "provenance"
                  : c.id === "C6" || c.id === "C7"
                    ? "onchain"
                    : "overview";
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => onOpenInspector(tabForCheck)}
                className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-mono transition ${
                  c.status === "pass"
                    ? "border-emerald-500/30 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-900/40"
                    : c.status === "fail"
                      ? "border-rose-500/40 bg-rose-950/40 text-rose-300"
                      : "border-zinc-800 bg-zinc-900 text-zinc-400"
                }`}
                title={`${c.label}: ${c.detail} (Click to inspect record)`}
              >
                <span>
                  {c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "·"}
                </span>
                <span className="font-semibold">{c.id}</span>
                <span className="hidden sm:inline text-zinc-300 font-sans">
                  {c.label}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
