"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import {
  CONFIDENTIAL_PROVIDERS,
  SPEC_V2_ROADMAP,
  filterProviders,
} from "@/lib/providers/catalog";

const HONEST_LIMITS = [
  {
    title: "Plaintext runs inside attested hardware enclaves (not pure FHE)",
    detail:
      "The launch tier decrypts and runs prompts inside hardware-attested Trusted Execution Environments (TEEs). Pure homomorphic encryption (FHE) and multi-party computation (MPC) cannot reach usable interactive speed for frontier models today, so FHE is a research tier.",
  },
  {
    title: "Tinfoil router and Kimi K3 enclave topology (262,144 token limit)",
    detail:
      "The live Tinfoil router (router-0.tinfoil.sh) attests with AMD SEV-SNP. The Kimi K3 model enclave (kimi-k3-inf14.tinfoil.containers.tinfoil.dev) runs on Intel TDX plus NVIDIA confidential-computing GPUs with a maximum context length of 262,144 tokens, not 1M.",
  },
  {
    title: "Tinfoil safeguards classifier and usage sidecars",
    detail:
      "Tinfoil's router runs a safeguards acceptable-use classifier sidecar (gpt-oss-safeguard-120b with kimi-k3 review) that reports policy violations to https://api.tinfoil.sh, plus a usage reporter.",
  },
  {
    title: "Simulated test nodes (sim-1, sim-2, sim-3)",
    detail:
      "Nodes sim-1, sim-2, and sim-3 are simulated software nodes built to test client verification and failure handling. They are not real hardware enclaves.",
  },
  {
    title: "TEEs are not perfect (physical memory-bus attacks exist)",
    detail:
      "Hardware enclaves reduce trust in the cloud host, but they are not invincible. Physical memory-bus interposers such as TEE.fail can probe deterministic CPU RAM lines, and silicon firmware bugs remain a real risk.",
  },
  {
    title: "Timing and size buckets remain visible",
    detail:
      "Encryption and power-of-two padding hide your text, but the relay and network operator still observe when a request happens and which coarse byte bucket it falls into.",
  },
] as const;

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
    <div className="min-h-screen flex flex-col bg-paper text-ink">
      <SpecimenHeader activePath="/about" rightSlot={<AuthPill />} />

      <main className="mx-auto w-full max-w-5xl flex-1 space-y-12 px-4 py-10 sm:px-6">
        {/* Intro / Why this exists */}
        <section className="space-y-4 border-b border-rule pb-8">
          <div className="ep-label">About dRouter</div>
          <h1 className="ep-display text-3xl sm:text-4xl">
            Why this exists, where it falls short, and who runs confidential hardware today.
          </h1>
          <p className="max-w-[68ch] text-base leading-relaxed text-ink-2">
            Standard AI APIs ask you to trust a privacy policy while reading your prompts in plaintext at the gateway. Pure cryptographic inference (FHE or MPC) would remove hardware trust completely, but non-linear attention layers make it thousands of times too slow for frontier models. dRouter bridges the gap by verifying hardware enclaves in your browser and encrypting requests directly to the enclave key before sending a single word.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <Link href="/" className="ep-btn-accent">
              Open console
            </Link>
            <Link href="/explain" className="ep-btn-ghost">
              How it works
            </Link>
            <Link href="/network" className="ep-btn-ghost">
              View node registry
            </Link>
          </div>
        </section>

        {/* Honest Limits */}
        <section className="space-y-4">
          <div className="space-y-1">
            <div className="ep-label">Limits &amp; Ground Truth</div>
            <h2 className="ep-display text-2xl">What you should know before trusting any enclave</h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Hardware attestation is stronger than a terms-of-service promise, but it has real boundaries. Here are the exact constraints of this system.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {HONEST_LIMITS.map((limit) => (
              <div key={limit.title} className="ep-card p-4 space-y-1.5">
                <h3 className="font-serif text-base font-medium text-ink">
                  {limit.title}
                </h3>
                <p className="text-xs leading-relaxed text-ink-2">
                  {limit.detail}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Provider Directory Table */}
        <section className="space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="space-y-1">
              <div className="ep-label">Provider Directory</div>
              <h2 className="ep-display text-2xl">
                Confidential inference providers ({filteredProviders.length} of {CONFIDENTIAL_PROVIDERS.length})
              </h2>
              <p className="max-w-[68ch] text-sm text-ink-2">
                Checked against each provider&apos;s documentation and live observations from{" "}
                <a
                  href="https://confidentialinference.net"
                  target="_blank"
                  rel="noreferrer"
                  className="ep-link"
                >
                  confidentialinference.net
                </a>
                . Claims that lack end-to-end route or freshness proof are marked unverified.
              </p>
            </div>
          </div>

          {/* Filter bar */}
          <div className="ep-inset p-3.5 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[220px]">
              <label htmlFor="provider-search" className="sr-only">
                Filter providers by model, name, or hardware
              </label>
              <input
                id="provider-search"
                type="text"
                value={modelQuery}
                onChange={(e) => setModelQuery(e.target.value)}
                placeholder="Filter by model (e.g. Kimi, DeepSeek), provider, or hardware..."
                className="ep-input max-w-xs"
              />
              <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-ink-2">
                <input
                  type="checkbox"
                  checked={requireE2ee}
                  onChange={(e) => setRequireE2ee(e.target.checked)}
                  className="h-3.5 w-3.5 accent-ink"
                />
                <span>E2EE / TEE-terminated TLS only</span>
              </label>
              <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-ink-2">
                <input
                  type="checkbox"
                  checked={requirePqc}
                  onChange={(e) => setRequirePqc(e.target.checked)}
                  className="h-3.5 w-3.5 accent-ink"
                />
                <span>Hybrid PQC observed</span>
              </label>
            </div>

            {(modelQuery || requireE2ee || requirePqc) && (
              <button
                type="button"
                onClick={() => {
                  setModelQuery("");
                  setRequireE2ee(false);
                  setRequirePqc(false);
                }}
                className="ep-btn-ghost text-xs py-1 px-2.5"
              >
                Reset filters
              </button>
            )}
          </div>

          {/* Clean Provider Table */}
          <div className="ep-card overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-rule bg-paper-2 text-ink-3 font-mono text-[11px] uppercase">
                  <th className="py-3 px-4">Provider</th>
                  <th className="py-3 px-4">Hardware</th>
                  <th className="py-3 px-4">What is verified</th>
                  <th className="py-3 px-4">Frontier models</th>
                  <th className="py-3 px-4">Links</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule align-top">
                {filteredProviders.map((provider) => (
                  <tr key={provider.id} className="hover:bg-paper-2/50">
                    <td className="py-3.5 px-4 min-w-[160px]">
                      <div className="font-serif text-sm font-medium text-ink">
                        {provider.name}
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-ink-3">
                        From {provider.inputUsdPerM}
                      </div>
                      <div className="mt-1.5">
                        {provider.statusInDrouter === "live-integrated" ? (
                          <span className="ep-pass">Live in dRouter</span>
                        ) : (
                          <span className="ep-muted-chip">
                            {provider.statusInDrouter === "compatible-openai-e2ee"
                              ? "E2EE / TEE TLS"
                              : "Gateway TEE"}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 min-w-[170px]">
                      <div className="font-mono text-xs text-ink">
                        {provider.cpuTee}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-ink-2">
                        {provider.gpuTee}
                      </div>
                      <div className="mt-1 text-[11px] text-ink-3">
                        {provider.pqcHybrid
                          ? "PQC: X25519MLKEM768"
                          : "PQC: Classical TLS"}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 min-w-[240px] max-w-[320px]">
                      <div className="mb-1.5 flex items-center gap-2">
                        {provider.verified ? (
                          <span className="ep-pass">Verified</span>
                        ) : (
                          <span className="ep-muted-chip">Unverified</span>
                        )}
                      </div>
                      <p className="text-xs leading-relaxed text-ink-2">
                        {provider.verificationSummary}
                      </p>
                      <details className="mt-1.5">
                        <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
                          Show details
                        </summary>
                        <p className="mt-1.5 text-[11px] leading-relaxed text-ink-2">
                          {provider.trustNotes}
                        </p>
                      </details>
                    </td>

                    <td className="py-3.5 px-4 min-w-[200px]">
                      <div className="flex flex-wrap gap-1">
                        {provider.frontierModels.map((model) => (
                          <span
                            key={model}
                            className="rounded border border-rule bg-paper-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2"
                          >
                            {model}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 min-w-[120px] font-mono text-[11px]">
                      <div className="flex flex-col gap-1">
                        <a
                          href={provider.url}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-link"
                        >
                          Website
                        </a>
                        <a
                          href={provider.docsUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-link"
                        >
                          Docs
                        </a>
                        <a
                          href={provider.sourceUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="ep-link text-ink-3"
                        >
                          Audit record
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Roadmap */}
        <section className="space-y-4">
          <div className="space-y-1">
            <div className="ep-label">Research Roadmap</div>
            <h2 className="ep-display text-2xl">Where the specification goes next</h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Five planned upgrades that reduce remaining hardware trust assumptions and scale settlement on Circle Arc (contract{" "}
              <code className="font-mono text-xs text-ink">
                0xbc8085c2b6fe6e0db05f169925c0b841828f4481
              </code>{" "}
              on chain 5042002).
            </p>
          </div>

          <div className="space-y-3">
            {SPEC_V2_ROADMAP.map((item) => (
              <div key={item.id} className="ep-card p-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div className="flex items-baseline gap-2.5">
                    <span className="font-mono text-xs text-ink-3">
                      {item.number}
                    </span>
                    <h3 className="font-serif text-lg text-ink">
                      {item.title}
                    </h3>
                  </div>
                  <span className="ep-muted-chip">{item.tierTarget}</span>
                </div>

                <p className="mt-1.5 max-w-[68ch] text-xs leading-relaxed text-ink-2">
                  {item.bottleneckSolved}
                </p>

                <details className="mt-2.5">
                  <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
                    Show details
                  </summary>
                  <div className="mt-2 grid grid-cols-1 gap-3 border-t border-rule pt-2.5 text-xs md:grid-cols-2">
                    <div>
                      <div className="ep-label mb-1">Mechanism</div>
                      <p className="text-ink-2 leading-relaxed">{item.mechanism}</p>
                    </div>
                    <div>
                      <div className="ep-label mb-1">Verification artifact</div>
                      <p className="text-ink-2 leading-relaxed">
                        {item.verificationArtifact}
                      </p>
                    </div>
                  </div>
                </details>
              </div>
            ))}
          </div>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
