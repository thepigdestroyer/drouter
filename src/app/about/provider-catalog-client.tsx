"use client";

import { useMemo, useState } from "react";
import {
  CATALOG_VERIFIED_ON,
  CONFIDENTIAL_PROVIDERS,
  filterProviders,
} from "@/lib/providers/catalog";
import type { ProviderLiveStatus } from "@/lib/providers/live-status";

export function ProviderCatalogClient({
  liveStatusById,
}: {
  liveStatusById: Record<string, ProviderLiveStatus>;
}) {
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
    <section className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="ep-label">Provider Directory</div>
          <h2 className="ep-display text-2xl">
            Confidential inference providers ({filteredProviders.length} of{" "}
            {CONFIDENTIAL_PROVIDERS.length})
          </h2>
          <p className="max-w-[68ch] text-sm text-ink-2">
            Every hardware, model, channel security, and pricing claim includes a{" "}
            <code className="font-mono text-xs text-ink">sourceUrl</code> and{" "}
            <code className="font-mono text-xs text-ink">
              verifiedOn={CATALOG_VERIFIED_ON}
            </code>{" "}
            checked against provider endpoints and{" "}
            <a
              href="https://confidentialinference.net"
              target="_blank"
              rel="noreferrer"
              className="ep-link"
            >
              confidentialinference.net
            </a>
            . Public attestation and model-list endpoints are probed server-side (cached 1 hour). Claims without cryptographic proof are shown as unverified.
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
              <th className="py-3 px-4">Hardware &amp; Channel</th>
              <th className="py-3 px-4">Live Endpoint Status (1h Cache)</th>
              <th className="py-3 px-4">Sourced Claims (Verified {CATALOG_VERIFIED_ON})</th>
              <th className="py-3 px-4">Frontier Models</th>
              <th className="py-3 px-4">Links</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-rule align-top">
            {filteredProviders.map((provider) => {
              const live = liveStatusById[provider.id];
              return (
                <tr key={provider.id} className="hover:bg-paper-2/50">
                  <td className="py-3.5 px-4 min-w-[155px]">
                    <div className="font-serif text-sm font-medium text-ink">
                      {provider.name}
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-ink-3">
                      From {provider.inputUsdPerM}
                    </div>
                    <div className="mt-1 font-mono text-[10px] text-ink-3">
                      Checked {provider.verifiedOn}
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

                  <td className="py-3.5 px-4 min-w-[175px]">
                    <div className="font-mono text-xs text-ink">
                      {provider.cpuTee}
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-ink-2">
                      {provider.gpuTee}
                    </div>
                    <div className="mt-1 text-[11px] text-ink-2">
                      {provider.channelSecurity}
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-ink-3">
                      {provider.pqcHybrid
                        ? "PQC: X25519MLKEM768"
                        : "PQC: Classical TLS"}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 min-w-[205px] max-w-[250px]">
                    {live ? (
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {live.attestationResponds ? (
                            <span className="ep-pass">Attestation responds</span>
                          ) : live.modelsEndpointResponds ? (
                            <span className="ep-pass">Models endpoint responds</span>
                          ) : (
                            <span className="ep-muted-chip">Auth required / offline</span>
                          )}
                        </div>
                        <div className="font-mono text-[11px] text-ink">
                          {live.statusLabel}
                        </div>
                        <p className="text-[11px] leading-relaxed text-ink-2">
                          {live.detail}
                        </p>
                      </div>
                    ) : (
                      <span className="ep-muted-chip">Status unavailable</span>
                    )}
                  </td>

                  <td className="py-3.5 px-4 min-w-[250px] max-w-[330px]">
                    <div className="mb-1.5 flex items-center gap-2">
                      {provider.verified ? (
                        <span className="ep-pass">Verified end-to-end</span>
                      ) : (
                        <span className="ep-muted-chip">Unverified</span>
                      )}
                    </div>
                    <p className="text-xs leading-relaxed text-ink-2">
                      {provider.verificationSummary}
                    </p>
                    <details className="mt-2">
                      <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
                        Inspect 4 sourced claims &amp; audit notes
                      </summary>
                      <div className="mt-2 space-y-2 border-t border-rule pt-2 text-[11px] leading-relaxed text-ink-2">
                        {(
                          [
                            ["Hardware", provider.claims.hardware],
                            ["Models", provider.claims.models],
                            ["Channel", provider.claims.channelSecurity],
                            ["Pricing", provider.claims.pricing],
                          ] as const
                        ).map(([label, claimObj]) => (
                          <div key={label} className="space-y-0.5">
                            <div className="flex items-center justify-between gap-2 font-mono text-[10px]">
                              <span className="font-semibold uppercase text-ink">
                                {label}:{" "}
                                {claimObj.status === "verified"
                                  ? "verified"
                                  : "unverified"}
                              </span>
                              <a
                                href={claimObj.sourceUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="ep-link"
                              >
                                source ({claimObj.verifiedOn})
                              </a>
                            </div>
                            <p>{claimObj.claim}</p>
                          </div>
                        ))}
                        <p className="border-t border-rule pt-1.5 text-ink-3">
                          {provider.trustNotes}
                        </p>
                      </div>
                    </details>
                  </td>

                  <td className="py-3.5 px-4 min-w-[195px]">
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

                  <td className="py-3.5 px-4 min-w-[110px] font-mono text-[11px]">
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
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
