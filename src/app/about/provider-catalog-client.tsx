"use client";

import { useMemo, useState } from "react";
import { InkButton } from "@/components/ink/ink-button";
import { TechDetails } from "@/components/ink/tech-details";
import {
  CATALOG_VERIFIED_ON,
  CONFIDENTIAL_PROVIDERS,
  type ConfidentialProvider,
  filterProviders,
} from "@/lib/providers/catalog";
import type { ProviderLiveStatus } from "@/lib/providers/live-status";

function plainProviderName(provider: ConfidentialProvider): string {
  return provider.name
    .replace(" (Bittensor TEE)", " (Bittensor)")
    .replace(" (E2EE Mode)", " (Locked Mode)");
}

function plainModelLabel(rawModel: string): string {
  const idx = rawModel.indexOf(" (");
  return idx > 0 ? rawModel.slice(0, idx) : rawModel;
}

function plainProtectionSummary(provider: ConfidentialProvider): string {
  if (provider.statusInDrouter === "live-integrated") {
    return "Locked on your device so only the sealed computer can open it.";
  }
  if (provider.statusInDrouter === "compatible-openai-e2ee") {
    return "Locked connection aimed at the sealed computer, though backend routing is not fully proved.";
  }
  return "The front-door server can see your message before passing it to the computer.";
}

function plainSealSummary(
  provider: ConfidentialProvider,
  live: ProviderLiveStatus | undefined,
): { badge: string; pass: boolean; liveLine: string } {
  const pass = provider.verified;
  const badge = pass ? "Seal check passed" : "Not fully proved";
  let liveLine = "Status check unavailable";
  if (live) {
    if (live.attestationResponds) {
      liveLine = "Live seal record online";
    } else if (live.modelsEndpointResponds) {
      liveLine = "Live model list online";
    } else {
      liveLine = "Requires account key to check live";
    }
  }
  return { badge, pass, liveLine };
}

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
    <section aria-label="Provider comparison" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="ep-label">Provider comparison</div>
          <h2 className="ep-display text-2xl sm:text-3xl">
            How private AI providers compare ({filteredProviders.length} of{" "}
            {CONFIDENTIAL_PROVIDERS.length})
          </h2>
          <p className="max-w-[68ch] text-sm text-ink-2 leading-relaxed">
            We check {CONFIDENTIAL_PROVIDERS.length} providers that run AI
            inside sealed computers. Only providers whose seal and software
            blueprint can be checked end to end are marked as passed.
          </p>
        </div>
      </div>

      {/* Filter bar */}
      <div className="ep-inset p-3.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[220px]">
          <label htmlFor="provider-search" className="sr-only">
            Search providers by AI brain or name
          </label>
          <input
            id="provider-search"
            type="text"
            value={modelQuery}
            onChange={(e) => setModelQuery(e.target.value)}
            placeholder="Search by AI brain (e.g. Kimi, DeepSeek) or provider..."
            className="ep-input max-w-xs"
          />
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-ink-2">
            <input
              type="checkbox"
              checked={requireE2ee}
              onChange={(e) => setRequireE2ee(e.target.checked)}
              className="h-3.5 w-3.5 accent-ink"
            />
            <span>Locked all the way to the sealed computer</span>
          </label>
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-ink-2">
            <input
              type="checkbox"
              checked={requirePqc}
              onChange={(e) => setRequirePqc(e.target.checked)}
              className="h-3.5 w-3.5 accent-ink"
            />
            <span>Extra future-proof lock</span>
          </label>
        </div>

        {(modelQuery || requireE2ee || requirePqc) && (
          <InkButton
            variant="ghost"
            onClick={() => {
              setModelQuery("");
              setRequireE2ee(false);
              setRequirePqc(false);
            }}
            className="text-xs py-1 px-2.5 cursor-pointer"
          >
            Reset filters
          </InkButton>
        )}
      </div>

      {/* Mobile stacked card list (sm:hidden) */}
      <div className="space-y-3 sm:hidden">
        {filteredProviders.map((provider) => {
          const live = liveStatusById[provider.id];
          const seal = plainSealSummary(provider, live);
          return (
            <div key={provider.id} className="ep-card p-4 space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div className="font-serif text-base font-medium text-ink">
                    {plainProviderName(provider)}
                  </div>
                  <div className="mt-0.5 font-mono text-[11px] text-ink-3">
                    From {provider.inputUsdPerM}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <span className={seal.pass ? "ep-pass" : "ep-muted-chip"}>
                    {seal.badge}
                  </span>
                  {provider.statusInDrouter === "live-integrated" && (
                    <span className="ep-pass">Used in deRoute</span>
                  )}
                </div>
              </div>

              <div className="text-[11px] text-ink-3">{seal.liveLine}</div>

              <div className="space-y-1">
                <div className="ep-label">How your chat is locked</div>
                <p className="text-xs leading-relaxed text-ink-2">
                  {plainProtectionSummary(provider)}
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="ep-label">AI brains</div>
                <div className="flex flex-wrap gap-1">
                  {provider.frontierModels.map((model) => (
                    <span
                      key={model}
                      className="rounded border border-rule bg-paper-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2"
                    >
                      {plainModelLabel(model)}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-4 pt-2 border-t border-rule font-mono text-xs">
                <a
                  href={provider.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ep-link"
                >
                  Website -&gt;
                </a>
                <a
                  href={provider.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ep-link"
                >
                  Docs -&gt;
                </a>
              </div>
            </div>
          );
        })}
      </div>

      {/* Desktop 5-column Provider Table (hidden sm:block) */}
      <div className="hidden sm:block ep-card overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-rule bg-paper-2 text-ink-3 font-mono text-[11px] uppercase">
              <th className="py-3 px-4">Provider</th>
              <th className="py-3 px-4">How your chat is locked</th>
              <th className="py-3 px-4">Seal check</th>
              <th className="py-3 px-4">AI brains</th>
              <th className="py-3 px-4">Links</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-rule align-top">
            {filteredProviders.map((provider) => {
              const live = liveStatusById[provider.id];
              const seal = plainSealSummary(provider, live);
              return (
                <tr key={provider.id} className="hover:bg-paper-2/50">
                  <td className="py-3.5 px-4 min-w-[160px]">
                    <div className="font-serif text-sm font-medium text-ink">
                      {plainProviderName(provider)}
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-ink-3">
                      From {provider.inputUsdPerM}
                    </div>
                    <div className="mt-1.5">
                      {provider.statusInDrouter === "live-integrated" ? (
                        <span className="ep-pass">Used in deRoute</span>
                      ) : (
                        <span className="ep-muted-chip">
                          {provider.statusInDrouter === "compatible-openai-e2ee"
                            ? "Direct lock"
                            : "Unlocked at front door"}
                        </span>
                      )}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 min-w-[200px] max-w-[260px]">
                    <p className="text-xs leading-relaxed text-ink-2">
                      {plainProtectionSummary(provider)}
                    </p>
                  </td>

                  <td className="py-3.5 px-4 min-w-[180px]">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={seal.pass ? "ep-pass" : "ep-muted-chip"}>
                        {seal.badge}
                      </span>
                    </div>
                    <div className="mt-1.5 text-[11px] text-ink-2">
                      {seal.liveLine}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 min-w-[190px]">
                    <div className="flex flex-wrap gap-1">
                      {provider.frontierModels.map((model) => (
                        <span
                          key={model}
                          className="rounded border border-rule bg-paper-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2"
                        >
                          {plainModelLabel(model)}
                        </span>
                      ))}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 min-w-[100px] font-mono text-[11px]">
                    <div className="flex flex-col gap-1">
                      <a
                        href={provider.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ep-link"
                      >
                        Website
                      </a>
                      <a
                        href={provider.docsUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ep-link"
                      >
                        Docs
                      </a>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Claims, sources and verification dates inside TechDetails */}
      <TechDetails label="Show technical details">
        <div className="space-y-4 pt-2 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 text-ink-2">
            <span>
              Sourced claims, hardware specifications, and verification dates (
              <code className="font-mono text-ink">
                verifiedOn={CATALOG_VERIFIED_ON}
              </code>
              ) checked against provider endpoints and{" "}
              <a
                href="https://confidentialinference.net"
                target="_blank"
                rel="noopener noreferrer"
                className="ep-link"
              >
                confidentialinference.net
              </a>
              .
            </span>
          </div>

          <div className="space-y-3">
            {filteredProviders.map((provider) => {
              const live = liveStatusById[provider.id];
              return (
                <div
                  key={provider.id}
                  className="ep-card p-4 space-y-3 text-ink-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule pb-2">
                    <div>
                      <span className="font-serif text-sm font-medium text-ink">
                        {provider.name}
                      </span>{" "}
                      <span className="font-mono text-[11px] text-ink-3">
                        (checked {provider.verifiedOn})
                      </span>
                    </div>
                    <a
                      href={provider.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ep-link font-mono text-[11px]"
                    >
                      Audit record -&gt;
                    </a>
                  </div>

                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 font-mono text-[11px]">
                    <div>
                      <span className="text-ink font-medium">CPU:</span>{" "}
                      {provider.cpuTee}
                    </div>
                    <div>
                      <span className="text-ink font-medium">GPU:</span>{" "}
                      {provider.gpuTee}
                    </div>
                    <div>
                      <span className="text-ink font-medium">Channel:</span>{" "}
                      {provider.channelSecurity} (
                      {provider.pqcHybrid
                        ? "X25519MLKEM768"
                        : "Classical TLS"}
                      )
                    </div>
                  </div>

                  {live && (
                    <div className="ep-inset p-2.5 font-mono text-[11px]">
                      <span className="text-ink font-medium">
                        Live probe ({live.statusLabel}):
                      </span>{" "}
                      {live.detail}
                    </div>
                  )}

                  <p className="text-ink-2">{provider.verificationSummary}</p>

                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 pt-1">
                    {(
                      [
                        ["Hardware", provider.claims.hardware],
                        ["Models", provider.claims.models],
                        ["Channel", provider.claims.channelSecurity],
                        ["Pricing", provider.claims.pricing],
                      ] as const
                    ).map(([label, claimObj]) => (
                      <div
                        key={label}
                        className="ep-inset p-2.5 space-y-1 text-[11px]"
                      >
                        <div className="flex items-center justify-between gap-2 font-mono text-[10px]">
                          <span className="font-semibold uppercase text-ink">
                            {label}: {claimObj.status}
                          </span>
                          <a
                            href={claimObj.sourceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="ep-link"
                          >
                            source ({claimObj.verifiedOn})
                          </a>
                        </div>
                        <p>{claimObj.claim}</p>
                      </div>
                    ))}
                  </div>

                  <p className="text-[11px] text-ink-3 border-t border-rule pt-2">
                    {provider.trustNotes.replace(/dRouter/g, "deRoute")}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </TechDetails>
    </section>
  );
}
