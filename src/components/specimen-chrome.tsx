"use client";

import React, { useState } from "react";
import Link from "next/link";

export type SpecimenRoutePath =
  | "/"
  | "/explain"
  | "/argon"
  | "/audit"
  | "/about"
  | "/network"
  | "/login";

export interface SpecimenHeaderProps {
  activePath?: SpecimenRoutePath;
  rightSlot?: React.ReactNode;
  onOpenTerminalModal?: () => void;
  onOpenInspector?: () => void;
}

export interface ExhibitSectionProps {
  number: string;
  tag: string;
  title: React.ReactNode;
  subtitle: React.ReactNode;
  children: React.ReactNode;
}

const NAV_ITEMS: ReadonlyArray<{
  code: string;
  label: string;
  href: SpecimenRoutePath;
}> = [
  { code: "01", label: "01 · Console", href: "/" },
  { code: "02", label: "02 · Interactive Game", href: "/explain" },
  { code: "03", label: "03 · Argon Agent", href: "/argon" },
  { code: "04", label: "04 · Security Lab", href: "/audit" },
  { code: "05", label: "05 · Providers & About", href: "/about" },
  { code: "06", label: "06 · Network Log", href: "/network" },
  { code: "07", label: "07 · ZK Vault Login", href: "/login" },
];

const VERIFICATION_AUTHORITIES: ReadonlyArray<{
  label: string;
  domain: string;
  href: string;
  role: string;
}> = [
  {
    label: "AMD SEV-SNP & GPU attestation log",
    domain: "atc.tinfoil.sh/attestation",
    href: "https://atc.tinfoil.sh/attestation",
    role: "Live enclave hardware measurements",
  },
  {
    label: "Confidential proxy manifest",
    domain: "inference.tinfoil.sh/.well-known/tinfoil-proxy",
    href: "https://inference.tinfoil.sh/.well-known/tinfoil-proxy",
    role: "Pinned TLS certificate & enclave routing keys",
  },
  {
    label: "Sigstore Rekor transparency log",
    domain: "search.sigstore.dev",
    href: "https://search.sigstore.dev",
    role: "Immutable build provenance & binary hashes",
  },
  {
    label: "Circle Arc testnet explorer",
    domain: "explorer.testnet.arc.io",
    href: "https://explorer.testnet.arc.io",
    role: "On-chain batch receipts & operator stakes",
  },
];

export function SpecimenGrainOverlay() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-50 opacity-[0.035]"
    >
      <svg className="h-full w-full" xmlns="http://www.w3.org/2000/svg">
        <filter id="specimen-cabinet-film-grain">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.82"
            numOctaves={3}
            stitchTiles="stitch"
          />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect
          width="100%"
          height="100%"
          filter="url(#specimen-cabinet-film-grain)"
        />
      </svg>
    </div>
  );
}

export function SpecimenHeader({
  activePath = "/",
  rightSlot,
  onOpenTerminalModal,
  onOpenInspector,
}: SpecimenHeaderProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      <SpecimenGrainOverlay />
      <header className="sticky top-0 z-40 w-full bg-[#050706]/90 backdrop-blur-md border-b border-[rgba(236,231,218,0.12)] text-[#ece7da]">
        {/* Top cabinet telemetry strip */}
        <div className="border-b border-[rgba(236,231,218,0.08)] bg-[#050706]">
          <div className="mx-auto flex max-w-[1440px] items-center justify-between px-4 py-1.5 sm:px-6">
            <div className="flex items-center gap-2.5 text-[10px] font-mono tracking-[0.16em] uppercase text-[#ece7da]/65">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
              <span>SPECIMEN CABINET · CONFIDENTIAL AI ROUTER</span>
              <span className="hidden md:inline text-[#ece7da]/30">|</span>
              <span className="hidden md:inline text-[#ece7da]/55">
                TWO-HOP HPKE · AMD SEV-SNP · NVIDIA H100 CC
              </span>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono tracking-[0.12em] text-[#ece7da]/60">
              <span className="hidden sm:inline-flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-[#ffb85c]" />
                <span>ZERO PLAINTEXT LOGS</span>
              </span>
              <span className="text-[#a6ff72]/90">ATTESTED LIVE</span>
            </div>
          </div>
        </div>

        {/* Main navigation bar */}
        <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-3 px-4 py-3 sm:px-6">
          {/* Brand mark */}
          <Link
            href="/"
            className="group flex items-center gap-3 shrink-0 focus:outline-none"
          >
            <div className="relative flex h-8 w-8 items-center justify-center rounded-full border border-[rgba(236,231,218,0.18)] bg-[#090d0b] transition-colors group-hover:border-[#a6ff72]/60">
              <span className="h-2.5 w-2.5 rounded-full bg-[#a6ff72] shadow-[0_0_12px_#a6ff72]" />
              <span className="pointer-events-none absolute inset-0 rounded-full ring-1 ring-[#a6ff72]/20 group-hover:ring-[#a6ff72]/45" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-baseline gap-2">
                <span className="text-base font-semibold tracking-tight text-[#ece7da] group-hover:text-white transition-colors">
                  dRouter
                </span>
                <span className="rounded border border-[#a6ff72]/30 bg-[#a6ff72]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] text-[#a6ff72]">
                  v2.4
                </span>
              </div>
              <span className="font-mono text-[9px] tracking-[0.14em] uppercase text-[#ece7da]/50">
                SPECIMEN CABINET · CONFIDENTIAL AI ROUTER
              </span>
            </div>
          </Link>

          {/* Primary desktop navigation links */}
          <nav
            aria-label="Specimen cabinet navigation"
            className="hidden xl:flex items-center gap-1 rounded-full border border-[rgba(236,231,218,0.12)] bg-[#090d0b]/90 p-1"
          >
            {NAV_ITEMS.map((item) => {
              const isActive = activePath === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive ? "page" : undefined}
                  className={`relative flex items-center gap-1.5 rounded-full px-3 py-1.5 font-mono text-[11px] tracking-[0.04em] transition-all ${
                    isActive
                      ? "bg-[#a6ff72]/14 text-[#a6ff72] border border-[#a6ff72]/40 shadow-[inset_0_0_12px_rgba(166,255,114,0.12)]"
                      : "text-[#ece7da]/70 hover:text-[#ece7da] hover:bg-[#ece7da]/[0.05] border border-transparent"
                  }`}
                >
                  {isActive && (
                    <span
                      aria-hidden="true"
                      className="h-1.5 w-1.5 rounded-full bg-[#a6ff72] shadow-[0_0_6px_#a6ff72]"
                    />
                  )}
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>

          {/* Right controls: quick actions + rightSlot + mobile toggle */}
          <div className="flex items-center gap-2">
            {onOpenTerminalModal && (
              <button
                type="button"
                onClick={onOpenTerminalModal}
                className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-[rgba(236,231,218,0.16)] bg-[#0b100d] px-3 py-1.5 font-mono text-[11px] text-[#ece7da]/85 transition-colors hover:border-[#a6ff72]/50 hover:text-[#a6ff72]"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-[#a6ff72]" />
                <span>Terminal / IDE ⌘</span>
              </button>
            )}

            {onOpenInspector && (
              <button
                type="button"
                onClick={onOpenInspector}
                className="hidden md:inline-flex items-center gap-1.5 rounded-full border border-[#ffb85c]/35 bg-[#ffb85c]/10 px-3 py-1.5 font-mono text-[11px] text-[#ffb85c] transition-colors hover:border-[#ffb85c]/65 hover:bg-[#ffb85c]/15"
              >
                <span>Verify Raw Records ↗</span>
              </button>
            )}

            {rightSlot && (
              <div className="flex items-center">{rightSlot}</div>
            )}

            <button
              type="button"
              onClick={() => setMobileOpen((prev) => !prev)}
              aria-expanded={mobileOpen}
              aria-label="Toggle specimen navigation menu"
              className="inline-flex xl:hidden items-center justify-center rounded-full border border-[rgba(236,231,218,0.16)] bg-[#090d0b] px-2.5 py-1.5 font-mono text-[11px] text-[#ece7da]/80 hover:border-[#a6ff72]/50 hover:text-[#a6ff72]"
            >
              {mobileOpen ? "Close ×" : "Exhibits ☰"}
            </button>
          </div>
        </div>

        {/* Compact tablet & mobile rail */}
        {mobileOpen && (
          <div className="xl:hidden border-t border-[rgba(236,231,218,0.12)] bg-[#050706] px-4 py-3 sm:px-6">
            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
              {NAV_ITEMS.map((item) => {
                const isActive = activePath === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    className={`flex items-center justify-between rounded-lg border px-3 py-2 font-mono text-xs transition-colors ${
                      isActive
                        ? "border-[#a6ff72]/45 bg-[#a6ff72]/12 text-[#a6ff72]"
                        : "border-[rgba(236,231,218,0.12)] bg-[#090d0b] text-[#ece7da]/80 hover:border-[rgba(236,231,218,0.25)] hover:text-[#ece7da]"
                    }`}
                  >
                    <span>{item.label}</span>
                    {isActive && (
                      <span className="h-2 w-2 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
                    )}
                  </Link>
                );
              })}
            </div>

            {(onOpenTerminalModal || onOpenInspector) && (
              <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[rgba(236,231,218,0.12)] pt-3">
                {onOpenTerminalModal && (
                  <button
                    type="button"
                    onClick={() => {
                      setMobileOpen(false);
                      onOpenTerminalModal();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-full border border-[rgba(236,231,218,0.16)] bg-[#0b100d] px-3 py-1.5 font-mono text-xs text-[#ece7da]/90 hover:border-[#a6ff72]/50 hover:text-[#a6ff72]"
                  >
                    <span>Terminal / IDE ⌘</span>
                  </button>
                )}
                {onOpenInspector && (
                  <button
                    type="button"
                    onClick={() => {
                      setMobileOpen(false);
                      onOpenInspector();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-full border border-[#ffb85c]/35 bg-[#ffb85c]/10 px-3 py-1.5 font-mono text-xs text-[#ffb85c] hover:border-[#ffb85c]/65"
                  >
                    <span>Verify Raw Records ↗</span>
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </header>
    </>
  );
}

export function ExhibitSection({
  number,
  tag,
  title,
  subtitle,
  children,
}: ExhibitSectionProps) {
  const formattedNumber = number.toLowerCase().startsWith("no.")
    ? number
    : `No. ${number}`;

  return (
    <section className="relative mx-auto w-full max-w-[1440px] px-4 py-10 sm:px-6 lg:py-14 text-[#ece7da]">
      {/* Specimen exhibit rail header */}
      <div className="mb-7 border-t border-[rgba(236,231,218,0.12)] pt-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex items-center gap-2.5">
            <span className="rounded border border-[rgba(236,231,218,0.18)] bg-[#090d0b] px-2 py-0.5 font-mono text-[11px] tracking-[0.14em] uppercase text-[#ece7da]/80">
              {formattedNumber}
            </span>
            <span className="h-1.5 w-1.5 rounded-full bg-[#a6ff72] shadow-[0_0_8px_#a6ff72]" />
            <span className="font-mono text-[11px] tracking-[0.16em] uppercase text-[#a6ff72]">
              {tag}
            </span>
          </div>
          <div className="font-mono text-[10px] tracking-[0.14em] uppercase text-[#ece7da]/40">
            SPECIMEN EXHIBIT · HARDWARE VERIFIED
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-end">
          <h2
            className="lg:col-span-7 text-2xl sm:text-3xl lg:text-4xl font-normal italic tracking-tight text-[#ece7da] leading-[1.15]"
            style={{
              fontFamily:
                "Instrument Serif, Playfair Display, Georgia, Cambria, Times New Roman, serif",
            }}
          >
            {title}
          </h2>
          <div className="lg:col-span-5 text-sm sm:text-[15px] leading-relaxed text-[#ece7da]/72">
            {subtitle}
          </div>
        </div>
      </div>

      {/* Stage container */}
      <div className="relative rounded-2xl border border-[rgba(236,231,218,0.12)] bg-[#070a08]/90 p-4 sm:p-6 shadow-[0_24px_60px_rgba(0,0,0,0.65)]">
        {/* Corner specimen ticks */}
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-2.5 left-2.5 h-2 w-2 border-t border-l border-[#a6ff72]/40"
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-2.5 right-2.5 h-2 w-2 border-t border-r border-[#a6ff72]/40"
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute bottom-2.5 left-2.5 h-2 w-2 border-b border-l border-[#a6ff72]/40"
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute bottom-2.5 right-2.5 h-2 w-2 border-b border-r border-[#a6ff72]/40"
        />
        {children}
      </div>
    </section>
  );
}

export function SpecimenFooter() {
  const [copiedCli, setCopiedCli] = useState(false);
  const cliCommand = "node scripts/drouter-cli.mjs verify";

  const handleCopyCli = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(cliCommand).catch(() => {});
      setCopiedCli(true);
      setTimeout(() => setCopiedCli(false), 1800);
    }
  };

  return (
    <footer className="mt-auto w-full border-t border-[rgba(236,231,218,0.12)] bg-[#050706] text-[#ece7da]">
      <div className="mx-auto max-w-[1440px] px-4 py-12 sm:px-6">
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-12">
          {/* Column 1: Brand & CLI command */}
          <div className="lg:col-span-5 flex flex-col justify-between space-y-6">
            <div>
              <div className="flex items-center gap-2.5">
                <span className="h-2.5 w-2.5 rounded-full bg-[#a6ff72] shadow-[0_0_10px_#a6ff72]" />
                <span className="text-base font-semibold tracking-tight text-[#ece7da]">
                  dRouter Specimen Cabinet
                </span>
                <span className="rounded border border-[#ffb85c]/35 bg-[#ffb85c]/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-[#ffb85c]">
                  Audit Ready
                </span>
              </div>
              <p className="mt-3 max-w-md text-sm leading-relaxed text-[#ece7da]/70">
                Confidential AI routing with two-hop HPKE encryption, AMD SEV-SNP
                and NVIDIA H100 hardware attestation, blind-signed Chaumian
                credits, and verifiable settlement on Circle Arc.
              </p>
            </div>

            {/* CLI Verifier Box */}
            <div className="rounded-xl border border-[rgba(236,231,218,0.12)] bg-[#090d0b] p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-[#a6ff72]">
                  Local terminal verification
                </span>
                <span className="font-mono text-[10px] text-[#ece7da]/45">
                  Zero-trust CLI check
                </span>
              </div>
              <div className="mt-2 flex items-center justify-between gap-2 rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#050706] px-3 py-2">
                <code className="font-mono text-xs text-[#ece7da] select-all">
                  $ {cliCommand}
                </code>
                <button
                  type="button"
                  onClick={handleCopyCli}
                  className="shrink-0 rounded border border-[rgba(236,231,218,0.16)] bg-[#0c120e] px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-[#a6ff72] transition-colors hover:border-[#a6ff72]/50"
                >
                  {copiedCli ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
          </div>

          {/* Column 2: Specimen Directory */}
          <div className="lg:col-span-3">
            <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#ece7da]/55">
              Cabinet exhibits
            </h3>
            <ul className="mt-4 space-y-2.5">
              {NAV_ITEMS.map((item) => (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="group inline-flex items-center gap-2 font-mono text-xs text-[#ece7da]/75 transition-colors hover:text-[#a6ff72]"
                  >
                    <span className="h-1 w-1 rounded-full bg-[#ece7da]/35 transition-colors group-hover:bg-[#a6ff72]" />
                    <span>{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Column 3: External Verification Authorities */}
          <div className="lg:col-span-4">
            <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-[#ece7da]/55">
              External verification authorities
            </h3>
            <ul className="mt-4 space-y-2.5">
              {VERIFICATION_AUTHORITIES.map((auth) => (
                <li
                  key={auth.domain}
                  className="rounded-lg border border-[rgba(236,231,218,0.1)] bg-[#090d0b]/70 p-2.5 transition-colors hover:border-[#a6ff72]/35"
                >
                  <a
                    href={auth.href}
                    target="_blank"
                    rel="noreferrer"
                    className="block"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-[#a6ff72] underline-offset-4 hover:underline">
                        {auth.domain}
                      </span>
                      <span className="font-mono text-[10px] text-[#ffb85c]">
                        ↗
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-[#ece7da]/65">
                      {auth.label} · {auth.role}
                    </p>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom hairline bar */}
        <div className="mt-10 flex flex-col items-start justify-between gap-3 border-t border-[rgba(236,231,218,0.12)] pt-5 text-xs text-[#ece7da]/50 sm:flex-row sm:items-center">
          <div className="font-mono text-[11px]">
            dRouter Specimen Cabinet · Hardware-enforced confidential routing
          </div>
          <div className="flex flex-wrap items-center gap-4 font-mono text-[11px]">
            <span className="text-[#a6ff72]/85">HPKE RFC 9180</span>
            <span>·</span>
            <span className="text-[#ffb85c]/85">RFC 9474 RSA-BSSA</span>
            <span>·</span>
            <span>AMD SEV-SNP + NVIDIA CC</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
