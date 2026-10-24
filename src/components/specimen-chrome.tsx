"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AuthPill } from "@/components/auth-pill";

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

export type SiteHeaderProps = SpecimenHeaderProps;

export interface ExhibitSectionProps {
  number?: string;
  tag?: string;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
}

export type SectionProps = ExhibitSectionProps;

const NAV_ITEMS: ReadonlyArray<{
  label: string;
  href: SpecimenRoutePath;
}> = [
  { label: "Chat", href: "/" },
  { label: "How it works", href: "/explain" },
  { label: "Agent", href: "/argon" },
  { label: "Proof", href: "/audit" },
  { label: "Network", href: "/network" },
  { label: "About", href: "/about" },
];

export function SpecimenGrainOverlay() {
  return null;
}

export function SpecimenHeader({
  activePath,
  rightSlot,
  onOpenTerminalModal,
  onOpenInspector,
}: SpecimenHeaderProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();
  const currentPath = activePath ?? (pathname as SpecimenRoutePath) ?? "/";

  return (
    <header className="w-full border-b border-rule bg-paper text-ink">
      <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3.5 sm:px-6">
        <div className="flex items-center gap-6">
          <Link
            href="/"
            className="ep-display text-xl font-normal tracking-tight text-ink hover:opacity-80"
          >
            dRouter
          </Link>

          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-1"
          >
            {NAV_ITEMS.map((item) => {
              const isActive = currentPath === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive ? "page" : undefined}
                  className={`rounded px-2.5 py-1 text-sm transition-colors ${
                    isActive
                      ? "bg-paper-2 font-medium text-ink underline decoration-ink underline-offset-4"
                      : "text-ink-2 hover:bg-paper-2 hover:text-ink"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="flex items-center gap-2">
          {onOpenTerminalModal && (
            <button
              type="button"
              onClick={onOpenTerminalModal}
              className="hidden sm:inline-flex ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Use from terminal
            </button>
          )}

          {onOpenInspector && (
            <button
              type="button"
              onClick={onOpenInspector}
              className="hidden lg:inline-flex ep-btn-ghost px-2.5 py-1 text-xs"
            >
              Inspect raw records
            </button>
          )}

          <div className="flex items-center">
            {rightSlot !== undefined ? rightSlot : <AuthPill />}
          </div>

          <button
            type="button"
            onClick={() => setMobileOpen((prev) => !prev)}
            aria-expanded={mobileOpen}
            aria-label="Toggle navigation menu"
            className="inline-flex md:hidden ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {mobileOpen ? "Close" : "Menu"}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <div className="md:hidden border-t border-rule bg-paper-2 px-4 py-3 sm:px-6">
          <nav aria-label="Mobile navigation" className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              const isActive = currentPath === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileOpen(false)}
                  aria-current={isActive ? "page" : undefined}
                  className={`rounded px-3 py-2 text-sm ${
                    isActive
                      ? "bg-paper font-medium text-ink"
                      : "text-ink-2 hover:bg-paper hover:text-ink"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {(onOpenTerminalModal || onOpenInspector) && (
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-rule pt-3">
              {onOpenTerminalModal && (
                <button
                  type="button"
                  onClick={() => {
                    setMobileOpen(false);
                    onOpenTerminalModal();
                  }}
                  className="ep-btn-ghost px-2.5 py-1 text-xs"
                >
                  Use from terminal
                </button>
              )}
              {onOpenInspector && (
                <button
                  type="button"
                  onClick={() => {
                    setMobileOpen(false);
                    onOpenInspector();
                  }}
                  className="ep-btn-ghost px-2.5 py-1 text-xs"
                >
                  Inspect raw records
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </header>
  );
}

export const SiteHeader = SpecimenHeader;

export function ExhibitSection({
  tag,
  title,
  subtitle,
  children,
}: ExhibitSectionProps) {
  return (
    <section className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6">
      <div className="mb-6 border-t border-rule pt-6">
        {tag && <div className="ep-label">{tag}</div>}
        <h2 className="ep-display mt-1.5 text-2xl sm:text-3xl">{title}</h2>
        {subtitle && (
          <p className="mt-2 max-w-[70ch] text-sm text-ink-2">{subtitle}</p>
        )}
      </div>
      <div>{children}</div>
    </section>
  );
}

export const Section = ExhibitSection;

export function SpecimenFooter() {
  return (
    <footer className="mt-auto w-full border-t border-rule bg-paper text-ink-3">
      <div className="mx-auto flex max-w-5xl flex-col items-start justify-between gap-3 px-4 py-6 text-xs sm:flex-row sm:items-center sm:px-6">
        <p className="text-ink-2">
          dRouter. Hardware-attested confidential AI routing.
        </p>
        <div className="flex flex-wrap items-center gap-4">
          <a
            href="https://testnet.arcscan.app/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481"
            target="_blank"
            rel="noreferrer"
            className="ep-link text-xs"
          >
            Arc testnet registry (0xbc80...4481)
          </a>
          <Link href="/about" className="ep-link text-xs">
            About
          </Link>
        </div>
      </div>
    </footer>
  );
}

export const SiteFooter = SpecimenFooter;
