"use client";

import React, { useEffect, useId, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AuthPill } from "@/components/auth-pill";
import { InkButton } from "@/components/ink/ink-button";
import {
  getCurrentVaultSession,
  lockVault,
  subscribeVaultSession,
} from "@/lib/auth/vault";

export type SpecimenRoutePath =
  | "/"
  | "/app"
  | "/explain"
  | "/argon"
  | "/audit"
  | "/about"
  | "/partners"
  | "/network"
  | "/login"
  | "/account"
  | (string & {});

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

export const SIGNED_OUT_NAV_ITEMS: ReadonlyArray<{
  label: string;
  href: SpecimenRoutePath;
}> = [
  { label: "Home", href: "/" },
  { label: "How it works", href: "/explain" },
  { label: "About", href: "/about" },
  { label: "Backend partners", href: "/partners" },
];

export const SIGNED_IN_NAV_ITEMS: ReadonlyArray<{
  label: string;
  href: SpecimenRoutePath;
}> = [
  { label: "Chat", href: "/app" },
  { label: "Agent", href: "/argon" },
  { label: "Proof", href: "/audit" },
  { label: "How it works", href: "/explain" },
  { label: "Backend partners", href: "/partners" },
];

export function SpecimenGrainOverlay() {
  return null;
}

function skipToMainContent(e: React.MouseEvent<HTMLAnchorElement>) {
  const target =
    document.getElementById("main-content") ?? document.querySelector("main");
  if (target instanceof HTMLElement) {
    e.preventDefault();
    if (!target.hasAttribute("tabindex")) {
      target.setAttribute("tabindex", "-1");
    }
    target.focus();
    target.scrollIntoView({ block: "start" });
  }
}

function DeRouteMarkIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width="24"
      height="24"
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <rect
        x="3"
        y="3"
        width="58"
        height="58"
        rx="13"
        fill="#f3f1ec"
        stroke="#151515"
        strokeWidth="3"
      />
      <circle cx="31" cy="35" r="14.2" stroke="#151515" strokeWidth="4.6" />
      <line
        x1="45.2"
        y1="11"
        x2="45.2"
        y2="49.2"
        stroke="#151515"
        strokeWidth="4.6"
        strokeLinecap="round"
      />
      <line
        x1="8"
        y1="35"
        x2="23.5"
        y2="35"
        stroke="#f3f1ec"
        strokeWidth="8.5"
        strokeLinecap="butt"
      />
      <line
        x1="9.5"
        y1="35"
        x2="22.5"
        y2="35"
        stroke="#151515"
        strokeWidth="3.8"
        strokeLinecap="round"
      />
      <circle cx="31" cy="35" r="5.2" fill="#151515" />
    </svg>
  );
}

const getServerVaultSession = () => null;

export function SpecimenHeader({
  activePath,
  rightSlot,
  onOpenTerminalModal,
  onOpenInspector,
}: SpecimenHeaderProps) {
  const [openForPath, setOpenForPath] = useState<string | null>(null);
  const session = useSyncExternalStore(
    subscribeVaultSession,
    getCurrentVaultSession,
    getServerVaultSession,
  );
  const mobileMenuId = useId();
  const pathname = usePathname();
  const currentPath = activePath ?? (pathname as SpecimenRoutePath) ?? "/";
  const mobileOpen = openForPath !== null && openForPath === (pathname ?? "");
  const setMobileOpen = (next: boolean | ((prev: boolean) => boolean)) => {
    const resolved = typeof next === "function" ? next(mobileOpen) : next;
    setOpenForPath(resolved ? (pathname ?? "") : null);
  };

  useEffect(() => {
    if (!mobileOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpenForPath(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [mobileOpen]);

  const navItems = session ? SIGNED_IN_NAV_ITEMS : SIGNED_OUT_NAV_ITEMS;

  return (
    <header className="w-full border-b border-rule bg-paper/90 backdrop-blur-[2px] text-ink">
      <a
        href="#main-content"
        onClick={skipToMainContent}
        className="ep-skip-link"
      >
        Skip to main content
      </a>

      <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3.5 sm:px-6">
        <div className="flex items-center gap-6">
          <Link
            href="/"
            aria-label="deRoute home"
            className="ep-display inline-flex items-center gap-2 text-xl font-normal tracking-tight text-ink hover:opacity-80"
          >
            <DeRouteMarkIcon />
            <span>deRoute</span>
          </Link>

          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-1"
          >
            {navItems.map((item) => {
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
            <InkButton
              type="button"
              variant="ghost"
              onClick={onOpenTerminalModal}
              className="hidden sm:inline-flex px-2.5 py-1 text-xs"
            >
              Use from terminal
            </InkButton>
          )}

          {onOpenInspector && (
            <InkButton
              type="button"
              variant="ghost"
              onClick={onOpenInspector}
              className="hidden lg:inline-flex px-2.5 py-1 text-xs"
            >
              Inspect raw records
            </InkButton>
          )}

          <div
            className={`${mobileOpen ? "hidden md:flex" : "flex"} items-center`}
          >
            {rightSlot !== undefined ? rightSlot : <AuthPill />}
          </div>

          <InkButton
            type="button"
            variant="ghost"
            onClick={() => setMobileOpen((prev) => !prev)}
            aria-expanded={mobileOpen}
            aria-controls={mobileMenuId}
            aria-label={
              mobileOpen ? "Close navigation menu" : "Open navigation menu"
            }
            className="inline-flex md:hidden px-2.5 py-1 text-xs"
          >
            {mobileOpen ? "Close" : "Menu"}
          </InkButton>
        </div>
      </div>

      {mobileOpen && (
        <div
          id={mobileMenuId}
          className="md:hidden border-t border-rule bg-paper-2/95 px-4 py-3 sm:px-6"
        >
          <nav aria-label="Mobile navigation" className="flex flex-col gap-1">
            {navItems.map((item) => {
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

          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-rule pt-3">
            {session ? (
              <>
                <Link
                  href="/account"
                  onClick={() => setMobileOpen(false)}
                  className="ep-btn-ghost px-2.5 py-1 text-xs"
                >
                  Account
                </Link>
                <button
                  type="button"
                  onClick={() => {
                    setMobileOpen(false);
                    lockVault();
                  }}
                  className="ep-btn-ghost px-2.5 py-1 text-xs"
                >
                  Sign out
                </button>
              </>
            ) : (
              <Link
                href="/login"
                onClick={() => setMobileOpen(false)}
                className="ep-btn px-3 py-1 text-xs"
              >
                Sign in
              </Link>
            )}

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
    <footer
      aria-label="Site footer"
      className="mt-auto w-full border-t border-rule bg-paper/90 text-ink-3"
    >
      <div className="mx-auto flex max-w-5xl flex-col items-start justify-between gap-3 px-4 py-6 text-xs sm:flex-row sm:items-center sm:px-6">
        <p className="text-ink-2">
          deRoute. Private AI chat where nobody, including us, can read what you ask.
        </p>
        <nav aria-label="Footer links" className="flex flex-wrap items-center gap-4">
          <Link href="/explain" className="ep-link text-xs">
            How it works
          </Link>
          <Link href="/network" className="ep-link text-xs">
            Network
          </Link>
          <Link href="/about" className="ep-link text-xs">
            About
          </Link>
          <Link href="/partners" className="ep-link text-xs">
            Backend partners
          </Link>
          <a
            href="https://testnet.arcscan.app/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481"
            target="_blank"
            rel="noreferrer"
            className="ep-link text-xs"
          >
            Public receipt book
          </a>
          <a
            href="https://github.com/thepigdestroyer/drouter"
            target="_blank"
            rel="noreferrer"
            className="ep-link text-xs"
          >
            Source on GitHub
          </a>
        </nav>
      </div>
    </footer>
  );
}

export const SiteFooter = SpecimenFooter;
