import Link from "next/link";
import { Console } from "@/components/console";
import { SpecimenHeader, ExhibitSection, SpecimenFooter } from "@/components/specimen-chrome";
import { AuthPill } from "@/components/auth-pill";
import { EnclaveGauntlet } from "@/components/game/enclave-gauntlet";
import { PacketSniffer } from "@/components/packet-sniffer";
import { AtlasExplorer } from "@/components/atlas-explorer";
import { ThreatMatrix } from "@/components/threat-matrix";

export default function Home() {
  return (
    <div className="min-h-screen bg-[#050706] text-[#ece7da]">
      <SpecimenHeader activePath="/" rightSlot={<AuthPill />} />

      <main className="mx-auto flex max-w-[1440px] flex-col gap-12 px-4 py-8 sm:px-6">
        {/* Hero strip */}
        <section className="rounded-xl border border-[rgba(236,231,218,0.14)] bg-gradient-to-b from-[#0f1512] to-[#050706] p-6 sm:p-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="max-w-3xl">
              <div className="font-mono text-xs uppercase tracking-[0.18em] text-[#a6ff72]">
                SPECIMEN NO. 00 · HARDWARE-ATTESTED CONFIDENTIAL AI ROUTER
              </div>
              <h1
                className="mt-2 text-3xl font-normal tracking-tight text-[#ece7da] sm:text-5xl"
                style={{ fontFamily: "var(--font-serif)" }}
              >
                Use frontier models inside a{" "}
                <em className="text-[#a6ff72]">verified hardware bubble</em> that pops when you leave.
              </h1>
              <p className="mt-3 text-sm leading-relaxed text-[#ece7da]/75 sm:text-base">
                Every prompt is scrubbed for personal identifiers on your device, padded to a fixed byte bucket, paid
                with an unlinkable blind-signed credit, and encrypted in your browser to keys held only inside an
                attested AMD SEV-SNP and 8-GPU Confidential Computing enclave. Not even dRouter, the relay, or the
                datacenter host can read what you ask.
              </p>
            </div>
            <div className="flex flex-col gap-2.5 sm:items-end">
              <Link
                href="/argon"
                className="inline-flex items-center gap-2 rounded-lg bg-[#a6ff72] px-4 py-2.5 text-sm font-semibold text-[#050706] hover:bg-[#5fe07a]"
              >
                <span>Launch Gemini 4 Argon Autonomous Agent</span>
                <span>→</span>
              </Link>
              <div className="flex flex-wrap gap-2 text-xs">
                <Link
                  href="/explain"
                  className="rounded-lg border border-[rgba(236,231,218,0.2)] bg-[#090d0b] px-3 py-1.5 text-[#ece7da] hover:border-[#a6ff72]"
                >
                  Play the 4-Exhibit Security Game
                </Link>
                <Link
                  href="/about"
                  className="rounded-lg border border-[rgba(236,231,218,0.2)] bg-[#090d0b] px-3 py-1.5 text-[#ece7da] hover:border-[#a6ff72]"
                >
                  Compare 10 Frontier TEE Providers
                </Link>
                <Link
                  href="/login"
                  className="rounded-lg border border-[rgba(236,231,218,0.2)] bg-[#090d0b] px-3 py-1.5 text-[#ece7da] hover:border-[#a6ff72]"
                >
                  Zero-Knowledge Vault Login
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Exhibit 01: Live Console */}
        <ExhibitSection
          number="01"
          tag="LIVE ROUTER · TWO-HOP CPU + 8x GPU ATTESTATION"
          title={
            <span>
              Route, verify seven hardware proofs, and talk inside the <em>bubble</em>.
            </span>
          }
          subtitle="Simple enough to verify at a glance with the green shield above, with one-click pop-out modals for technical auditors to inspect the raw 1,184-byte AMD SEV-SNP report, the 8-GPU confidential cluster manifest, Sigstore Rekor logs, and Circle Arc stakes."
        >
          <Console />
        </ExhibitSection>

        {/* Exhibit 02: Interactive Game */}
        <ExhibitSection
          number="02"
          tag="PLAYABLE FIELD GUIDE · FOUR INTERACTIVE EXPERIMENTS"
          title={
            <span>
              Learn why each layer exists by trying to <em>break</em> it yourself.
            </span>
          }
          subtitle="Clip a $900 logic analyzer onto a DDR5 memory stick, blind a credit token inside carbon-paper math, catch a forged enclave with debug mode left on, and pop a session bubble before a forensic memory dump arrives."
        >
          <EnclaveGauntlet />
        </ExhibitSection>

        {/* Exhibit 03: Live Wire Sniffer */}
        <ExhibitSection
          number="03"
          tag="WIRE INSPECTOR · ZERO-LEAK PIPELINE"
          title={
            <span>
              Watch what happens to your prompt at every hop on the <em>wire</em>.
            </span>
          }
          subtitle="Type any sentence with an email, API key, date, or dollar amount and compare what stays on your device against what the relay, the ISP, and the GPU enclave actually see."
        >
          <PacketSniffer />
        </ExhibitSection>

        {/* Exhibit 04: MongoDB Atlas Hybrid Search */}
        <ExhibitSection
          number="04"
          tag="MONGODB ATLAS · VECTOR + FULL-TEXT HYBRID SEARCH"
          title={
            <span>
              Search live enclave intelligence with <em>Atlas Vector Search</em> and Reciprocal Rank Fusion.
            </span>
          }
          subtitle="Powered by our live MongoDB Atlas cluster using $vectorSearch (128-dimensional semantic embeddings), $search (Lucene full-text), Reciprocal Rank Fusion, and real-time multi-collection stream analytics."
        >
          <AtlasExplorer />
        </ExhibitSection>

        {/* Exhibit 05: Interactive Threat Simulator */}
        <ExhibitSection
          number="05"
          tag="ADVERSARY SIMULATOR · DEFENSE IN DEPTH"
          title={
            <span>
              What if an operator, relay, or verifier <em>cheats</em>?
            </span>
          }
          subtitle="Toggle any combination of real-world hardware, software, or network attacks to see which cryptographic or economic layer catches it."
        >
          <ThreatMatrix />
        </ExhibitSection>
      </main>

      <SpecimenFooter />
    </div>
  );
}
