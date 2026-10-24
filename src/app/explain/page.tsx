import type { Metadata } from "next";
import Link from "next/link";
import { EnclaveGauntlet } from "@/components/game/enclave-gauntlet";

export const metadata: Metadata = {
  title: "How dRouter Works · Four Interactive Experiments",
  description:
    "Play through four interactive security exhibits to see how dRouter protects AI prompts against memory-bus probes, billing correlation, forged enclaves, and server subpoenas.",
};

export default function ExplainPage() {
  return (
    <main
      className="min-h-screen w-full text-[#ece7da]"
      style={{ backgroundColor: "#050706" }}
    >
      <div className="mx-auto max-w-[1380px] px-4 py-8 md:px-8 md:py-12">
        {/* Specimen-Cabinet Header & Navigation */}
        <header
          className="flex flex-wrap items-end justify-between gap-4 border-b pb-6"
          style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}
        >
          <div>
            <div
              className="font-mono text-xs uppercase tracking-widest"
              style={{ color: "#a6ff72" }}
            >
              dRouter Specimen Cabinet · Interactive Field Guide
            </div>
            <h1 className="mt-2 font-serif text-3xl italic tracking-tight text-[#ece7da] md:text-4xl">
              How dRouter Works · Four Interactive Experiments
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-[#ece7da]/80">
              Most AI routers ask you to trust their privacy policy. dRouter replaces legal promises with verifiable hardware physics and browser-side cryptography. Poke the four interactive exhibits below to test every claim yourself.
            </p>
          </div>

          <nav className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            <Link
              href="/"
              className="rounded border px-3 py-1.5 transition-colors hover:bg-white/5"
              style={{
                backgroundColor: "#090d0b",
                borderColor: "rgba(236, 231, 218, 0.12)",
                color: "#ece7da",
              }}
            >
              Console (/)
            </Link>
            <Link
              href="/audit"
              className="rounded border px-3 py-1.5 transition-colors hover:bg-white/5"
              style={{
                backgroundColor: "#090d0b",
                borderColor: "rgba(236, 231, 218, 0.12)",
                color: "#ece7da",
              }}
            >
              Security Lab (/audit)
            </Link>
            <Link
              href="/about"
              className="rounded border px-3 py-1.5 transition-colors hover:bg-white/5"
              style={{
                backgroundColor: "#090d0b",
                borderColor: "rgba(236, 231, 218, 0.12)",
                color: "#ece7da",
              }}
            >
              Architecture &amp; Providers (/about)
            </Link>
            <Link
              href="/login"
              className="rounded border px-3 py-1.5 transition-colors hover:bg-white/5"
              style={{
                backgroundColor: "#090d0b",
                borderColor: "rgba(166, 255, 114, 0.35)",
                color: "#a6ff72",
              }}
            >
              Zero-Knowledge Vault (/login)
            </Link>
          </nav>
        </header>

        {/* Plain-English Visual Guide to the 4 Stages of a dRouter Request */}
        <section className="mt-8">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="font-serif text-xl italic text-[#ece7da]">
              Anatomy of a private prompt from your browser to the GPU die
            </h2>
            <span className="font-mono text-xs text-[#ece7da]/60">
              Zero plaintext on the relay · Zero wallet-to-prompt link
            </span>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-4">
            {[
              {
                tag: "Stage 01 · Verify",
                accent: "#a6ff72",
                title: "Verify the enclave in your browser",
                body: "Before sending a single word, your browser checks the AMD SEV-SNP hardware signature, verifies guest policy debug bit 19 is 0, and matches the container root hash against Sigstore.",
              },
              {
                tag: "Stage 02 · Pay blindly",
                accent: "#ffb85c",
                title: "Spend an unblinded Chaumian credit",
                body: "You buy credits with a public wallet using a blinded envelope, then unblind the token locally. When you spend the credit, the billing server cannot link your wallet to your chat session.",
              },
              {
                tag: "Stage 03 · Compute in HBM",
                accent: "#a6ff72",
                title: "Keep weights and KV inside GPU HBM",
                body: "Your prompt decrypts only inside the attested enclave and runs inside on-package GPU HBM. Any host bus transfer uses fresh monotonic AES-256-GCM nonces to defeat DDR5 interposers.",
              },
              {
                tag: "Stage 04 · Freeze or pop",
                accent: "#ff6d4d",
                title: "Pop the bubble when you finish",
                body: "Save an optional zero-knowledge backup encrypted under your local key, then pop the enclave bubble to overwrite GPU HBM pages and session keys with 0x00.",
              },
            ].map((card) => (
              <div
                key={card.tag}
                className="rounded-lg border p-4"
                style={{
                  backgroundColor: "#090d0b",
                  borderColor: "rgba(236, 231, 218, 0.12)",
                }}
              >
                <div
                  className="font-mono text-xs uppercase tracking-wider"
                  style={{ color: card.accent }}
                >
                  {card.tag}
                </div>
                <h3 className="mt-1.5 font-serif text-lg italic text-[#ece7da]">
                  {card.title}
                </h3>
                <p className="mt-2 text-xs leading-relaxed text-[#ece7da]/80">
                  {card.body}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Interactive Game Component */}
        <div className="mt-8">
          <EnclaveGauntlet />
        </div>

        {/* Footer */}
        <footer
          className="mt-10 flex flex-wrap items-center justify-between gap-4 border-t pt-6 font-mono text-xs text-[#ece7da]/60"
          style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}
        >
          <div>
            The Enclave Gauntlet · Built with real AES-256-GCM, RSA blind signatures, and SEV-SNP register checks.
          </div>
          <div className="flex gap-4">
            <Link href="/" className="hover:text-[#a6ff72]">
              Launch Console →
            </Link>
            <Link href="/audit" className="hover:text-[#ffb85c]">
              Open Security Lab →
            </Link>
          </div>
        </footer>
      </div>
    </main>
  );
}
