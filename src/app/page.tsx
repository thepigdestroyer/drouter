import Link from "next/link";
import { Console } from "@/components/console";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-[1500px] flex-col gap-4 p-4 lg:h-screen">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-zinc-50">
            dRouter <span className="font-normal text-zinc-500">· TEE-trusted inference</span>
          </h1>
          <p className="text-sm text-zinc-400">
            Route to a confidential-compute enclave, verify its hardware and code in your browser, then talk to a
            frontier model over a channel only that enclave can read.
          </p>
        </div>
        <nav className="flex gap-4 text-sm text-zinc-400">
          <Link className="hover:text-zinc-100" href="/audit">
            Security &amp; Accountability Lab
          </Link>
          <Link className="hover:text-zinc-100" href="/network">
            Network &amp; transparency log
          </Link>
          <a className="hover:text-zinc-100" href="/api/v1/verify" target="_blank" rel="noreferrer">
            Terminal / Harness API ↗
          </a>
          <a className="hover:text-zinc-100" href="https://explorer.testnet.arc.io" target="_blank" rel="noreferrer">
            Arc testnet ↗
          </a>
        </nav>
      </header>
      <Console />
      <footer className="text-xs text-zinc-600">
        Demo. Real-enclave sessions run on Tinfoil&apos;s attested AMD SEV-SNP infrastructure through the dRouter relay,
        which forwards ciphertext only. Simulated nodes run the dRouter protocol with real cryptography but simulated
        hardware roots, and are labelled as such.
      </footer>
    </main>
  );
}
