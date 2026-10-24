import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { SPEC_V2_ROADMAP } from "@/lib/providers/catalog";
import { getAllProvidersLiveStatus } from "@/lib/providers/live-status";
import { ProviderCatalogClient } from "./provider-catalog-client";

export const HONEST_LIMITS = [
  {
    title: "Plaintext runs inside attested hardware enclaves (not frontier LLM FHE)",
    detail:
      "The launch tier decrypts and runs prompts inside hardware-attested Trusted Execution Environments (TEEs). Pure homomorphic encryption (FHE) and multi-party computation (MPC) cannot reach usable interactive speed for frontier models today.",
  },
  {
    title: "FHE Tier C is a real small CKKS linear classifier, not a frontier LLM",
    detail:
      "Live Tier C (node-seal 7.0.0 / Microsoft SEAL 4.1.2 WASM at /api/ashi) executes a real CKKS homomorphic linear computation (4x128 matrix-vector dot products plus encrypted squared L2 norm over a 128-dimensional embedding vector, N=4096, 128-bit security) where the server never sees plaintext or the secret key. Frontier 3T MoE FHE numbers remain an explicitly labelled analytical simulation.",
  },
  {
    title: "Vercel Sandbox is an isolated Firecracker microVM, not a hardware TEE",
    detail:
      "Tool execution at /api/sandbox runs inside a Vercel Sandbox Firecracker microVM (@vercel/sandbox 3.9.0, 1 vCPU, ephemeral filesystem, zero host environment variables passed). It provides hypervisor-level microVM isolation, not an AMD SEV-SNP or Intel TDX hardware-attested enclave.",
  },
  {
    title: "Tinfoil router and Kimi K3 enclave topology (262,144 token limit)",
    detail:
      "The live Tinfoil router (router-0.tinfoil.sh) attests with AMD SEV-SNP. The Kimi K3 model enclave (kimi-k3-inf14.tinfoil.containers.tinfoil.dev) runs on Intel TDX plus NVIDIA confidential-computing GPUs with a maximum context length of 262,144 tokens, not 1M. Gemini 4 Argon supports 1,000,000 tokens for outer orchestration over scrubbed metadata.",
  },
  {
    title: "Tinfoil safeguards classifier and usage sidecars",
    detail:
      "Tinfoil's router runs a safeguards acceptable-use classifier sidecar (gpt-oss-safeguard-120b with kimi-k3 review) that reports policy violations to https://api.tinfoil.sh, plus a usage reporter.",
  },
  {
    title: "Simulated test nodes (sim-1, sim-2, sim-3)",
    detail:
      "Nodes sim-1, sim-2, and sim-3 are simulated software nodes derived from SIM_HARDWARE_SEED to test client verification and failure handling. They are not real hardware enclaves.",
  },
  {
    title: "TEEs are not perfect (physical memory-bus attacks exist)",
    detail:
      "Hardware enclaves reduce trust in the cloud host, but they are not invincible. Physical memory-bus interposers such as TEE.fail can probe deterministic CPU RAM lines on socketed DDR5 DIMMs, and silicon firmware bugs remain a real risk.",
  },
  {
    title: "Timing and size buckets remain visible",
    detail:
      "Encryption and 4,096-byte bucket padding hide your text, but the relay and network operator still observe when a request happens and which coarse byte bucket it falls into.",
  },
] as const;

async function LiveProviderDirectorySection() {
  await connection();
  const liveStatusById = await getAllProvidersLiveStatus();
  return <ProviderCatalogClient liveStatusById={liveStatusById} />;
}

export default function AboutArchitecturePage() {
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
            Standard AI APIs ask you to trust a privacy policy while reading your prompts in plaintext at the gateway. Pure cryptographic inference (FHE or MPC) removes hardware trust for small linear models, but non-linear attention layers make it too slow for frontier LLMs today. dRouter bridges the gap by verifying hardware enclaves in your browser and encrypting requests directly to the enclave key before sending a single word.
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
            <h2 className="ep-display text-2xl">
              What you should know before trusting any enclave
            </h2>
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

        {/* FHE Tier C & Vercel Sandbox Ground Truth */}
        <section className="space-y-4">
          <div className="space-y-1">
            <div className="ep-label">Execution Tiers</div>
            <h2 className="ep-display text-2xl">
              FHE linear computation and Firecracker microVM sandbox as they really are
            </h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Alongside hardware-attested TEEs (Tinfoil AMD SEV-SNP router plus Intel TDX and NVIDIA Confidential Computing GPUs), dRouter exposes two specialized execution primitives with strict scope boundaries.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="ep-card p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="ep-label">Tier C: Small FHE Linear Computation</span>
                <span className="ep-pass">Live CKKS (node-seal 7.0.0)</span>
              </div>
              <h3 className="font-serif text-base font-medium text-ink">
                Encrypted 4x128 linear classifier &amp; L2 norm (not a frontier LLM)
              </h3>
              <p className="text-xs leading-relaxed text-ink-2">
                The <code className="font-mono text-ink">/api/ashi</code> endpoint runs real Microsoft SEAL 4.1.2 WebAssembly (CKKS scheme, polynomial modulus degree N=4096, 128-bit security). The client encrypts a 128-dimensional embedding vector locally and sends only the ciphertext, relinearization keys, and Galois rotation keys. The server computes four 128-dimensional dot products and a squared L2 norm homomorphically without ever seeing plaintext or the secret key. Frontier 3T MoE FHE numbers are an explicitly labelled analytical simulation.
              </p>
            </div>

            <div className="ep-card p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="ep-label">Tool Runner: Vercel Sandbox</span>
                <span className="ep-muted-chip">Firecracker microVM (Not a TEE)</span>
              </div>
              <h3 className="font-serif text-base font-medium text-ink">
                Isolated ephemeral Firecracker microVM via @vercel/sandbox
              </h3>
              <p className="text-xs leading-relaxed text-ink-2">
                The <code className="font-mono text-ink">/api/sandbox</code> endpoint executes Python and Node.js snippets inside an isolated Vercel Sandbox Firecracker microVM (1 vCPU, 2,048 MB RAM, non-persistent rootfs, zero host environment variables passed, and automatic teardown after execution). Firecracker provides hardware-virtualized KVM isolation between tenants, but it is not an AMD SEV-SNP or Intel TDX hardware-attested confidential enclave.
              </p>
            </div>
          </div>
        </section>

        {/* Provider Directory Table */}
        <Suspense
          fallback={
            <div className="ep-card p-5 font-mono text-xs text-ink-3">
              Checking confidential provider endpoints (cached 1 hour)...
            </div>
          }
        >
          <LiveProviderDirectorySection />
        </Suspense>

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
