import type { Metadata } from "next";
import { AuthPill } from "@/components/auth-pill";
import { EnclaveGauntlet } from "@/components/game/enclave-gauntlet";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { PacketSniffer } from "@/components/packet-sniffer";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";

export const metadata: Metadata = {
  title: "How it works · deRoute",
  description:
    "A short story in four scenes showing how deRoute checks the seal on a distant computer, hides your personal details, locks your message, and dissolves the key when you finish.",
};

export default function ExplainPage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/explain" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        className="mx-auto w-full max-w-5xl flex-1 space-y-12 px-4 py-10 sm:px-6"
      >
        <style>{`
          @keyframes deroute-ink-pulse {
            0%, 100% { transform: scale(1); opacity: 0.85; }
            50% { transform: scale(1.08); opacity: 1; }
          }
          @keyframes deroute-ink-flow {
            0% { stroke-dashoffset: 24; }
            100% { stroke-dashoffset: 0; }
          }
          @keyframes deroute-ink-drift {
            0%, 100% { transform: translateY(0px) scale(1); opacity: 0.75; }
            50% { transform: translateY(-4px) scale(0.88); opacity: 0.3; }
          }
          .deroute-anim-pulse {
            transform-origin: center;
            animation: deroute-ink-pulse 3.6s ease-in-out infinite;
          }
          .deroute-anim-flow {
            stroke-dasharray: 4 4;
            animation: deroute-ink-flow 2.4s linear infinite;
          }
          .deroute-anim-drift {
            transform-origin: center;
            animation: deroute-ink-drift 3.2s ease-in-out infinite;
          }
          @media (prefers-reduced-motion: reduce) {
            .deroute-anim-pulse,
            .deroute-anim-flow,
            .deroute-anim-drift {
              animation: none !important;
            }
          }
        `}</style>

        {/* Hero */}
        <InkReveal>
          <section className="space-y-4 border-b border-rule pb-8">
            <div className="ep-label">How it works</div>
            <h1 className="ep-display text-3xl sm:text-4xl">
              How deRoute keeps your private questions private.
            </h1>
            <p className="max-w-[64ch] text-base leading-relaxed text-ink-2">
              Follow one message through four simple scenes, then play four tiny
              rounds to test each step with your own hands.
            </p>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <InkButton href="/app" variant="primary">
                Open chat
              </InkButton>
              <InkButton href="#play-game" variant="ghost">
                Play the game
              </InkButton>
              <InkButton href="/about" variant="ghost">
                About deRoute
              </InkButton>
            </div>
          </section>
        </InkReveal>

        {/* A Short Story in 4 Scenes */}
        <section className="space-y-5" aria-label="A short story in four scenes">
          <div className="space-y-1">
            <div className="ep-label">A short story in four scenes</div>
            <h2 className="ep-display text-2xl">
              From your screen to a sealed computer and back
            </h2>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* Scene 1 */}
            <InkReveal delayMs={0} className="h-full">
              <div className="ep-card p-5 h-full flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="ep-label">Scene One · Seal check</div>
                  <svg
                    viewBox="0 0 140 76"
                    className="h-16 w-full text-ink"
                    fill="none"
                    aria-hidden="true"
                  >
                    {/* Browser card */}
                    <rect
                      x="10"
                      y="16"
                      width="40"
                      height="44"
                      rx="4"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      fill="var(--color-paper-2)"
                    />
                    <line
                      x1="18"
                      y1="28"
                      x2="42"
                      y2="28"
                      stroke="currentColor"
                      strokeWidth="1.4"
                      strokeLinecap="round"
                    />
                    <line
                      x1="18"
                      y1="36"
                      x2="36"
                      y2="36"
                      stroke="currentColor"
                      strokeWidth="1.4"
                      strokeLinecap="round"
                    />
                    {/* Flowing ink line */}
                    <path
                      d="M54 38 H82"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      className="deroute-anim-flow"
                    />
                    {/* Living wax/ink seal */}
                    <g className="deroute-anim-pulse">
                      <circle
                        cx="104"
                        cy="38"
                        r="18"
                        fill="currentColor"
                      />
                      <path
                        d="M96 38 L102 44 L113 32"
                        stroke="var(--color-paper)"
                        strokeWidth="2.2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </g>
                  </svg>
                  <p className="text-sm leading-relaxed text-ink">
                    Before a single word leaves your screen, your browser runs a
                    seal check to make sure the distant sealed computer is
                    genuine and untouched.
                  </p>
                </div>
              </div>
            </InkReveal>

            {/* Scene 2 */}
            <InkReveal delayMs={80} className="h-full">
              <div className="ep-card p-5 h-full flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="ep-label">Scene Two · Hide and lock</div>
                  <svg
                    viewBox="0 0 140 76"
                    className="h-16 w-full text-ink"
                    fill="none"
                    aria-hidden="true"
                  >
                    {/* Note with ink blot masking personal details */}
                    <rect
                      x="10"
                      y="20"
                      width="42"
                      height="36"
                      rx="4"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      fill="var(--color-paper-2)"
                    />
                    <rect
                      x="17"
                      y="28"
                      width="28"
                      height="8"
                      rx="3"
                      fill="currentColor"
                      className="deroute-anim-pulse"
                    />
                    <line
                      x1="17"
                      y1="44"
                      x2="38"
                      y2="44"
                      stroke="currentColor"
                      strokeWidth="1.4"
                      strokeLinecap="round"
                    />
                    <path
                      d="M56 38 H82"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      className="deroute-anim-flow"
                    />
                    {/* Padlocked box */}
                    <g className="deroute-anim-pulse">
                      <rect
                        x="88"
                        y="30"
                        width="34"
                        height="26"
                        rx="4"
                        fill="currentColor"
                      />
                      <path
                        d="M97 30 V23 C97 17 113 17 113 23 V30"
                        stroke="currentColor"
                        strokeWidth="1.8"
                      />
                      <circle
                        cx="105"
                        cy="43"
                        r="2.5"
                        fill="var(--color-paper)"
                      />
                    </g>
                  </svg>
                  <p className="text-sm leading-relaxed text-ink">
                    We hide your personal details before anything leaves your
                    device, make every message look the same size from outside,
                    and lock it so only the sealed computer can open it.
                  </p>
                </div>
              </div>
            </InkReveal>

            {/* Scene 3 */}
            <InkReveal delayMs={160} className="h-full">
              <div className="ep-card p-5 h-full flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="ep-label">Scene Three · Inside the room</div>
                  <svg
                    viewBox="0 0 140 76"
                    className="h-16 w-full text-ink"
                    fill="none"
                    aria-hidden="true"
                  >
                    {/* Outer sealed chamber */}
                    <rect
                      x="22"
                      y="10"
                      width="96"
                      height="56"
                      rx="6"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      strokeDasharray="5 3"
                      fill="var(--color-paper-2)"
                    />
                    {/* Inner sealed computer with living ink drop */}
                    <rect
                      x="38"
                      y="20"
                      width="64"
                      height="36"
                      rx="4"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      fill="var(--color-paper)"
                    />
                    <g className="deroute-anim-pulse">
                      <circle cx="58" cy="38" r="7" fill="currentColor" />
                      <circle cx="70" cy="38" r="5" fill="currentColor" />
                      <circle cx="81" cy="38" r="6" fill="currentColor" />
                    </g>
                  </svg>
                  <p className="text-sm leading-relaxed text-ink">
                    The sealed computer opens your message inside its locked
                    room, writes the answer, and locks the reply back to you
                    without our server ever seeing a word.
                  </p>
                </div>
              </div>
            </InkReveal>

            {/* Scene 4 */}
            <InkReveal delayMs={240} className="h-full">
              <div className="ep-card p-5 h-full flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="ep-label">Scene Four · Dissolve the key</div>
                  <svg
                    viewBox="0 0 140 76"
                    className="h-16 w-full text-ink"
                    fill="none"
                    aria-hidden="true"
                  >
                    {/* Half key dissolving into floating ink droplets */}
                    <circle
                      cx="40"
                      cy="38"
                      r="11"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      fill="var(--color-paper-2)"
                    />
                    <path
                      d="M51 38 H74"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                    />
                    <g className="deroute-anim-drift">
                      <circle cx="86" cy="34" r="3" fill="currentColor" />
                      <circle cx="98" cy="43" r="2.2" fill="currentColor" />
                      <circle cx="109" cy="29" r="2" fill="currentColor" />
                      <circle cx="118" cy="39" r="1.5" fill="currentColor" />
                    </g>
                  </svg>
                  <p className="text-sm leading-relaxed text-ink">
                    When you close the chat, the temporary key dissolves into
                    blank paper so nobody can ever open that conversation later.
                  </p>
                </div>
              </div>
            </InkReveal>
          </div>

          <TechDetails label="What really happened">
            <div className="space-y-2 pt-2 text-xs text-ink-2 max-w-[72ch]">
              <p className="leading-relaxed">
                <strong>Scene 1 (Attestation):</strong> Your browser fetches the
                1,184-byte AMD SEV-SNP hardware report from{" "}
                <code className="font-mono text-ink">/api/relay/attestation</code>
                , verifies the ECDSA P-384 VCEK signature chain, checks that
                guest policy bit 19 (DEBUG) is 0, and matches the launch
                measurement against the Sigstore / Rekor transparency log and
                Arc testnet anchor.
              </p>
              <p className="leading-relaxed">
                <strong>Scene 2 (PII Scrub + HPKE):</strong>{" "}
                <code className="font-mono text-ink">preparePrompt</code>{" "}
                replaces emails, API keys, dates, and currency amounts with
                local placeholders, pads the JSON payload to a power-of-two
                bucket, and encapsulates it with RFC 9180 HPKE (DHKEM(X25519,
                HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the enclave&apos;s
                bound public key.
              </p>
              <p className="leading-relaxed">
                <strong>Scene 3 (Enclave Execution):</strong> The deRoute relay
                forwards the encrypted EHBP frame without holding the private
                key. Decryption and inference happen solely inside hardware-encrypted
                CPU/GPU enclave memory.
              </p>
              <p className="leading-relaxed">
                <strong>Scene 4 (Key Zeroization):</strong> Ending the session
                overwrites the 256-bit ephemeral session key and buffers with
                zeros (<code className="font-mono text-ink">0x00</code>), so any
                captured ciphertext or RAM dump fails AES-256-GCM authentication.
              </p>
            </div>
          </TechDetails>
        </section>

        {/* Interactive 4-round Game */}
        <section id="play-game" className="space-y-3 scroll-mt-6">
          <div className="space-y-1">
            <div className="ep-label">Play the four rounds</div>
            <h2 className="ep-display text-2xl">
              Try each step yourself in under a minute
            </h2>
            <p className="max-w-[68ch] text-sm text-ink-2">
              Collect all four ink drops below. Each round uses the real locks
              underneath and explains what happened in one plain sentence.
            </p>
          </div>
          <EnclaveGauntlet />
        </section>

        {/* What each person can see */}
        <section className="space-y-3">
          <PacketSniffer />
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
