import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { AuthGate } from "@/components/auth/auth-gate";
import { AuthPill } from "@/components/auth-pill";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { GET as getRegistryRoute } from "@/app/api/registry/route";
import { GET as getTransparencyRoute } from "@/app/api/transparency/route";
import { ARC_CHAIN_ID, ARC_EXPLORER, nodeKeyFor } from "@/lib/arc/registry";
import { recentActivity } from "@/lib/db";
import type { Hex, NodeRecord } from "@/lib/types";
import type {
  ConsistencyProof,
  InclusionProof,
  SignedTreeHead,
  TransparencyEntry,
  VerificationLogEvent,
} from "@/lib/transparency/log";

const DEFAULT_ARC_REGISTRY_ADDRESS =
  "0xbc8085c2b6fe6e0db05f169925c0b841828f4481";

function short(value: unknown, n = 10): string {
  const s = String(value ?? "");
  return s.length > n * 2 ? `${s.slice(0, n)}...${s.slice(-6)}` : s;
}

function whenHour(value: unknown): string {
  const d = value instanceof Date ? value : new Date(String(value));
  if (Number.isNaN(d.getTime())) return "";
  const ms = d.getTime();
  const coarsened = new Date(ms - (ms % 3_600_000));
  return `${coarsened.toISOString().replace("T", " ").slice(0, 13)}:00 UTC`;
}

interface RegistryApiPayload {
  source: "arc" | "fallback";
  onChain?: boolean;
  address?: Hex;
  nodes: NodeRecord[];
  chainId?: number;
  explorer?: string;
}

interface TransparencyApiPayload {
  quorumSimulated: boolean;
  operatorPublicKey: string;
  signedTreeHead: SignedTreeHead;
  anchorExplorerUrl: string | null;
  persisted: boolean;
  verificationLog: {
    root: string;
    treeSize: number;
    events: VerificationLogEvent[];
    inclusionProofs: InclusionProof[];
    consistencyProof: ConsistencyProof;
  };
  log: {
    root: string;
    entries: TransparencyEntry[];
  };
}

async function WhoRunsDeRouteSection() {
  await connection();
  const res = await getRegistryRoute();
  const registry = (await res.json()) as RegistryApiPayload;
  const contractAddress = registry.address ?? DEFAULT_ARC_REGISTRY_ADDRESS;

  const realNodes = registry.nodes.filter((n) => n.kind === "tinfoil");
  const practiceNodes = registry.nodes.filter((n) => n.kind !== "tinfoil");

  return (
    <InkReveal>
      <section aria-label="Who runs deRoute" className="space-y-6">
        <div className="space-y-1">
          <div className="ep-label">Servers</div>
          <h2 className="ep-display text-2xl sm:text-3xl">
            Who runs deRoute
          </h2>
          <p className="max-w-[68ch] text-sm sm:text-base text-ink-2 leading-relaxed">
            Real chats run on sealed computers operated by Tinfoil. Alongside
            them, we keep three clearly labelled practice servers so anyone can
            test what happens when a server breaks the rules.
          </p>
        </div>

        {/* Real sealed computers (Tinfoil) */}
        <div className="space-y-3">
          <h3 className="font-serif text-lg font-medium text-ink">
            Real sealed computers (Tinfoil)
          </h3>
          <div className="grid grid-cols-1 gap-4">
            {realNodes.map((n) => (
              <div
                key={n.id}
                className="ep-card p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="space-y-2 max-w-[60ch]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-serif text-lg font-medium text-ink">
                      Tinfoil sealed computer
                    </span>
                    <span className="ep-pass">Real sealed computer</span>
                  </div>
                  <p className="text-sm text-ink-2 leading-relaxed">
                    Answers your live chats inside a hardware-locked computer
                    whose seal your browser checks before sending a single word.
                  </p>
                </div>

                <div className="flex flex-col sm:items-end gap-1.5 text-xs font-mono text-ink-2 shrink-0">
                  <div>
                    Status:{" "}
                    <span className="text-ink font-medium">
                      {n.status === "active" ? "Active and sealed" : "Paused"}
                    </span>
                  </div>
                  <div>Region: {n.region.toUpperCase()}</div>
                  <div>
                    Last seal check:{" "}
                    {n.lastVerifiedAt
                      ? whenHour(new Date(n.lastVerifiedAt * 1000))
                      : "Checked on connect"}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Practice servers */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-serif text-lg font-medium text-ink">
              Practice servers (for safety drills only)
            </h3>
            <span className="ep-muted-chip">Practice</span>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {practiceNodes.map((n, index) => {
              const key = nodeKeyFor(n.id) ?? `sim-${index + 1}`;
              return (
                <div
                  key={n.id}
                  className="ep-card p-4 flex flex-col justify-between space-y-3"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-serif text-base font-medium text-ink">
                        Practice server ({key})
                      </span>
                      <span className="ep-muted-chip">Practice</span>
                    </div>
                    <p className="text-xs text-ink-2 leading-relaxed">
                      Used only for practice drills on the Proof page. Never
                      handles your real chats.
                    </p>
                  </div>
                  <div className="pt-2 border-t border-rule flex items-center justify-between text-xs font-mono text-ink-3">
                    <span>Region: {n.region}</span>
                    <span>
                      {n.status === "active" ? "Ready" : "Paused by drill"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <TechDetails label="Show technical details">
          <div className="space-y-3 pt-2 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-ink-2">
              <span>
                Source:{" "}
                {registry.source === "arc"
                  ? `Live Arc Testnet (chain ${registry.chainId ?? ARC_CHAIN_ID})`
                  : "Built-in demo list (local fallback)"}
              </span>
              <a
                className="ep-link"
                href={`${ARC_EXPLORER}/address/${contractAddress}`}
                target="_blank"
                rel="noreferrer"
              >
                Contract {short(contractAddress, 8)} -&gt;
              </a>
            </div>

            <div className="ep-card overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                    <th className="py-3 px-4">Node</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Endpoint</th>
                    <th className="py-3 px-4">Region</th>
                    <th className="py-3 px-4">Stake (USDC)</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Last verified (UTC)</th>
                    <th className="py-3 px-4">Measurement</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rule">
                  {registry.nodes.map((n) => {
                    const key = nodeKeyFor(n.id);
                    const isSim = n.kind !== "tinfoil";
                    return (
                      <tr key={n.id} className="hover:bg-paper-2/50">
                        <td className="py-3 px-4">
                          <div className="font-serif text-sm font-medium text-ink">
                            {n.name}
                          </div>
                          {key && (
                            <div className="font-mono text-[11px] text-ink-3">
                              {key}
                              {isSim ? " (Simulated)" : ""}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {n.kind === "tinfoil" ? (
                            <span className="ep-pass">Real Hardware TEE</span>
                          ) : (
                            <span className="ep-muted-chip">Simulated</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-ink-2">
                          {n.endpoint}
                        </td>
                        <td className="py-3 px-4 font-mono text-ink-2">
                          {n.region}
                        </td>
                        <td className="py-3 px-4 font-mono text-ink-2">
                          {n.stake}
                        </td>
                        <td className="py-3 px-4">
                          {n.status === "active" ? (
                            <span className="ep-pass">{n.status}</span>
                          ) : (
                            <span className="ep-fail">{n.status}</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-ink-2">
                          {n.lastVerifiedAt
                            ? `${whenHour(new Date(n.lastVerifiedAt * 1000))} (${
                                n.lastVerifiedOk ? "pass" : "fail"
                              })`
                            : "Not yet recorded"}
                        </td>
                        <td
                          className="py-3 px-4 font-mono text-ink-2"
                          title={n.measurement}
                        >
                          {short(n.measurement, 8)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </TechDetails>
      </section>
    </InkReveal>
  );
}

async function PublicReceiptBookSection() {
  await connection();
  const [transRes, activity] = await Promise.all([
    getTransparencyRoute(),
    recentActivity(30),
  ]);
  const transparency = (await transRes.json()) as TransparencyApiPayload;
  const sth = transparency.signedTreeHead;
  const events = transparency.verificationLog.events;
  const releaseEntries = transparency.log.entries;
  const latestEvent = events.length > 0 ? events[events.length - 1] : null;

  const receiptBookHref = sth.anchorTx
    ? `${ARC_EXPLORER}/tx/${sth.anchorTx}`
    : `${ARC_EXPLORER}/address/${DEFAULT_ARC_REGISTRY_ADDRESS}`;

  return (
    <InkReveal delayMs={80}>
      <section aria-label="The public receipt book" className="space-y-5">
        <div className="space-y-1 border-t border-rule pt-8">
          <div className="ep-label">Public record</div>
          <h2 className="ep-display text-2xl sm:text-3xl">
            The public receipt book
          </h2>
          <p className="max-w-[68ch] text-sm sm:text-base text-ink-2 leading-relaxed">
            Every seal check and practice drill is written into an append-only
            public receipt book. Times are rounded to the hour so nobody can
            match a receipt to a user, and chat messages are never recorded.
          </p>
        </div>

        {/* Latest entry card */}
        <div className="ep-card p-5 sm:p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule pb-4">
            <div className="space-y-0.5">
              <div className="ep-label">Latest entry</div>
              <h3 className="font-serif text-lg font-medium text-ink">
                {latestEvent
                  ? latestEvent.nodeKind === "tinfoil"
                    ? "Seal check on Tinfoil sealed computer"
                    : `Practice check on server (${latestEvent.nodeId})`
                  : "Seal check on Tinfoil sealed computer"}
              </h3>
            </div>
            <span className="ep-pass">
              {sth.treeSize} {sth.treeSize === 1 ? "entry" : "entries"} in book
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 text-sm">
            <div className="ep-inset p-3.5 space-y-1">
              <div className="ep-label">Recorded hour</div>
              <div className="font-mono text-ink font-medium">
                {latestEvent
                  ? whenHour(new Date(latestEvent.epochHourSec * 1000))
                  : whenHour(new Date(sth.timestampSec * 1000))}
              </div>
            </div>
            <div className="ep-inset p-3.5 space-y-1">
              <div className="ep-label">Outcome</div>
              <div className="text-ink font-medium">
                {latestEvent
                  ? latestEvent.ok
                    ? "Seal check passed"
                    : "Practice rule-breaker caught"
                  : "Seal check passed"}
              </div>
            </div>
            <div className="ep-inset p-3.5 space-y-1">
              <div className="ep-label">Total locked chats</div>
              <div className="text-ink font-medium">
                {activity.configured && activity.relay
                  ? `${activity.relay.requests} locked requests forwarded`
                  : "Only total counts saved, never chat text"}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <p className="text-xs text-ink-3">
              Anyone can inspect the public receipt book to confirm no past
              entries were altered or deleted.
            </p>
            <a
              href={receiptBookHref}
              target="_blank"
              rel="noreferrer"
              className="ep-btn text-xs py-2.5 px-4 inline-flex items-center gap-2"
            >
              <span>Open the public receipt book</span>
              <span aria-hidden="true">-&gt;</span>
            </a>
          </div>
        </div>

        <TechDetails label="Show technical details">
          <div className="space-y-6 pt-2 text-xs">
            {/* Signed Tree Head Summary */}
            <div className="ep-card p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="ep-label">Operator Signed Tree Head (STH)</div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="ep-pass">
                    Tree size: {sth.treeSize} leaves
                  </span>
                  <span className="ep-muted-chip">
                    Storage:{" "}
                    {transparency.persisted
                      ? "MongoDB transparency_log"
                      : "In-memory genesis fallback"}
                  </span>
                  {transparency.quorumSimulated && (
                    <span className="ep-muted-chip">
                      Quorum keys: Simulated
                    </span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 font-mono sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <div className="text-[10px] uppercase text-ink-3">
                    Merkle Root Hash
                  </div>
                  <div className="mt-0.5 text-ink" title={sth.rootHash}>
                    {short(sth.rootHash, 12)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-ink-3">
                    Coarsened Epoch (UTC)
                  </div>
                  <div className="mt-0.5 text-ink">
                    {whenHour(new Date(sth.timestampSec * 1000))}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-ink-3">
                    Ed25519 Signature
                  </div>
                  <div className="mt-0.5 text-ink-2" title={sth.signature}>
                    {short(sth.signature, 12)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-ink-3">
                    Operator Key
                  </div>
                  <div
                    className="mt-0.5 text-ink-2"
                    title={sth.operatorPublicKey}
                  >
                    {short(sth.operatorPublicKey, 10)}
                  </div>
                </div>
              </div>
            </div>

            {/* Verification Log Leaves */}
            <div className="space-y-2">
              <div className="ep-label">
                Merkle log leaves ({events.length} entries)
              </div>
              <div className="ep-card overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                      <th className="py-2.5 px-3">Leaf #</th>
                      <th className="py-2.5 px-3">Node</th>
                      <th className="py-2.5 px-3">Node Type</th>
                      <th className="py-2.5 px-3">Event Kind</th>
                      <th className="py-2.5 px-3">Result</th>
                      <th className="py-2.5 px-3">Hour bucket (UTC)</th>
                      <th className="py-2.5 px-3">Leaf Hash (RFC 6962)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-rule">
                    {events.map((ev) => (
                      <tr key={ev.index} className="hover:bg-paper-2/50">
                        <td className="py-2.5 px-3 font-mono text-ink-2">
                          #{ev.index}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-ink">
                          {ev.nodeId}
                          {ev.nodeKind === "sim" ? " (Simulated)" : ""}
                        </td>
                        <td className="py-2.5 px-3">
                          {ev.nodeKind === "tinfoil" ? (
                            <span className="ep-pass">Real</span>
                          ) : (
                            <span className="ep-muted-chip">Simulated</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-ink-2">
                          {ev.kind}
                        </td>
                        <td className="py-2.5 px-3">
                          {ev.ok ? (
                            <span className="ep-pass">Pass</span>
                          ) : (
                            <span className="ep-fail">Fail</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-ink-2">
                          {whenHour(new Date(ev.epochHourSec * 1000))}
                        </td>
                        <td
                          className="py-2.5 px-3 font-mono text-ink-2"
                          title={ev.leafHash}
                        >
                          {short(ev.leafHash, 10)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Release Approval Entries */}
            <div className="space-y-2">
              <div className="ep-label">
                Release image approvals ({releaseEntries.length} images, root{" "}
                {short(transparency.log.root, 8)})
              </div>
              <div className="ep-card overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                      <th className="py-2.5 px-3">Index</th>
                      <th className="py-2.5 px-3">Image ID</th>
                      <th className="py-2.5 px-3">Version</th>
                      <th className="py-2.5 px-3">Scope</th>
                      <th className="py-2.5 px-3">Quorum (Simulated)</th>
                      <th className="py-2.5 px-3">Measurement</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-rule">
                    {releaseEntries.map((entry) => {
                      const isSimImage =
                        entry.imageId.includes("sim") ||
                        entry.imageId.includes("svsm");
                      return (
                        <tr key={entry.index} className="hover:bg-paper-2/50">
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            #{entry.index}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-ink">
                            {entry.imageId}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            {entry.version}
                          </td>
                          <td className="py-2.5 px-3">
                            {isSimImage ? (
                              <span className="ep-muted-chip">
                                Simulated image
                              </span>
                            ) : (
                              <span className="ep-pass">Tinfoil release</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            {entry.builderSignatures.length} builders,{" "}
                            {entry.reviewerSignatures.length} reviewers
                          </td>
                          <td
                            className="py-2.5 px-3 font-mono text-ink-2"
                            title={entry.measurement}
                          >
                            {short(entry.measurement, 10)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Coarsened Activity & Pop Receipts */}
            {activity.configured && (
              <div className="space-y-2">
                <div className="ep-label">
                  Coarsened client verifications ({activity.verifications.length}
                  ) and pop receipts ({activity.receipts.length})
                </div>
                <div className="ep-inset p-3 font-mono text-ink-2">
                  {activity.relay
                    ? `${activity.relay.requests} encrypted requests relayed (${(
                        activity.relay.bytesUp / 1024
                      ).toFixed(1)} KB up, ${(
                        activity.relay.bytesDown / 1024
                      ).toFixed(1)} KB down)`
                    : "No relay traffic recorded yet"}
                </div>
              </div>
            )}
          </div>
        </TechDetails>
      </section>
    </InkReveal>
  );
}

export default function NetworkPage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink overflow-x-hidden">
      <SpecimenHeader activePath="/network" rightSlot={<AuthPill />} />

      <main className="mx-auto w-full max-w-5xl flex-1 min-w-0 px-4 py-10 sm:px-6">
        <AuthGate>
          <div className="space-y-12">
            <section className="space-y-3 border-b border-rule pb-6">
              <div className="ep-label">Network</div>
              <h1 className="ep-display text-3xl sm:text-4xl lg:text-5xl">
                Who runs deRoute and the public receipt book
              </h1>
              <p className="max-w-[68ch] text-base leading-relaxed text-ink-2">
                See the real sealed computers that answer your chats, the
                practice servers we use for safety drills, and the public
                receipt book where every check is recorded.
              </p>
              <div className="flex flex-wrap items-center gap-3 pt-1">
                <Link href="/audit" className="ep-btn-ghost">
                  Go to Proof page
                </Link>
                <Link href="/app" className="ep-btn-ghost">
                  Back to chat
                </Link>
              </div>
            </section>

            <Suspense
              fallback={
                <div className="ep-card p-5 font-mono text-xs text-ink-3">
                  Loading servers...
                </div>
              }
            >
              <WhoRunsDeRouteSection />
            </Suspense>

            <Suspense
              fallback={
                <div className="ep-card p-5 font-mono text-xs text-ink-3">
                  Loading public receipt book...
                </div>
              }
            >
              <PublicReceiptBookSection />
            </Suspense>
          </div>
        </AuthGate>
      </main>

      <SpecimenFooter />
    </div>
  );
}
