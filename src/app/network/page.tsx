import { connection } from "next/server";
import { Suspense } from "react";
import { AuthGate } from "@/components/auth/auth-gate";
import { AuthPill } from "@/components/auth-pill";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { GET as getRegistryRoute } from "@/app/api/registry/route";
import { GET as getTransparencyRoute } from "@/app/api/transparency/route";
import {
  ARC_CHAIN_ID,
  ARC_EXPLORER,
  nodeKeyFor,
  type EnrichedNodeRecord,
} from "@/lib/arc/registry";
import { recentActivity } from "@/lib/db";
import type { Hex } from "@/lib/types";
import type {
  ConsistencyProof,
  InclusionProof,
  SignedTreeHead,
  VerificationLogEvent,
  VerifierSubmissionRecord,
} from "@/lib/transparency/log";

const DEFAULT_ARC_REGISTRY_ADDRESS =
  "0xbc8085c2b6fe6e0db05f169925c0b841828f4481";

function plainNodeName(rawName: unknown): string {
  const s = String(rawName ?? "Tinfoil sealed computer");
  return s
    .replace(/\bconfidential router\b/i, "router")
    .replace(/\benclave\b/gi, "sealed computer");
}

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
  nodes: EnrichedNodeRecord[];
  chainId?: number;
  explorer?: string;
}

interface TransparencyApiPayload {
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
  distinctVerifierCount?: number;
  totalSubmissions?: number;
  recentSubmissions?: VerifierSubmissionRecord[];
}

async function WhoRunsDeRouteSection() {
  await connection();
  const res = await getRegistryRoute();
  const registry = (await res.json()) as RegistryApiPayload;
  const contractAddress = registry.address ?? DEFAULT_ARC_REGISTRY_ADDRESS;

  const realNodes = registry.nodes.filter((n) => n.kind === "tinfoil");

  return (
    <InkReveal>
      <section aria-label="Who runs deRoute" className="space-y-6">
        <div className="space-y-1">
          <div className="ep-label">Servers</div>
          <h2 className="ep-display text-2xl sm:text-3xl">
            Who runs deRoute
          </h2>
          <p className="max-w-[68ch] text-sm sm:text-base text-ink-2 leading-relaxed">
            Every chat runs on sealed computers operated by Tinfoil. Your
            browser checks the factory seal and software release on these
            computers before sending a single word.
          </p>
        </div>

        {/* Real sealed computers (Tinfoil) */}
        <div className="space-y-3">
          <h3 className="font-serif text-lg font-medium text-ink">
            Sealed computers (Tinfoil) ({realNodes.length})
          </h3>
          <div className="grid grid-cols-1 gap-4">
            {realNodes.map((n) => {
              const hostCount =
                n.healthyHosts ??
                n.verifiedHosts ??
                n.configuredHosts ??
                n.enclaveHosts?.length ??
                1;
              return (
                <div
                  key={n.id}
                  className="ep-card p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="space-y-2 max-w-[60ch]">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-serif text-lg font-medium text-ink">
                        {plainNodeName(n.name)}
                      </span>
                      <span className="ep-pass">Sealed computer</span>
                      {n.releaseTag && (
                        <span className="ep-muted-chip">
                          Release {n.releaseTag}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-ink-2 leading-relaxed">
                      Answers your live chats inside a hardware-locked computer
                      whose seal your browser checks before sending a single
                      word.
                    </p>
                  </div>

                  <div className="flex flex-col sm:items-end gap-1.5 text-xs font-mono text-ink-2 shrink-0">
                    <div>
                      Status:{" "}
                      <span className="text-ink font-medium">
                        {n.status === "active" ? "Active and sealed" : "Paused"}
                      </span>
                    </div>
                    <div>
                      Active computers:{" "}
                      <span className="text-ink font-medium">
                        {hostCount} sealed{" "}
                        {hostCount === 1 ? "computer" : "computers"}
                      </span>
                    </div>
                    {n.releaseTag && (
                      <div>Software version: {n.releaseTag}</div>
                    )}
                    <div>Region: {n.region.toUpperCase()}</div>
                    <div>
                      Last seal check:{" "}
                      {n.lastVerifiedAt
                        ? whenHour(new Date(n.lastVerifiedAt * 1000))
                        : "Checked on connect"}
                    </div>
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
                  : "On-chain registry cache"}
              </span>
              <a
                className="ep-link"
                href={`${ARC_EXPLORER}/address/${contractAddress}`}
                target="_blank"
                rel="noopener noreferrer"
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
                  {realNodes.map((n) => {
                    const key = nodeKeyFor(n.id);
                    return (
                      <tr key={n.id} className="hover:bg-paper-2/50">
                        <td className="py-3 px-4">
                          <div className="font-serif text-sm font-medium text-ink">
                            {n.name}
                          </div>
                          {key && (
                            <div className="font-mono text-[11px] text-ink-3">
                              {key}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className="ep-pass">Hardware TEE</span>
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
  const events = (transparency.verificationLog?.events ?? []).filter(
    (ev) => ev.nodeKind === "tinfoil",
  );
  const recentSubmissions = transparency.recentSubmissions ?? [];
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
            Every server seal check is written into an append-only public
            receipt book. Times are rounded to the hour so nobody can match a
            receipt to a user, and chat messages are never recorded.
          </p>
        </div>

        {/* Latest entry card */}
        <div className="ep-card p-5 sm:p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule pb-4">
            <div className="space-y-0.5">
              <div className="ep-label">Latest entry</div>
              <h3 className="font-serif text-lg font-medium text-ink">
                Seal check on{" "}
                {latestEvent
                  ? plainNodeName(latestEvent.nodeId)
                  : "Tinfoil sealed computer"}
              </h3>
            </div>
            <span className="ep-pass">
              {events.length} {events.length === 1 ? "entry" : "entries"} in
              book
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 text-sm">
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
                    : "Seal check failed"
                  : "Seal check passed"}
              </div>
            </div>
            <div className="ep-inset p-3.5 space-y-1">
              <div className="ep-label">Independent checks</div>
              <div className="text-ink font-medium">
                {transparency.distinctVerifierCount ?? 0}{" "}
                {(transparency.distinctVerifierCount ?? 0) === 1
                  ? "person has"
                  : "people have"}{" "}
                independently checked deRoute (
                {transparency.totalSubmissions ?? 0} signed{" "}
                {(transparency.totalSubmissions ?? 0) === 1
                  ? "check"
                  : "checks"}
                )
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
              rel="noopener noreferrer"
              className="ep-btn ep-ink-button ep-ink-button-primary text-xs py-2.5 px-4 inline-flex items-center gap-2"
            >
              <span className="ep-ink-button-label">
                Open the public receipt book -&gt;
              </span>
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
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="ep-pass">Hardware TEE</span>
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

            {/* Independent Verifier Submissions */}
            <div className="space-y-2">
              <div className="ep-label">
                Independent CLI verifications (
                {transparency.distinctVerifierCount ?? 0} verifiers,{" "}
                {transparency.totalSubmissions ?? 0} submissions)
              </div>
              <div className="ep-inset p-3 font-mono text-ink-2">
                Run <code>node scripts/drouter-cli.mjs verify --submit</code> to
                sign and submit an independent C1-C7 verification claim.
              </div>
              {recentSubmissions.length > 0 && (
                <div className="ep-card overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                        <th className="py-2.5 px-3">Leaf #</th>
                        <th className="py-2.5 px-3">Verifier Fingerprint</th>
                        <th className="py-2.5 px-3">Router Host</th>
                        <th className="py-2.5 px-3">Result</th>
                        <th className="py-2.5 px-3">Hour bucket (UTC)</th>
                        <th className="py-2.5 px-3">Evidence Hash</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-rule">
                      {recentSubmissions.map((sub) => (
                        <tr
                          key={`${sub.verifierFingerprint}-${sub.leafIndex}`}
                          className="hover:bg-paper-2/50"
                        >
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            #{sub.leafIndex}
                          </td>
                          <td
                            className="py-2.5 px-3 font-mono text-ink"
                            title={sub.verifierFingerprint}
                          >
                            {short(sub.verifierFingerprint, 10)}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            {sub.router?.enclaveHost ?? "router-0.tinfoil.sh"}
                          </td>
                          <td className="py-2.5 px-3">
                            {sub.overallOk ? (
                              <span className="ep-pass">Pass</span>
                            ) : (
                              <span className="ep-fail">Fail</span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-ink-2">
                            {whenHour(new Date(sub.epochHourSec * 1000))}
                          </td>
                          <td
                            className="py-2.5 px-3 font-mono text-ink-2"
                            title={sub.evidenceHash}
                          >
                            {short(sub.evidenceHash, 10)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
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
                See the sealed computers that answer your chats and the public
                receipt book where every seal check is recorded.
              </p>
              <div className="flex flex-wrap items-center gap-3 pt-1">
                <InkButton href="/audit" variant="ghost">
                  Go to Proof page
                </InkButton>
                <InkButton href="/app" variant="ghost">
                  Back to chat
                </InkButton>
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
