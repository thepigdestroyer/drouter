import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { ARC_CHAIN_ID, ARC_EXPLORER, listNodes } from "@/lib/arc/registry";
import { recentActivity } from "@/lib/db";

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

async function Registry() {
  await connection();
  const registry = await listNodes();
  const contractAddress = registry.address ?? DEFAULT_ARC_REGISTRY_ADDRESS;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="ep-label">Registered Nodes</div>
          <h2 className="ep-display text-2xl mt-0.5">
            Node directory ({registry.nodes.length} nodes)
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-ink-2">
          <span className="ep-muted-chip">
            Source:{" "}
            {registry.source === "arc"
              ? `Live Arc Testnet (chain ${ARC_CHAIN_ID})`
              : "Built-in demo list (local fallback)"}
          </span>
          <a
            className="ep-link"
            href={`${ARC_EXPLORER}/address/${contractAddress}`}
            target="_blank"
            rel="noreferrer"
          >
            Arc registry {short(contractAddress, 8)}
          </a>
        </div>
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
            {registry.nodes.map((n) => (
              <tr key={n.id} className="hover:bg-paper-2/50">
                <td className="py-3 px-4 font-serif text-sm font-medium text-ink">
                  {n.name}
                </td>
                <td className="py-3 px-4">
                  {n.kind === "tinfoil" ? (
                    <span className="ep-pass">Real</span>
                  ) : (
                    <span className="ep-muted-chip">Simulated</span>
                  )}
                </td>
                <td className="py-3 px-4 font-mono text-ink-2">{n.endpoint}</td>
                <td className="py-3 px-4 font-mono text-ink-2">{n.region}</td>
                <td className="py-3 px-4 font-mono text-ink-2">{n.stake}</td>
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
                <td className="py-3 px-4 font-mono text-ink-2" title={n.measurement}>
                  {short(n.measurement, 8)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

async function Activity() {
  await connection();
  const activity = await recentActivity(30);

  if (!activity.configured) {
    return (
      <section className="ep-card p-5 space-y-2">
        <div className="ep-label">Coarsened Transparency Log</div>
        <p className="text-sm text-ink-2">
          MongoDB transparency log is not connected in this environment. When connected, only hour-coarsened verification records, receipt hashes, and aggregate relay byte counters are stored.
        </p>
      </section>
    );
  }

  return (
    <div className="space-y-8">
      {/* Aggregate Relay Counter */}
      <section className="ep-card p-5 space-y-2">
        <div className="ep-label">Aggregate Relay Counter</div>
        <div className="font-serif text-lg text-ink">
          {activity.relay
            ? `${activity.relay.requests} encrypted requests relayed (${(
                activity.relay.bytesUp / 1024
              ).toFixed(1)} KB up, ${(activity.relay.bytesDown / 1024).toFixed(
                1,
              )} KB down)`
            : "No relay traffic recorded yet"}
        </div>
        <p className="max-w-[68ch] text-xs text-ink-2">
          The relay increments one global counter instead of writing per-request rows. HTTP bodies are encrypted to the enclave and cannot be read here.
        </p>
      </section>

      {/* Coarsened Client Verifications */}
      <section className="space-y-3">
        <div>
          <div className="ep-label">Recent Coarsened Records</div>
          <h2 className="ep-display text-2xl mt-0.5">
            Client verifications (timestamps rounded to UTC hour)
          </h2>
        </div>

        <div className="ep-card overflow-x-auto">
          {activity.verifications.length === 0 ? (
            <div className="p-4 text-xs text-ink-2">
              No verification records logged yet.
            </div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                  <th className="py-3 px-4">Hour bucket (UTC)</th>
                  <th className="py-3 px-4">Node</th>
                  <th className="py-3 px-4">Result</th>
                  <th className="py-3 px-4">Checks</th>
                  <th className="py-3 px-4">Evidence hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule">
                {activity.verifications.map((v, i) => (
                  <tr key={i} className="hover:bg-paper-2/50">
                    <td className="py-3 px-4 font-mono text-ink-2">
                      {whenHour(v.at)}
                    </td>
                    <td className="py-3 px-4 font-medium text-ink">
                      {String(v.nodeName)}
                    </td>
                    <td className="py-3 px-4">
                      {v.ok ? (
                        <span className="ep-pass">Verified</span>
                      ) : (
                        <span className="ep-fail">Failed</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-ink-2">
                      {Array.isArray(v.checks)
                        ? (v.checks as { id: string; status: string }[])
                            .map(
                              (c) =>
                                `${c.id}:${
                                  c.status === "pass"
                                    ? "ok"
                                    : c.status === "fail"
                                      ? "fail"
                                      : "skip"
                                }`,
                            )
                            .join(" ")
                        : ""}
                    </td>
                    <td className="py-3 px-4 font-mono text-ink-2">
                      {short(v.evidenceHash)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {/* Coarsened Pop Receipts */}
      <section className="space-y-3">
        <div>
          <div className="ep-label">Session Destruction Proofs</div>
          <h2 className="ep-display text-2xl mt-0.5">
            Pop receipts (timestamps rounded to UTC hour)
          </h2>
        </div>

        <div className="ep-card overflow-x-auto">
          {activity.receipts.length === 0 ? (
            <div className="p-4 text-xs text-ink-2">
              No pop receipts logged yet.
            </div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-rule bg-paper-2 font-mono text-[11px] uppercase text-ink-3">
                  <th className="py-3 px-4">Hour bucket (UTC)</th>
                  <th className="py-3 px-4">Receipt hash</th>
                  <th className="py-3 px-4">Signature</th>
                  <th className="py-3 px-4">Arc transaction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule">
                {activity.receipts.map((r, i) => (
                  <tr key={i} className="hover:bg-paper-2/50">
                    <td className="py-3 px-4 font-mono text-ink-2">
                      {whenHour(r.at)}
                    </td>
                    <td className="py-3 px-4 font-mono text-ink">
                      {short(r.receiptHash)}
                    </td>
                    <td className="py-3 px-4">
                      {r.signatureVerified ? (
                        <span className="ep-pass">Verified</span>
                      ) : (
                        <span className="ep-fail">Invalid</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      {r.anchorTx ? (
                        <a
                          className="ep-link"
                          href={`${ARC_EXPLORER}/tx/${r.anchorTx}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {short(r.anchorTx, 8)}
                        </a>
                      ) : (
                        <span className="text-ink-3">Not anchored</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}

export default function NetworkPage() {
  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink">
      <SpecimenHeader activePath="/network" rightSlot={<AuthPill />} />

      <main className="mx-auto w-full max-w-5xl flex-1 space-y-10 px-4 py-10 sm:px-6">
        <section className="space-y-3 border-b border-rule pb-6">
          <div className="ep-label">Network &amp; Transparency Log</div>
          <h1 className="ep-display text-3xl sm:text-4xl">
            Registered nodes and coarsened public records.
          </h1>
          <p className="max-w-[68ch] text-base leading-relaxed text-ink-2">
            Public records show which hardware nodes are registered on Circle Arc and whether verification checks passed, while timestamps are rounded to the UTC hour and prompts are never logged.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <a
              href={`${ARC_EXPLORER}/address/${DEFAULT_ARC_REGISTRY_ADDRESS}`}
              target="_blank"
              rel="noreferrer"
              className="ep-btn-accent"
            >
              View Arc registry on explorer
            </a>
            <Link href="/" className="ep-btn-ghost">
              Back to console
            </Link>
          </div>
        </section>

        <Suspense
          fallback={
            <div className="ep-card p-5 font-mono text-xs text-ink-3">
              Loading node registry...
            </div>
          }
        >
          <Registry />
        </Suspense>

        <Suspense
          fallback={
            <div className="ep-card p-5 font-mono text-xs text-ink-3">
              Loading coarsened transparency log...
            </div>
          }
        >
          <Activity />
        </Suspense>
      </main>

      <SpecimenFooter />
    </div>
  );
}
