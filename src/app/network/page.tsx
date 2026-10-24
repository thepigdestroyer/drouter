import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { ARC_EXPLORER, listNodes } from "@/lib/arc/registry";
import { recentActivity } from "@/lib/db";

function short(value: unknown, n = 10): string {
  const s = String(value ?? "");
  return s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s;
}

function when(value: unknown): string {
  const d = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().replace("T", " ").slice(0, 19);
}

async function Registry() {
  await connection();
  const registry = await listNodes();
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">Node registry</h2>
        <span className="text-xs text-zinc-500">
          {registry.source === "arc" && registry.address ? (
            <a className="underline" href={`${ARC_EXPLORER}/address/${registry.address}`} target="_blank" rel="noreferrer">
              On Arc testnet · {short(registry.address, 8)}
            </a>
          ) : (
            "Built-in list (Arc contract not deployed yet)"
          )}
        </span>
      </div>
      <table className="w-full text-left text-xs">
        <thead className="text-zinc-500">
          <tr>
            <th className="py-1">Node</th>
            <th>Kind</th>
            <th>Region</th>
            <th>Stake (USDC)</th>
            <th>Status</th>
            <th>Last verified</th>
            <th>Measurement</th>
          </tr>
        </thead>
        <tbody className="text-zinc-300">
          {registry.nodes.map((n) => (
            <tr key={n.id} className="border-t border-zinc-900">
              <td className="py-1.5">{n.name}</td>
              <td>{n.kind === "tinfoil" ? "Real enclave" : "Simulated"}</td>
              <td>{n.region}</td>
              <td>{n.stake}</td>
              <td>{n.status}</td>
              <td>{n.lastVerifiedAt ? `${when(new Date(n.lastVerifiedAt * 1000))} ${n.lastVerifiedOk ? "✓" : "✗"}` : "never"}</td>
              <td className="font-mono">{short(n.measurement)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

async function Activity() {
  await connection();
  const activity = await recentActivity(30);
  if (!activity.configured) {
    return (
      <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-sm text-zinc-400">
        Transparency log not connected (MongoDB not configured).
      </section>
    );
  }
  return (
    <>
      <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-zinc-400">Relay</h2>
        <p className="text-sm text-zinc-300">
          {activity.relay
            ? `${activity.relay.requests} encrypted requests relayed · ${(activity.relay.bytesUp / 1024).toFixed(1)} KB up · ${(activity.relay.bytesDown / 1024).toFixed(1)} KB down`
            : "No relay traffic yet"}
        </p>
        <p className="mt-1 text-xs text-zinc-500">
          The relay records byte counts only. Bodies are HPKE-encrypted to the enclave and cannot be read or stored here.
        </p>
      </section>
      <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">Client verifications</h2>
        <table className="w-full text-left text-xs">
          <thead className="text-zinc-500">
            <tr>
              <th className="py-1">Time (UTC)</th>
              <th>Node</th>
              <th>Result</th>
              <th>Checks</th>
              <th>Evidence hash</th>
            </tr>
          </thead>
          <tbody className="text-zinc-300">
            {activity.verifications.map((v, i) => (
              <tr key={i} className="border-t border-zinc-900">
                <td className="py-1.5">{when(v.at)}</td>
                <td>{String(v.nodeName)}</td>
                <td className={v.ok ? "text-emerald-400" : "text-rose-400"}>{v.ok ? "verified" : "failed"}</td>
                <td className="font-mono">
                  {(v.checks as { id: string; status: string }[])
                    .map((c) => `${c.id}${c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "–"}`)
                    .join(" ")}
                </td>
                <td className="font-mono">{short(v.evidenceHash)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">Pop receipts</h2>
        <table className="w-full text-left text-xs">
          <thead className="text-zinc-500">
            <tr>
              <th className="py-1">Time (UTC)</th>
              <th>Receipt hash</th>
              <th>Signature</th>
              <th>Arc anchor</th>
            </tr>
          </thead>
          <tbody className="text-zinc-300">
            {activity.receipts.map((r, i) => (
              <tr key={i} className="border-t border-zinc-900">
                <td className="py-1.5">{when(r.at)}</td>
                <td className="font-mono">{short(r.receiptHash)}</td>
                <td>{r.signatureVerified ? "verified" : "invalid"}</td>
                <td>
                  {r.anchorTx ? (
                    <a className="underline" href={`${ARC_EXPLORER}/tx/${r.anchorTx}`} target="_blank" rel="noreferrer">
                      {short(r.anchorTx, 8)}
                    </a>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}

export default function NetworkPage() {
  return (
    <main className="mx-auto flex max-w-6xl flex-col gap-4 p-4">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-50">Network &amp; transparency log</h1>
          <p className="text-sm text-zinc-400">
            Nodes and stakes come from the registry contract on Arc. Verification results and receipt hashes are public;
            prompts and outputs never are.
          </p>
        </div>
        <Link className="text-sm text-zinc-400 hover:text-zinc-100" href="/">
          ← Console
        </Link>
      </header>
      <Suspense fallback={<p className="text-sm text-zinc-500">Loading registry…</p>}>
        <Registry />
      </Suspense>
      <Suspense fallback={<p className="text-sm text-zinc-500">Loading transparency log…</p>}>
        <Activity />
      </Suspense>
    </main>
  );
}
