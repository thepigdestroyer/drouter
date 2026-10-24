"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { CheckResult, NodeRecord, PopReceipt } from "@/lib/types";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import {
  hashHex,
  openSession,
  pickNode,
  postJson,
  type ActiveSession,
  type ChatMessage,
  type RegistryResponse,
} from "@/components/session";
import { CheckList, EvidenceTable, NodeBadge, ReceiptView } from "@/components/trust-panel";

type Phase = "idle" | "verifying" | "ready" | "streaming" | "closed" | "error";

interface AnchorResult {
  anchorTx: string | null;
  verificationTx: string | null;
  anchorUrl: string | null;
  verificationUrl: string | null;
}

export function Console() {
  const [registry, setRegistry] = useState<RegistryResponse | null>(null);
  const [kind, setKind] = useState<NodeRecord["kind"]>("tinfoil");
  const [model, setModel] = useState<string>(TINFOIL_MODELS[0].id);
  const [node, setNode] = useState<NodeRecord | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [checks, setChecks] = useState<CheckResult[]>([]);
  const [session, setSession] = useState<ActiveSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [verifyAnchor, setVerifyAnchor] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<PopReceipt | null>(null);
  const [receiptAnchor, setReceiptAnchor] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/registry")
      .then((r) => r.json())
      .then(setRegistry)
      .catch(() => setError("Could not load the node registry"));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [messages]);

  const connect = useCallback(async () => {
    if (!registry) return;
    const chosen = pickNode(registry.nodes, kind);
    if (!chosen) {
      setError("No active node of that kind in the registry");
      return;
    }
    setNode(chosen);
    setPhase("verifying");
    setChecks([]);
    setSession(null);
    setMessages([]);
    setReceipt(null);
    setReceiptAnchor(null);
    setVerifyAnchor(null);
    setError(null);
    const seen = new Map<string, CheckResult>();
    try {
      const active = await openSession(chosen, registry, (c) => {
        seen.set(c.id, c);
        setChecks([...seen.values()]);
      });
      setChecks(active.checks);
      setSession(active);
      setPhase("ready");
      const ok = !active.checks.some((c) => c.status === "fail");
      void postJson("/api/log", {
        type: "verification",
        nodeId: chosen.id,
        nodeName: chosen.name,
        kind: chosen.kind,
        ok,
        checks: active.checks.map(({ id, status }) => ({ id, status })),
        measurement: active.evidence["Enclave fingerprint"] ?? active.evidence["Measurement"] ?? "",
        evidenceHash: active.evidenceHash,
        releaseDigest: active.evidence["Release"],
        enclaveHost: active.evidence["Enclave host"],
      });
      const anchored = await postJson<AnchorResult>("/api/anchor", {
        receiptHash: active.evidenceHash,
        nodeId: chosen.id,
        ok,
        evidenceHash: active.evidenceHash,
      });
      setVerifyAnchor(anchored?.verificationUrl ?? anchored?.anchorUrl ?? null);
    } catch (e) {
      const err = e as Error & { checks?: CheckResult[] };
      if (err.checks?.length) setChecks(err.checks);
      setError(err.message);
      setPhase("error");
    }
  }, [registry, kind]);

  const send = useCallback(async () => {
    const text = input.trim();
    if (!session || !text || phase !== "ready") return;
    setInput("");
    const history: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages([...history, { role: "assistant", content: "" }]);
    setPhase("streaming");
    try {
      let reply = "";
      for await (const delta of session.send(history, model)) {
        reply += delta;
        setMessages([...history, { role: "assistant", content: reply }]);
      }
      setPhase("ready");
    } catch (e) {
      setError((e as Error).message);
      setPhase("ready");
    }
  }, [input, messages, model, phase, session]);

  const pop = useCallback(async () => {
    if (!session) return;
    if (session.close) {
      const r = await session.close();
      setReceipt(r);
      const receiptHash = hashHex(r);
      const anchored = await postJson<AnchorResult>("/api/anchor", { receiptHash, nodeId: session.node.id });
      setReceiptAnchor(anchored?.anchorUrl ?? null);
      void postJson("/api/log", {
        type: "receipt",
        nodeId: session.node.id,
        receiptHash,
        signatureVerified: r.verified,
        anchorTx: anchored?.anchorTx ?? null,
      });
    }
    setSession(null);
    setPhase("closed");
  }, [session]);

  const passed = checks.filter((c) => c.status === "pass").length;

  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[18rem_1fr_24rem]">
      {/* Route */}
      <section className="flex flex-col gap-4 rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">1 · Route</h2>
        <div className="flex rounded-md border border-zinc-800 p-0.5 text-sm">
          {(["tinfoil", "sim"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setKind(k)}
              className={`flex-1 rounded px-2 py-1.5 ${kind === k ? "bg-zinc-800 text-white" : "text-zinc-400"}`}
            >
              {k === "tinfoil" ? "Real enclave" : "Simulated"}
            </button>
          ))}
        </div>
        {kind === "tinfoil" && (
          <label className="text-xs text-zinc-400">
            Model
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-sm text-zinc-100"
            >
              {TINFOIL_MODELS.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          onClick={connect}
          disabled={!registry || phase === "verifying" || phase === "streaming"}
          className="rounded-md bg-emerald-600 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-40"
        >
          {phase === "verifying" ? "Verifying…" : session ? "Re-route" : "Route & verify"}
        </button>
        <div className="space-y-2 text-xs text-zinc-400">
          <p>
            Your browser picks a node at random, weighted by stake, from the{" "}
            {registry?.source === "arc" ? (
              <a className="underline" href={`${registry.explorer}/address/${registry.address}`} target="_blank" rel="noreferrer">
                Arc registry
              </a>
            ) : (
              "built-in node list (Arc registry pending)"
            )}
            . No operator can steer you.
          </p>
          <ul className="space-y-1.5">
            {registry?.nodes
              .filter((n) => n.kind === kind)
              .map((n) => (
                <li
                  key={n.id}
                  className={`rounded border px-2 py-1.5 ${node?.id === n.id ? "border-emerald-700 bg-emerald-950/30" : "border-zinc-800"}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-zinc-200">{n.name}</span>
                    <NodeBadge node={n} />
                  </div>
                  <div className="mt-0.5 text-zinc-500">
                    {n.region} · {n.stake} USDC staked · {n.status}
                  </div>
                </li>
              ))}
          </ul>
        </div>
      </section>

      {/* Chat */}
      <section className="flex min-h-[32rem] flex-col rounded-lg border border-zinc-800 bg-zinc-950">
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">3 · Private session</h2>
          <span className="text-xs text-zinc-500">
            {session
              ? `${session.node.name} · ${session.node.kind === "tinfoil" ? model : "sim-echo-1"}`
              : phase === "closed"
                ? "Session ended"
                : "Not connected"}
          </span>
        </div>
        <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
          {messages.length === 0 && (
            <div className="mx-auto max-w-md pt-16 text-center text-sm text-zinc-500">
              {session
                ? "Verified. Everything you type is encrypted in this browser to the attested enclave. The relay and dRouter only ever see ciphertext."
                : "Route to a node to start. Your browser verifies the hardware and the code before anything is sent."}
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-2 text-sm leading-relaxed ${
                  m.role === "user" ? "bg-emerald-700 text-white" : "bg-zinc-900 text-zinc-100"
                }`}
              >
                {m.content || (phase === "streaming" ? "…" : "")}
              </div>
            </div>
          ))}
        </div>
        <form
          className="flex gap-2 border-t border-zinc-800 p-3"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={phase !== "ready"}
            placeholder={phase === "ready" ? "Message (end-to-end encrypted)…" : "Verify a node first"}
            className="flex-1 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={phase !== "ready" || !input.trim()}
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-semibold text-zinc-900 disabled:opacity-30"
          >
            Send
          </button>
          <button
            type="button"
            onClick={pop}
            disabled={!session || phase === "streaming"}
            className="rounded-md border border-sky-800 px-3 py-2 text-sm text-sky-300 disabled:opacity-30"
            title="End the session and destroy its keys"
          >
            Pop bubble
          </button>
        </form>
      </section>

      {/* Trust */}
      <section className="flex flex-col gap-4 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">2 · Verify</h2>
          {checks.length > 0 && (
            <span className="text-xs text-zinc-500">
              {passed}/{checks.length} passed
            </span>
          )}
        </div>
        {node && (
          <div className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2 text-sm">
            <span className="text-zinc-200">{node.name}</span>
            <NodeBadge node={node} />
          </div>
        )}
        {error && <p className="rounded-md border border-rose-900 bg-rose-950/40 p-3 text-xs text-rose-200">{error}</p>}
        <CheckList checks={checks} pending={phase === "verifying"} />
        {verifyAnchor && (
          <a className="text-xs text-emerald-300 underline" href={verifyAnchor} target="_blank" rel="noreferrer">
            Verification recorded on Arc ↗
          </a>
        )}
        {session && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">Evidence</h3>
            <EvidenceTable evidence={session.evidence} />
          </div>
        )}
        {receipt && <ReceiptView receipt={receipt} anchorUrl={receiptAnchor} />}
        {phase === "closed" && !receipt && (
          <p className="text-xs text-zinc-400">
            Session ended. Tinfoil requests are stateless: the attested router code keeps no conversation state between requests.
          </p>
        )}
      </section>
    </div>
  );
}
