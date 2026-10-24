"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { CheckResult, FreezeReceipt, NodeRecord, PopReceipt, ScrubResult } from "@/lib/types";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import { mintCredits, spendOneCredit, storedCreditBalance } from "@/lib/credits/client";
import { downloadAndResume, freezeAndUpload } from "@/lib/freeze/client";
import { createSessionScrubber } from "@/lib/privacy/scrubber";
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
import { PrivacyBar } from "@/components/privacy-bar";
import { FreezeDrawer } from "@/components/freeze-drawer";
import { VisualTrustDashboard, type InspectorTab } from "@/components/visual-trust-dashboard";
import { RecordInspectorModal } from "@/components/record-inspector-modal";
import { TerminalModal } from "@/components/terminal-modal";

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
  const [publishingProof, setPublishingProof] = useState(false);
  const [receipt, setReceipt] = useState<PopReceipt | null>(null);
  const [receiptAnchor, setReceiptAnchor] = useState<string | null>(null);
  const [scrubEnabled, setScrubEnabled] = useState(true);
  const [zeroTelemetry, setZeroTelemetry] = useState(true);
  const [lastScrubbed, setLastScrubbed] = useState<ScrubResult | null>(null);
  const [creditBalance, setCreditBalance] = useState(0);
  const [mintingCredits, setMintingCredits] = useState(false);
  const [lastNullifier, setLastNullifier] = useState<string | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("overview");
  const [terminalModalOpen, setTerminalModalOpen] = useState(false);
  const scrubberRef = useRef(createSessionScrubber());
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setCreditBalance(storedCreditBalance());
    fetch("/api/registry")
      .then((r) => r.json())
      .then(setRegistry)
      .catch(() => setError("Could not load the node registry"));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [messages]);

  const openInspector = useCallback((tab: InspectorTab = "overview") => {
    setInspectorTab(tab);
    setInspectorOpen(true);
  }, []);

  const handleMintCredits = useCallback(async () => {
    setMintingCredits(true);
    try {
      await mintCredits(window.location.origin, 5, 1);
      setCreditBalance(storedCreditBalance());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setMintingCredits(false);
    }
  }, []);

  const publishVerificationProof = useCallback(async (activeSession: ActiveSession) => {
    setPublishingProof(true);
    try {
      const chosen = activeSession.node;
      const ok = !activeSession.checks.some((c) => c.status === "fail");
      void postJson("/api/log", {
        type: "verification",
        nodeId: chosen.id,
        nodeName: chosen.name,
        kind: chosen.kind,
        ok,
        checks: activeSession.checks.map(({ id, status }) => ({ id, status })),
        measurement: activeSession.evidence["Enclave fingerprint"] ?? activeSession.evidence["Measurement"] ?? "",
        evidenceHash: activeSession.evidenceHash,
        releaseDigest: activeSession.evidence["Release"],
        enclaveHost: activeSession.evidence["Enclave host"],
      });
      const anchored = await postJson<AnchorResult>("/api/anchor", {
        receiptHash: activeSession.evidenceHash,
        nodeId: chosen.id,
        ok,
        evidenceHash: activeSession.evidenceHash,
      });
      setVerifyAnchor(anchored?.verificationUrl ?? anchored?.anchorUrl ?? null);
    } finally {
      setPublishingProof(false);
    }
  }, []);

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
    setLastScrubbed(null);
    setError(null);
    scrubberRef.current.clear();
    const seen = new Map<string, CheckResult>();
    try {
      const active = await openSession(
        chosen,
        registry,
        (c) => {
          seen.set(c.id, c);
          setChecks([...seen.values()]);
        },
        model,
      );
      setChecks(active.checks);
      setSession(active);
      setPhase("ready");
      if (!zeroTelemetry) {
        void publishVerificationProof(active);
      }
    } catch (e) {
      const err = e as Error & { checks?: CheckResult[] };
      if (err.checks?.length) setChecks(err.checks);
      setError(err.message);
      setPhase("error");
    }
  }, [registry, kind, model, publishVerificationProof, zeroTelemetry]);

  const send = useCallback(async () => {
    const text = input.trim();
    if (!session || !text || phase !== "ready") return;
    setInput("");

    // Auto-mint blind-signed credits if wallet is empty, then spend 1 unlinkable token for this turn.
    try {
      if (storedCreditBalance() === 0) {
        await mintCredits(window.location.origin, 5, 1);
      }
      const spent = await spendOneCredit(window.location.origin, session.node.id);
      setCreditBalance(spent.remaining);
      if (spent.nullifier) setLastNullifier(spent.nullifier);
    } catch {
      // Non-fatal if credit endpoint is unreachable
    }

    const scrubRes = scrubEnabled
      ? scrubberRef.current.scrub(text)
      : { scrubbed: text, replacements: [] };
    setLastScrubbed(scrubRes);

    const displayHistory: ChatMessage[] = [...messages, { role: "user", content: text }];
    const wireHistory: ChatMessage[] = displayHistory.map((m) => ({
      role: m.role,
      content: scrubEnabled ? scrubberRef.current.scrub(m.content).scrubbed : m.content,
    }));

    setMessages([...displayHistory, { role: "assistant", content: "" }]);
    setPhase("streaming");
    try {
      let wireReply = "";
      for await (const delta of session.send(wireHistory, model)) {
        wireReply += delta;
        const restored = scrubEnabled ? scrubberRef.current.restore(wireReply) : wireReply;
        setMessages([...displayHistory, { role: "assistant", content: restored }]);
      }
      setPhase("ready");
    } catch (e) {
      setError((e as Error).message);
      setPhase("ready");
    }
  }, [input, messages, model, phase, scrubEnabled, session]);

  const pop = useCallback(async () => {
    if (!session) return;
    if (session.close) {
      const r = await session.close();
      setReceipt(r);
      if (!zeroTelemetry) {
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
    }
    scrubberRef.current.clear();
    setSession(null);
    setPhase("closed");
  }, [session, zeroTelemetry]);

  const handleFreeze = useCallback(async (): Promise<FreezeReceipt | null> => {
    if (!session) return null;
    const saved = await freezeAndUpload(window.location.origin, {
      modelId: session.node.kind === "tinfoil" ? model : "sim-echo-1",
      nodeKind: session.node.kind,
      messages,
      simContextTokens: messages.reduce((sum, m) => sum + Math.max(1, Math.ceil(m.content.length / 4)), 0),
      createdAt: Date.now(),
      turnCount: messages.filter((m) => m.role === "user").length,
    });
    await pop();
    return saved;
  }, [messages, model, pop, session]);

  const handleResume = useCallback(
    async (blobId: string, freezeSecretHex: string) => {
      const restored = await downloadAndResume(window.location.origin, blobId, freezeSecretHex);
      setKind(restored.nodeKind);
      if (restored.nodeKind === "tinfoil") setModel(restored.modelId);
      if (!session && registry) {
        const chosen = pickNode(registry.nodes, restored.nodeKind);
        if (chosen) {
          setNode(chosen);
          setPhase("verifying");
          const active = await openSession(chosen, registry, () => {}, restored.modelId);
          setChecks(active.checks);
          setSession(active);
          setPhase("ready");
        }
      }
      setMessages(restored.messages);
    },
    [registry, session],
  );

  const passed = checks.filter((c) => c.status === "pass").length;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <VisualTrustDashboard
        phase={phase}
        node={node}
        model={kind === "tinfoil" ? model : "sim-echo-1"}
        checks={checks}
        scrubEnabled={scrubEnabled}
        zeroTelemetry={zeroTelemetry}
        onToggleZeroTelemetry={setZeroTelemetry}
        creditBalance={creditBalance}
        evidence={session?.evidence ?? {}}
        onOpenInspector={openInspector}
        onOpenTerminalModal={() => setTerminalModalOpen(true)}
      />

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[19rem_1fr_25rem]">
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
              Model (2-hop router + 8× GPU enclave attested)
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
            {phase === "verifying" ? "Verifying 7 hardware & code checks…" : session ? "Re-route to fresh enclave" : "Route & verify enclave"}
          </button>
          <div className="space-y-2 text-xs text-zinc-400">
            <p>
              Your browser picks a node at random, weighted by stake, from the{" "}
              {registry?.source === "arc" ? (
                <a className="underline text-emerald-300" href={`${registry.explorer}/address/${registry.address}`} target="_blank" rel="noreferrer">
                  Arc registry ↗
                </a>
              ) : (
                "built-in node list"
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

          <button
            type="button"
            onClick={() => setTerminalModalOpen(true)}
            className="mt-auto rounded-md border border-emerald-800/70 bg-emerald-950/30 p-3 text-left text-xs text-emerald-200 hover:bg-emerald-950/50"
          >
            <div className="font-semibold text-emerald-300">Use from Terminal, OpenCode or Cursor ⌘</div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Click for one-click setup (`opencode.json`, local zero-trust CLI proxy, `OPENAI_BASE_URL`, `curl` &amp; Python/TS SDK).
            </p>
          </button>
        </section>

        {/* Chat */}
        <section className="flex min-h-[28rem] flex-col rounded-lg border border-zinc-800 bg-zinc-950">
          <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">3 · Encrypted Bubble Session</h2>
            <span className="text-xs text-zinc-500">
              {session
                ? `${session.node.name} · ${session.node.kind === "tinfoil" ? model : "sim-echo-1"}`
                : phase === "closed"
                  ? "Bubble popped — keys zeroed"
                  : "Not connected"}
            </span>
          </div>
          <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
            {messages.length === 0 && (
              <div className="mx-auto max-w-md pt-8 text-center text-sm text-zinc-500">
                {session
                  ? "All 7 checks passed. Type a message (try including an email like alice@acme.com or an API key like sk-secret123456 to see live client-side PII scrubbing before encryption)."
                  : "Click 'Route & verify enclave' on the left, or click 'Use in Terminal / IDE' above to route directly from OpenCode, Claude Code, Cursor, or curl."}
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
          <div className="border-t border-zinc-800 px-3 pt-2">
            <PrivacyBar
              scrubEnabled={scrubEnabled}
              onToggleScrub={setScrubEnabled}
              lastScrubbed={lastScrubbed}
              draftText={input}
              creditBalance={creditBalance}
              onMintCredits={handleMintCredits}
              mintingCredits={mintingCredits}
              lastNullifier={lastNullifier}
            />
          </div>
          <form
            className="flex gap-2 p-3"
            onSubmit={(e) => {
              e.preventDefault();
              void send();
            }}
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={phase !== "ready"}
              placeholder={
                phase === "ready"
                  ? "Message (scrubbed locally + HPKE encrypted to enclave)…"
                  : "Verify a node first"
              }
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
        <section className="flex flex-col gap-3 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">2 · 7-Point Verification</h2>
            <button
              type="button"
              onClick={() => openInspector("overview")}
              className="rounded border border-emerald-700/60 bg-emerald-950/40 px-2 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-900/50"
            >
              Inspect Raw Proofs ↗ ({passed}/{checks.length || 7})
            </button>
          </div>
          {node && (
            <div className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2 text-sm">
              <span className="text-zinc-200">{node.name}</span>
              <NodeBadge node={node} />
            </div>
          )}
          {error && <p className="rounded-md border border-rose-900 bg-rose-950/40 p-3 text-xs text-rose-200">{error}</p>}
          <CheckList checks={checks} pending={phase === "verifying"} />
          <div className="flex flex-wrap items-center gap-2">
            {session && !verifyAnchor && (
              <button
                type="button"
                disabled={publishingProof}
                onClick={() => void publishVerificationProof(session)}
                className="rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
              >
                {publishingProof ? "Anchoring on Arc…" : "Anchor proof on Arc & log (opt-in)"}
              </button>
            )}
            {verifyAnchor && (
              <a className="text-xs text-emerald-300 underline" href={verifyAnchor} target="_blank" rel="noreferrer">
                Verification tx on Arc Explorer ↗
              </a>
            )}
          </div>
          <FreezeDrawer
            canFreeze={Boolean(session) && phase === "ready" && messages.length > 0}
            onFreeze={handleFreeze}
            onResume={handleResume}
          />
          {session && (
            <div>
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Live Attested Registers</h3>
                <button
                  type="button"
                  onClick={() => openInspector("gpu")}
                  className="text-[11px] text-emerald-400 underline"
                >
                  Verify on GitHub / Sigstore / AMD ↗
                </button>
              </div>
              <EvidenceTable evidence={session.evidence} />
            </div>
          )}
          {receipt && <ReceiptView receipt={receipt} anchorUrl={receiptAnchor} />}
          {phase === "closed" && !receipt && (
            <p className="text-xs text-zinc-400">
              Bubble popped: per-session cache secret, PII placeholder map, and ephemeral keys zeroed in browser memory.
            </p>
          )}
        </section>
      </div>

      <RecordInspectorModal
        open={inspectorOpen}
        initialTab={inspectorTab}
        onClose={() => setInspectorOpen(false)}
        node={node}
        model={kind === "tinfoil" ? model : "sim-echo-1"}
        checks={checks}
        evidence={session?.evidence ?? {}}
        deepBundle={session?.deepBundle}
        verifyAnchorUrl={verifyAnchor}
        registryAddress={registry?.address ?? null}
      />

      <TerminalModal
        open={terminalModalOpen}
        onClose={() => setTerminalModalOpen(false)}
        baseUrl={typeof window !== "undefined" ? window.location.origin : "https://drouter-demo.vercel.app"}
        defaultModel={model}
      />
    </div>
  );
}
