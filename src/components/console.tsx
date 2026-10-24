"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CheckResult,
  FreezeReceipt,
  NodeRecord,
  PopReceipt,
  ScrubResult,
} from "@/lib/types";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";
import {
  getActiveCustomScrubTerms,
  subscribeVaultSession,
} from "@/lib/auth/vault";
import {
  mintCredits,
  storedCreditBalance,
} from "@/lib/credits/client";
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
import {
  prepareOutboundTurn,
  type MessagePrivacyReport,
} from "@/components/console/send-pipeline";
import {
  ForensicProofCard,
  exportSessionProof,
  type ExportedSessionProof,
} from "@/components/console/proof-exporter";
import { NodeBadge, ReceiptView } from "@/components/trust-panel";
import { PrivacyBar } from "@/components/privacy-bar";
import { FreezeDrawer } from "@/components/freeze-drawer";
import {
  VisualTrustDashboard,
  type InspectorTab,
} from "@/components/visual-trust-dashboard";
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
  const [lastEvidence, setLastEvidence] = useState<Record<string, string>>({});
  const [lastDeepBundle, setLastDeepBundle] = useState<
    DeepAttestationBundle | undefined
  >(undefined);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [verifyAnchor, setVerifyAnchor] = useState<string | null>(null);
  const [publishingProof, setPublishingProof] = useState(false);
  const [receipt, setReceipt] = useState<PopReceipt | null>(null);
  const [receiptAnchor, setReceiptAnchor] = useState<string | null>(null);
  const [scrubEnabled, setScrubEnabled] = useState(true);
  const [normalizeStyle, setNormalizeStyle] = useState(false);
  const [zeroTelemetry, setZeroTelemetry] = useState(true);
  const [lastScrubbed, setLastScrubbed] = useState<ScrubResult | null>(null);
  const [lastPrivacyReport, setLastPrivacyReport] =
    useState<MessagePrivacyReport | null>(null);
  const [customTermsCount, setCustomTermsCount] = useState(0);
  const [creditBalance, setCreditBalance] = useState<number | null>(null);
  const [mintingCredits, setMintingCredits] = useState(false);
  const [lastNullifier, setLastNullifier] = useState<string | null>(null);
  const [exportedProof, setExportedProof] =
    useState<ExportedSessionProof | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("overview");
  const [terminalModalOpen, setTerminalModalOpen] = useState(false);
  const scrubberRef = useRef(createSessionScrubber());
  const scrollRef = useRef<HTMLDivElement>(null);
  const didAutoConnectRef = useRef(false);

  useEffect(() => {
    setCreditBalance(storedCreditBalance());
    setCustomTermsCount(getActiveCustomScrubTerms().length);
    const unsub = subscribeVaultSession(() => {
      setCustomTermsCount(getActiveCustomScrubTerms().length);
      setCreditBalance(storedCreditBalance());
    });
    fetch("/api/registry")
      .then((r) => r.json())
      .then(setRegistry)
      .catch(() => {
        setError("Could not load the node registry from /api/registry.");
        setPhase("error");
      });
    return unsub;
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

  const publishVerificationProof = useCallback(
    async (activeSession: ActiveSession) => {
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
          measurement:
            activeSession.evidence["Enclave fingerprint"] ??
            activeSession.evidence["Measurement"] ??
            "",
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
        setVerifyAnchor(
          anchored?.verificationUrl ?? anchored?.anchorUrl ?? null,
        );
      } finally {
        setPublishingProof(false);
      }
    },
    [],
  );

  const connectWith = useCallback(
    async (targetKind: NodeRecord["kind"], targetModel: string) => {
      if (!registry) return;
      const chosen = pickNode(registry.nodes, targetKind);
      if (!chosen) {
        setError(`No active ${targetKind} node found in the registry.`);
        setSession(null);
        setPhase("error");
        return;
      }
      setNode(chosen);
      setPhase("verifying");
      setChecks([]);
      setSession(null);
      setLastEvidence({});
      setLastDeepBundle(undefined);
      setMessages([]);
      setReceipt(null);
      setReceiptAnchor(null);
      setVerifyAnchor(null);
      setLastScrubbed(null);
      setLastPrivacyReport(null);
      setExportedProof(null);
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
          targetModel,
        );
        const failed = active.checks.filter((c) => c.status === "fail");
        setChecks(active.checks);
        setLastEvidence(active.evidence);
        setLastDeepBundle(active.deepBundle);
        if (failed.length > 0) {
          setSession(null);
          setError(
            failed.map((c) => `${c.id} (${c.label}): ${c.detail}`).join(" · "),
          );
          setPhase("error");
          return;
        }
        setSession(active);
        setPhase("ready");
        if (!zeroTelemetry) {
          void publishVerificationProof(active);
        }
      } catch (e) {
        const err = e as Error & {
          checks?: CheckResult[];
          evidence?: Record<string, string>;
          deepBundle?: DeepAttestationBundle;
        };
        if (err.checks?.length) setChecks(err.checks);
        if (err.evidence) setLastEvidence(err.evidence);
        if (err.deepBundle) setLastDeepBundle(err.deepBundle);
        setSession(null);
        setError(err.message);
        setPhase("error");
      }
    },
    [registry, publishVerificationProof, zeroTelemetry],
  );

  const connect = useCallback(async () => {
    await connectWith(kind, model);
  }, [connectWith, kind, model]);

  useEffect(() => {
    if (registry && !didAutoConnectRef.current) {
      didAutoConnectRef.current = true;
      void connectWith(kind, model);
    }
  }, [registry, kind, model, connectWith]);

  const handleSwitchKind = useCallback(
    (nextKind: NodeRecord["kind"]) => {
      setKind(nextKind);
      if (registry && phase !== "streaming") {
        void connectWith(nextKind, model);
      }
    },
    [connectWith, model, phase, registry],
  );

  const handleSwitchModel = useCallback(
    (nextModel: string) => {
      setModel(nextModel);
      if (
        registry &&
        kind === "tinfoil" &&
        messages.length === 0 &&
        phase !== "streaming"
      ) {
        void connectWith("tinfoil", nextModel);
      }
    },
    [connectWith, kind, messages.length, phase, registry],
  );

  const hasFailedCheck = checks.some((c) => c.status === "fail");
  const canSend =
    phase === "ready" &&
    Boolean(session) &&
    !hasFailedCheck &&
    checks.length > 0;

  const send = useCallback(async () => {
    const text = input.trim();
    if (!session || !text || !canSend) return;
    setInput("");
    setError(null);

    const turnPrepared = await prepareOutboundTurn(text, {
      scrubEnabled,
      normalizeStyle,
      scrubber: scrubberRef.current,
    });

    setCreditBalance(turnPrepared.creditBalanceAfter);
    if (turnPrepared.report.creditNullifier) {
      setLastNullifier(turnPrepared.report.creditNullifier);
    }
    setLastPrivacyReport(turnPrepared.report);
    setLastScrubbed({
      scrubbed: turnPrepared.outboundText,
      replacements: turnPrepared.report.redactions,
    });

    const userMsg: ChatMessage = {
      role: "user",
      content: text,
      wireContent: turnPrepared.outboundText,
      privacyReport: turnPrepared.report,
    };

    const displayHistory: ChatMessage[] = [...messages, userMsg];
    const wireHistory: ChatMessage[] = displayHistory.map((m) => ({
      role: m.role,
      content:
        m.wireContent ??
        (scrubEnabled
          ? scrubberRef.current.scrub(m.content).scrubbed
          : m.content),
      wireContent:
        m.wireContent ??
        (scrubEnabled
          ? scrubberRef.current.scrub(m.content).scrubbed
          : m.content),
    }));

    setMessages([...displayHistory, { role: "assistant", content: "" }]);
    setPhase("streaming");
    let wireReply = "";
    try {
      for await (const delta of session.send(wireHistory, model, {
        creditHeader: turnPrepared.creditHeader,
      })) {
        wireReply += delta;
        const restored = turnPrepared.restore(wireReply);
        setMessages([
          ...displayHistory,
          {
            role: "assistant",
            content: restored,
            wireContent: wireReply,
          },
        ]);
      }
      setPhase("ready");
    } catch (e) {
      const msg = (e as Error).message || "Failed to stream response from node.";
      setError(msg);
      if (!wireReply) {
        // Recoverable error: restore user prompt to input if no reply tokens arrived
        setMessages(messages);
        setInput(text);
      }
      setPhase("ready");
    }
  }, [canSend, input, messages, model, normalizeStyle, scrubEnabled, session]);

  const pop = useCallback(async () => {
    if (!session) return;
    setLastEvidence(session.evidence);
    setLastDeepBundle(session.deepBundle);
    if (session.close) {
      const r = await session.close();
      setReceipt(r);
      if (!zeroTelemetry) {
        const receiptHash = hashHex(r);
        const anchored = await postJson<AnchorResult>("/api/anchor", {
          receiptHash,
          nodeId: session.node.id,
        });
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

  const handleExportProof = useCallback(() => {
    const activeNode = session?.node ?? node;
    const activeEvidence = session?.evidence ?? lastEvidence;
    if (!activeNode || checks.length === 0) {
      setError("Verify hardware first before exporting a forensic proof bundle.");
      return;
    }
    try {
      const exported = exportSessionProof({
        session: session ?? {
          node: activeNode,
          checks,
          evidence: activeEvidence,
          deepBundle: lastDeepBundle,
        },
        node: activeNode,
        model: activeNode.kind === "tinfoil" ? model : "sim-echo-1",
        checks,
        evidence: activeEvidence,
        receipt,
        verifyAnchorUrl: verifyAnchor,
        receiptAnchorUrl: receiptAnchor,
      });
      setExportedProof(exported);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [
    checks,
    lastDeepBundle,
    lastEvidence,
    model,
    node,
    receipt,
    receiptAnchor,
    session,
    verifyAnchor,
  ]);

  const handleFreeze = useCallback(async (): Promise<FreezeReceipt | null> => {
    if (!session) return null;
    const saved = await freezeAndUpload(window.location.origin, {
      modelId: session.node.kind === "tinfoil" ? model : "sim-echo-1",
      nodeKind: session.node.kind,
      messages,
      simContextTokens: messages.reduce(
        (sum, m) => sum + Math.max(1, Math.ceil(m.content.length / 4)),
        0,
      ),
      createdAt: Date.now(),
      turnCount: messages.filter((m) => m.role === "user").length,
    });
    await pop();
    return saved;
  }, [messages, model, pop, session]);

  const handleResume = useCallback(
    async (blobId: string, freezeSecretHex: string) => {
      const restored = await downloadAndResume(
        window.location.origin,
        blobId,
        freezeSecretHex,
      );
      setKind(restored.nodeKind);
      if (restored.nodeKind === "tinfoil") setModel(restored.modelId);
      if (!session && registry) {
        const chosen = pickNode(registry.nodes, restored.nodeKind);
        if (chosen) {
          setNode(chosen);
          setPhase("verifying");
          const active = await openSession(
            chosen,
            registry,
            () => {},
            restored.modelId,
          );
          setChecks(active.checks);
          setLastEvidence(active.evidence);
          setLastDeepBundle(active.deepBundle);
          setSession(active);
          setPhase("ready");
        }
      }
      setMessages(restored.messages);
    },
    [registry, session],
  );

  const activeEvidence = session?.evidence ?? lastEvidence;
  const activeDeepBundle = session?.deepBundle ?? lastDeepBundle;
  const canExportProof = Boolean(node && checks.length > 0);

  return (
    <div className="flex flex-col gap-5">
      <VisualTrustDashboard
        phase={phase}
        node={node}
        model={kind === "tinfoil" ? model : "sim-echo-1"}
        checks={checks}
        scrubEnabled={scrubEnabled}
        zeroTelemetry={zeroTelemetry}
        onToggleZeroTelemetry={setZeroTelemetry}
        creditBalance={creditBalance}
        evidence={activeEvidence}
        onOpenInspector={openInspector}
        onOpenTerminalModal={() => setTerminalModalOpen(true)}
        onExportProof={handleExportProof}
        canExportProof={canExportProof}
        onRetryVerify={() => void connect()}
        onDismissError={() => setError(null)}
        errorMessage={error}
        verifyAnchorUrl={verifyAnchor}
        publishingProof={publishingProof}
        onPublishProof={
          session ? () => void publishVerificationProof(session) : undefined
        }
      />

      {exportedProof && (
        <ForensicProofCard
          exportedProof={exportedProof}
          onDismiss={() => setExportedProof(null)}
          onRedownload={handleExportProof}
        />
      )}

      {/* Chat Card */}
      <div className="ep-card flex flex-col overflow-hidden">
        {/* Top bar: Model picker, Node mode, Re-verify, Export proof */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-4 py-3">
          <div className="flex flex-wrap items-center gap-3">
            <div
              className="inline-flex rounded border border-rule-2 bg-paper p-0.5 text-xs"
              role="group"
              aria-label="Enclave mode"
            >
              {(["tinfoil", "sim"] as const).map((k) => (
                <button
                  key={k}
                  type="button"
                  onClick={() => handleSwitchKind(k)}
                  disabled={phase === "verifying" || phase === "streaming"}
                  className={`rounded px-2.5 py-1 font-medium transition-colors ${
                    kind === k
                      ? "bg-ink text-paper"
                      : "text-ink-2 hover:text-ink"
                  }`}
                >
                  {k === "tinfoil" ? "Real enclave" : "Simulated"}
                </button>
              ))}
            </div>

            {kind === "tinfoil" ? (
              <div className="flex items-center gap-2">
                <label htmlFor="console-model-select" className="ep-label">
                  Model
                </label>
                <select
                  id="console-model-select"
                  value={model}
                  onChange={(e) => handleSwitchModel(e.target.value)}
                  disabled={phase === "streaming"}
                  className="ep-input w-auto py-1 text-xs font-medium"
                >
                  {TINFOIL_MODELS.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.label}
                    </option>
                  ))}
                </select>
              </div>
            ) : (
              <span className="font-mono text-xs text-ink-2">
                Model: sim-echo-1 (Simulated in software)
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {node && (
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-ink-2">
                  {node.name}
                </span>
                <NodeBadge node={node} />
              </div>
            )}

            <button
              type="button"
              onClick={() => void connect()}
              disabled={
                !registry || phase === "verifying" || phase === "streaming"
              }
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              {phase === "verifying"
                ? "Verifying..."
                : session
                  ? "Re-verify"
                  : "Verify hardware"}
            </button>

            <button
              type="button"
              onClick={handleExportProof}
              disabled={!canExportProof}
              className="ep-btn-ghost px-2.5 py-1 text-xs disabled:opacity-45"
              title="Export signed forensic proof (.drouter-proof.json)"
            >
              Export proof
            </button>

            {session && (
              <button
                type="button"
                onClick={() => void pop()}
                disabled={phase === "streaming"}
                className="ep-btn-ghost px-2.5 py-1 text-xs"
                title="Close session and clear keys from browser memory"
              >
                End session
              </button>
            )}
          </div>
        </div>

        {kind === "sim" && (
          <div className="border-b border-rule bg-paper-2 px-4 py-2 text-xs text-ink-2">
            <strong className="font-medium text-ink">Simulated mode:</strong>{" "}
            Connected to software simulation ({node?.name ?? "sim node"}).
            Hardware roots are derived from{" "}
            <code className="font-mono">SIM_HARDWARE_SEED</code> and replies come
            from a fixed echo template. Switch to{" "}
            <strong className="font-medium text-ink">Real enclave</strong> to
            query Tinfoil confidential GPUs.
          </div>
        )}

        {/* Message thread */}
        <div
          ref={scrollRef}
          className="min-h-[18rem] max-h-[28rem] flex-1 space-y-4 overflow-y-auto p-4 sm:p-6"
        >
          {messages.length === 0 ? (
            <div className="mx-auto max-w-[60ch] py-8 text-center">
              <p className="text-sm text-ink-2">
                {phase === "verifying"
                  ? "Checking enclave hardware before opening your encrypted session..."
                  : phase === "error" || hasFailedCheck
                    ? `Not verified. ${
                        error ||
                        "Hardware attestation failed. Sending is blocked until verification passes."
                      }`
                    : session
                      ? "Session verified and encrypted. Type a prompt below. If you include an email like dana.reyes@example.com or a secret like sk-demo123456, your browser replaces it with a placeholder before encryption."
                      : "Click Verify hardware above to establish an attested session."}
              </p>
              {session && canSend && (
                <div className="mt-4 flex flex-wrap justify-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setInput(
                        "Draft a short note to Dana Reyes at dana.reyes@example.com about rotating key sk-prod987654.",
                      )
                    }
                    className="ep-btn-ghost px-3 py-1 text-xs"
                  >
                    Try PII scrubbing example
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setInput(
                        "Explain in two plain sentences how AMD SEV-SNP protects memory from the host OS.",
                      )
                    }
                    className="ep-btn-ghost px-3 py-1 text-xs"
                  >
                    Ask about hardware memory encryption
                  </button>
                </div>
              )}
            </div>
          ) : (
            messages.map((m, i) => (
              <div
                key={i}
                className={`flex flex-col ${
                  m.role === "user" ? "items-end" : "items-start"
                }`}
              >
                <div
                  className={
                    m.role === "user"
                      ? "ep-inset max-w-[85%] whitespace-pre-wrap px-3.5 py-2.5 text-sm text-ink"
                      : "max-w-[70ch] whitespace-pre-wrap border-l-2 border-ink pl-4 py-1 text-sm text-ink"
                  }
                >
                  <div className="ep-label mb-1">
                    {m.role === "user"
                      ? kind === "sim"
                        ? "You (AEAD sealed · Simulated)"
                        : "You (HPKE sealed)"
                      : kind === "sim"
                        ? "sim-echo-1 (Simulated)"
                        : model}
                  </div>
                  <div>
                    {m.content || (phase === "streaming" ? "Thinking..." : "")}
                  </div>
                </div>

                {m.role === "user" && m.privacyReport && (
                  <div
                    className="mt-1 flex flex-wrap items-center justify-end gap-2 font-mono text-[11px] text-ink-3"
                    data-testid="message-privacy-badge"
                  >
                    <span>
                      Redactions: {m.privacyReport.redactions.length}
                      {m.privacyReport.redactions.length > 0
                        ? ` (${m.privacyReport.redactions
                            .map((r) => r.placeholder)
                            .join(", ")})`
                        : ""}
                    </span>
                    <span>·</span>
                    <span>
                      Bucket:{" "}
                      {m.privacyReport.bucketBytes.toLocaleString("en-US")} B
                    </span>
                    <span>·</span>
                    <span>
                      Risk: {m.privacyReport.riskBefore}/100 -&gt;{" "}
                      {m.privacyReport.riskAfter}/100
                    </span>
                    <span>·</span>
                    <span>
                      {m.privacyReport.creditAttached
                        ? "x-drouter-credit attached"
                        : "free tier (no credit attached)"}
                    </span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Input form */}
        <form
          className="flex gap-2 border-t border-rule bg-paper-2 p-3 sm:p-4"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <label htmlFor="console-prompt-input" className="sr-only">
            Message
          </label>
          <input
            id="console-prompt-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={!canSend}
            placeholder={
              canSend
                ? "Write your prompt (scrubbed locally, then encrypted to enclave)..."
                : phase === "verifying"
                  ? "Verifying enclave hardware..."
                  : phase === "error" || hasFailedCheck
                    ? "Not verified: hardware attestation failed (sending blocked)"
                    : "Verify hardware first to unlock input"
            }
            className="ep-input min-w-0 flex-1"
          />
          <button
            type="submit"
            disabled={!canSend || !input.trim()}
            className="ep-btn px-5"
          >
            Send
          </button>
        </form>
      </div>

      {receipt && (
        <ReceiptView
          receipt={receipt}
          anchorUrl={receiptAnchor}
          onExportProof={handleExportProof}
        />
      )}

      {/* Plain-language Privacy Summary, Freeze/Resume, and Disclosures */}
      <div className="ep-card space-y-4 p-4 sm:p-5">
        <PrivacyBar
          scrubEnabled={scrubEnabled}
          onToggleScrub={setScrubEnabled}
          normalizeStyle={normalizeStyle}
          onToggleNormalizeStyle={setNormalizeStyle}
          lastScrubbed={lastScrubbed}
          lastPrivacyReport={lastPrivacyReport}
          customTermsCount={customTermsCount}
          draftText={input}
          creditBalance={creditBalance}
          onMintCredits={handleMintCredits}
          mintingCredits={mintingCredits}
          lastNullifier={lastNullifier}
          zeroTelemetry={zeroTelemetry}
          onToggleZeroTelemetry={setZeroTelemetry}
        />

        <FreezeDrawer
          canFreeze={Boolean(session) && canSend && messages.length > 0}
          onFreeze={handleFreeze}
          onResume={handleResume}
        />
      </div>

      <RecordInspectorModal
        open={inspectorOpen}
        initialTab={inspectorTab}
        onClose={() => setInspectorOpen(false)}
        node={node}
        model={kind === "tinfoil" ? model : "sim-echo-1"}
        checks={checks}
        evidence={activeEvidence}
        deepBundle={activeDeepBundle}
        verifyAnchorUrl={verifyAnchor}
        registryAddress={registry?.address ?? null}
      />

      <TerminalModal
        open={terminalModalOpen}
        onClose={() => setTerminalModalOpen(false)}
        baseUrl={
          typeof window !== "undefined"
            ? window.location.origin
            : "https://drouter-demo.vercel.app"
        }
        defaultModel={model}
      />
    </div>
  );
}
