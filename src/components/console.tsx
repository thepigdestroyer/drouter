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
import { ReceiptView } from "@/components/trust-panel";
import { PrivacyBar } from "@/components/privacy-bar";
import { FreezeDrawer } from "@/components/freeze-drawer";
import {
  VisualTrustDashboard,
  type InspectorTab,
} from "@/components/visual-trust-dashboard";
import { RecordInspectorModal } from "@/components/record-inspector-modal";
import { TerminalModal } from "@/components/terminal-modal";
import { TechDetails } from "@/components/ink/tech-details";

type Phase = "idle" | "verifying" | "ready" | "streaming" | "closed" | "error";

interface AnchorResult {
  anchorTx: string | null;
  verificationTx: string | null;
  anchorUrl: string | null;
  verificationUrl: string | null;
}

export interface FriendlyModelDescriptor {
  id: string;
  name: string;
  summary: string;
}

export const FRIENDLY_MODELS: Record<string, FriendlyModelDescriptor> = {
  "kimi-k3": {
    id: "kimi-k3",
    name: "Kimi K3",
    summary: "Great for writing, planning, and deep thinking.",
  },
  "glm-5-3": {
    id: "glm-5-3",
    name: "GLM 5.3",
    summary: "Balanced everyday helper for questions and drafts.",
  },
  "deepseek-v4-1-flash": {
    id: "deepseek-v4-1-flash",
    name: "DeepSeek Flash",
    summary: "Quick replies for short questions and summaries.",
  },
  "gpt-oss-120b": {
    id: "gpt-oss-120b",
    name: "Open GPT",
    summary: "Clear, general-purpose open assistant.",
  },
  "llama3-3-70b": {
    id: "llama3-3-70b",
    name: "Llama 3.3",
    summary: "Reliable open model for everyday tasks.",
  },
};

export function describeModel(modelId: string): FriendlyModelDescriptor {
  return (
    FRIENDLY_MODELS[modelId] ?? {
      id: modelId,
      name: modelId,
      summary: "Private AI assistant running on a sealed computer.",
    }
  );
}

export function formatHiddenDetailsSummary(count: number): string {
  if (count <= 0) return "0 personal details hidden";
  return `${count} personal detail${count === 1 ? "" : "s"} hidden`;
}

function FlowingInkTypingIndicator() {
  return (
    <div
      className="inline-flex items-center gap-2 py-1 text-xs text-ink-2"
      data-testid="flowing-ink-indicator"
    >
      <span
        className="inline-flex items-center gap-1"
        aria-hidden="true"
      >
        <span className="h-2 w-2 rounded-full bg-ink motion-safe:animate-pulse" />
        <span
          className="h-2.5 w-3.5 rounded-full bg-ink-2 motion-safe:animate-pulse"
          style={{ animationDelay: "160ms" }}
        />
        <span
          className="h-2 w-2 rounded-full bg-ink-3 motion-safe:animate-pulse"
          style={{ animationDelay: "320ms" }}
        />
      </span>
      <span>Writing reply...</span>
    </div>
  );
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
        setError("Could not load the server list right now.");
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
        setError("No available server was found in the directory.");
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
      const msg = (e as Error).message || "Could not get a reply right now.";
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
      setError("Run the seal check first before exporting a proof receipt.");
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
  const currentModelInfo = describeModel(model);

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

      {/* Main Conversation Card */}
      <div className="ep-card flex flex-col overflow-hidden">
        {/* Top bar: Mode toggle, Friendly model picker, Seal check & End chat */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-4 py-3">
          <div className="flex flex-wrap items-center gap-3">
            <div
              className="inline-flex rounded border border-rule-2 bg-paper p-0.5 text-xs"
              role="group"
              aria-label="Connection mode"
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
                  {k === "tinfoil" ? "Sealed computer" : "Practice mode"}
                </button>
              ))}
            </div>

            {kind === "tinfoil" ? (
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="console-model-select" className="ep-label">
                  Assistant
                </label>
                <select
                  id="console-model-select"
                  value={model}
                  onChange={(e) => handleSwitchModel(e.target.value)}
                  disabled={phase === "streaming"}
                  className="ep-input w-auto py-1 text-xs font-medium"
                >
                  {TINFOIL_MODELS.map((m) => {
                    const info = describeModel(m.id);
                    return (
                      <option key={m.id} value={m.id}>
                        {info.name}
                      </option>
                    );
                  })}
                </select>
                <span className="text-xs text-ink-2">
                  {currentModelInfo.summary}
                </span>
              </div>
            ) : (
              <span className="text-xs text-ink-2">
                Practice assistant (instant echo replies for testing)
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <button
              type="button"
              onClick={() => void connect()}
              disabled={
                !registry || phase === "verifying" || phase === "streaming"
              }
              className="ep-btn-ghost px-2.5 py-1 text-xs"
            >
              {phase === "verifying"
                ? "Checking seal..."
                : session
                  ? "Check seal again"
                  : "Check seal"}
            </button>

            {session && (
              <button
                type="button"
                onClick={() => void pop()}
                disabled={phase === "streaming"}
                className="ep-btn-ghost px-2.5 py-1 text-xs"
                title="Close chat and clear keys from browser memory"
              >
                End chat
              </button>
            )}
          </div>
        </div>

        {kind === "sim" && (
          <div className="border-b border-rule bg-paper-2 px-4 py-2 text-xs text-ink-2">
            <strong className="font-medium text-ink">Practice mode:</strong>{" "}
            You are connected to a software practice server. Your messages stay
            in this practice sandbox and do not use a real sealed computer.
            Switch to{" "}
            <strong className="font-medium text-ink">Sealed computer</strong>{" "}
            anytime for real private AI replies.
          </div>
        )}

        {/* Message thread */}
        <div
          ref={scrollRef}
          className="min-h-[20rem] max-h-[30rem] flex-1 space-y-4 overflow-y-auto p-4 sm:p-6"
        >
          {messages.length === 0 ? (
            <div className="mx-auto max-w-[58ch] py-8 text-center">
              <h3 className="ep-display text-xl text-ink sm:text-2xl">
                {phase === "verifying"
                  ? "Checking the seal on your private computer..."
                  : phase === "error" || hasFailedCheck
                    ? "Not safe to send right now"
                    : session
                      ? "Say hello. Your personal details stay on your device."
                      : "Check the seal above to start chatting."}
              </h3>
              <p className="mt-2 text-sm text-ink-2">
                {phase === "verifying"
                  ? "This only takes a moment. We make sure no one in the middle can read your messages."
                  : phase === "error" || hasFailedCheck
                    ? "We paused sending because the seal check did not pass. Click Retry above to try again."
                    : session
                      ? "If you type an email like dana.reyes@example.com or a secret key, your browser hides it automatically before your message leaves your device, then puts it back in the reply."
                      : "Click Check seal above to open your private chat."}
              </p>
              {session && canSend && (
                <div className="mt-5 flex flex-wrap justify-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setInput(
                        "Write a polite reply to Dana Reyes at dana.reyes@example.com about rescheduling our Friday call.",
                      )
                    }
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Draft an email with hidden names
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setInput(
                        "Summarize this note for my doctor and keep my phone number 415-555-0199 private.",
                      )
                    }
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Summarize a private note
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setInput(
                        "Give me three simple dinner ideas I can cook in 20 minutes.",
                      )
                    }
                    className="ep-btn-ghost px-3 py-1.5 text-xs"
                  >
                    Ask an everyday question
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
                      ? "max-w-[85%] rounded-2xl rounded-br-sm border border-ink bg-paper-2 px-4 py-3 text-sm text-ink whitespace-pre-wrap"
                      : "max-w-[75ch] rounded-2xl rounded-bl-sm border border-ink bg-paper px-4 py-3 text-sm text-ink whitespace-pre-wrap"
                  }
                >
                  <div className="ep-label mb-1">
                    {m.role === "user"
                      ? kind === "sim"
                        ? "You (Practice mode)"
                        : "You"
                      : kind === "sim"
                        ? "Practice assistant"
                        : currentModelInfo.name}
                  </div>
                  <div>
                    {m.content ? (
                      m.content
                    ) : phase === "streaming" ? (
                      <FlowingInkTypingIndicator />
                    ) : (
                      ""
                    )}
                  </div>
                </div>

                {m.role === "user" && m.privacyReport && (
                  <div
                    className="mt-1.5 flex flex-col items-end gap-1 text-xs text-ink-3"
                    data-testid="message-privacy-badge"
                  >
                    <span>
                      {formatHiddenDetailsSummary(
                        m.privacyReport.redactions.length,
                      )}
                    </span>
                    <TechDetails label="Show technical details">
                      <div className="ep-inset mt-1 max-w-[60ch] p-2.5 text-left font-mono text-[11px] text-ink-2 space-y-1">
                        <div>
                          Hidden items: {m.privacyReport.redactions.length}
                          {m.privacyReport.redactions.length > 0
                            ? ` (${m.privacyReport.redactions
                                .map((r) => `${r.placeholder}:${r.kind}`)
                                .join(", ")})`
                            : ""}
                        </div>
                        <div>
                          Padded size:{" "}
                          {m.privacyReport.bucketBytes.toLocaleString("en-US")}{" "}
                          B · Risk score: {m.privacyReport.riskBefore}/100 -&gt;{" "}
                          {m.privacyReport.riskAfter}/100
                        </div>
                        <div>
                          Anonymous token:{" "}
                          {m.privacyReport.creditAttached
                            ? "x-drouter-credit attached"
                            : "not attached (standard limit)"}
                        </div>
                        {m.privacyReport.outboundPreview && (
                          <div className="border-t border-rule pt-1 text-ink">
                            Sent text: {m.privacyReport.outboundPreview}
                          </div>
                        )}
                      </div>
                    </TechDetails>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Big friendly input form */}
        <form
          className="flex items-end gap-2.5 border-t border-rule bg-paper-2 p-3 sm:p-4"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <label htmlFor="console-prompt-input" className="sr-only">
            Message
          </label>
          <textarea
            id="console-prompt-input"
            rows={2}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send();
              }
            }}
            disabled={!canSend}
            placeholder={
              canSend
                ? "Type a message... (personal details are hidden automatically before sending)"
                : phase === "verifying"
                  ? "Checking the seal on the computer..."
                  : phase === "error" || hasFailedCheck
                    ? "Not safe to send right now (seal check did not pass)"
                    : "Check the seal first to unlock the chat"
            }
            className="ep-input min-h-[3.25rem] min-w-0 flex-1 resize-y py-2.5 text-sm sm:text-base"
          />
          <button
            type="submit"
            disabled={!canSend || !input.trim()}
            className="ep-btn h-[3.25rem] px-6 text-sm font-medium"
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

      {/* Plain-language Privacy Summary, Pause/Lock, and Technical Disclosures */}
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
