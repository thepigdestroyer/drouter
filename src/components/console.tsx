"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CheckResult,
  FreezeReceipt,
  PopReceipt,
  ScrubResult,
} from "@/lib/types";
import { TINFOIL_MODELS } from "@/lib/tinfoil/client";
import type { DeepAttestationBundle } from "@/lib/tinfoil/deep-inspect";
import {
  getActiveCustomScrubTerms,
  getCurrentVaultSession,
  subscribeVaultSession,
} from "@/lib/auth/vault";
import {
  mintCredits,
  storedCreditBalance,
} from "@/lib/credits/client";
import { downloadAndResume, freezeAndUpload } from "@/lib/freeze/client";
import {
  createMechanicalSession,
  type MechanicalSession,
} from "@/lib/privacy/mechanical";
import {
  hashHex,
  openSession,
  pickNode,
  postJson,
  type ActiveSession,
  type ChatMessage,
  type RegistryNodeRecord,
  type RegistryResponse,
} from "@/components/session";
import {
  prepareHistoryForWire,
  prepareOutboundTurn,
  rebuildMechanicalSessionFromMessages,
  restoreUnspentCreditHeader,
  type MessagePrivacyReport,
} from "@/components/console/send-pipeline";
import {
  ForensicProofCard,
  exportSessionProof,
  type ExportedSessionProof,
} from "@/components/console/proof-exporter";
import { ReceiptView } from "@/components/trust-panel";
import { PrivacyBar } from "@/components/privacy-bar";
import {
  FilterFingerprintBadge,
  useFilterFingerprintStatus,
} from "@/components/privacy/filter-fingerprint-badge";
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

export const CONSOLE_HIDE_MARKER_HINT =
  "Wrap anything in ££ like ££this££ to hide it.";

export interface ConsoleExamplePrompt {
  id: "non-technical" | "technical" | "everyday";
  label: string;
  prompt: string;
  sensitiveItems: readonly string[];
}

export const CONSOLE_EXAMPLE_PROMPTS: readonly ConsoleExamplePrompt[] = [
  {
    id: "non-technical",
    label: "Draft an email with hidden names",
    prompt:
      "Write a polite reply to Dana Reyes at dana.reyes@example.com about rescheduling our call to 2026-10-30 and keeping my number 415-555-0199 and ££our merger offer££ private.",
    sensitiveItems: [
      "Dana Reyes",
      "dana.reyes@example.com",
      "2026-10-30",
      "415-555-0199",
      "our merger offer",
      "££",
    ],
  },
  {
    id: "technical",
    label: "Debug a deploy with hidden technical details",
    prompt: [
      "Why does our deploy fail? Server 10.42.7.19, key ",
      "sk",
      "_live_",
      "51HxYz9876543210fictional, host billing.int.acme.internal, logs in /Users/dana/acme/deploy.log. ££Project Falcon££ launches Friday.",
    ].join(""),
    sensitiveItems: [
      "10.42.7.19",
      ["sk", "_live_", "51HxYz9876543210fictional"].join(""),
      "billing.int.acme.internal",
      "/Users/dana/acme/deploy.log",
      "Project Falcon",
      "££",
    ],
  },
  {
    id: "everyday",
    label: "Ask an everyday question",
    prompt: "Give me three simple dinner ideas I can cook in 20 minutes.",
    sensitiveItems: [],
  },
];

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
  const [model, setModel] = useState<string>(TINFOIL_MODELS[0].id);
  const [node, setNode] = useState<RegistryNodeRecord | null>(null);
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
  const filterFingerprintStatus = useFilterFingerprintStatus();
  const mechanicalSessionRef = useRef<MechanicalSession | null>(null);
  if (!mechanicalSessionRef.current) {
    mechanicalSessionRef.current = createMechanicalSession();
  }
  const scrollRef = useRef<HTMLDivElement>(null);
  const didAutoConnectRef = useRef(false);

  useEffect(() => {
    setCreditBalance(storedCreditBalance());
    setCustomTermsCount(getActiveCustomScrubTerms().length);
    const unsub = subscribeVaultSession(() => {
      if (!getCurrentVaultSession()) {
        mechanicalSessionRef.current?.clear();
      }
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
    async (targetModel: string) => {
      if (!registry) return;
      const chosen = pickNode(registry.nodes, "tinfoil", targetModel);
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
      mechanicalSessionRef.current?.clear();
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
    await connectWith(model);
  }, [connectWith, model]);

  useEffect(() => {
    if (registry && !didAutoConnectRef.current) {
      didAutoConnectRef.current = true;
      void connectWith(model);
    }
  }, [registry, model, connectWith]);

  const handleSwitchModel = useCallback(
    (nextModel: string) => {
      setModel(nextModel);
      if (registry && messages.length === 0 && phase !== "streaming") {
        void connectWith(nextModel);
      }
    },
    [connectWith, messages.length, phase, registry],
  );

  const hasFailedCheck = checks.some((c) => c.status === "fail");
  const filterBlocked = filterFingerprintStatus.blockingSend;
  const canSend =
    phase === "ready" &&
    Boolean(session) &&
    !hasFailedCheck &&
    !filterBlocked &&
    checks.length > 0;

  const send = useCallback(async () => {
    const text = input.trim();
    if (!session || !text || !canSend) return;
    setInput("");
    setError(null);

    let turnPrepared;
    let preparedHistoryMessages: ChatMessage[];
    try {
      preparedHistoryMessages = prepareHistoryForWire(messages, {
        normalizeStyle,
        session: mechanicalSessionRef.current ?? undefined,
      });

      turnPrepared = await prepareOutboundTurn(text, {
        scrubEnabled,
        normalizeStyle,
        session: mechanicalSessionRef.current ?? undefined,
      });
    } catch (e) {
      setError((e as Error).message || "Could not prepare your message right now.");
      setInput(text);
      return;
    }

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

    const displayHistory: ChatMessage[] = [...preparedHistoryMessages, userMsg];
    const wireHistory: ChatMessage[] = displayHistory.map((m) => ({
      role: m.role,
      content: m.wireContent ?? m.content,
      wireContent: m.wireContent ?? m.content,
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
        // Recoverable error: restore user prompt to input and refund unspent credit token
        if (turnPrepared.creditHeader) {
          const refunded = restoreUnspentCreditHeader(
            turnPrepared.creditHeader,
          );
          setCreditBalance(refunded);
        }
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
    mechanicalSessionRef.current?.clear();
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
        model,
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
      modelId: model,
      nodeKind: "tinfoil",
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
      const targetModel =
        restored.modelId && FRIENDLY_MODELS[restored.modelId]
          ? restored.modelId
          : model;
      setModel(targetModel);

      if (
        registry &&
        (!session ||
          session.node.kind !== "tinfoil" ||
          model !== targetModel)
      ) {
        const chosen = pickNode(registry.nodes, "tinfoil", targetModel);
        if (!chosen) {
          const noNodeErr = new Error(
            "No available server was found in the directory.",
          );
          setSession(null);
          setError(noNodeErr.message);
          setPhase("error");
          throw noNodeErr;
        }
        setNode(chosen);
        setPhase("verifying");
        setChecks([]);
        setSession(null);
        setError(null);
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
            const failMsg = failed
              .map((c) => `${c.id} (${c.label}): ${c.detail}`)
              .join(" · ");
            setSession(null);
            setError(failMsg);
            setPhase("error");
            throw new Error(failMsg);
          }
          setSession(active);
          setPhase("ready");
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
          throw err;
        }
      }
      if (mechanicalSessionRef.current) {
        rebuildMechanicalSessionFromMessages(restored.messages, {
          normalizeStyle,
          session: mechanicalSessionRef.current,
        });
      }
      setMessages(restored.messages);
    },
    [model, normalizeStyle, registry, session],
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
        model={model}
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
        {/* Top bar: Friendly model picker, Seal check & End chat */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-paper-2 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="console-model-select" className="ep-label">
              Assistant
            </label>
            <select
              id="console-model-select"
              value={model}
              onChange={(e) => handleSwitchModel(e.target.value)}
              disabled={phase === "streaming" || phase === "verifying"}
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
                  {CONSOLE_EXAMPLE_PROMPTS.map((example) => (
                    <button
                      key={example.id}
                      type="button"
                      onClick={() => setInput(example.prompt)}
                      className="ep-btn-ghost px-3 py-1.5 text-xs"
                    >
                      {example.label}
                    </button>
                  ))}
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
                    {m.role === "user" ? "You" : currentModelInfo.name}
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
                    className="mt-1 flex flex-col items-end text-xs text-ink-3"
                    data-testid="message-privacy-badge"
                  >
                    <span>
                      {formatHiddenDetailsSummary(
                        m.privacyReport.redactions.length,
                      )}
                    </span>
                    {m.wireContent && m.wireContent !== m.content && (
                      <details
                        className="mt-1 max-w-[85%] text-right"
                        data-testid="message-sent-text"
                      >
                        <summary className="cursor-pointer underline">
                          Show exactly what was sent
                        </summary>
                        <div className="mt-1 whitespace-pre-wrap rounded border border-rule bg-paper px-3 py-2 text-left font-mono text-ink-2">
                          {m.wireContent}
                        </div>
                      </details>
                    )}
                  </div>
                )}

                {m.role === "assistant" &&
                  m.wireContent &&
                  m.wireContent !== m.content &&
                  !(phase === "streaming" && i === messages.length - 1) && (
                    <details
                      className="mt-1 max-w-[75ch] text-xs text-ink-3"
                      data-testid="message-restored-badge"
                    >
                      <summary className="cursor-pointer">
                        Your hidden details were put back on this device. The AI
                        only saw placeholders.{" "}
                        <span className="underline">Show what the AI wrote</span>
                      </summary>
                      <div className="mt-1 whitespace-pre-wrap rounded border border-rule bg-paper px-3 py-2 font-mono text-ink-2">
                        {m.wireContent}
                      </div>
                    </details>
                  )}
              </div>
            ))
          )}
        </div>

        {/* Big friendly input form */}
        {filterBlocked && (
          <div
            role="alert"
            data-testid="console-filter-mismatch-block"
            className="border-t border-accent bg-accent-soft px-4 py-2.5 text-xs text-accent"
          >
            Sending is paused right now because this browser&apos;s personal-detail filter does not match the published version. Reload the page to get the latest version; see the filter card below for details.
          </div>
        )}
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
                ? "Type a message... Personal details are hidden automatically."
                : filterBlocked
                  ? "Sending is paused because the personal-detail filter does not match the published version"
                  : phase === "verifying"
                    ? "Checking the seal on the computer..."
                    : phase === "error" || hasFailedCheck
                      ? "Not safe to send right now (seal check did not pass)"
                      : "Check the seal first to unlock the chat"
            }
            className="ep-input min-h-[3.5rem] min-w-0 flex-1 resize-y py-2.5 leading-snug text-sm sm:text-base"
          />
          <button
            type="submit"
            disabled={!canSend || !input.trim()}
            className="ep-btn h-[3.5rem] px-6 text-sm font-medium"
          >
            Send
          </button>
        </form>
        <div
          className="border-t border-rule bg-paper-2 px-4 py-1.5 text-xs text-ink-3"
          data-testid="console-hide-marker-hint"
        >
          {CONSOLE_HIDE_MARKER_HINT}
        </div>
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
        <FilterFingerprintBadge status={filterFingerprintStatus} />

        <PrivacyBar
          scrubEnabled={scrubEnabled}
          onToggleScrub={setScrubEnabled}
          normalizeStyle={normalizeStyle}
          onToggleNormalizeStyle={setNormalizeStyle}
          lastScrubbed={lastScrubbed}
          lastPrivacyReport={lastPrivacyReport}
          customTermsCount={customTermsCount}
          draftText={input}
          session={mechanicalSessionRef.current ?? undefined}
          creditBalance={creditBalance}
          onMintCredits={handleMintCredits}
          onCreditBalanceChange={setCreditBalance}
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
        model={model}
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
