"use client";

import React, { useEffect, useMemo, useState } from "react";
import { InkButton } from "@/components/ink/ink-button";
import { InkReveal } from "@/components/ink/ink-reveal";
import { TechDetails } from "@/components/ink/tech-details";
import {
  DEFAULT_HEART_GRID,
  PRESET_GRIDS,
  blindEnvelopeRound,
  evaluateNodeChoice,
  fetchAndJudgeLiveAttestationNodes,
  judgeCandidateNodes,
  simulateSubpoenaPop,
  tapMemoryBus,
  type CandidateEnclaveNode,
  type CandidateNodeId,
  type MemoryBusMode,
  type MemoryBusProbeResult,
  type SubpoenaAction,
} from "@/lib/game/gauntlet";

export interface EnclaveGauntletProps {
  compact?: boolean;
}

const PLAIN_GUESS_NAMES = [
  "First guess",
  "Second guess",
  "Third guess",
  "Fourth guess",
  "Fifth guess",
  "Sixth guess",
] as const;

const PLAIN_GUESS_DESCRIPTIONS = [
  "You are Chat A · Buyer B is Chat B · Buyer C is Chat C",
  "You are Chat A · Buyer B is Chat C · Buyer C is Chat B",
  "You are Chat B · Buyer B is Chat A · Buyer C is Chat C",
  "You are Chat C · Buyer B is Chat A · Buyer C is Chat B",
  "You are Chat B · Buyer B is Chat C · Buyer C is Chat A",
  "You are Chat C · Buyer B is Chat B · Buyer C is Chat A",
] as const;

const PLAIN_COMPUTER_CARDS: Record<
  CandidateNodeId,
  {
    title: string;
    subtitle: string;
    sealStatusLabel: string;
    checks: Array<{ label: string; value: string; ok: boolean }>;
  }
> = {
  "node-alpha": {
    title: "Computer Alpha",
    subtitle: "Practice copy with a broken seal",
    sealStatusLabel: "Broken seal",
    checks: [
      { label: "Maker stamp", value: "Genuine", ok: true },
      { label: "Snooping door", value: "Left open", ok: false },
      { label: "Public receipt book", value: "Matches", ok: true },
    ],
  },
  "node-bravo": {
    title: "Computer Bravo",
    subtitle: "Practice copy with altered software",
    sealStatusLabel: "Broken seal",
    checks: [
      { label: "Maker stamp", value: "Genuine", ok: true },
      { label: "Snooping door", value: "Locked shut", ok: true },
      { label: "Public receipt book", value: "Does not match", ok: false },
    ],
  },
  "node-charlie": {
    title: "Computer Charlie",
    subtitle: "Genuine sealed computer",
    sealStatusLabel: "Seal intact",
    checks: [
      { label: "Maker stamp", value: "Genuine", ok: true },
      { label: "Snooping door", value: "Locked shut", ok: true },
      { label: "Public receipt book", value: "Matches", ok: true },
    ],
  },
};

export function EnclaveGauntlet({ compact = false }: EnclaveGauntletProps) {
  // Round 1 state ("Spy on the wire")
  const [grid, setGrid] = useState<Array<0 | 1>>([...DEFAULT_HEART_GRID]);
  const [busMode, setBusMode] = useState<MemoryBusMode>("naive-cpu-xts");
  const [round1Solved, setRound1Solved] = useState(false);

  // Round 2 state ("Pay without a name")
  const [tokenSecret, setTokenSecret] = useState<number>(42);
  const [blindingFactor, setBlindingFactor] = useState<number>(19);
  const [selectedPermIdx, setSelectedPermIdx] = useState<number | null>(null);
  const [round2Solved, setRound2Solved] = useState(false);

  // Round 3 state ("Spot the fake"): starts with synchronous binary report verification, then upgrades to live /api/relay/attestation in useEffect
  const [candidateNodes, setCandidateNodes] = useState<CandidateEnclaveNode[]>([]);
  const [liveAttestationLoaded, setLiveAttestationLoaded] = useState(false);
  const [chosenNodeId, setChosenNodeId] = useState<CandidateNodeId | null>(null);
  const [round3Solved, setRound3Solved] = useState(false);

  // Round 4 state ("Vanish")
  const [subpoenaActions, setSubpoenaActions] = useState<SubpoenaAction[]>([]);
  const [round4Solved, setRound4Solved] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setCandidateNodes(judgeCandidateNodes());
    fetchAndJudgeLiveAttestationNodes("/api/relay/attestation")
      .then((liveNodes) => {
        if (!cancelled) {
          setCandidateNodes(liveNodes);
          setLiveAttestationLoaded(true);
        }
      })
      .catch(() => {
        // Keep baseline binary report verification if offline
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Computed results (prerender-safe: tapMemoryBus runs after mount)
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const probeResult = useMemo<MemoryBusProbeResult>(
    () =>
      mounted
        ? tapMemoryBus(grid, busMode)
        : {
            mode: busMode,
            grid,
            blocks: [],
            repeatedBlocks: 0,
            uniqueBlocks: 0,
            entropyBitsPerByte: 0,
            leakRatePct: 0,
            reconstructedGrid: grid.map((cell) =>
              busMode === "naive-cpu-xts" ? cell : null
            ),
            summary: "Locking your drawing in your browser...",
          },
    [mounted, grid, busMode]
  );

  const blindRound = useMemo(
    () => blindEnvelopeRound({ t: tokenSecret, r: blindingFactor }),
    [tokenSecret, blindingFactor]
  );
  const nodeEval = useMemo(
    () => (chosenNodeId ? evaluateNodeChoice(chosenNodeId, candidateNodes) : null),
    [chosenNodeId, candidateNodes]
  );
  const subpoenaState = useMemo(
    () => simulateSubpoenaPop(subpoenaActions),
    [subpoenaActions]
  );

  const completedCount =
    (round1Solved ? 1 : 0) +
    (round2Solved ? 1 : 0) +
    (round3Solved ? 1 : 0) +
    (round4Solved ? 1 : 0);

  const progressMessage =
    completedCount === 0
      ? "Four tiny rounds to play. Each one takes a few seconds."
      : completedCount === 1
        ? "First ink drop collected. Three tiny rounds left."
        : completedCount === 2
          ? "Halfway there. Two ink drops collected."
          : completedCount === 3
            ? "Almost finished. One ink drop left to collect."
            : "All ink drops collected! You tested every step from start to finish.";

  function handleSwitchBusMode(nextMode: MemoryBusMode) {
    setBusMode(nextMode);
    if (nextMode === "drouter-gpu-hbm") {
      setRound1Solved(true);
    }
  }

  function toggleGridCell(idx: number) {
    setGrid((prev) => {
      const next = [...prev];
      next[idx] = prev[idx] === 1 ? 0 : 1;
      return next;
    });
  }

  function handleSelectPermutation(permIndex: number) {
    setSelectedPermIdx(permIndex);
    setRound2Solved(true);
  }

  function handleSpendAnonymousToken() {
    setSelectedPermIdx((prev) => (prev === null ? 0 : (prev + 1) % 6));
    setRound2Solved(true);
  }

  function handlePickCandidateNode(nodeId: CandidateNodeId) {
    setChosenNodeId(nodeId);
    const verdict = evaluateNodeChoice(nodeId, candidateNodes);
    if (verdict.correct) {
      setRound3Solved(true);
    }
  }

  function handleRunSubpoenaSequence(nextActions: SubpoenaAction[]) {
    setSubpoenaActions(nextActions);
    const sim = simulateSubpoenaPop(nextActions);
    if (
      sim.gpuPagesZeroed &&
      !sim.sessionDecryptable &&
      nextActions.includes("host-ram-dump")
    ) {
      setRound4Solved(true);
    }
  }

  function handleToggleSubpoenaStep(action: SubpoenaAction) {
    setSubpoenaActions((prev) => {
      const filtered = prev.filter((a) => a !== action);
      const next = [...filtered, action];
      const sim = simulateSubpoenaPop(next);
      if (
        sim.gpuPagesZeroed &&
        !sim.sessionDecryptable &&
        next.includes("host-ram-dump")
      ) {
        setRound4Solved(true);
      }
      return next;
    });
  }

  const progressDrops = [
    { id: "round-wire", label: "Spy on the wire", done: round1Solved },
    { id: "round-pay", label: "Pay without a name", done: round2Solved },
    { id: "round-fake", label: "Spot the fake", done: round3Solved },
    { id: "round-vanish", label: "Vanish", done: round4Solved },
  ];

  return (
    <div className="space-y-6">
      {/* Cheerful progress row of ink drops */}
      <div className="ep-card p-4 sm:p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <div className="ep-label">Ink drop progress</div>
          <p className="text-sm font-medium text-ink">{progressMessage}</p>
        </div>

        <div
          className="flex flex-wrap items-center gap-3"
          role="list"
          aria-label="Game rounds progress"
        >
          {progressDrops.map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              role="listitem"
              className={`group inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition-all ${
                item.done
                  ? "border-ink bg-ink text-paper"
                  : "border-rule bg-paper-2 text-ink-2 hover:border-ink hover:text-ink"
              }`}
            >
              <svg
                viewBox="0 0 20 24"
                className={`h-4 w-3.5 transition-transform duration-300 ${
                  item.done ? "scale-110" : "group-hover:scale-105"
                }`}
                aria-hidden="true"
              >
                <path
                  d="M10 2 C10 2 3 10.5 3 15.5 C3 19.4 6.1 22.5 10 22.5 C13.9 22.5 17 19.4 17 15.5 C17 10.5 10 2 10 2 Z"
                  fill={item.done ? "currentColor" : "none"}
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinejoin="round"
                />
                {item.done && (
                  <circle
                    cx="7.5"
                    cy="15"
                    r="1.4"
                    fill="var(--color-paper)"
                  />
                )}
              </svg>
              <span className="font-medium">{item.label}</span>
            </a>
          ))}
        </div>
      </div>

      <div className={compact ? "space-y-4" : "space-y-6"}>
        {/* ROUND 1: Spy on the wire */}
        <InkReveal>
          <article id="round-wire" className="ep-card p-5 sm:p-6 space-y-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div>
                <div className="ep-label">First round · Quick play</div>
                <h3 className="ep-display text-xl sm:text-2xl mt-0.5">
                  Spy on the wire
                </h3>
              </div>
              <span className={round1Solved ? "ep-pass" : "ep-muted-chip"}>
                {round1Solved ? "Ink drop earned" : "Ready to try"}
              </span>
            </div>

            {/* One sentence goal */}
            <p className="max-w-[68ch] text-sm sm:text-base text-ink-2">
              Tap squares to draw a little ink picture, then switch from a lazy
              lock to a good lock so a snooper on the wire sees only random
              noise.
            </p>

            {/* Visual drawing canvas + wire snooper view */}
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="ep-inset p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="ep-label">Your secret ink drawing</span>
                  <div className="flex flex-wrap items-center gap-1">
                    {Object.entries(PRESET_GRIDS).map(([key, preset]) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => setGrid([...preset.grid])}
                        className="ep-muted-chip hover:border-ink hover:text-ink cursor-pointer"
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-4 gap-2 max-w-[220px] mx-auto py-1">
                  {grid.map((cell, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => toggleGridCell(idx)}
                      aria-label={
                        cell === 1
                          ? "Filled ink square, tap to clear"
                          : "Blank square, tap to paint with ink"
                      }
                      aria-pressed={cell === 1}
                      className={`aspect-square rounded-md border transition-all flex items-center justify-center cursor-pointer ${
                        cell === 1
                          ? "border-ink bg-ink text-paper scale-[0.98]"
                          : "border-rule bg-paper hover:bg-paper-3 text-ink-3"
                      }`}
                    >
                      <svg
                        viewBox="0 0 24 24"
                        className="h-5 w-5"
                        aria-hidden="true"
                      >
                        {cell === 1 ? (
                          <path
                            d="M12 4 C16 4 20 7.5 19.5 12.5 C19 17 15.5 20 11.5 19.5 C7 19 4 16 4.5 11.5 C5 7 8 4 12 4 Z"
                            fill="currentColor"
                          />
                        ) : (
                          <circle
                            cx="12"
                            cy="12"
                            r="1.5"
                            fill="currentColor"
                            opacity="0.35"
                          />
                        )}
                      </svg>
                    </button>
                  ))}
                </div>
              </div>

              <div className="ep-inset p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="ep-label">What a snooper on the wire sees</span>
                  <span
                    className={
                      busMode === "naive-cpu-xts" ? "ep-fail" : "ep-pass"
                    }
                  >
                    {busMode === "naive-cpu-xts" ? "Shape leaked" : "Only noise"}
                  </span>
                </div>

                <div className="grid grid-cols-4 gap-2 max-w-[220px] mx-auto py-1">
                  {probeResult.reconstructedGrid.map((rec, idx) => (
                    <div
                      key={idx}
                      className={`aspect-square rounded-md border flex items-center justify-center transition-all ${
                        rec === null
                          ? "border-rule bg-paper text-ink-2"
                          : rec === 1
                            ? "border-accent bg-accent-soft text-accent"
                            : "border-rule bg-paper-2 text-ink-4"
                      }`}
                    >
                      <svg
                        viewBox="0 0 24 24"
                        className="h-5 w-5"
                        aria-hidden="true"
                      >
                        {rec === null ? (
                          <>
                            <circle cx="7" cy="8" r="1.4" fill="currentColor" />
                            <circle cx="16" cy="10" r="1.1" fill="currentColor" />
                            <circle cx="10" cy="16" r="1.3" fill="currentColor" />
                            <circle cx="17" cy="17" r="1" fill="currentColor" />
                          </>
                        ) : rec === 1 ? (
                          <path
                            d="M12 4 C16 4 20 7.5 19.5 12.5 C19 17 15.5 20 11.5 19.5 C7 19 4 16 4.5 11.5 C5 7 8 4 12 4 Z"
                            fill="currentColor"
                          />
                        ) : (
                          <circle
                            cx="12"
                            cy="12"
                            r="1.5"
                            fill="currentColor"
                            opacity="0.25"
                          />
                        )}
                      </svg>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* One big obvious interaction */}
            <div className="flex flex-wrap items-center gap-3">
              {busMode === "naive-cpu-xts" ? (
                <InkButton
                  type="button"
                  variant="primary"
                  onClick={() => handleSwitchBusMode("drouter-gpu-hbm")}
                >
                  Switch to a good lock (hide the shape)
                </InkButton>
              ) : (
                <InkButton
                  type="button"
                  variant="ghost"
                  onClick={() => handleSwitchBusMode("naive-cpu-xts")}
                >
                  Compare with lazy lock (see the leak again)
                </InkButton>
              )}
            </div>

            {/* One plain result sentence */}
            <div className="ep-inset px-4 py-3 text-sm text-ink">
              {busMode === "naive-cpu-xts"
                ? "With a lazy lock, matching ink squares look identical on the wire, so the snooper can see the outline of your picture."
                : "With a good lock, every square is scrambled in a fresh way, so the snooper sees only random static."}
            </div>

            <TechDetails label="What really happened">
              <div className="space-y-3 pt-2 text-xs text-ink-2">
                <p className="max-w-[68ch] leading-relaxed">
                  Physical memory interposers sit passively between the CPU and
                  DDR5 DIMMs. When identical 16-byte blocks are encrypted
                  deterministically with AES-256-ECB (
                  <code className="font-mono text-ink">naive-cpu-xts</code>),
                  duplicate ciphertext blocks reveal the 4x4 silhouette.
                  Switching to AES-256-GCM with a fresh 96-bit nonce per
                  transfer (
                  <code className="font-mono text-ink">drouter-gpu-hbm</code>)
                  makes every 16-byte ciphertext block unique (
                  {probeResult.uniqueBlocks} of 16 unique blocks,{" "}
                  {probeResult.entropyBitsPerByte.toFixed(2)} bits/byte
                  entropy, {probeResult.leakRatePct}% leaked).
                </p>
                <div className="ep-inset p-3">
                  <div className="ep-label mb-2">
                    16-byte bus ciphertext ({probeResult.repeatedBlocks}{" "}
                    duplicates)
                  </div>
                  <div className="grid grid-cols-4 gap-1.5 max-w-xs">
                    {probeResult.blocks.map((blk) => (
                      <div
                        key={blk.index}
                        title={`Block #${blk.index}: 0x${blk.cipherBlockHex}`}
                        className={`flex h-7 items-center justify-center rounded border font-mono text-[10px] px-1 truncate ${
                          blk.matchesFirstActiveBlock
                            ? "border-accent bg-accent-soft text-ink font-semibold"
                            : "border-rule bg-paper text-ink-2"
                        }`}
                      >
                        0x{blk.cipherBlockHex.slice(0, 4)}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="font-mono text-[11px] text-ink">
                  {probeResult.summary}
                </div>
              </div>
            </TechDetails>
          </article>
        </InkReveal>

        {/* ROUND 2: Pay without a name */}
        <InkReveal>
          <article id="round-pay" className="ep-card p-5 sm:p-6 space-y-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div>
                <div className="ep-label">Second round · Quick play</div>
                <h3 className="ep-display text-xl sm:text-2xl mt-0.5">
                  Pay without a name
                </h3>
              </div>
              <span className={round2Solved ? "ep-pass" : "ep-muted-chip"}>
                {round2Solved ? "Ink drop earned" : "Ready to try"}
              </span>
            </div>

            {/* One sentence goal */}
            <p className="max-w-[68ch] text-sm sm:text-base text-ink-2">
              Turn a prepaid token anonymous and spend it so the shop knows it
              is paid for, but cannot tell it was you.
            </p>

            {/* Visual envelope stamp flow */}
            <div className="ep-inset p-4 space-y-4">
              <svg
                viewBox="0 0 360 72"
                className="h-16 w-full max-w-lg mx-auto text-ink"
                fill="none"
                aria-hidden="true"
              >
                {/* Step A: Token in envelope */}
                <rect
                  x="12"
                  y="14"
                  width="84"
                  height="44"
                  rx="4"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  fill="var(--color-paper)"
                />
                <path
                  d="M12 18 L54 38 L96 18"
                  stroke="currentColor"
                  strokeWidth="1.3"
                />
                <path
                  d="M106 36 H132 M127 31 L133 36 L127 41"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                {/* Step B: Shop stamps outside */}
                <rect
                  x="140"
                  y="14"
                  width="84"
                  height="44"
                  rx="4"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  fill="var(--color-paper)"
                />
                <circle
                  cx="182"
                  cy="36"
                  r="11"
                  stroke="currentColor"
                  strokeWidth="1.5"
                />
                <circle cx="182" cy="36" r="5" fill="currentColor" />
                <path
                  d="M234 36 H260 M255 31 L261 36 L255 41"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                {/* Step C: Clean stamped token */}
                <rect
                  x="268"
                  y="18"
                  width="80"
                  height="36"
                  rx="18"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  fill={round2Solved ? "var(--color-ink)" : "var(--color-paper)"}
                />
                <circle
                  cx="308"
                  cy="36"
                  r="7"
                  fill={round2Solved ? "var(--color-paper)" : "currentColor"}
                />
              </svg>

              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {blindRound.permutations.map((perm, idx) => {
                  const isSelected = selectedPermIdx === idx;
                  return (
                    <button
                      key={perm.mappingSummary}
                      type="button"
                      onClick={() => handleSelectPermutation(idx)}
                      className={`rounded border p-2.5 text-left text-xs transition-colors cursor-pointer ${
                        isSelected
                          ? "border-ink bg-ink text-paper"
                          : "border-rule bg-paper text-ink hover:bg-paper-3"
                      }`}
                    >
                      <div className="font-semibold">
                        {PLAIN_GUESS_NAMES[idx]}
                      </div>
                      <div
                        className={`mt-0.5 text-[11px] ${
                          isSelected ? "text-paper/85" : "text-ink-2"
                        }`}
                      >
                        {PLAIN_GUESS_DESCRIPTIONS[idx]}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* One big obvious interaction */}
            <div className="flex flex-wrap items-center gap-3">
              <InkButton
                type="button"
                variant={round2Solved ? "ghost" : "primary"}
                onClick={handleSpendAnonymousToken}
              >
                {round2Solved
                  ? "Test another shop guess"
                  : "Make token anonymous and spend it"}
              </InkButton>
            </div>

            {/* One plain result sentence */}
            <div className="ep-inset px-4 py-3 text-sm text-ink">
              {selectedPermIdx === null
                ? "Tap the button above to wrap a prepaid token in an anonymous envelope, get it stamped, and spend it at the shop."
                : "The shop checked its stamp and accepted your anonymous token, yet every buyer fits every chat equally well so it cannot tell which chat was yours."}
            </div>

            <TechDetails label="What really happened">
              <div className="space-y-3 pt-2 text-xs text-ink-2">
                <p className="max-w-[68ch] leading-relaxed">
                  Your browser hashes the token with Full-Domain Hash (
                  <code className="font-mono text-ink">hashTokenMessage</code>)
                  and blinds it with <code className="font-mono text-ink">r^e mod n</code>{" "}
                  (<code className="font-mono text-ink">blindToken</code>)
                  before the mint signs it (
                  <code className="font-mono text-ink">signBlinded</code>), then
                  divides out <code className="font-mono text-ink">r</code>{" "}
                  locally (
                  <code className="font-mono text-ink">unblindSignature</code>).
                  All {blindRound.validPermutationsCount} of 6 buyer-to-session
                  permutations are mathematically consistent with the{" "}
                  {blindRound.modulusBits}-bit RSA blind signature transcript.
                </p>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 max-w-md">
                  <label className="block font-mono text-xs">
                    <span className="text-ink-3">Token seed</span>
                    <input
                      type="number"
                      min={2}
                      max={3000}
                      value={tokenSecret}
                      onChange={(e) =>
                        setTokenSecret(Number(e.target.value) || 42)
                      }
                      className="ep-input mt-1"
                    />
                  </label>
                  <label className="block font-mono text-xs">
                    <span className="text-ink-3">Blinding factor seed</span>
                    <input
                      type="number"
                      min={2}
                      max={3000}
                      value={blindingFactor}
                      onChange={(e) =>
                        setBlindingFactor(Number(e.target.value) || 19)
                      }
                      className="ep-input mt-1"
                    />
                  </label>
                </div>
                <div className="ep-inset p-3 font-mono text-[11px] space-y-1 break-all">
                  <div>
                    1. RSA modulus size: {blindRound.modulusBits} bits (e ={" "}
                    {blindRound.e.toString()})
                  </div>
                  <div>
                    2. Blinded envelope hex: 0x
                    {blindRound.blindedHex.slice(0, 32)}...
                  </div>
                  <div>
                    3. Unblinded signature hex: 0x
                    {blindRound.signatureHex.slice(0, 32)}...
                  </div>
                  <div>
                    4. Spend nullifier SHA-256: 0x
                    {blindRound.nullifierHex.slice(0, 32)}...
                  </div>
                  <div>
                    5. verifyTokenSignature(token, pub):{" "}
                    {blindRound.signatureValid
                      ? "Valid (s^e mod n == H(token))"
                      : "Invalid"}
                  </div>
                </div>
              </div>
            </TechDetails>
          </article>
        </InkReveal>

        {/* ROUND 3: Spot the fake */}
        <InkReveal>
          <article id="round-fake" className="ep-card p-5 sm:p-6 space-y-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div>
                <div className="ep-label">Third round · Quick play</div>
                <h3 className="ep-display text-xl sm:text-2xl mt-0.5">
                  Spot the fake
                </h3>
              </div>
              <span className={round3Solved ? "ep-pass" : "ep-muted-chip"}>
                {round3Solved ? "Ink drop earned" : "Ready to try"}
              </span>
            </div>

            {/* One sentence goal */}
            <p className="max-w-[68ch] text-sm sm:text-base text-ink-2">
              Three sealed computers are waiting for your message, and two have
              broken seals; pick the only safe one.
            </p>

            {/* Three sealed computers */}
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {candidateNodes.map((node) => {
                const isSelected = chosenNodeId === node.id;
                const plainCard = PLAIN_COMPUTER_CARDS[node.id];
                return (
                  <div
                    key={node.id}
                    className={`ep-inset p-4 flex flex-col justify-between gap-4 transition-all ${
                      isSelected ? "border-ink ring-1 ring-ink" : ""
                    }`}
                  >
                    <div className="space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-serif text-base font-medium text-ink">
                          {plainCard.title}
                        </span>
                        <span
                          className={
                            node.isAuthentic ? "ep-pass" : "ep-fail"
                          }
                        >
                          {plainCard.sealStatusLabel}
                        </span>
                      </div>

                      <p className="text-xs text-ink-3">{plainCard.subtitle}</p>

                      {/* Wax/Ink seal illustration */}
                      <svg
                        viewBox="0 0 120 48"
                        className="h-11 w-full text-ink"
                        fill="none"
                        aria-hidden="true"
                      >
                        <rect
                          x="16"
                          y="6"
                          width="88"
                          height="36"
                          rx="4"
                          stroke="currentColor"
                          strokeWidth="1.4"
                          fill="var(--color-paper)"
                        />
                        {node.isAuthentic ? (
                          <>
                            <circle
                              cx="60"
                              cy="24"
                              r="11"
                              fill="currentColor"
                            />
                            <path
                              d="M55 24 L58.5 27.5 L66 20"
                              stroke="var(--color-paper)"
                              strokeWidth="2"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            />
                          </>
                        ) : (
                          <>
                            <circle
                              cx="60"
                              cy="24"
                              r="11"
                              stroke="var(--color-accent)"
                              strokeWidth="1.8"
                              fill="var(--color-accent-soft)"
                            />
                            <path
                              d="M55 17 L62 24 L57 27 L64 31"
                              stroke="var(--color-accent)"
                              strokeWidth="1.8"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            />
                          </>
                        )}
                      </svg>

                      <div className="space-y-1.5 border-t border-rule pt-2.5 text-xs">
                        {plainCard.checks.map((chk) => (
                          <div
                            key={chk.label}
                            className="flex items-center justify-between gap-2"
                          >
                            <span className="text-ink-2">{chk.label}</span>
                            <span
                              className={chk.ok ? "ep-pass" : "ep-fail"}
                            >
                              {chk.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <InkButton
                      type="button"
                      variant={isSelected ? "primary" : "ghost"}
                      onClick={() => handlePickCandidateNode(node.id)}
                      className="w-full"
                    >
                      Pick {plainCard.title}
                    </InkButton>
                  </div>
                );
              })}
            </div>

            {/* One plain result sentence */}
            <div className="ep-inset px-4 py-3 text-sm text-ink">
              {chosenNodeId === null
                ? "Inspect the three seal checks above and pick the only sealed computer whose seal is completely intact."
                : chosenNodeId === "node-alpha"
                  ? "Hold on! That computer left its snooping door open, so your browser refused to send a single word. Try the computer with an intact seal."
                  : chosenNodeId === "node-bravo"
                    ? "Hold on! That computer is running software that does not match the public receipt book, so your browser blocked it. Try the computer with an intact seal."
                    : "Safe choice! We checked the seal is intact, so your browser locked your message so only this sealed computer can open it."}
            </div>

            <TechDetails label="What really happened">
              <div className="space-y-3 pt-2 text-xs text-ink-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="ep-muted-chip">
                    {liveAttestationLoaded
                      ? "Live /api/relay/attestation"
                      : "Binary SEV-SNP verifier"}
                  </span>
                </div>
                <p className="max-w-[68ch] leading-relaxed">
                  Candidate Charlie uses the authentic 1,184-byte AMD SEV-SNP
                  report from{" "}
                  <code className="font-mono text-ink">router-0.tinfoil.sh</code>
                  . Candidate Alpha has bit 19 (DEBUG) flipped at byte offset
                  0x08 of the binary report. Candidate Bravo has a tampered
                  release digest that fails the Sigstore transparency log check.
                </p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 font-mono text-[11px]">
                  {candidateNodes.map((n) => (
                    <div key={n.id} className="ep-inset p-2.5 space-y-1">
                      <div className="font-semibold text-ink">{n.name}</div>
                      {n.checks.map((c) => (
                        <div
                          key={c.id}
                          className="flex items-center justify-between gap-1"
                        >
                          <span className="text-ink-3 truncate">
                            {c.registerName}
                          </span>
                          <span className="text-ink">
                            {c.passed ? "PASS" : "FAIL"}
                          </span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
                {nodeEval && (
                  <p className="font-mono text-[11px] text-ink">
                    {nodeEval.verdictHeadline} ({nodeEval.caughtRegister}):{" "}
                    {nodeEval.explanation}
                  </p>
                )}
                {nodeEval?.chosenNode.verifierError && (
                  <p className="font-mono text-[11px] text-accent">
                    Verifier error: {nodeEval.chosenNode.verifierError}
                  </p>
                )}
              </div>
            </TechDetails>
          </article>
        </InkReveal>

        {/* ROUND 4: Vanish */}
        <InkReveal>
          <article id="round-vanish" className="ep-card p-5 sm:p-6 space-y-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div>
                <div className="ep-label">Fourth round · Quick play</div>
                <h3 className="ep-display text-xl sm:text-2xl mt-0.5">
                  Vanish
                </h3>
              </div>
              <span className={round4Solved ? "ep-pass" : "ep-muted-chip"}>
                {round4Solved ? "Ink drop earned" : "Ready to try"}
              </span>
            </div>

            {/* One sentence goal */}
            <p className="max-w-[68ch] text-sm sm:text-base text-ink-2">
              End the chat and watch the temporary key dissolve so nothing can
              be read later.
            </p>

            {/* Living ink key dissolving visual */}
            <div className="ep-inset p-5 flex flex-col items-center justify-center gap-3">
              <svg
                viewBox="0 0 260 68"
                className="h-16 w-full max-w-md text-ink"
                fill="none"
                aria-hidden="true"
              >
                {round4Solved ? (
                  <>
                    {/* Dissolved ink droplets */}
                    <circle cx="66" cy="34" r="3" fill="currentColor" opacity="0.25" />
                    <circle cx="84" cy="22" r="2" fill="currentColor" opacity="0.2" />
                    <circle cx="96" cy="44" r="2.5" fill="currentColor" opacity="0.18" />
                    <circle cx="122" cy="30" r="2" fill="currentColor" opacity="0.22" />
                    <circle cx="145" cy="38" r="1.8" fill="currentColor" opacity="0.15" />
                    <circle cx="168" cy="26" r="2.2" fill="currentColor" opacity="0.2" />
                    <circle cx="192" cy="36" r="2.5" fill="currentColor" opacity="0.15" />
                  </>
                ) : (
                  <>
                    {/* Solid ink key */}
                    <circle
                      cx="78"
                      cy="34"
                      r="16"
                      stroke="currentColor"
                      strokeWidth="2.5"
                      fill="var(--color-paper)"
                    />
                    <circle cx="78" cy="34" r="5" fill="currentColor" />
                    <path
                      d="M94 34 H188 M166 34 V48 M182 34 V44"
                      stroke="currentColor"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                    />
                  </>
                )}
              </svg>
              <div className="text-xs font-medium text-ink-2">
                {round4Solved
                  ? "Key dissolved into blank paper"
                  : "Temporary chat key is currently active"}
              </div>
            </div>

            {/* One big obvious interaction */}
            <div className="flex flex-wrap items-center gap-3">
              <InkButton
                type="button"
                variant={round4Solved ? "ghost" : "primary"}
                onClick={() =>
                  handleRunSubpoenaSequence(["pop", "host-ram-dump"])
                }
              >
                {round4Solved
                  ? "Key dissolved! Tap to test again"
                  : "End chat and dissolve the key"}
              </InkButton>
              {subpoenaActions.length > 0 && (
                <InkButton
                  type="button"
                  variant="ghost"
                  onClick={() => setSubpoenaActions([])}
                >
                  Bring key back
                </InkButton>
              )}
            </div>

            {/* One plain result sentence */}
            <div className="ep-inset px-4 py-3 text-sm text-ink">
              {round4Solved
                ? "The key dissolved into blank paper, and when someone tried to read the computer memory afterward, nothing could be opened."
                : "While your practice chat is open, the temporary key lives only inside the sealed computer."}
            </div>

            <TechDetails label="What really happened">
              <div className="space-y-3 pt-2 text-xs text-ink-2">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 font-mono text-xs">
                  <div className="ep-inset p-3">
                    <div className="ep-label">256-bit session key</div>
                    <div className="mt-1 font-semibold text-ink truncate">
                      0x{subpoenaState.sessionKeyHex.slice(0, 16)}...
                    </div>
                  </div>
                  <div className="ep-inset p-3">
                    <div className="ep-label">AES-256-GCM decrypt test</div>
                    <div className="mt-1 font-semibold text-ink">
                      {subpoenaState.sessionDecryptable
                        ? "Decrypts (key live)"
                        : "Failed (tag mismatch)"}
                    </div>
                  </div>
                  <div className="ep-inset p-3">
                    <div className="ep-label">Server RAM dump readable</div>
                    <div className="mt-1 font-semibold text-ink">
                      {subpoenaState.hostDumpReadableBytes} bytes
                    </div>
                  </div>
                </div>
                <div className="font-mono text-[11px] text-ink">
                  {subpoenaState.subpoenaYieldSummary}
                </div>
                {subpoenaState.decryptionError && (
                  <div className="ep-inset p-2.5 font-mono text-[11px] text-ink">
                    {subpoenaState.decryptionError}
                  </div>
                )}
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleToggleSubpoenaStep("freeze")}
                    className="ep-btn-ghost py-1 px-2.5 text-xs"
                  >
                    1. Freeze encrypted backup
                  </button>
                  <button
                    type="button"
                    onClick={() => handleToggleSubpoenaStep("pop")}
                    className="ep-btn-ghost py-1 px-2.5 text-xs"
                  >
                    2. Pop session (zero key)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleToggleSubpoenaStep("shred-secret")}
                    className="ep-btn-ghost py-1 px-2.5 text-xs"
                  >
                    3. Destroy local key
                  </button>
                  <button
                    type="button"
                    onClick={() => handleToggleSubpoenaStep("host-ram-dump")}
                    className="ep-btn-ghost py-1 px-2.5 text-xs"
                  >
                    4. Run RAM dump decrypt
                  </button>
                </div>
                <ul className="space-y-1 font-mono text-[11px] text-ink-2">
                  {subpoenaState.timelineLog.map((entry, idx) => (
                    <li key={idx}>
                      [{idx}] {entry}
                    </li>
                  ))}
                </ul>
              </div>
            </TechDetails>
          </article>
        </InkReveal>
      </div>
    </div>
  );
}
