"use client";

import React, { useMemo, useState } from "react";
import {
  DEFAULT_HEART_GRID,
  PRESET_GRIDS,
  blindEnvelopeRound,
  evaluateNodeChoice,
  judgeCandidateNodes,
  simulateSubpoenaPop,
  tapMemoryBus,
  type CandidateNodeId,
  type MemoryBusMode,
  type SubpoenaAction,
} from "@/lib/game/gauntlet";

export interface EnclaveGauntletProps {
  compact?: boolean;
}

export function EnclaveGauntlet({ compact = false }: EnclaveGauntletProps) {
  // Round 1 state
  const [grid, setGrid] = useState<Array<0 | 1>>([...DEFAULT_HEART_GRID]);
  const [busMode, setBusMode] = useState<MemoryBusMode>("naive-cpu-xts");
  const [round1Solved, setRound1Solved] = useState(false);

  // Round 2 state (starts unselected so clicking any matching solves the round)
  const [tokenSecret, setTokenSecret] = useState<number>(42);
  const [blindingFactor, setBlindingFactor] = useState<number>(19);
  const [selectedPermIdx, setSelectedPermIdx] = useState<number | null>(null);
  const [round2Solved, setRound2Solved] = useState(false);

  // Round 3 state
  const candidateNodes = useMemo(() => judgeCandidateNodes(), []);
  const [chosenNodeId, setChosenNodeId] = useState<CandidateNodeId | null>(null);
  const [round3Solved, setRound3Solved] = useState(false);

  // Round 4 state
  const [subpoenaActions, setSubpoenaActions] = useState<SubpoenaAction[]>([]);
  const [round4Solved, setRound4Solved] = useState(false);

  // Computed results
  const probeResult = useMemo(() => tapMemoryBus(grid, busMode), [grid, busMode]);
  const blindRound = useMemo(
    () => blindEnvelopeRound({ t: tokenSecret, r: blindingFactor }),
    [tokenSecret, blindingFactor],
  );
  const nodeEval = useMemo(
    () => (chosenNodeId ? evaluateNodeChoice(chosenNodeId, candidateNodes) : null),
    [chosenNodeId, candidateNodes],
  );
  const subpoenaState = useMemo(
    () => simulateSubpoenaPop(subpoenaActions),
    [subpoenaActions],
  );

  const completedCount =
    (round1Solved ? 1 : 0) +
    (round2Solved ? 1 : 0) +
    (round3Solved ? 1 : 0) +
    (round4Solved ? 1 : 0);

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
    if (sim.gpuPagesZeroed && nextActions.includes("host-ram-dump")) {
      setRound4Solved(true);
    }
  }

  function handleToggleSubpoenaStep(action: SubpoenaAction) {
    setSubpoenaActions((prev) => {
      const filtered = prev.filter((a) => a !== action);
      const next = [...filtered, action];
      const sim = simulateSubpoenaPop(next);
      if (sim.gpuPagesZeroed && next.includes("host-ram-dump")) {
        setRound4Solved(true);
      }
      return next;
    });
  }

  return (
    <div className="space-y-6">
      {/* Simple Progress Indicator */}
      <div className="ep-card p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="ep-label">Interactive Verification Game</span>
          <span className="font-mono text-xs text-ink">
            {completedCount} of 4 rounds solved
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {[
            { id: "1", label: "1. Memory bus", done: round1Solved },
            { id: "2", label: "2. Blind credit", done: round2Solved },
            { id: "3", label: "3. Enclave check", done: round3Solved },
            { id: "4", label: "4. Session wipe", done: round4Solved },
          ].map((item) => (
            <span
              key={item.id}
              className={item.done ? "ep-pass" : "ep-muted-chip"}
            >
              {item.label} {item.done ? "✓" : ""}
            </span>
          ))}
        </div>
      </div>

      <div className={compact ? "space-y-4" : "space-y-6"}>
        {/* ROUND 1: Memory-Bus Probe */}
        <article className="ep-card p-5 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <div className="ep-label">Round 1 of 4</div>
              <h3 className="ep-display text-xl mt-0.5">
                Defeat a physical memory-bus wire tap
              </h3>
            </div>
            <span className={round1Solved ? "ep-pass" : "ep-muted-chip"}>
              {round1Solved ? "Solved" : "Unsolved"}
            </span>
          </div>

          {/* One-sentence goal */}
          <p className="max-w-[68ch] text-sm text-ink-2">
            Switch from static CPU memory encryption to fresh GPU nonces so a physical wire tap on the RAM bus cannot see repeated blocks.
          </p>

          {/* One primary interaction */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => handleSwitchBusMode("naive-cpu-xts")}
              className={
                busMode === "naive-cpu-xts" ? "ep-btn" : "ep-btn-ghost"
              }
            >
              Static CPU memory (leaks)
            </button>
            <button
              type="button"
              onClick={() => handleSwitchBusMode("drouter-gpu-hbm")}
              className={
                busMode === "drouter-gpu-hbm" ? "ep-btn" : "ep-btn-ghost"
              }
            >
              Fresh GPU nonce (blocks tap)
            </button>
          </div>

          {/* Compact visual comparison: Secret vs Wire tap view */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 max-w-xl">
            <div className="ep-inset p-3">
              <div className="ep-label mb-2">Your 4x4 secret pattern</div>
              <div className="grid grid-cols-4 gap-1.5">
                {grid.map((cell, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => toggleGridCell(idx)}
                    aria-label={`Toggle secret grid cell ${idx + 1}`}
                    className={`h-7 rounded border font-mono text-[10px] transition-colors ${
                      cell === 1
                        ? "border-ink bg-ink text-paper"
                        : "border-rule bg-paper text-ink-3"
                    }`}
                  >
                    {cell === 1 ? "1" : "0"}
                  </button>
                ))}
              </div>
            </div>

            <div className="ep-inset p-3">
              <div className="ep-label mb-2">
                What the physical wire tap reconstructs ({probeResult.leakRatePct}% leaked)
              </div>
              <div className="grid grid-cols-4 gap-1.5">
                {probeResult.reconstructedGrid.map((rec, idx) => (
                  <div
                    key={idx}
                    className={`flex h-7 items-center justify-center rounded border font-mono text-[10px] ${
                      rec === null
                        ? "border-rule bg-paper text-ink-3"
                        : rec === 1
                          ? "border-ink bg-ink text-paper"
                          : "border-rule bg-paper-2 text-ink-3"
                    }`}
                  >
                    {rec === null ? "?" : rec === 1 ? "1" : "0"}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* One result line */}
          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {probeResult.summary}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-3 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                Physical memory interposers like TEE.fail sit passively between the CPU and DDR5 DIMMs. When identical 16-byte blocks are encrypted with a fixed address tweak, duplicates reveal the silhouette. Keeping active pages inside on-package GPU HBM and using a monotonic 96-bit AES-256-GCM nonce for every transfer makes every block unique ({probeResult.entropyBitsPerByte.toFixed(2)} bits/byte entropy).
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <span className="ep-label">Pattern presets:</span>
                {Object.entries(PRESET_GRIDS).map(([key, preset]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setGrid([...preset.grid])}
                    className="ep-btn-ghost py-1 px-2 text-xs"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>
          </details>
        </article>

        {/* ROUND 2: Blind Credit */}
        <article className="ep-card p-5 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <div className="ep-label">Round 2 of 4</div>
              <h3 className="ep-display text-xl mt-0.5">
                Pay without linking your wallet to your prompt
              </h3>
            </div>
            <span className={round2Solved ? "ep-pass" : "ep-muted-chip"}>
              {round2Solved ? "Solved" : "Unsolved"}
            </span>
          </div>

          {/* One-sentence goal */}
          <p className="max-w-[68ch] text-sm text-ink-2">
            Click any of the six possible buyer-to-session matchings below to see whether the billing server can link Alice, Bob, or Carol to their anonymous chats.
          </p>

          {/* One primary interaction */}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {blindRound.permutations.map((perm, idx) => {
              const isSelected = selectedPermIdx === idx;
              return (
                <button
                  key={perm.mappingSummary}
                  type="button"
                  onClick={() => handleSelectPermutation(idx)}
                  className={`rounded border p-2.5 text-left font-mono text-xs transition-colors ${
                    isSelected
                      ? "border-ink bg-ink text-paper"
                      : "border-rule bg-paper-2 text-ink hover:bg-paper-3"
                  }`}
                >
                  <div className="font-semibold">Matching #{idx + 1}</div>
                  <div
                    className={`mt-0.5 text-[11px] ${
                      isSelected ? "text-paper/85" : "text-ink-2"
                    }`}
                  >
                    {perm.mappingSummary}
                  </div>
                </button>
              );
            })}
          </div>

          {/* One result line */}
          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {selectedPermIdx === null
              ? "Select any buyer-to-session matching above to test if the billing server can rule it out."
              : `Matching #${selectedPermIdx + 1} is 100% consistent with the bank log (${blindRound.validPermutationsCount} of 6 matchings are equally valid, so the server learns nothing).`}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-3 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                Your browser multiplies token serial <code className="font-mono text-ink">t</code> by a random blinding factor <code className="font-mono text-ink">r^e mod n</code> before the mint signs it, then divides out <code className="font-mono text-ink">r</code> locally. For every possible buyer-to-spend pair, there is an exact factor <code className="font-mono text-ink">r_ij</code> that satisfies the equation.
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 max-w-md">
                <label className="block font-mono text-xs">
                  <span className="text-ink-3">Token serial (t)</span>
                  <input
                    type="number"
                    min={2}
                    max={3000}
                    value={tokenSecret}
                    onChange={(e) => setTokenSecret(Number(e.target.value) || 42)}
                    className="ep-input mt-1"
                  />
                </label>
                <label className="block font-mono text-xs">
                  <span className="text-ink-3">Blinding factor (r)</span>
                  <input
                    type="number"
                    min={2}
                    max={3000}
                    value={blindingFactor}
                    onChange={(e) => setBlindingFactor(Number(e.target.value) || 19)}
                    className="ep-input mt-1"
                  />
                </label>
              </div>
              <div className="ep-inset p-3 font-mono text-[11px] space-y-1">
                <div>1. Blinded envelope (t * r^e mod {blindRound.n.toString()}): {blindRound.blinded.toString()}</div>
                <div>2. Bank signature on envelope (s&apos;): {blindRound.sPrime.toString()}</div>
                <div>3. Unblinded signature (s = s&apos; * r^-1 mod n): {blindRound.s.toString()}</div>
                <div>4. Enclave check (s^e mod n == t): {blindRound.recomputedFromSignature.toString()} == {blindRound.t.toString()} (Valid)</div>
              </div>
            </div>
          </details>
        </article>

        {/* ROUND 3: Spot the Forged Enclave */}
        <article className="ep-card p-5 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <div className="ep-label">Round 3 of 4</div>
              <h3 className="ep-display text-xl mt-0.5">
                Spot the forged enclave before sending your prompt
              </h3>
            </div>
            <span className={round3Solved ? "ep-pass" : "ep-muted-chip"}>
              {round3Solved ? "Solved" : "Unsolved"}
            </span>
          </div>

          {/* One-sentence goal */}
          <p className="max-w-[68ch] text-sm text-ink-2">
            Check the hardware reports from three servers and route your prompt to the only node where every check passes.
          </p>

          {/* One primary interaction */}
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            {candidateNodes.map((node) => {
              const isSelected = chosenNodeId === node.id;
              return (
                <div
                  key={node.id}
                  className={`ep-inset p-3.5 flex flex-col justify-between gap-3 ${
                    isSelected ? "border-ink" : ""
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between font-mono text-xs">
                      <span className="font-semibold text-ink">{node.name}</span>
                      <span className="text-ink-3">{node.region}</span>
                    </div>

                    <div className="space-y-1.5 border-t border-rule pt-2 font-mono text-[11px]">
                      {node.checks.slice(0, 3).map((chk) => (
                        <div
                          key={chk.id}
                          className="flex items-center justify-between gap-2"
                        >
                          <span className="text-ink-2 truncate">{chk.registerName}</span>
                          <span className={chk.passed ? "ep-pass" : "ep-fail"}>
                            {chk.passed ? "Pass" : "Fail"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handlePickCandidateNode(node.id)}
                    className={isSelected ? "ep-btn w-full" : "ep-btn-ghost w-full"}
                  >
                    Route to {node.id}
                  </button>
                </div>
              );
            })}
          </div>

          {/* One result line */}
          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {nodeEval
              ? `${nodeEval.verdictHeadline} (${nodeEval.caughtRegister})`
              : "Pick one of the three servers above to verify its hardware report."}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-2 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                A valid AMD hardware signature alone is not enough. Node Alpha has guest policy bit 19 (DEBUG) enabled, which lets the host operator read enclave memory. Node Bravo has debug disabled, but its container root hash does not match the public Sigstore build log. Only Node Charlie passes all five hardware and transparency checks.
              </p>
              {nodeEval && (
                <p className="font-mono text-[11px] text-ink">
                  {nodeEval.explanation}
                </p>
              )}
            </div>
          </details>
        </article>

        {/* ROUND 4: Subpoena Pop */}
        <article className="ep-card p-5 space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <div className="ep-label">Round 4 of 4</div>
              <h3 className="ep-display text-xl mt-0.5">
                Destroy enclave memory when you leave
              </h3>
            </div>
            <span className={round4Solved ? "ep-pass" : "ep-muted-chip"}>
              {round4Solved ? "Solved" : "Unsolved"}
            </span>
          </div>

          {/* One-sentence goal */}
          <p className="max-w-[68ch] text-sm text-ink-2">
            Pop the enclave session to zero out GPU memory, then run a server RAM dump to confirm zero readable bytes remain.
          </p>

          {/* One primary interaction */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => handleRunSubpoenaSequence(["pop", "host-ram-dump"])}
              className={round4Solved ? "ep-btn" : "ep-btn-ghost"}
            >
              {round4Solved
                ? "Session popped & RAM dump verified (0 bytes)"
                : "Pop session & run server RAM dump"}
            </button>
            {subpoenaActions.length > 0 && (
              <button
                type="button"
                onClick={() => setSubpoenaActions([])}
                className="ep-btn-ghost text-xs"
              >
                Reset
              </button>
            )}
          </div>

          {/* One result line */}
          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {subpoenaState.subpoenaYieldSummary}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-3 border-t border-rule pt-3">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 font-mono text-xs">
                <div className="ep-inset p-3">
                  <div className="ep-label">Enclave GPU memory</div>
                  <div className="mt-1 font-semibold text-ink">
                    {subpoenaState.gpuPagesZeroed
                      ? "Zeroed (0x00)"
                      : "Live (4,096 B active)"}
                  </div>
                </div>
                <div className="ep-inset p-3">
                  <div className="ep-label">Server RAM dump readable</div>
                  <div className="mt-1 font-semibold text-ink">
                    {subpoenaState.hostDumpReadableBytes} bytes
                  </div>
                </div>
                <div className="ep-inset p-3">
                  <div className="ep-label">Decryptable by server</div>
                  <div className="mt-1 font-semibold text-ink">No (0 keys held)</div>
                </div>
              </div>
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
                  2. Pop session
                </button>
                <button
                  type="button"
                  onClick={() => handleToggleSubpoenaStep("shred-secret")}
                  className="ep-btn-ghost py-1 px-2.5 text-xs"
                >
                  3. Shred local key
                </button>
                <button
                  type="button"
                  onClick={() => handleToggleSubpoenaStep("host-ram-dump")}
                  className="ep-btn-ghost py-1 px-2.5 text-xs"
                >
                  4. Run RAM dump
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
          </details>
        </article>
      </div>
    </div>
  );
}
