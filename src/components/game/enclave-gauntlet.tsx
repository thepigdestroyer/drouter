"use client";

import React, { useEffect, useMemo, useState } from "react";
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

  // Round 3 state: starts with synchronous binary report verification, then upgrades to live /api/relay/attestation in useEffect
  // Computed in an effect: signing uses crypto randomness, which must not run during prerender.
  const [candidateNodes, setCandidateNodes] = useState<CandidateEnclaveNode[]>([]);
  const [liveAttestationLoaded, setLiveAttestationLoaded] = useState(false);
  const [chosenNodeId, setChosenNodeId] = useState<CandidateNodeId | null>(null);
  const [round3Solved, setRound3Solved] = useState(false);

  // Round 4 state
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

  // Computed results
  // tapMemoryBus encrypts with random keys and nonces, so it only runs after mount (never during prerender).
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
            reconstructedGrid: grid.map(() => null),
            summary: "Encrypting the pattern in your browser...",
          },
    [mounted, grid, busMode],
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
    if (sim.gpuPagesZeroed && !sim.sessionDecryptable && nextActions.includes("host-ram-dump")) {
      setRound4Solved(true);
    }
  }

  function handleToggleSubpoenaStep(action: SubpoenaAction) {
    setSubpoenaActions((prev) => {
      const filtered = prev.filter((a) => a !== action);
      const next = [...filtered, action];
      const sim = simulateSubpoenaPop(next);
      if (sim.gpuPagesZeroed && !sim.sessionDecryptable && next.includes("host-ram-dump")) {
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
              {item.label} {item.done ? "(Done)" : ""}
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

          <p className="max-w-[68ch] text-sm text-ink-2">
            Switch from deterministic AES-256-ECB memory encryption to AES-256-GCM with fresh per-transfer nonces so a physical wire tap on the RAM bus cannot spot repeated 16-byte blocks.
          </p>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => handleSwitchBusMode("naive-cpu-xts")}
              className={
                busMode === "naive-cpu-xts" ? "ep-btn" : "ep-btn-ghost"
              }
            >
              Static CPU memory (AES-ECB leaks)
            </button>
            <button
              type="button"
              onClick={() => handleSwitchBusMode("drouter-gpu-hbm")}
              className={
                busMode === "drouter-gpu-hbm" ? "ep-btn" : "ep-btn-ghost"
              }
            >
              Fresh GPU nonce (AES-GCM blocks tap)
            </button>
          </div>

          {/* Visual comparison: Secret vs Observed Ciphertext Blocks vs Wire tap reconstruction */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
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
                16-byte bus ciphertext ({probeResult.repeatedBlocks} duplicates)
              </div>
              <div className="grid grid-cols-4 gap-1.5">
                {probeResult.blocks.map((blk) => (
                  <div
                    key={blk.index}
                    title={`Block #${blk.index}: 0x${blk.cipherBlockHex}`}
                    className={`flex h-7 items-center justify-center rounded border font-mono text-[9px] px-1 truncate ${
                      blk.matchesFirstActiveBlock
                        ? "border-accent bg-accent-soft text-ink font-semibold"
                        : "border-rule bg-paper text-ink-2"
                    }`}
                  >
                    {blk.cipherBlockHex.slice(0, 4)}
                  </div>
                ))}
              </div>
            </div>

            <div className="ep-inset p-3">
              <div className="ep-label mb-2">
                Wire tap reconstruction ({probeResult.leakRatePct}% leaked)
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

          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {probeResult.summary}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-3 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                Physical memory interposers sit passively between the CPU and DDR5 DIMMs. When identical 16-byte blocks are encrypted deterministically without a fresh nonce, duplicate ciphertext blocks reveal the silhouette. Using a fresh 96-bit AES-256-GCM nonce per transfer makes every 16-byte ciphertext block unique ({probeResult.uniqueBlocks} of 16 unique blocks, {probeResult.entropyBitsPerByte.toFixed(2)} bits/byte entropy).
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

          <p className="max-w-[68ch] text-sm text-ink-2">
            Click any of the six possible buyer-to-session matchings below to test whether the billing server can link Dana Reyes or other buyers to their anonymous chats.
          </p>

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

          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {selectedPermIdx === null
              ? "Select any buyer-to-session matching above to test if the billing server can rule it out."
              : `Matching #${selectedPermIdx + 1} is 100% consistent with the ${blindRound.modulusBits}-bit RSA blind signature log (${blindRound.validPermutationsCount} of 6 matchings are equally valid, so the server learns nothing).`}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-3 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                Your browser hashes the token with Full-Domain Hash (<code className="font-mono text-ink">hashTokenMessage</code>) and blinds it with <code className="font-mono text-ink">r^e mod n</code> (<code className="font-mono text-ink">blindToken</code>) before the mint signs it (<code className="font-mono text-ink">signBlinded</code>), then divides out <code className="font-mono text-ink">r</code> locally (<code className="font-mono text-ink">unblindSignature</code>).
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 max-w-md">
                <label className="block font-mono text-xs">
                  <span className="text-ink-3">Token seed</span>
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
                  <span className="text-ink-3">Blinding factor seed</span>
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
              <div className="ep-inset p-3 font-mono text-[11px] space-y-1 break-all">
                <div>1. RSA modulus size: {blindRound.modulusBits} bits (e = {blindRound.e.toString()})</div>
                <div>2. Blinded envelope hex: 0x{blindRound.blindedHex.slice(0, 32)}...</div>
                <div>3. Unblinded signature hex: 0x{blindRound.signatureHex.slice(0, 32)}...</div>
                <div>4. Spend nullifier SHA-256: 0x{blindRound.nullifierHex.slice(0, 32)}...</div>
                <div>5. verifyTokenSignature(token, pub): {blindRound.signatureValid ? "Valid (s^e mod n == H(token))" : "Invalid"}</div>
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
            <div className="flex items-center gap-2">
              <span className="ep-muted-chip">
                {liveAttestationLoaded
                  ? "Live /api/relay/attestation"
                  : "Binary SEV-SNP verifier"}
              </span>
              <span className={round3Solved ? "ep-pass" : "ep-muted-chip"}>
                {round3Solved ? "Solved" : "Unsolved"}
              </span>
            </div>
          </div>

          <p className="max-w-[68ch] text-sm text-ink-2">
            Compare the live hardware attestation report from <code className="font-mono text-xs">router-0.tinfoil.sh</code> against two tampered copies, and route your prompt to the only candidate where every check passes.
          </p>

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
                    <div className="flex items-center justify-between gap-2 font-mono text-xs">
                      <span className="font-semibold text-ink">{node.name}</span>
                    </div>
                    <div className="font-mono text-[11px] text-ink-3 truncate">
                      {node.region}
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

          <div className="ep-inset px-3.5 py-2.5 font-mono text-xs text-ink">
            {nodeEval
              ? `${nodeEval.verdictHeadline} (${nodeEval.caughtRegister})`
              : "Pick one of the three attestation reports above to run the hardware and Sigstore checks."}
          </div>

          <details className="text-xs text-ink-2">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 hover:text-ink">
              Show details
            </summary>
            <div className="mt-2.5 space-y-2 border-t border-rule pt-3">
              <p className="max-w-[68ch] leading-relaxed">
                Candidate Charlie uses the authentic 1,184-byte AMD SEV-SNP report from <code className="font-mono text-ink">router-0.tinfoil.sh</code>. Candidate Alpha has bit 19 (DEBUG) flipped at byte offset 0x08 of the binary report. Candidate Bravo has a tampered release digest that fails the Sigstore transparency log check.
              </p>
              {nodeEval && (
                <p className="font-mono text-[11px] text-ink">
                  {nodeEval.explanation}
                </p>
              )}
              {nodeEval?.chosenNode.verifierError && (
                <p className="font-mono text-[11px] text-accent">
                  Verifier error: {nodeEval.chosenNode.verifierError}
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
                Destroy the session key when you leave
              </h3>
            </div>
            <span className={round4Solved ? "ep-pass" : "ep-muted-chip"}>
              {round4Solved ? "Solved" : "Unsolved"}
            </span>
          </div>

          <p className="max-w-[68ch] text-sm text-ink-2">
            Pop the enclave session to overwrite the 256-bit AES-GCM session key with zeros, then attempt decryption on a server RAM dump to confirm decryption fails.
          </p>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => handleRunSubpoenaSequence(["pop", "host-ram-dump"])}
              className={round4Solved ? "ep-btn" : "ep-btn-ghost"}
            >
              {round4Solved
                ? "Key zeroed & AES-GCM decryption failed (0 bytes)"
                : "Destroy session key & test RAM dump decryption"}
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
          </details>
        </article>
      </div>
    </div>
  );
}
