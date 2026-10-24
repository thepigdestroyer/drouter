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
  // Exhibit 01 state
  const [grid, setGrid] = useState<Array<0 | 1>>([...DEFAULT_HEART_GRID]);
  const [busMode, setBusMode] = useState<MemoryBusMode>("naive-cpu-xts");
  const [selectedCipherHex, setSelectedCipherHex] = useState<string | null>(null);
  const [exhibit1Solved, setExhibit1Solved] = useState(false);

  // Exhibit 02 state
  const [tokenSecret, setTokenSecret] = useState<number>(42);
  const [blindingFactor, setBlindingFactor] = useState<number>(19);
  const [envelopeStage, setEnvelopeStage] = useState<"draft" | "blinded" | "signed" | "unblinded">("unblinded");
  const [selectedPermIdx, setSelectedPermIdx] = useState<number>(0);
  const [exhibit2Solved, setExhibit2Solved] = useState(false);

  // Exhibit 03 state
  const candidateNodes = useMemo(() => judgeCandidateNodes(), []);
  const [chosenNodeId, setChosenNodeId] = useState<CandidateNodeId | null>(null);
  const [exhibit3Solved, setExhibit3Solved] = useState(false);

  // Exhibit 04 state
  const [subpoenaActions, setSubpoenaActions] = useState<SubpoenaAction[]>([]);
  const [exhibit4Solved, setExhibit4Solved] = useState(false);

  // Computed exhibit results
  const probeResult = useMemo(() => tapMemoryBus(grid, busMode), [grid, busMode]);
  const blindRound = useMemo(
    () => blindEnvelopeRound({ t: tokenSecret, r: blindingFactor }),
    [tokenSecret, blindingFactor]
  );
  const nodeEval = useMemo(
    () => (chosenNodeId ? evaluateNodeChoice(chosenNodeId, candidateNodes) : null),
    [chosenNodeId, candidateNodes]
  );
  const subpoenaState = useMemo(() => simulateSubpoenaPop(subpoenaActions), [subpoenaActions]);

  const completedCount =
    (exhibit1Solved ? 1 : 0) +
    (exhibit2Solved ? 1 : 0) +
    (exhibit3Solved ? 1 : 0) +
    (exhibit4Solved ? 1 : 0);

  function toggleGridCell(idx: number) {
    setGrid((prev) => {
      const next = [...prev];
      next[idx] = prev[idx] === 1 ? 0 : 1;
      return next;
    });
  }

  function handleSwitchBusMode(nextMode: MemoryBusMode) {
    setBusMode(nextMode);
    setSelectedCipherHex(null);
    if (nextMode === "drouter-gpu-hbm") {
      setExhibit1Solved(true);
    }
  }

  function handleRunUnlinkabilityProof(permIndex: number) {
    setSelectedPermIdx(permIndex);
    setEnvelopeStage("unblinded");
    setExhibit2Solved(true);
  }

  function handlePickCandidateNode(nodeId: CandidateNodeId) {
    setChosenNodeId(nodeId);
    const verdict = evaluateNodeChoice(nodeId, candidateNodes);
    if (verdict.correct) {
      setExhibit3Solved(true);
    }
  }

  function handlePushSubpoenaAction(action: SubpoenaAction) {
    setSubpoenaActions((prev) => {
      const next = [...prev, action];
      const sim = simulateSubpoenaPop(next);
      if (sim.gpuPagesZeroed && next.includes("host-ram-dump")) {
        setExhibit4Solved(true);
      }
      return next;
    });
  }

  function handleResetSubpoena() {
    setSubpoenaActions([]);
  }

  return (
    <section
      className="w-full rounded-xl border text-[#ece7da]"
      style={{
        backgroundColor: "#050706",
        borderColor: "rgba(236, 231, 218, 0.12)",
      }}
    >
      {/* Top Specimen Cabinet Score Bar */}
      <div
        className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b px-5 py-3.5 backdrop-blur-md"
        style={{
          backgroundColor: "rgba(9, 13, 11, 0.92)",
          borderColor: "rgba(236, 231, 218, 0.12)",
        }}
      >
        <div className="flex items-center gap-3">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{
              backgroundColor: completedCount === 4 ? "#a6ff72" : "#ffb85c",
              boxShadow:
                completedCount === 4
                  ? "0 0 10px rgba(166, 255, 114, 0.7)"
                  : "0 0 8px rgba(255, 184, 92, 0.45)",
            }}
          />
          <span className="font-mono text-xs tracking-wider uppercase text-[#ece7da]">
            Field Notebook: {completedCount} / 4 Experiments Completed
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {[
            { id: "No. 01", label: "Bus probe", done: exhibit1Solved },
            { id: "No. 02", label: "Blind credit", done: exhibit2Solved },
            { id: "No. 03", label: "Forged enclave", done: exhibit3Solved },
            { id: "No. 04", label: "Subpoena pop", done: exhibit4Solved },
          ].map((badge) => (
            <span
              key={badge.id}
              className="rounded px-2.5 py-1 transition-colors"
              style={{
                backgroundColor: badge.done ? "rgba(166, 255, 114, 0.12)" : "#0f1512",
                border: `1px solid ${
                  badge.done ? "rgba(166, 255, 114, 0.45)" : "rgba(236, 231, 218, 0.12)"
                }`,
                color: badge.done ? "#a6ff72" : "rgba(236, 231, 218, 0.68)",
              }}
            >
              {badge.id} · {badge.label} {badge.done ? "✓" : ""}
            </span>
          ))}
        </div>
      </div>

      <div className={compact ? "space-y-6 p-4" : "space-y-10 p-6 md:p-8"}>
        {/* Exhibit 01 */}
        <article
          className="rounded-lg border p-5 md:p-6"
          style={{
            backgroundColor: "#090d0b",
            borderColor: "rgba(236, 231, 218, 0.12)",
          }}
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-4" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
            <div>
              <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffb85c" }}>
                No. 01 · Specimen: Physical DDR5 Interposer (TEE.fail)
              </div>
              <h2 className="mt-1 font-serif text-2xl italic text-[#ece7da]">
                The $900 memory-bus probe
              </h2>
            </div>
            <span
              className="rounded px-2.5 py-1 font-mono text-xs"
              style={{
                backgroundColor: exhibit1Solved ? "rgba(166, 255, 114, 0.12)" : "#0f1512",
                color: exhibit1Solved ? "#a6ff72" : "#ffb85c",
                border: "1px solid rgba(236, 231, 218, 0.12)",
              }}
            >
              {exhibit1Solved ? "Solved: 0% bus leakage verified" : "Task: Switch to GPU HBM custody"}
            </span>
          </div>

          <p className="mt-4 text-sm leading-relaxed text-[#ece7da]/85">
            Suppose a data center technician clips a $900 logic analyzer onto the server RAM stick. Even when CPU memory is encrypted, older deterministic memory encryption turns identical input blocks into identical ciphertext blocks. Click cells in the 4x4 secret grid below, click any ciphertext block on the wire to highlight duplicates, and then switch to dRouter GPU HBM mode to break the pattern.
          </p>

          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => handleSwitchBusMode("naive-cpu-xts")}
                className="rounded px-3.5 py-2 font-mono text-xs transition-all"
                style={{
                  backgroundColor: busMode === "naive-cpu-xts" ? "rgba(255, 109, 77, 0.18)" : "#0f1512",
                  color: busMode === "naive-cpu-xts" ? "#ff6d4d" : "#ece7da",
                  border: `1px solid ${
                    busMode === "naive-cpu-xts" ? "#ff6d4d" : "rgba(236, 231, 218, 0.12)"
                  }`,
                }}
              >
                Mode A: Naive CPU RAM (deterministic XTS)
              </button>
              <button
                type="button"
                onClick={() => handleSwitchBusMode("drouter-gpu-hbm")}
                className="rounded px-3.5 py-2 font-mono text-xs transition-all"
                style={{
                  backgroundColor: busMode === "drouter-gpu-hbm" ? "rgba(166, 255, 114, 0.16)" : "#0f1512",
                  color: busMode === "drouter-gpu-hbm" ? "#a6ff72" : "#ece7da",
                  border: `1px solid ${
                    busMode === "drouter-gpu-hbm" ? "#a6ff72" : "rgba(236, 231, 218, 0.12)"
                  }`,
                }}
              >
                Mode B: dRouter GPU HBM + monotonic GCM nonce
              </button>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-[#ece7da]/60">Presets:</span>
              {Object.entries(PRESET_GRIDS).map(([key, preset]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setGrid([...preset.grid])}
                  className="rounded px-2.5 py-1 hover:bg-white/5"
                  style={{
                    backgroundColor: "#0f1512",
                    border: "1px solid rgba(236, 231, 218, 0.12)",
                  }}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-6 grid gap-5 lg:grid-cols-3">
            {/* Column 1: Secret 4x4 pattern */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#ece7da]/80">1. Your secret 4x4 prompt grid</span>
                <span className="text-[#ece7da]/50">Click cells to toggle</span>
              </div>
              <div className="mt-3 grid grid-cols-4 gap-2">
                {grid.map((cell, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => toggleGridCell(idx)}
                    className="flex h-12 items-center justify-center rounded font-mono text-xs transition-all"
                    style={{
                      backgroundColor: cell === 1 ? "rgba(166, 255, 114, 0.2)" : "#050706",
                      color: cell === 1 ? "#a6ff72" : "rgba(236, 231, 218, 0.4)",
                      border: `1px solid ${
                        cell === 1 ? "rgba(166, 255, 114, 0.55)" : "rgba(236, 231, 218, 0.12)"
                      }`,
                    }}
                  >
                    {cell === 1 ? "ON" : "OFF"}
                  </button>
                ))}
              </div>
            </div>

            {/* Column 2: Captured 16-byte bus blocks */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#ece7da]/80">2. Captured 16-byte bus blocks</span>
                <span className="text-[#ece7da]/50">Click block to match</span>
              </div>
              <div className="mt-3 grid grid-cols-4 gap-2">
                {probeResult.blocks.map((b) => {
                  const isHighlighted =
                    selectedCipherHex !== null && b.cipherBlockHex === selectedCipherHex;
                  return (
                    <button
                      key={b.index}
                      type="button"
                      onClick={() => setSelectedCipherHex(b.cipherBlockHex)}
                      className="flex h-12 flex-col items-center justify-center rounded px-1 font-mono text-[10px] leading-tight transition-all"
                      style={{
                        backgroundColor: isHighlighted
                          ? "rgba(255, 184, 92, 0.24)"
                          : "#050706",
                        color: isHighlighted ? "#ffb85c" : "#ece7da",
                        border: `1px solid ${
                          isHighlighted
                            ? "#ffb85c"
                            : "rgba(236, 231, 218, 0.12)"
                        }`,
                      }}
                      title={`Cell #${b.index} · Nonce ${b.nonceHex} · Cipher ${b.cipherBlockHex}`}
                    >
                      <span>{b.cipherBlockHex.slice(0, 6)}</span>
                      <span className="opacity-60">..{b.cipherBlockHex.slice(-4)}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Column 3: Attacker silhouette reconstruction */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-[#ece7da]/80">3. Attacker probe reconstruction</span>
                <span
                  style={{
                    color: probeResult.leakRatePct > 0 ? "#ff6d4d" : "#a6ff72",
                  }}
                >
                  Leak: {probeResult.leakRatePct}%
                </span>
              </div>
              <div className="mt-3 grid grid-cols-4 gap-2">
                {probeResult.reconstructedGrid.map((rec, idx) => (
                  <div
                    key={idx}
                    className="flex h-12 items-center justify-center rounded font-mono text-xs"
                    style={{
                      backgroundColor:
                        rec === null
                          ? "#050706"
                          : rec === 1
                            ? "rgba(255, 109, 77, 0.22)"
                            : "rgba(236, 231, 218, 0.04)",
                      color:
                        rec === null
                          ? "rgba(236, 231, 218, 0.35)"
                          : rec === 1
                            ? "#ff6d4d"
                            : "rgba(236, 231, 218, 0.5)",
                      border: `1px solid ${
                        rec === 1
                          ? "rgba(255, 109, 77, 0.55)"
                          : "rgba(236, 231, 218, 0.12)"
                      }`,
                    }}
                  >
                    {rec === null ? "???" : rec === 1 ? "LEAK" : "IDLE"}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div
            className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded border px-4 py-3 font-mono text-xs"
            style={{
              backgroundColor: "#050706",
              borderColor: "rgba(236, 231, 218, 0.12)",
            }}
          >
            <div>
              Duplicate 16B blocks:{" "}
              <strong style={{ color: probeResult.repeatedBlocks > 0 ? "#ff6d4d" : "#a6ff72" }}>
                {probeResult.repeatedBlocks}
              </strong>{" "}
              · Unique blocks: <strong>{probeResult.uniqueBlocks} / 16</strong> · Bus entropy:{" "}
              <strong style={{ color: probeResult.entropyBitsPerByte > 7.8 ? "#a6ff72" : "#ffb85c" }}>
                {probeResult.entropyBitsPerByte.toFixed(2)} bits/byte
              </strong>
            </div>
            <div className="text-[#ece7da]/75">{probeResult.summary}</div>
          </div>

          <details className="mt-4 rounded border px-4 py-2.5 text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)", backgroundColor: "#050706" }}>
            <summary className="cursor-pointer font-mono uppercase tracking-wider text-[#ffb85c]">
              Under the hood · Why deterministic memory encryption leaks silhouettes
            </summary>
            <p className="mt-2 leading-relaxed text-[#ece7da]/80">
              Physical memory interposers like TEE.fail sit passively between the CPU and DDR5 DIMMs. When a system relies on deterministic XTS tweaks at fixed physical addresses or reuses static IVs, writing the same token block twice yields the exact same 16-byte ciphertext block (the classic ECB penguin problem). dRouter keeps active weights and KV cache inside on-package GPU HBM and wraps any PCIe or host-DRAM offload page in AES-256-GCM with a strictly monotonic 96-bit counter derived from an attested CTR-DRBG.
            </p>
          </details>
        </article>

        {/* Exhibit 02 */}
        <article
          className="rounded-lg border p-5 md:p-6"
          style={{
            backgroundColor: "#090d0b",
            borderColor: "rgba(236, 231, 218, 0.12)",
          }}
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-4" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
            <div>
              <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffb85c" }}>
                No. 02 · Specimen: Chaumian RSA Blind Signatures
              </div>
              <h2 className="mt-1 font-serif text-2xl italic text-[#ece7da]">
                The carbon-paper blind credit
              </h2>
            </div>
            <span
              className="rounded px-2.5 py-1 font-mono text-xs"
              style={{
                backgroundColor: exhibit2Solved ? "rgba(166, 255, 114, 0.12)" : "#0f1512",
                color: exhibit2Solved ? "#a6ff72" : "#ffb85c",
                border: "1px solid rgba(236, 231, 218, 0.12)",
              }}
            >
              {exhibit2Solved ? "Solved: 6 / 6 permutations verified unlinkable" : "Task: Test a bank matching permutation"}
            </span>
          </div>

          <p className="mt-4 text-sm leading-relaxed text-[#ece7da]/85">
            How do you pay for AI inference with a public wallet without letting the billing server link your wallet to your prompts? Imagine slipping a serial number <code className="font-mono text-[#a6ff72]">t</code> inside a carbon-paper envelope multiplied by a random disguise <code className="font-mono text-[#ffb85c]">r</code>. The bank stamps the outside of the envelope. You peel off the envelope at home and hand the clean stamped note to the enclave.
          </p>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            {/* Left panel: Interactive Carbon-Paper Envelope Math */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              <div className="font-mono text-xs uppercase tracking-wider text-[#ffb85c]">
                Step-by-step envelope math (RSA modulus n = {blindRound.n.toString()}, e = {blindRound.e.toString()})
              </div>

              <div className="mt-4 grid grid-cols-2 gap-3">
                <label className="block font-mono text-xs">
                  <span className="text-[#ece7da]/75">Secret token serial (t)</span>
                  <input
                    type="number"
                    min={2}
                    max={3000}
                    value={tokenSecret}
                    onChange={(e) => setTokenSecret(Number(e.target.value) || 42)}
                    className="mt-1 w-full rounded border bg-[#050706] px-3 py-1.5 font-mono text-sm text-[#a6ff72]"
                    style={{ borderColor: "rgba(236, 231, 218, 0.18)" }}
                  />
                </label>
                <label className="block font-mono text-xs">
                  <span className="text-[#ece7da]/75">Carbon-paper factor (r)</span>
                  <input
                    type="number"
                    min={2}
                    max={3000}
                    value={blindingFactor}
                    onChange={(e) => setBlindingFactor(Number(e.target.value) || 19)}
                    className="mt-1 w-full rounded border bg-[#050706] px-3 py-1.5 font-mono text-sm text-[#ffb85c]"
                    style={{ borderColor: "rgba(236, 231, 218, 0.18)" }}
                  />
                </label>
              </div>

              <div className="mt-4 flex flex-wrap gap-2 font-mono text-xs">
                {(["draft", "blinded", "signed", "unblinded"] as const).map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setEnvelopeStage(st)}
                    className="rounded px-2.5 py-1 capitalize"
                    style={{
                      backgroundColor: envelopeStage === st ? "rgba(166, 255, 114, 0.15)" : "#050706",
                      color: envelopeStage === st ? "#a6ff72" : "#ece7da",
                      border: `1px solid ${
                        envelopeStage === st ? "#a6ff72" : "rgba(236, 231, 218, 0.12)"
                      }`,
                    }}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div className="mt-4 space-y-2 rounded border bg-[#050706] p-3 font-mono text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
                <div className="flex justify-between">
                  <span className="text-[#ece7da]/65">1. Blinded envelope (t * r^e mod n):</span>
                  <span className="text-[#ffb85c]">{blindRound.blinded.toString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#ece7da]/65">2. Bank stamp on envelope (s&apos; = blinded^d mod n):</span>
                  <span className="text-[#ece7da]">{blindRound.sPrime.toString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#ece7da]/65">3. Unblinded signature (s = s&apos; * r^-1 mod n):</span>
                  <span className="text-[#a6ff72]">{blindRound.s.toString()}</span>
                </div>
                <div className="flex justify-between border-t pt-2" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
                  <span className="text-[#ece7da]/65">4. Enclave check (s^e mod n == t):</span>
                  <span style={{ color: blindRound.signatureValid ? "#a6ff72" : "#ff6d4d" }}>
                    {blindRound.recomputedFromSignature.toString()} == {blindRound.t.toString()} (VALID)
                  </span>
                </div>
              </div>
            </div>

            {/* Right panel: Play as the Bank matching challenge */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              <div className="font-mono text-xs uppercase tracking-wider text-[#ffb85c]">
                Play as the bank · Try to link 3 buyers to 3 anonymous spends
              </div>
              <p className="mt-2 text-xs leading-relaxed text-[#ece7da]/80">
                The bank recorded 3 blinded purchases from Alice, Bob, and Carol. Later, 3 unblinded tokens arrive at the enclave. Click any of the 6 possible buyer-to-spend permutations below to see if the bank can rule any of them out:
              </p>

              <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-xs">
                {blindRound.permutations.map((perm, idx) => (
                  <button
                    key={perm.mappingSummary}
                    type="button"
                    onClick={() => handleRunUnlinkabilityProof(idx)}
                    className="rounded border px-2.5 py-2 text-left transition-all"
                    style={{
                      backgroundColor:
                        selectedPermIdx === idx ? "rgba(166, 255, 114, 0.14)" : "#050706",
                      color: selectedPermIdx === idx ? "#a6ff72" : "#ece7da",
                      borderColor:
                        selectedPermIdx === idx ? "#a6ff72" : "rgba(236, 231, 218, 0.12)",
                    }}
                  >
                    <div>Permutation #{idx + 1}</div>
                    <div className="mt-0.5 text-[10px] opacity-75">{perm.mappingSummary}</div>
                  </button>
                ))}
              </div>

              <div
                className="mt-3 rounded border bg-[#050706] p-3 font-mono text-xs"
                style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}
              >
                <div className="text-[#a6ff72]">
                  Permutation #{selectedPermIdx + 1} is 100% mathematically consistent ({blindRound.validPermutationsCount} / 6 valid)
                </div>
                <div className="mt-1 text-[11px] text-[#ece7da]/75">
                  Implied blinding factors (r_1, r_2, r_3) = (
                  {blindRound.permutations[selectedPermIdx].impliedBlindingFactors
                    .map((v) => v.toString())
                    .join(", ")}
                  ) satisfy blinded_i = t_j * r_ij^e mod n for every pair.
                </div>
              </div>
            </div>
          </div>

          <details className="mt-4 rounded border px-4 py-2.5 text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)", backgroundColor: "#050706" }}>
            <summary className="cursor-pointer font-mono uppercase tracking-wider text-[#ffb85c]">
              Under the hood · Why all 6 permutations are equally likely
            </summary>
            <p className="mt-2 leading-relaxed text-[#ece7da]/80">
              Because multiplication by r^e mod n is a bijection on the multiplicative group Z_n*, for any blinded transcript (blinded_i, s&apos;_i) and any valid token (t_j, s_j), there exists a unique blinding factor r_ij = s&apos;_i * s_j^-1 mod n that maps one to the other. Even if the bank and the relay collude, all 3! = 6 permutations have identical probability.
            </p>
          </details>
        </article>

        {/* Exhibit 03 */}
        <article
          className="rounded-lg border p-5 md:p-6"
          style={{
            backgroundColor: "#090d0b",
            borderColor: "rgba(236, 231, 218, 0.12)",
          }}
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-4" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
            <div>
              <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffb85c" }}>
                No. 03 · Specimen: Hardware Attestation &amp; Sigstore Verification
              </div>
              <h2 className="mt-1 font-serif text-2xl italic text-[#ece7da]">
                Spot the forged enclave
              </h2>
            </div>
            <span
              className="rounded px-2.5 py-1 font-mono text-xs"
              style={{
                backgroundColor: exhibit3Solved ? "rgba(166, 255, 114, 0.12)" : "#0f1512",
                color: exhibit3Solved ? "#a6ff72" : "#ffb85c",
                border: "1px solid rgba(236, 231, 218, 0.12)",
              }}
            >
              {exhibit3Solved ? "Solved: Authentic enclave isolated" : "Task: Inspect registers and pick the safe node"}
            </span>
          </div>

          <p className="mt-4 text-sm leading-relaxed text-[#ece7da]/85">
            Three servers claim to be genuine dRouter enclaves. All three present a real AMD hardware signature, so a surface check would let all three through. Inspect their hardware registers below and click the only server that is actually safe to receive your prompt.
          </p>

          <div className="mt-5 grid gap-4 lg:grid-cols-3">
            {candidateNodes.map((node) => {
              const isSelected = chosenNodeId === node.id;
              return (
                <div
                  key={node.id}
                  className="flex flex-col justify-between rounded-lg border p-4 transition-all"
                  style={{
                    backgroundColor: "#0f1512",
                    borderColor: isSelected
                      ? node.isAuthentic
                        ? "#a6ff72"
                        : "#ff6d4d"
                      : "rgba(236, 231, 218, 0.12)",
                  }}
                >
                  <div>
                    <div className="flex items-center justify-between font-mono text-xs">
                      <span className="font-semibold text-[#ece7da]">{node.name}</span>
                      <span className="text-[#ece7da]/55">{node.region}</span>
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-[#ffb85c]">
                      {node.hardwareLabel}
                    </div>

                    <div className="mt-3 space-y-2 border-t pt-3 font-mono text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
                      {node.checks.map((chk) => (
                        <div key={chk.id} className="rounded bg-[#050706] p-2">
                          <div className="flex items-center justify-between text-[10px] text-[#ece7da]/60">
                            <span>{chk.registerName}</span>
                            <span style={{ color: chk.passed ? "#a6ff72" : "#ff6d4d" }}>
                              {chk.passed ? "OK" : "ALERT"}
                            </span>
                          </div>
                          <div className="mt-0.5 truncate text-[11px] text-[#ece7da]">
                            {chk.observedValue}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handlePickCandidateNode(node.id)}
                    className="mt-4 w-full rounded py-2 font-mono text-xs font-medium transition-all"
                    style={{
                      backgroundColor: isSelected
                        ? node.isAuthentic
                          ? "rgba(166, 255, 114, 0.2)"
                          : "rgba(255, 109, 77, 0.2)"
                        : "#050706",
                      color: isSelected
                        ? node.isAuthentic
                          ? "#a6ff72"
                          : "#ff6d4d"
                        : "#ece7da",
                      border: `1px solid ${
                        isSelected
                          ? node.isAuthentic
                            ? "#a6ff72"
                            : "#ff6d4d"
                          : "rgba(236, 231, 218, 0.18)"
                      }`,
                    }}
                  >
                    Route my prompt to {node.id}
                  </button>
                </div>
              );
            })}
          </div>

          {nodeEval && (
            <div
              className="mt-4 rounded border p-4 font-mono text-xs"
              style={{
                backgroundColor: "#050706",
                borderColor: nodeEval.correct ? "#a6ff72" : "#ff6d4d",
              }}
            >
              <div
                className="text-sm font-semibold"
                style={{ color: nodeEval.correct ? "#a6ff72" : "#ff6d4d" }}
              >
                {nodeEval.verdictHeadline} (Register: {nodeEval.caughtRegister})
              </div>
              <p className="mt-1.5 font-sans text-xs leading-relaxed text-[#ece7da]/85">
                {nodeEval.explanation}
              </p>
            </div>
          )}

          <details className="mt-4 rounded border px-4 py-2.5 text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)", backgroundColor: "#050706" }}>
            <summary className="cursor-pointer font-mono uppercase tracking-wider text-[#ffb85c]">
              Under the hood · Why hardware signature alone is never enough
            </summary>
            <p className="mt-2 leading-relaxed text-[#ece7da]/80">
              An AMD SEV-SNP attestation report proves that an AMD chip signed the measurement, but the verifier in your browser must still inspect the guest policy bits (confirming bit 19 DEBUG is 0) and compare the initrd dm-verity root hash against the public Sigstore transparency log. Otherwise, a genuine AMD CPU could be running a debug-enabled VM or a modified container image that logs your prompts.
            </p>
          </details>
        </article>

        {/* Exhibit 04 */}
        <article
          className="rounded-lg border p-5 md:p-6"
          style={{
            backgroundColor: "#090d0b",
            borderColor: "rgba(236, 231, 218, 0.12)",
          }}
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-4" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
            <div>
              <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "#ffb85c" }}>
                No. 04 · Specimen: Cryptographic Amnesia &amp; Zero-Knowledge Freeze
              </div>
              <h2 className="mt-1 font-serif text-2xl italic text-[#ece7da]">
                Pop the bubble before the subpoena
              </h2>
            </div>
            <span
              className="rounded px-2.5 py-1 font-mono text-xs"
              style={{
                backgroundColor: exhibit4Solved ? "rgba(166, 255, 114, 0.12)" : "#0f1512",
                color: exhibit4Solved ? "#a6ff72" : "#ffb85c",
                border: "1px solid rgba(236, 231, 218, 0.12)",
              }}
            >
              {exhibit4Solved
                ? "Solved: 0 readable bytes on forensic dump"
                : "Task: Pop the bubble and trigger a host RAM dump"}
            </span>
          </div>

          <p className="mt-4 text-sm leading-relaxed text-[#ece7da]/85">
            What happens if a subpoena or physical raid hits the data center after you finish chatting? In dRouter, you can optionally freeze your session with a key held only on your device (<code className="font-mono text-[#ffb85c]">K_freeze</code>), then pop the enclave bubble to overwrite all GPU HBM pages with zeros (<code className="font-mono text-[#a6ff72]">0x00</code>). Try the controls in any order and run a forensic RAM dump.
          </p>

          <div className="mt-5 flex flex-wrap gap-2.5 font-mono text-xs">
            <button
              type="button"
              onClick={() => handlePushSubpoenaAction("freeze")}
              className="rounded border px-3.5 py-2 transition-all hover:bg-white/5"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(255, 184, 92, 0.5)",
                color: "#ffb85c",
              }}
            >
              1. Freeze to MongoDB (user K_freeze)
            </button>
            <button
              type="button"
              onClick={() => handlePushSubpoenaAction("pop")}
              className="rounded border px-3.5 py-2 transition-all hover:bg-white/5"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(166, 255, 114, 0.5)",
                color: "#a6ff72",
              }}
            >
              2. Pop enclave bubble (zeroize HBM)
            </button>
            <button
              type="button"
              onClick={() => handlePushSubpoenaAction("shred-secret")}
              className="rounded border px-3.5 py-2 transition-all hover:bg-white/5"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(255, 109, 77, 0.5)",
                color: "#ff6d4d",
              }}
            >
              3. Shred local K_freeze key
            </button>
            <button
              type="button"
              onClick={() => handlePushSubpoenaAction("host-ram-dump")}
              className="rounded border px-3.5 py-2 transition-all hover:bg-white/5"
              style={{
                backgroundColor: "#0f1512",
                borderColor: "rgba(236, 231, 218, 0.35)",
                color: "#ece7da",
              }}
            >
              4. Serve subpoena (host RAM dump)
            </button>
            <button
              type="button"
              onClick={handleResetSubpoena}
              className="rounded border px-3 py-2 text-[#ece7da]/60 hover:text-[#ece7da]"
              style={{
                backgroundColor: "#050706",
                borderColor: "rgba(236, 231, 218, 0.12)",
              }}
            >
              Reset session
            </button>
          </div>

          <div className="mt-5 grid gap-4 md:grid-cols-4 font-mono text-xs">
            <div className="rounded border bg-[#0f1512] p-3.5" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
              <div className="text-[#ece7da]/60">GPU HBM pages zeroed</div>
              <div
                className="mt-1 text-base font-semibold"
                style={{ color: subpoenaState.gpuPagesZeroed ? "#a6ff72" : "#ffb85c" }}
              >
                {subpoenaState.gpuPagesZeroed ? "YES (0x00 verified)" : "LIVE (4,096 B active)"}
              </div>
              <div className="mt-1 truncate text-[10px] text-[#ece7da]/50">
                HBM[0..16]: 0x{subpoenaState.gpuHexPreview}
              </div>
            </div>

            <div className="rounded border bg-[#0f1512] p-3.5" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
              <div className="text-[#ece7da]/60">Host RAM dump readable</div>
              <div className="mt-1 text-base font-semibold text-[#a6ff72]">
                {subpoenaState.hostDumpReadableBytes} bytes
              </div>
              <div className="mt-1 truncate text-[10px] text-[#ece7da]/50">
                Bus sample: 0x{subpoenaState.hostDumpHexPreview}
              </div>
            </div>

            <div className="rounded border bg-[#0f1512] p-3.5" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
              <div className="text-[#ece7da]/60">Decryptable by you</div>
              <div
                className="mt-1 text-base font-semibold"
                style={{
                  color: subpoenaState.cloudBlobDecryptableWithUserKey ? "#a6ff72" : "#ece7da",
                }}
              >
                {subpoenaState.cloudBlobDecryptableWithUserKey ? "YES (with K_freeze)" : "NO"}
              </div>
              <div className="mt-1 text-[10px] text-[#ece7da]/50">
                MongoDB blob: {subpoenaState.freezeBlobSavedInMongo ? "Stored (AES-GCM)" : "None"}
              </div>
            </div>

            <div className="rounded border bg-[#0f1512] p-3.5" style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}>
              <div className="text-[#ece7da]/60">Decryptable by server</div>
              <div className="mt-1 text-base font-semibold text-[#a6ff72]">
                FALSE (0 keys held)
              </div>
              <div className="mt-1 text-[10px] text-[#ece7da]/50">
                Zero-knowledge storage invariant
              </div>
            </div>
          </div>

          <div
            className="mt-4 rounded border bg-[#050706] p-3.5 font-mono text-xs"
            style={{ borderColor: "rgba(236, 231, 218, 0.12)" }}
          >
            <div className="text-[#ffb85c]">{subpoenaState.subpoenaYieldSummary}</div>
            <ul className="mt-2 space-y-1 text-[11px] text-[#ece7da]/75">
              {subpoenaState.timelineLog.map((entry, idx) => (
                <li key={idx}>
                  [{idx}] {entry}
                </li>
              ))}
            </ul>
          </div>

          <details className="mt-4 rounded border px-4 py-2.5 text-xs" style={{ borderColor: "rgba(236, 231, 218, 0.12)", backgroundColor: "#050706" }}>
            <summary className="cursor-pointer font-mono uppercase tracking-wider text-[#ffb85c]">
              Under the hood · How Pop zeroizes the CTR-DRBG and prefix cache
            </summary>
            <p className="mt-2 leading-relaxed text-[#ece7da]/80">
              Calling Pop invokes <code className="font-mono">prefixPool.popSession()</code> and <code className="font-mono">drbg.zeroize()</code> inside the enclave custody runtime. Every session key, AES-GCM nonce prefix, CTR-DRBG state buffer, and GPU HBM staging page is synchronously overwritten with zeros before the HTTP response returns. Even if the user previously froze their conversation into MongoDB, the ciphertext was encrypted client-side under <code className="font-mono">K_freeze</code>, which never leaves the user&apos;s browser.
            </p>
          </details>
        </article>

        {/* Completion Summary Card */}
        {completedCount === 4 && (
          <div
            className="rounded-lg border p-6"
            style={{
              backgroundColor: "rgba(166, 255, 114, 0.07)",
              borderColor: "#a6ff72",
            }}
          >
            <div className="font-mono text-xs uppercase tracking-widest text-[#a6ff72]">
              Field Notebook Complete · All 4 / 4 Security Exhibits Verified
            </div>
            <h3 className="mt-1 font-serif text-2xl italic text-[#ece7da]">
              You have verified the entire dRouter zero-trust chain
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-[#ece7da]/85">
              1. On-package GPU HBM custody and monotonic AES-256-GCM nonces defeat physical $900 DDR5 interposers. 2. Chaumian RSA blind credits separate your public wallet from your private inference sessions across all permutations. 3. Client-side SEV-SNP policy and Sigstore dm-verity checks catch debug-enabled or tampered enclaves before a single byte of plaintext leaves your browser. 4. Popping the session bubble overwrites GPU HBM and session keys with 0x00 so a server subpoena yields nothing.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
