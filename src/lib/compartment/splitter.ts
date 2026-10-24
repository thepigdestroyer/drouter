import { bytesToHex } from "@noble/hashes/utils.js";

function csprngBytesHex(byteLength: number): string {
  const buf = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

function csprngInt(minInclusive: number, maxExclusive: number): number {
  const range = maxExclusive - minInclusive;
  if (range <= 1) return minInclusive;
  const maxUint32PlusOne = 0x100000000;
  const limit = maxUint32PlusOne - (maxUint32PlusOne % range);
  const buf = new Uint32Array(1);
  let sample = 0;
  do {
    globalThis.crypto.getRandomValues(buf);
    sample = buf[0];
  } while (sample >= limit);
  return minInclusive + (sample % range);
}

export interface FragmentCompromiseRisk {
  fullLeakProbability: number;
  anyFragmentLeakProbability: number;
  singleNodeLeakProbability: number;
  fullLeakReductionFactor: number;
}

export interface CompartmentFragment {
  index: number;
  fragmentId: string;
  assignedNodeId: string;
  jitterDelayMs: number;
  subPrompt: string;
  isolatedKeyId: string;
}

export interface CompartmentPlan {
  fragments: CompartmentFragment[];
  synthesisPlan: string;
}

export interface CompartmentOutput {
  index: number;
  assignedNodeId: string;
  response: string;
}

export const DEFAULT_COMPARTMENT_NODES = [
  // Chat models listed in Tinfoil's live model table (inference.tinfoil.sh/.well-known/tinfoil-proxy).
  "tinfoil-kimi-k3",
  "tinfoil-gemma4-31b",
  "tinfoil-llama3-3-70b",
  "tinfoil-deepseek-v4-1-flash",
  "tinfoil-glm-5-3",
  "tinfoil-gpt-oss-120b",
];

/**
 * Computes the probability of full task exposure vs partial fragment exposure
 * when splitting a sensitive task into `fragmentCount` independent compartments
 * routed across distinct attested enclaves.
 */
export function computeFragmentCompromiseRisk(
  compromisedNodeFraction: number,
  fragmentCount: number
): FragmentCompromiseRisk {
  const safeFraction = Number.isFinite(compromisedNodeFraction) ? compromisedNodeFraction : 0;
  const safeCount = Number.isFinite(fragmentCount) ? fragmentCount : 1;
  const p = Math.min(Math.max(safeFraction, 0), 1);
  const m = Math.max(1, Math.floor(safeCount));

  const singleNodeLeakProbability = p;
  const fullLeakProbability = Math.pow(p, m);
  const anyFragmentLeakProbability = 1 - Math.pow(1 - p, m);
  const fullLeakReductionFactor =
    fullLeakProbability > 0 ? singleNodeLeakProbability / fullLeakProbability : Infinity;

  return {
    fullLeakProbability,
    anyFragmentLeakProbability,
    singleNodeLeakProbability,
    fullLeakReductionFactor,
  };
}

/**
 * Extracts raw logical sections from a prompt using markdown headers,
 * numbered list items, fenced code blocks, or sentences, then normalizes
 * into 2..5 self-contained compartments.
 */
function partitionPromptIntoSections(prompt: string): string[] {
  const trimmed = prompt.trim();
  if (!trimmed) {
    return ["[Compartment 1] Empty task segment A", "[Compartment 2] Empty task segment B"];
  }

  // 1. Try splitting by Markdown headings (e.g. ## Section or # Section)
  const headingParts = trimmed
    .split(/(?=^#{1,6}\s+)/m)
    .map((s) => s.trim())
    .filter(Boolean);
  if (headingParts.length >= 2) {
    return normalizeSectionCount(headingParts);
  }

  // 2. Try splitting by numbered list items (e.g. "1. ", "2. ", or "1) ")
  const numberedParts = trimmed
    .split(/(?=^\d+[\.\)]\s+)/m)
    .map((s) => s.trim())
    .filter(Boolean);
  if (numberedParts.length >= 2) {
    return normalizeSectionCount(numberedParts);
  }

  // 3. Try splitting by fenced code blocks
  if (trimmed.includes("```")) {
    const codeParts = trimmed
      .split(/(```[\s\S]*?```)/g)
      .map((s) => s.trim())
      .filter(Boolean);
    if (codeParts.length >= 2) {
      return normalizeSectionCount(codeParts);
    }
  }

  // 4. Try splitting by double-newline paragraphs
  const paragraphs = trimmed
    .split(/\n\s*\n+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (paragraphs.length >= 2) {
    return normalizeSectionCount(paragraphs);
  }

  // 5. Try splitting by sentence boundaries
  const sentences = trimmed
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (sentences.length >= 2) {
    return normalizeSectionCount(sentences);
  }

  // 6. Fallback: split string in half by words or characters so we always have at least 2 compartments
  const words = trimmed.split(/\s+/).filter(Boolean);
  if (words.length >= 2) {
    const mid = Math.ceil(words.length / 2);
    return [words.slice(0, mid).join(" "), words.slice(mid).join(" ")];
  }

  const midChar = Math.max(1, Math.ceil(trimmed.length / 2));
  return [trimmed.slice(0, midChar), trimmed.slice(midChar) || trimmed];
}

/**
 * Ensures the section array has between 2 and 5 items by merging excess chunks.
 */
function normalizeSectionCount(parts: string[]): string[] {
  const minCompartments = 2;
  const maxCompartments = 5;

  if (parts.length < minCompartments) {
    return partitionPromptIntoSections(parts[0] ?? "");
  }
  if (parts.length <= maxCompartments) {
    return parts;
  }

  const merged: string[] = [];
  const total = parts.length;
  for (let i = 0; i < maxCompartments; i++) {
    const start = Math.floor((i * total) / maxCompartments);
    const end = Math.floor(((i + 1) * total) / maxCompartments);
    merged.push(parts.slice(start, end).join("\n\n"));
  }
  return merged;
}

/**
 * Performs a Fisher-Yates shuffle using crypto.randomInt so node assignment order is randomized.
 */
function shuffleNodes(nodes: string[]): string[] {
  const copy = [...nodes];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = csprngInt(0, i + 1);
    const tmp = copy[i];
    copy[i] = copy[j];
    copy[j] = tmp;
  }
  return copy;
}

/**
 * Splits a multi-section prompt into 2..5 isolated compartments, assigning each
 * fragment to a distinct enclave node (cycling only after all distinct nodes are used),
 * with an independent ephemeral session key and randomized timing jitter (50..600 ms).
 */
export function splitTaskIntoCompartments(
  prompt: string,
  availableNodes: string[]
): CompartmentPlan {
  const sections = partitionPromptIntoSections(prompt);
  const validAvailable = Array.isArray(availableNodes)
    ? availableNodes.filter((n) => typeof n === "string" && n.trim().length > 0)
    : [];
  const nodePool =
    validAvailable.length > 0 ? validAvailable : DEFAULT_COMPARTMENT_NODES;

  // Deduplicate while preserving all distinct nodes, then shuffle each cycle
  const distinctNodes = Array.from(new Set(nodePool));
  const assignedNodes: string[] = [];

  while (assignedNodes.length < sections.length) {
    const cycle = shuffleNodes(distinctNodes);
    for (const node of cycle) {
      if (assignedNodes.length < sections.length) {
        assignedNodes.push(node);
      }
    }
  }

  const fragments: CompartmentFragment[] = sections.map((section, index) => {
    const fragmentHex = csprngBytesHex(6);
    const keyHex = csprngBytesHex(8);
    const jitterDelayMs = csprngInt(50, 601); // 50..600 ms inclusive

    return {
      index,
      fragmentId: `frag-${index + 1}-${fragmentHex}`,
      assignedNodeId: assignedNodes[index],
      jitterDelayMs,
      subPrompt: section,
      isolatedKeyId: `ephem-key-${keyHex}`,
    };
  });

  const synthesisPlan =
    `Dispatch ${fragments.length} compartmentalized sub-prompts across ${new Set(assignedNodes).size} distinct attested enclaves ` +
    `with independent HPKE session keys and 50-600ms unlinkable timing jitter; verify enclave receipts and reassemble ordered outputs [0..${fragments.length - 1}] locally on the client.`;

  return {
    fragments,
    synthesisPlan,
  };
}

/**
 * Reassembles out-of-order sub-agent compartment responses in their original
 * deterministic compartment index order on the client.
 */
export function reassembleCompartmentOutputs(outputs: CompartmentOutput[]): string {
  return [...outputs]
    .sort((a, b) => a.index - b.index)
    .map(
      (item) =>
        `[Compartment #${item.index + 1} | ${item.assignedNodeId}]\n${item.response.trim()}`
    )
    .join("\n\n");
}
