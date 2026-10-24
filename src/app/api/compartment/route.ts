import { NextRequest, NextResponse, connection } from "next/server";
import {
  computeFragmentCompromiseRisk,
  DEFAULT_COMPARTMENT_NODES,
  reassembleCompartmentOutputs,
  splitTaskIntoCompartments,
} from "@/lib/compartment/splitter";
import { listNodes } from "@/lib/arc/registry";
import { preparePrompt } from "@/lib/pipeline";
import {
  BodyTooLargeError,
  InvalidJsonBodyError,
  createTokenBucketLimiter,
  readBoundedJson,
} from "@/lib/ratelimit";

const MAX_COMPARTMENT_BODY_BYTES = 65_536;
const MAX_PROMPT_CHARS = 32_768;

const compartmentLimiter = createTokenBucketLimiter({
  name: "compartment-route",
  capacity: 60,
  refillPerSec: 2,
});

/**
 * Sourced five-section technical verification prompt derived from
 * IETF RFC 9180 (HPKE), AMD SEV-SNP ABI Rev 1.55, Intel TDX DCAP QuoteV4,
 * DMTF DSP0274 (SPDM 1.2), and Circle Arc Testnet registry verification.
 */
const SPECIFICATION_FIVE_FRAGMENT_PROMPT = [
  "## 1. RFC 9180 HPKE Key Schedule",
  "Verify DHKEM(X25519, HKDF-SHA256) encapsulation context binding and AES-256-GCM nonce derivation for single-shot prompt sealing.",
  "## 2. AMD SEV-SNP Attestation Report",
  "Validate the 1184-byte SEV-SNP Guest Report signature against the Milan/Genoa VCEK certificate chain and check Policy.Debug == 0.",
  "## 3. Intel TDX QuoteV4 & RTMR3 Binding",
  "Confirm ECDSA-P256 QuoteV4 attestation signature, QE Report certification data, and runtime measurement register RTMR3 digest match.",
  "## 4. DMTF SPDM 1.2 GPU Device Transcript",
  "Check PCIe DOE SPDM 1.2 GET_MEASUREMENTS transcript binding between the host TDX enclave and NVIDIA H100/H200 confidential GPU.",
  "## 5. On-Chain Registry & Receipt Verification",
  "Cross-check enclave measurement hashes against Arc Testnet contract 0xbc8085c2b6fe6e0db05f169925c0b841828f4481 and verify Ed25519 receipt signatures.",
].join("\n\n");

async function resolveActiveNodeIds(): Promise<string[]> {
  try {
    const registry = await listNodes();
    const activeIds = registry.nodes
      .filter((n) => n.status === "active" && n.kind === "tinfoil")
      .map((n) => n.name || n.id);
    return activeIds.length >= 2 ? activeIds : DEFAULT_COMPARTMENT_NODES;
  } catch {
    return DEFAULT_COMPARTMENT_NODES;
  }
}

export async function GET(request?: NextRequest) {
  await connection();
  if (request) {
    const limited = compartmentLimiter.check(request);
    if (limited) return limited;
  }

  const compromisedNodeFraction = 0.02;
  const activeNodes = await resolveActiveNodeIds();
  const plan = splitTaskIntoCompartments(
    SPECIFICATION_FIVE_FRAGMENT_PROMPT,
    activeNodes,
  );

  const riskCurve = [1, 2, 3, 4, 5, 6].map((fragmentCount) => ({
    fragmentCount,
    ...computeFragmentCompromiseRisk(compromisedNodeFraction, fragmentCount),
  }));

  const currentRisk = computeFragmentCompromiseRisk(
    compromisedNodeFraction,
    plan.fragments.length,
  );

  const sampleReassembled = reassembleCompartmentOutputs(
    plan.fragments.map((f) => ({
      index: f.index,
      assignedNodeId: f.assignedNodeId,
      response: f.subPrompt,
    })),
  );

  return NextResponse.json({
    compromisedNodeFraction,
    samplePrompt: SPECIFICATION_FIVE_FRAGMENT_PROMPT,
    plan,
    riskMetrics: currentRisk,
    riskCurve,
    sampleReassembled,
  });
}

export async function POST(request: NextRequest) {
  const limited = compartmentLimiter.check(request);
  if (limited) return limited;

  try {
    const body = await readBoundedJson<{
      prompt?: string;
      compromisedNodeFraction?: number;
      availableNodes?: string[];
      customTerms?: string[];
      normalizeStyle?: boolean;
    }>(request, MAX_COMPARTMENT_BODY_BYTES);

    const rawPrompt =
      typeof body?.prompt === "string" && body.prompt.trim().length > 0
        ? body.prompt.slice(0, MAX_PROMPT_CHARS)
        : SPECIFICATION_FIVE_FRAGMENT_PROMPT;

    const prepared = preparePrompt(rawPrompt, {
      customTerms: Array.isArray(body?.customTerms) ? body.customTerms : undefined,
      normalizeStyle: Boolean(body?.normalizeStyle),
    });

    const rawFraction =
      typeof body?.compromisedNodeFraction === "number"
        ? body.compromisedNodeFraction
        : 0.02;
    const compromisedNodeFraction =
      Number.isFinite(rawFraction) && rawFraction >= 0 && rawFraction <= 1
        ? rawFraction
        : 0.02;

    const validNodes = Array.isArray(body?.availableNodes)
      ? body.availableNodes
          .filter((n): n is string => typeof n === "string" && n.trim().length > 0 && n.length <= 64)
          .slice(0, 16)
      : [];
    const availableNodes =
      validNodes.length > 0 ? validNodes : await resolveActiveNodeIds();

    const plan = splitTaskIntoCompartments(prepared.outboundText, availableNodes);
    const riskMetrics = computeFragmentCompromiseRisk(
      compromisedNodeFraction,
      plan.fragments.length,
    );

    const riskCurve = [1, 2, 3, 4, 5, 6].map((fragmentCount) => ({
      fragmentCount,
      ...computeFragmentCompromiseRisk(compromisedNodeFraction, fragmentCount),
    }));

    return NextResponse.json({
      compromisedNodeFraction,
      plan,
      riskMetrics,
      riskCurve,
      pipelineReport: prepared.report,
      bucketBytes: prepared.bucketBytes,
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return NextResponse.json({ error: err.message }, { status: 413 });
    }
    return NextResponse.json(
      {
        error:
          err instanceof InvalidJsonBodyError
            ? err.message
            : "Invalid compartment request body",
      },
      { status: 400 },
    );
  }
}
