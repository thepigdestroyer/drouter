import { NextRequest, NextResponse, connection } from "next/server";
import {
  computeFragmentCompromiseRisk,
  DEFAULT_COMPARTMENT_NODES,
  reassembleCompartmentOutputs,
  splitTaskIntoCompartments,
} from "@/lib/compartment/splitter";
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

const SAMPLE_FIVE_FRAGMENT_PROMPT = [
  "## 1. M&A Valuation Model",
  "Evaluate the discounted cash flow assumptions for Project Helios using the confidential Q4 revenue table.",
  "## 2. Patent Litigation Exposure",
  "Summarize prior-art invalidity arguments for Claims 1-9 of the disputed photonic interconnect patent.",
  "## 3. Supply-Chain Vendor Audit",
  "Cross-check foundry wafer yield variance across TSMC N3P lots against contractual SLA penalties.",
  "## 4. Key-Person Retention Schedule",
  "Calculate unvested equity acceleration triggers for the 12 principal silicon architects.",
  "## 5. Regulatory Filing Timeline",
  "Draft the HSR Second Request compliance checklist and antitrust divestiture remedies.",
].join("\n\n");

export async function GET(request?: NextRequest) {
  await connection();
  if (request) {
    const limited = compartmentLimiter.check(request);
    if (limited) return limited;
  }

  const compromisedNodeFraction = 0.02;
  const plan = splitTaskIntoCompartments(
    SAMPLE_FIVE_FRAGMENT_PROMPT,
    DEFAULT_COMPARTMENT_NODES
  );

  const riskCurve = [1, 2, 3, 4, 5, 6].map((fragmentCount) => ({
    fragmentCount,
    ...computeFragmentCompromiseRisk(compromisedNodeFraction, fragmentCount),
  }));

  const currentRisk = computeFragmentCompromiseRisk(
    compromisedNodeFraction,
    plan.fragments.length
  );

  const sampleReassembled = reassembleCompartmentOutputs(
    plan.fragments.map((f) => ({
      index: f.index,
      assignedNodeId: f.assignedNodeId,
      response: `Verified enclave sub-agent output for ${f.fragmentId}`,
    }))
  );

  return NextResponse.json({
    compromisedNodeFraction,
    samplePrompt: SAMPLE_FIVE_FRAGMENT_PROMPT,
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
    }>(request, MAX_COMPARTMENT_BODY_BYTES);

    const prompt =
      typeof body?.prompt === "string" && body.prompt.trim().length > 0
        ? body.prompt.slice(0, MAX_PROMPT_CHARS)
        : SAMPLE_FIVE_FRAGMENT_PROMPT;

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
      validNodes.length > 0 ? validNodes : DEFAULT_COMPARTMENT_NODES;

    const plan = splitTaskIntoCompartments(prompt, availableNodes);
    const riskMetrics = computeFragmentCompromiseRisk(
      compromisedNodeFraction,
      plan.fragments.length
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
      { status: 400 }
    );
  }
}
