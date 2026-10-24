import { NextRequest, NextResponse, connection } from "next/server";
import {
  computeFragmentCompromiseRisk,
  DEFAULT_COMPARTMENT_NODES,
  reassembleCompartmentOutputs,
  splitTaskIntoCompartments,
} from "@/lib/compartment/splitter";

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

export async function GET() {
  await connection();

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
  try {
    const body = (await request.json()) as {
      prompt?: string;
      compromisedNodeFraction?: number;
      availableNodes?: string[];
    };

    const prompt =
      typeof body.prompt === "string" && body.prompt.trim().length > 0
        ? body.prompt
        : SAMPLE_FIVE_FRAGMENT_PROMPT;

    const rawFraction =
      typeof body.compromisedNodeFraction === "number"
        ? body.compromisedNodeFraction
        : 0.02;
    const compromisedNodeFraction =
      Number.isFinite(rawFraction) && rawFraction >= 0 && rawFraction <= 1
        ? rawFraction
        : 0.02;

    const availableNodes =
      Array.isArray(body.availableNodes) && body.availableNodes.length > 0
        ? body.availableNodes
        : DEFAULT_COMPARTMENT_NODES;

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
    return NextResponse.json(
      {
        error:
          err instanceof Error ? err.message : "Invalid compartment request body",
      },
      { status: 400 }
    );
  }
}
