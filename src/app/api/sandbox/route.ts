import { NextResponse, connection } from "next/server";
import {
  destroySandbox,
  execInSandbox,
  forkSandbox,
  pauseSandbox,
  spawnSandbox,
} from "@/lib/sandbox/microvm";

export async function GET() {
  await connection();

  const sessionId = "ehbp-sess-kimi-k3-1m-demo";
  const parent = spawnSandbox(sessionId);

  const parentExec1 = execInSandbox(parent, {
    tool: "python",
    code: "portfolio_npv = 1250000; print(portfolio_npv)",
  });

  const parentExec2 = execInSandbox(parent, {
    tool: "bash",
    code: 'echo "CONFIDENTIAL_MERGER_TARGET=Helios" > /tmp/deal.env',
  });

  const pauseReceipt = pauseSandbox(parent);

  const child = forkSandbox(parent);

  const childSpeculativeExec = execInSandbox(child, {
    tool: "python",
    code: "portfolio_npv = 0; print(portfolio_npv)",
  });

  const parentVerifyExec = execInSandbox(parent, {
    tool: "python",
    code: "print(portfolio_npv)",
  });

  const childDestroyReceipt = destroySandbox(child);
  const parentDestroyReceipt = destroySandbox(parent);

  return NextResponse.json({
    sessionId,
    specReference: "Kimi K3 §5.3.2 AgentENV Attested MicroVM Sandbox",
    trace: {
      spawn: {
        sandboxId: parent.sandboxId,
        imageMeasurementHex: parent.imageMeasurementHex,
        rtmr3Hex: parent.rtmr3Hex,
      },
      exec: [parentExec1, parentExec2],
      pause: pauseReceipt,
      fork: {
        childSandboxId: child.sandboxId,
        parentSandboxId: child.parentSandboxId,
        childSpeculativeExec,
        parentVerifyExec,
        parentStatePreserved:
          parentVerifyExec.decryptedStdoutForTest === "1250000",
      },
      destroy: {
        child: childDestroyReceipt,
        parent: parentDestroyReceipt,
      },
    },
  });
}
