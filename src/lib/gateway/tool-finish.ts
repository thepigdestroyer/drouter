/** Some enclave models finish a successful tool call with `stop`. Agent clients
 * use the OpenAI finish reason to decide whether to execute and return results. */
export function hasToolCalls(payload: unknown): boolean {
  if (!payload || typeof payload !== "object" || !("tool_calls" in payload)) return false;
  return Array.isArray(payload.tool_calls) && payload.tool_calls.length > 0;
}

export function trackToolFinish(choice: Record<string, unknown>, seen: Set<number>, index: number): void {
  if (hasToolCalls(choice.delta)) seen.add(index);
  if (seen.has(index) && choice.finish_reason === "stop") choice.finish_reason = "tool_calls";
}
