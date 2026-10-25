/**
 * Re-exports client-safe orchestrator types, data-handling statements, and
 * restore verification helpers from `./shared`.
 */

export {
  DEFAULT_TASK_PROMPT,
  DEMO_PERSONA,
  GEMINI_4_ARGON_MODEL_ID,
  HONEST_DATA_HANDLING_STATEMENT,
  MAX_ALWAYS_HIDE_TERM_CHARS,
  MAX_ALWAYS_HIDE_TERMS,
  sanitizeAlwaysHideTerms,
  verifyRedactionAndSymmetryRestore,
  type ArgonAutonomousRunResult,
  type ClosedAgentPlan,
  type ClosedPlannerStep,
  type DataHandlingStatement,
  type GeminiEgressReceipt,
  type MechanicalRedactFn,
  type MechanicalRedactionItem,
  type MechanicalRedactResult,
  type NamedUserPersona,
  type SandboxAttemptRecord,
  type SevenCheckStatus,
  type Stage1PrivacyFilterResult,
  type Stage2SubagentSwarmResult,
  type Stage3SandboxVerificationResult,
  type Stage4ArgonSynthesisResult,
  type Stage5HumanInTheLoopResult,
  type Stage6MultimodalReadoutResult,
  type SubagentTaskTrace,
} from "./shared";
