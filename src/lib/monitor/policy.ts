/**
 * Subsystem 6 — VMPL0 Inner Monitor Formal Exit-Policy Checker (Spec §2.2 & V3 / SP1 AC5)
 *
 * Models every possible outbound/attestation action from the confidential VM and
 * exhaustively verifies all 1,344 states against the 5 safety invariants.
 */

export const ACTOR_VMPLS = [0, 1, 2] as const;
export type ActorVmpl = (typeof ACTOR_VMPLS)[number];

export const CHANNELS = [
  "relay-stream",
  "control-plane",
  "blob-storage",
  "raw-socket",
  "disk-write",
  "shell-exec",
  "snp-attest",
] as const;
export type Channel = (typeof CHANNELS)[number];

export const PAYLOAD_ENCRYPTIONS = [
  "custody-aes-gcm",
  "freeze-aes-gcm",
  "plaintext",
  "control-schema",
] as const;
export type PayloadEncryption = (typeof PAYLOAD_ENCRYPTIONS)[number];

export interface Action {
  actorVmpl: ActorVmpl;
  channel: Channel;
  payloadEncryption: PayloadEncryption;
  nonceFresh: boolean;
  fixedFrameCadence: boolean;
  hasPerSessionFields: boolean;
  startsWithForbiddenPrefix: boolean;
}

export interface MonitorDecision {
  allowed: boolean;
  rule: string;
}

export type PolicyPredicate = (action: Action) => MonitorDecision | boolean;

export interface InvariantResult {
  id: string;
  description: string;
  passed: boolean;
  counterexample?: Action;
}

export interface VerificationReport {
  verified: boolean;
  statesChecked: number;
  allowedStates: number;
  deniedStates: number;
  invariants: InvariantResult[];
}

const BOOLEANS = [false, true] as const;

/**
 * Evaluates the VMPL0 Inner Monitor exit policy for a single candidate action.
 */
export function evaluateMonitorExit(action: Action): MonitorDecision {
  // Rule M0: Only actorVmpl === 0 may perform external I/O or request SNP reports.
  if (action.actorVmpl !== 0) {
    return { allowed: false, rule: "DENY_NON_VMPL0_EGRESS" };
  }

  switch (action.channel) {
    // Rule M1 ("relay-stream"): allowed iff custody-aes-gcm AND nonceFresh AND fixedFrameCadence
    case "relay-stream": {
      if (action.payloadEncryption !== "custody-aes-gcm") {
        return { allowed: false, rule: "M1_DENY_RELAY_ENCRYPTION" };
      }
      if (!action.nonceFresh) {
        return { allowed: false, rule: "M1_DENY_RELAY_NONCE_REUSE" };
      }
      if (!action.fixedFrameCadence) {
        return { allowed: false, rule: "M1_DENY_RELAY_VARIABLE_CADENCE" };
      }
      return { allowed: true, rule: "M1_ALLOW_RELAY_STREAM" };
    }

    // Rule M2 ("control-plane"): allowed iff control-schema AND hasPerSessionFields === false
    case "control-plane": {
      if (action.payloadEncryption !== "control-schema") {
        return { allowed: false, rule: "M2_DENY_CONTROL_SCHEMA" };
      }
      if (action.hasPerSessionFields) {
        return { allowed: false, rule: "M2_DENY_PER_SESSION_CONTROL_FIELDS" };
      }
      return { allowed: true, rule: "M2_ALLOW_CONTROL_PLANE" };
    }

    // Rule M3 ("blob-storage"): allowed iff (custody-aes-gcm || freeze-aes-gcm) AND nonceFresh
    case "blob-storage": {
      if (
        action.payloadEncryption !== "custody-aes-gcm" &&
        action.payloadEncryption !== "freeze-aes-gcm"
      ) {
        return { allowed: false, rule: "M3_DENY_BLOB_ENCRYPTION" };
      }
      if (!action.nonceFresh) {
        return { allowed: false, rule: "M3_DENY_BLOB_NONCE_REUSE" };
      }
      return { allowed: true, rule: "M3_ALLOW_BLOB_STORAGE" };
    }

    // Rule M4 ("snp-attest"): allowed iff startsWithForbiddenPrefix === false
    case "snp-attest": {
      if (action.startsWithForbiddenPrefix) {
        return { allowed: false, rule: "M4_DENY_FORBIDDEN_ATTEST_PREFIX" };
      }
      return { allowed: true, rule: "M4_ALLOW_SNP_ATTEST" };
    }

    // Rule M5: "raw-socket", "disk-write", and "shell-exec" are unconditionally denied
    case "raw-socket":
    case "disk-write":
    case "shell-exec": {
      return { allowed: false, rule: "M5_DENY_FORBIDDEN_CHANNEL" };
    }
  }
}

/**
 * Enumerates the full Cartesian product of all state/action variables:
 * 3 × 7 × 4 × 2 × 2 × 2 × 2 = 1,344 states.
 */
export function enumerateMonitorActions(): Action[] {
  const actions: Action[] = [];
  for (const actorVmpl of ACTOR_VMPLS) {
    for (const channel of CHANNELS) {
      for (const payloadEncryption of PAYLOAD_ENCRYPTIONS) {
        for (const nonceFresh of BOOLEANS) {
          for (const fixedFrameCadence of BOOLEANS) {
            for (const hasPerSessionFields of BOOLEANS) {
              for (const startsWithForbiddenPrefix of BOOLEANS) {
                actions.push({
                  actorVmpl,
                  channel,
                  payloadEncryption,
                  nonceFresh,
                  fixedFrameCadence,
                  hasPerSessionFields,
                  startsWithForbiddenPrefix,
                });
              }
            }
          }
        }
      }
    }
  }
  return actions;
}

interface InvariantSpec {
  id: string;
  description: string;
  holdsWhenAllowed: (action: Action) => boolean;
}

const INVARIANT_SPECS: readonly InvariantSpec[] = [
  {
    id: "I1_NoPlaintextEgress",
    description:
      'No allowed state on any network/storage channel has payloadEncryption === "plaintext".',
    holdsWhenAllowed: (action) =>
      action.channel === "snp-attest" || action.payloadEncryption !== "plaintext",
  },
  {
    id: "I2_NoNonceReuse",
    description: "No allowed ciphertext egress has nonceFresh === false.",
    holdsWhenAllowed: (action) => {
      const isCiphertextEgress =
        action.channel === "relay-stream" ||
        action.channel === "blob-storage" ||
        (action.channel !== "snp-attest" &&
          (action.payloadEncryption === "custody-aes-gcm" ||
            action.payloadEncryption === "freeze-aes-gcm"));
      return !isCiphertextEgress || action.nonceFresh === true;
    },
  },
  {
    id: "I3_NoEngineBypass",
    description: "No allowed state has actorVmpl !== 0.",
    holdsWhenAllowed: (action) => action.actorVmpl === 0,
  },
  {
    id: "I4_NoPerSessionControlLeak",
    description: "No allowed control-plane message has hasPerSessionFields === true.",
    holdsWhenAllowed: (action) =>
      action.channel !== "control-plane" || action.hasPerSessionFields === false,
  },
  {
    id: "I5_ForbiddenPrefixNeverSigned",
    description: "No allowed snp-attest action has startsWithForbiddenPrefix === true.",
    holdsWhenAllowed: (action) =>
      action.channel !== "snp-attest" || action.startsWithForbiddenPrefix === false,
  },
];

/**
 * Exhaustively verifies the VMPL0 Inner Monitor policy across all 1,344 states
 * and checks all 5 safety invariants. Accepts an optional custom predicate for
 * fault-injection testing.
 */
export function verifyMonitorPolicyExhaustive(
  predicate: PolicyPredicate = evaluateMonitorExit,
): VerificationReport {
  const actions = enumerateMonitorActions();
  let allowedStates = 0;
  let deniedStates = 0;

  const counterexamples = new Map<string, Action>();

  for (const action of actions) {
    const decision = predicate(action);
    const allowed = typeof decision === "boolean" ? decision : decision.allowed;

    if (allowed) {
      allowedStates += 1;
      for (const spec of INVARIANT_SPECS) {
        if (!counterexamples.has(spec.id) && !spec.holdsWhenAllowed(action)) {
          counterexamples.set(spec.id, { ...action });
        }
      }
    } else {
      deniedStates += 1;
    }
  }

  const invariants: InvariantResult[] = INVARIANT_SPECS.map((spec) => {
    const counterexample = counterexamples.get(spec.id);
    if (counterexample) {
      return {
        id: spec.id,
        description: spec.description,
        passed: false,
        counterexample,
      };
    }
    return {
      id: spec.id,
      description: spec.description,
      passed: true,
    };
  });

  return {
    verified: invariants.every((inv) => inv.passed),
    statesChecked: actions.length,
    allowedStates,
    deniedStates,
    invariants,
  };
}
