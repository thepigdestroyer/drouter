export interface PartnerVisibilityRow {
  whatTheySee: string;
  whatTheyNeverSee: string;
}

export interface BackendPartnerSpec {
  id: "gemini-4-argon" | "mongodb-atlas";
  name: string;
  roleLabel: string;
  plainPrivacyLine: string;
  whyNeeded: string;
  howItWorks: readonly string[];
  honestNotes: readonly string[];
  visibilityRows: readonly PartnerVisibilityRow[];
}

export interface GoogleEgressCapacityRow {
  messageKind: string;
  variableFields: string;
  maxCardinality: string;
  maxCapacity: string;
}

export const ARCHITECTURE_DOCS_GITHUB_URL =
  "https://github.com/thepigdestroyer/drouter/blob/main/docs/ARCHITECTURE.md" as const;

export const CONFIDENTIAL_SPACE_DOCS_GITHUB_URL =
  "https://github.com/thepigdestroyer/drouter/blob/main/docs/confidential-space.md" as const;

export const BACKEND_PARTNERS_INTRO = {
  eyebrow: "Backend partners",
  heading:
    "How Google Gemini and MongoDB Atlas work inside deRoute without seeing your words",
  lead: "deRoute relies on two specialized partners behind the scenes: Google Gemini 4 Argon to plan multi-step agent tasks, and MongoDB Atlas to hold the public reference library and anonymous accountability records. Neither partner ever receives your plain messages, your personal details, or your IP address.",
} as const;

export const SPLIT_KNOWLEDGE_EXPLAINER = {
  eyebrow: "Split knowledge",
  heading: "Why not just send everything to one AI company?",
  body: "When you use a normal AI website, one company runs the front door, holds your account, plans the work, searches the library, and reads your plain words. That single company sees both who you are and what you asked. deRoute splits those jobs across separate parties so no single company ever sees both who you are and what you asked. Your device hides your personal details before anything leaves and puts them back when the answer returns. Our web server only sees your network connection and a locked, uniform-sized envelope it cannot open. Tinfoil's sealed computer opens that envelope inside hardware-locked memory to write the answer without learning your identity or IP address. Google Gemini only sees a short, content-free task description with placeholders like $INPUT to pick the tool steps. MongoDB Atlas only holds the public reference library and anonymous, hour-rounded receipts.",
} as const;

export const BACKEND_PARTNERS: readonly BackendPartnerSpec[] = [
  {
    id: "gemini-4-argon",
    name: "Gemini 4 Argon",
    roleLabel: "The planner",
    plainPrivacyLine: "Gemini decides what to do. It never sees what you wrote.",
    whyNeeded:
      "When you ask the AI agent to handle a multi-step job, it needs a strong planner that decides which steps an agent task needs and in what order.",
    howItWorks: [
      "Your device removes personal details first using an on-device filter, followed by a second pass inside a Tinfoil sealed computer.",
      "Your browser then writes a short task description containing none of your words: only the task kind (summarize, analyze, draft, review, or question), a rough power-of-two size bucket, rounded counts of hidden details (0, 1, or 2+), yes-or-no flags for which checks to run, and the allowed tools.",
      "Our server asks Gemini for a plan through Google's Interactions API with storage turned off.",
      "Every request must match an exact closed shape and pass a content-free check before leaving, which limits what any planning request could carry to about 67 bits (less than 9 bytes of variable choices).",
      "Gemini answers with tool steps that refer only to placeholders like $INPUT and $RESULT_1.",
      "The exact bytes Google received are fingerprinted into the public transparency log (our public receipt book) and returned to your browser in a signed receipt.",
      "The actual work on your words happens inside a Tinfoil sealed computer, and your names and personal details are put back on your device.",
    ],
    honestNotes: [
      "Regular chat on /app does not use Gemini at all. Chat messages go straight from your browser to a Tinfoil sealed computer.",
      "Moving the Gemini planner into a Google Confidential Space sealed computer is built and wired in our codebase, but that sealed computer deployment is not yet live in production.",
    ],
    visibilityRows: [
      {
        whatTheySee:
          "Short task description with no user words: task kind, $INPUT placeholder, rough size bucket, coarse counts of hidden details (0, 1, or 2+), check flags, and allowed tools (about 67 bits max).",
        whatTheyNeverSee:
          "Your prompt text, chat messages, or any words you typed.",
      },
      {
        whatTheySee:
          "Content-free tool steps and results using placeholders ($INPUT, $RESULT_1), status labels, rounded counts, and yes-or-no flags.",
        whatTheyNeverSee:
          "Your personal details, names, emails, secrets, dates, or numbers.",
      },
      {
        whatTheySee:
          "Our server's outbound IP address and our server's Gemini API key (with Google storage turned off).",
        whatTheyNeverSee:
          "The answer written by the Tinfoil sealed computer, what you searched in the library, or your IP address.",
      },
    ],
  },
  {
    id: "mongodb-atlas",
    name: "MongoDB Atlas",
    roleLabel: "The library and the public record",
    plainPrivacyLine:
      "MongoDB holds public facts and anonymous receipts. Never your messages, names or IP address.",
    whyNeeded:
      "deRoute needs a fast, searchable home for the public reference library and for anonymous accountability records that anyone can inspect.",
    howItWorks: [
      "The public library holds 16 sourced documents about sealed computers and seal checks, each with a 768-number embedding computed inside a Tinfoil sealed computer.",
      "Public search uses MongoDB Atlas $vectorSearch (meaning), $search (keywords), and $rankFusion (blends them), with typed text filtered on your device and again on the server first.",
      "Private agent runs download the whole public library (identical for everyone, fingerprint-checked on your device, with query parameters forbidden) and search it locally on your device, so MongoDB never learns what you looked up.",
      "It also stores the public transparency log, hourly monitoring results, independent verifications, and anonymous payment records (claim-code fingerprints, transaction amounts without senders, and one-time spend codes).",
    ],
    honestNotes: [
      "Every accountability, monitoring, and token-spend timestamp stored in MongoDB is rounded down to the full UTC hour so records cannot be linked to the minute you connected.",
    ],
    visibilityRows: [
      {
        whatTheySee:
          "The 16 public reference documents about sealed computers and their 768-number meaning vectors.",
        whatTheyNeverSee:
          "Your chat messages, agent tasks, or AI answers.",
      },
      {
        whatTheySee:
          "Public library search terms after personal details are removed on your device and on our server (never used during private agent runs).",
        whatTheyNeverSee:
          "What your AI agent looked up during a private agent run (because the whole library is searched on your device).",
      },
      {
        whatTheySee:
          "Public transparency log entries, hourly monitoring results, independent verifications, claim-code fingerprints, sender-stripped payment amounts, and one-time spend codes.",
        whatTheyNeverSee:
          "Your personal details, your wallet sender address, your IP address, or exact minute-by-minute timestamps.",
      },
    ],
  },
] as const;

export const GOOGLE_EGRESS_CAPACITY_TABLE: readonly GoogleEgressCapacityRow[] = [
  {
    messageKind: "taskDescriptor (TaskDescriptor)",
    variableFields:
      "taskKind (5) x inputHandle (1) x inputTokenEstimate (21 powers of 2) x redactionCounts (4^16 - 1 over coarse buckets 0..2) x verification (3^8 - 1 booleans) x allowedTools (31 canonical subsets)",
    maxCardinality: "9.18 x 10^16",
    maxCapacity: "56.35 bits (7.04 B)",
  },
  {
    messageKind: "interactionsPayload (InteractionsCreatePayload)",
    variableFields:
      "taskDescriptor (56.35 b) x thinking_level (3) x background (2) x max_output_tokens (8 powers of 2) x tools (31 canonical subsets); model, system_instruction, subagent_routing, metadata fixed",
    maxCardinality: "1.37 x 10^20",
    maxCapacity: "66.89 bits (8.36 B)",
  },
  {
    messageKind: "createRequest (GeminiCreateRequest)",
    variableFields:
      "input[0].text (canonicalJson(taskDescriptor), 56.35 b) x background (2) x generation_config (3 x 8 = 24) x tools (31 canonical subsets); model, store: false, system_instruction fixed",
    maxCardinality: "1.37 x 10^20",
    maxCapacity: "66.89 bits (8.36 B)",
  },
  {
    messageKind: "toolCall:scrub_and_symmetry_mask",
    variableFields:
      "inputHandle (17: $INPUT or $RESULT_1..16) x bucketQuantumBytes (8 powers of 2 in 512..65536)",
    maxCardinality: "136",
    maxCapacity: "7.09 bits (0.89 B)",
  },
  {
    messageKind: "toolCall:verify_two_hop_enclave_and_quorum",
    variableFields:
      "providerId (1: 'tinfoil') x enclaveModel (2: 'gemma4-31b' | 'kimi-k3')",
    maxCardinality: "2",
    maxCapacity: "1.00 bit (0.13 B)",
  },
  {
    messageKind: "toolCall:search_atlas_hybrid_kb",
    variableFields:
      "topic (29 allowlisted enums) x inputHandle (18: omitted or 17) x category (5: omitted or 4)",
    maxCardinality: "2,610",
    maxCapacity: "11.35 bits (1.42 B)",
  },
  {
    messageKind: "toolCall:invoke_attested_enclave",
    variableFields:
      "inputHandle (17) x enclaveModel (2) x taskKind (6: omitted or 5)",
    maxCardinality: "204",
    maxCapacity: "7.67 bits (0.96 B)",
  },
  {
    messageKind: "toolCall:anchor_arc_settlement_with_human_gate",
    variableFields:
      "actionKind (1: 'anchor_receipt') x humanApproved (2) x resultHandle (18: omitted or 17)",
    maxCardinality: "36",
    maxCapacity: "5.17 bits (0.65 B)",
  },
  {
    messageKind: "toolResult:scrub_and_symmetry_mask",
    variableFields:
      "status (2) x passed (2) x outputHandle (16) x (redactionCount, mechanicalRedactionCount, attestedRedactionCount in {0,1,2,4,8,16,32,64} with sum invariant: 30 triples) x bucketBytes (8) x plaintextLeakCount (6) x contentHandle (16)",
    maxCardinality: "1,474,560",
    maxCapacity: "20.49 bits (2.56 B)",
  },
  {
    messageKind: "toolResult:verify_two_hop_enclave_and_quorum",
    variableFields:
      "status (2) x passed (2) x providerId (1) x enclaveModel (2) x checksPassed (17) x checksTotal (16) x routerHandle (16) x enclaveMeasurementHandle (16) x selfHealed (3) x failedOver (3)",
    maxCardinality: "5.01 x 10^6",
    maxCapacity: "22.26 bits (2.78 B)",
  },
  {
    messageKind: "toolResult:search_atlas_hybrid_kb",
    variableFields:
      "status (2) x outputHandle (16) x vectorEngine (2) x textEngine (2) x fusionEngine (4) x totalDocs (65) x matchingReceiptsCount (65) x topDocHandle (16)",
    maxCardinality: "3.46 x 10^7",
    maxCapacity: "25.04 bits (3.13 B)",
  },
  {
    messageKind: "toolResult:invoke_attested_enclave",
    variableFields:
      "status (2) x outputHandle (16) x enclaveModel (2) x outputTokenEstimate (21 powers of 2) x outputDigestHandle (16) x attested (2)",
    maxCardinality: "43,008",
    maxCapacity: "15.39 bits (1.92 B)",
  },
  {
    messageKind: "toolResult:anchor_arc_settlement_with_human_gate",
    variableFields:
      "status (5) x requiresHumanApproval (2) x humanApproved (2) x stateChangedOnChain (2) x receiptHandle (16)",
    maxCardinality: "640",
    maxCapacity: "9.32 bits (1.17 B)",
  },
  {
    messageKind: "functionResult (FunctionResultStep)",
    variableFields:
      "type (1) x call_id (1,167 in CLOSED_CALL_ID_REGEX) x (name + result across 5 tool result schemas, 41,142,912)",
    maxCardinality: "4.80 x 10^10",
    maxCapacity: "35.48 bits (4.44 B)",
  },
  {
    messageKind: "followUpRequest (1 step / max 5 steps)",
    variableFields:
      "background (2) x generation_config (24) x previous_interaction_id (1,167) x tools (31) x input (1..5 unique functionResult steps)",
    maxCardinality: "8.34 x 10^16 (1 step); 5.24 x 10^59 (5 steps)",
    maxCapacity: "56.21 bits (7.03 B / 1 step); 198.37 bits (24.80 B / 5 steps)",
  },
] as const;

export const ATLAS_TECHNICAL_SPEC = {
  databaseName: "drouter",
  testDatabaseName: "drouter_test",
  vectorIndexName: "drouter_vector_index",
  textIndexName: "drouter_text_search",
  embeddingModel: "nomic-embed-text (Tinfoil attested enclave, 768 dimensions, cosine similarity)",
  pipelineStages: [
    "$vectorSearch",
    "$search",
    "$rankFusion",
    "$project",
    "$limit",
    "$facet",
    "$group",
    "$count",
    "$sort",
  ],
  collections: [
    {
      name: "enclave_intelligence",
      purpose:
        "16 curated reference documents with 768-dimensional nomic-embed-text embeddings; served as a deterministic, hash-verified whole corpus at GET /api/knowledge/corpus (query parameters forbidden) for local BM25 ranking in browser memory during private agent runs.",
    },
    {
      name: "agent_verification_receipts",
      purpose:
        "Prompt-free live agent verification receipts with UTC-hour coarsened timestamps and Ed25519 forensic digest signatures.",
    },
    {
      name: "transparency_log",
      purpose:
        "RFC 6962 append-only Merkle tree leaves (including Gemini canonicalRequest SHA-256 egress receipts) and Ed25519-signed tree heads anchored hourly on Circle Arc Testnet.",
    },
    {
      name: "verifier_submissions",
      purpose:
        "Independent Ed25519-signed C1-C7 verification claims storing only verifier public-key fingerprint, coarse UTC hour, and verified hardware measurements.",
    },
    {
      name: "monitor_runs",
      purpose:
        "Hourly continuous enclave monitor records with a 30-day TTL index (at_ttl_30d) and coarse UTC-hour timestamps.",
    },
    {
      name: "credit_invoices",
      purpose:
        "One-time BIP32 deposit-address invoice records storing only { invoiceId, derivationIndex, amount, claimHash, expiresAt, paid } with TTL index expiresAt_ttl.",
    },
    {
      name: "credit_payments",
      purpose:
        "Redeemed USDC deposit records storing only { txHash, amount } with ERC-20 Transfer sender (from) stripped before ingestion.",
    },
    {
      name: "credit_nullifiers",
      purpose:
        "Spent Chaumian RSA blind-credit nullifiers { nullifier, denomination, nodeId, spentAt, redeemed } with UTC-hour coarsened spentAt.",
    },
  ],
} as const;
