import { preparePrompt, type PreparedPrompt } from "@/lib/pipeline";

export interface StoryStep {
  step: number;
  shortLabel: string;
  title: string;
  metaphor: string;
  body: string;
  takeaway: string;
  techSummary: string;
  techDetail: string;
}

export interface ReassurancePoint {
  label: string;
  title: string;
  body: string;
  techDetail: string;
}

export interface FaqItem {
  question: string;
  answer: string;
  techDetail: string;
}

export interface ScrubPreset {
  id: string;
  label: string;
  sample: string;
}

export interface OutboundSegment {
  type: "text" | "placeholder";
  value: string;
  kind?: string;
  friendlyKind?: string;
}

export interface LandingPromptPreview {
  inputText: string;
  outboundText: string;
  segments: OutboundSegment[];
  hiddenCount: number;
  hiddenItems: Array<{
    placeholder: string;
    kind: string;
    friendlyKind: string;
  }>;
  uniformSizeChars: number;
  simulatedModelRawReply: string;
  restoredModelReply: string;
  rawPrepared: PreparedPrompt;
}

export const HERO_COPY = {
  eyebrow: "deRoute · Private AI Chat",
  headline:
    "Talk to the world's most powerful AI. Nobody else can read what you say.",
  subheadline:
    "Not us, not the AI company, not anyone in between. Your browser hides your personal details on your device and locks every message so only a sealed computer can open it.",
  primaryCtaLabel: "Get started",
  primaryCtaHref: "/login?next=/app",
  secondaryCtaLabel: "See how it works",
  secondaryCtaHref: "/explain",
  quickNote:
    "No email or password needed. Sign in with your fingerprint, face, or device in 10 seconds.",
} as const;

export const STORY_STEPS: ReadonlyArray<StoryStep> = [
  {
    step: 1,
    shortLabel: "Hide details",
    title: "Your personal details get hidden on your device",
    metaphor: "Like putting black tape over names and numbers before handing over a letter.",
    body: "Before a single word leaves your browser, deRoute spots emails, phone numbers, street addresses, and account numbers and swaps them for simple placeholders like [EMAIL_1] or [PHONE_1]. Your real details stay on your screen.",
    takeaway: "We hide your personal details before anything leaves your device.",
    techSummary: "Client-side regex, Luhn, and ISO 7064 Mod-97 PII scrubber",
    techDetail:
      "Runs entirely in browser memory via preparePrompt(). Normalizes Unicode homoglyphs and strips zero-width splitters before matching emails, phones, street addresses, SSNs, IBANs, Luhn-valid payment cards, and API keys.",
  },
  {
    step: 2,
    shortLabel: "Seal check",
    title: "The sealed computer proves its seal is intact",
    metaphor: "Like checking the tamper-proof wax seal on a locked ballot box before dropping your note inside.",
    body: "The AI runs inside a special sealed computer whose memory is locked even from the people who own the building. Before you send anything, your browser runs a seal check to make sure that computer is genuine and untouched.",
    takeaway: "If the seal check fails, your browser refuses to send a single word.",
    techSummary: "Browser-verified AMD SEV-SNP and Intel TDX hardware attestation",
    techDetail:
      "Your browser verifies the hardware quote signed by the silicon vendor root (AMD VCEK or Intel PCS), checks the Sigstore Rekor transparency log entry, and confirms the pinned model weights and dm-verity root digest.",
  },
  {
    step: 3,
    shortLabel: "Locked envelope",
    title: "Your words get locked in a uniform envelope",
    metaphor: "Like sealing your letter inside a steel box that only the sealed computer has the key to open.",
    body: "Once the seal check passes, your browser locks your message directly to the key inside that sealed computer. It also pads every message so every message looks the same size from outside.",
    takeaway: "Locked so only the sealed computer can open it, and every message looks the same size from outside.",
    techSummary: "HPKE (RFC 9180) encryption, power-of-two bucket bytes, and OHTTP relay",
    techDetail:
      "Prompts are padded to coarse power-of-two byte buckets and encrypted in the browser with Hybrid Public Key Encryption (HPKE) directly to the enclave ephemeral public key, then forwarded through a blind Oblivious HTTP relay hop.",
  },
  {
    step: 4,
    shortLabel: "Leaves no trace",
    title: "The conversation disappears when you leave",
    metaphor: "Like writing on a slate inside a locked room that wipes itself clean the moment you walk out.",
    body: "The sealed computer reads your question, writes back using the same placeholders, and your browser swaps your real details back in for your eyes only. When you close the tab, the chat is gone, or you can pause and lock this chat to pick up where you left off later.",
    takeaway: "Nothing is stored in plain text, and you can verify every session in the public receipt book.",
    techSummary: "Stateless enclave memory, AES-256-GCM state freeze, and Arc testnet anchoring",
    techDetail:
      "Enclave RAM is encrypted by the CPU memory controller and discarded after each turn. Optional state freeze encrypts your transcript client-side with AES-256-GCM under a fresh key that the server never sees.",
  },
];

export const LIVE_SCRUB_PRESETS: ReadonlyArray<ScrubPreset> = [
  {
    id: "contact",
    label: "Email and phone",
    sample:
      "Hi, can you draft a reply to alex.rivera@example.com or text me at 415-555-0199 before Friday?",
  },
  {
    id: "address",
    label: "Home address",
    sample:
      "Please summarize the lease renewal rules for 742 Evergreen Terrace, Apt 4B and email landlord@oakproperty.org.",
  },
  {
    id: "account",
    label: "Account and ID",
    sample:
      "Check why invoice #902 on account number: 4829103847 was billed twice, and ping ops@billing-team.io.",
  },
];

export const REASSURANCE_POINTS: ReadonlyArray<ReassurancePoint> = [
  {
    label: "01 · On your device",
    title: "We hide your personal details first",
    body: "Emails, phone numbers, home addresses, and account numbers are swapped for safe placeholders in your browser before anything is locked and sent.",
    techDetail:
      "Client-side session scrubber maps detected spans to deterministic placeholders ([EMAIL_1], [PHONE_1], [ENTITY_1], [ACCT_1]) and restores them locally on the streamed reply.",
  },
  {
    label: "02 · Verified hardware",
    title: "Seal check before every chat",
    body: "Your browser checks that the sealed computer is genuine before sending a single word, then locks your message so only that sealed computer can open it.",
    techDetail:
      "End-to-end HPKE encryption bound to the hardware-attested public key inside Tinfoil AMD SEV-SNP and Intel TDX + NVIDIA confidential GPU enclaves.",
  },
  {
    label: "03 · Private account",
    title: "Sign in without an email or password",
    body: "You sign in with your fingerprint, face, or device and use prepaid anonymous tokens that cannot be traced back to you.",
    techDetail:
      "WebAuthn PRF extension derives a local HKDF vault key in browser memory. Payments use RSA blind-signature tokens with one-time nullifiers.",
  },
];

export const FAQ_ITEMS: ReadonlyArray<FaqItem> = [
  {
    question: "Who can read my messages?",
    answer:
      "Nobody else. Your browser hides your personal details on your device and locks your message so only the sealed computer running the AI can open it. We cannot read what you write, the internet relay in between cannot read it, and the cloud host cannot see it outside the sealed computer.",
    techDetail:
      "Messages are scrubbed client-side, padded to fixed power-of-two byte buckets, and encrypted with HPKE to the enclave key verified via AMD SEV-SNP and Intel TDX attestation.",
  },
  {
    question: "Do I need an email?",
    answer:
      "No. You never give us an email address, a phone number, or a password. You sign in with your fingerprint, face, or device (or with six secret words saved on your device), so we never learn who you are.",
    techDetail:
      "Accounts use client-side WebAuthn passkeys with the PRF extension (or a 6-word BIP39 recovery phrase) to derive keys locally via HKDF. The server stores zero account rows.",
  },
  {
    question: "Is it free?",
    answer:
      "Yes. This is a free demo and comes with a free daily allowance of anonymous tokens. Those tokens are prepaid in your browser and cannot be linked back to your identity when you spend them.",
    techDetail:
      "Your browser mints blind-signed credits using RSA-PSS blind signatures so the spender cannot be correlated with the minter.",
  },
  {
    question: "What is the AI?",
    answer:
      "You can chat with leading open-weight AI models, including Kimi K3, DeepSeek V4.1 Flash, GLM-5.3, GPT-OSS 120B, and Llama 3.3 70B. The live models run inside Tinfoil's sealed computers, and every one is checked every hour.",
    techDetail:
      "Live inference routes to Tinfoil attested enclaves (AMD SEV-SNP router + Intel TDX and NVIDIA H100/H200 confidential GPUs), verified against AMD KDS VCEK certificates, Sigstore Rekor transparency logs, and dm-verity root digests.",
  },
];

export const APP_PAGE_COPY = {
  eyebrow: "deRoute · Private Chat",
  heading: "Your private chat is ready. Everything you type is hidden and locked before it leaves your device.",
} as const;

const FRIENDLY_KIND_LABELS: Readonly<Record<string, string>> = {
  EMAIL: "Email address",
  PHONE: "Phone number",
  SECRET: "Secret key",
  ACCT: "Account or ID number",
  IP: "Network address",
  ENTITY: "Address or date",
};

export function friendlyRedactionLabel(kind: string): string {
  return FRIENDLY_KIND_LABELS[kind.toUpperCase()] ?? "Personal detail";
}

const PLACEHOLDER_TOKEN_RE = /(\[(?:SECRET|EMAIL|PHONE|IP|ACCT|ENTITY)_\d+\])/g;
const PLACEHOLDER_KIND_RE = /^\[(SECRET|EMAIL|PHONE|IP|ACCT|ENTITY)_\d+\]$/;

export function tokenizeOutboundText(outboundText: string): OutboundSegment[] {
  if (!outboundText) return [];
  const parts = outboundText.split(PLACEHOLDER_TOKEN_RE);
  const segments: OutboundSegment[] = [];
  for (const part of parts) {
    if (!part) continue;
    const match = PLACEHOLDER_KIND_RE.exec(part);
    if (match) {
      const kind = match[1];
      segments.push({
        type: "placeholder",
        value: part,
        kind,
        friendlyKind: friendlyRedactionLabel(kind),
      });
    } else {
      segments.push({
        type: "text",
        value: part,
      });
    }
  }
  return segments;
}

export function runLandingPromptPreview(inputText: string): LandingPromptPreview {
  const prepared = preparePrompt(inputText);
  const segments = tokenizeOutboundText(prepared.outboundText);
  const hiddenItems = prepared.report.redactions.map((r) => ({
    placeholder: r.placeholder,
    kind: r.kind,
    friendlyKind: friendlyRedactionLabel(r.kind),
  }));

  let simulatedModelRawReply: string;
  if (hiddenItems.length > 0) {
    const placeholdersList = hiddenItems.map((h) => h.placeholder).join(" and ");
    simulatedModelRawReply = `I prepared your draft using ${placeholdersList}. Your real details never left your browser.`;
  } else {
    simulatedModelRawReply =
      "Type a fake email address or phone number above to watch it get replaced with a safe placeholder.";
  }

  const restoredModelReply =
    hiddenItems.length > 0
      ? prepared.restore(simulatedModelRawReply)
      : simulatedModelRawReply;

  return {
    inputText,
    outboundText: prepared.outboundText,
    segments,
    hiddenCount: hiddenItems.length,
    hiddenItems,
    uniformSizeChars: prepared.bucketBytes,
    simulatedModelRawReply,
    restoredModelReply,
    rawPrepared: prepared,
  };
}
