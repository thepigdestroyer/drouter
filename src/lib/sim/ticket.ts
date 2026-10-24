import { gcm } from "@noble/ciphers/aes.js";
import { concat, fromHex, toHex, utf8 } from "./bytes";
import { TICKET_IDLE_MS } from "./constants";
import { SimError } from "./errors";
import { ticketKey } from "./hardware";

/**
 * Sealed session tickets.
 *
 * A real enclave node keeps session keys, counters and context in GPU/CPU memory that never leaves
 * the confidential VM. These simulated routes run on stateless serverless functions, so the node
 * instead encrypts that state to itself (AES-256-GCM under a per-node ticket key) and hands the
 * opaque ticket to the client to send back on the next request. The client cannot read or forge it.
 * Tickets exist only because the routes are stateless; they are not part of the dRouter protocol.
 */

export interface PendingTicketBody {
  kind: "pending";
  simId: string;
  clientNonce: string;
  modelId: string;
  /** canonical(hello) ‖ canonical(evidence) as text, completed with the client key share later. */
  transcriptPrefix: string;
  custodyX25519Sk: string;
  custodyMlkemSk: string;
}

export interface SessionTicketBody {
  kind: "session";
  simId: string;
  kUp: string;
  kDown: string;
  sessionId: string;
  /** Lowest acceptable counter for the next upstream message. */
  upNext: number;
  /** Next downstream counter the node will use. */
  downNext: number;
  /** Index the next user turn must carry (turn 0 is the session params). */
  nextTurn: number;
  /** Session context tokens (UTF-8 bytes), hex. */
  context: string;
}

export type TicketBody = PendingTicketBody | SessionTicketBody;
type Stored<T> = T & { expires: number };

const NONCE_BYTES = 12;

function aad(simId: string): Uint8Array {
  return utf8(`drouter/v1/ticket/${simId}`);
}

export function sealTicket(body: TicketBody, now: number): string {
  const stored: Stored<TicketBody> = { ...body, expires: now + TICKET_IDLE_MS };
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ct = gcm(ticketKey(body.simId), nonce, aad(body.simId)).encrypt(utf8(JSON.stringify(stored)));
  return toHex(concat(nonce, ct));
}

export function openTicket<K extends TicketBody["kind"]>(
  simId: string,
  ticket: string,
  kind: K,
  now: number,
): Extract<TicketBody, { kind: K }> {
  let stored: Stored<TicketBody>;
  try {
    const raw = fromHex(ticket);
    if (raw.length < NONCE_BYTES + 16) throw new Error("short");
    const plain = gcm(ticketKey(simId), raw.subarray(0, NONCE_BYTES), aad(simId)).decrypt(raw.subarray(NONCE_BYTES));
    stored = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new SimError(401, "invalid ticket");
  }
  if (stored.simId !== simId || stored.kind !== kind) throw new SimError(401, "invalid ticket");
  if (typeof stored.expires !== "number" || stored.expires < now) throw new SimError(401, "ticket expired");
  return stored as unknown as Extract<TicketBody, { kind: K }>;
}
