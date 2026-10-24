import crypto from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { getWholeKnowledgeCorpus } from "./corpus.js";
import {
  ContentFreeEgressError,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  TaskDescriptorValidationError,
  ToolPolicyViolationError,
} from "./firewall.js";
import { getKeyRing, getPublicKeysResponse } from "./keys.js";
import { planWithGemini } from "./planner.js";
import {
  TreeHeadStateVerificationError,
  verifyAndSignTreeHead,
} from "./receipts.js";

export const ALLOWED_CORS_ORIGINS = new Set([
  "https://drouter-demo.vercel.app",
  "http://localhost:3000",
]);

export const MAX_BODY_BYTES = 16_384;

function buildCorsHeaders(originHeader) {
  if (!originHeader) {
    return { allowed: true, headers: {} };
  }
  const cleanOrigin = String(originHeader).trim();
  if (!ALLOWED_CORS_ORIGINS.has(cleanOrigin)) {
    return { allowed: false, headers: { Vary: "Origin" } };
  }
  return {
    allowed: true,
    headers: {
      "Access-Control-Allow-Origin": cleanOrigin,
      Vary: "Origin",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    },
  };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body, "utf8"),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

class PayloadTooLargeError extends Error {
  constructor(limitBytes) {
    super(`Request body exceeds maximum allowed size of ${limitBytes} bytes.`);
    this.name = "PayloadTooLargeError";
  }
}

/**
 * Scans a syntactically valid RFC 8259 JSON string and throws `SyntaxError`
 * if any JSON object contains duplicate keys (including Unicode-escaped equivalents).
 */
export function assertNoDuplicateJsonKeys(jsonText) {
  const stack = [];
  let i = 0;
  const len = jsonText.length;

  while (i < len) {
    const ch = jsonText[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    if (ch === "{") {
      stack.push({ type: "object", keys: new Set() });
      i += 1;
      continue;
    }
    if (ch === "[") {
      stack.push({ type: "array" });
      i += 1;
      continue;
    }
    if (ch === "}" || ch === "]") {
      stack.pop();
      i += 1;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i += 1;
      while (i < len) {
        const c = jsonText[i];
        if (c === "\\") {
          i += 2;
          continue;
        }
        if (c === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      const rawStringLiteral = jsonText.slice(start, i);
      let j = i;
      while (
        j < len &&
        (jsonText[j] === " " ||
          jsonText[j] === "\t" ||
          jsonText[j] === "\n" ||
          jsonText[j] === "\r")
      ) {
        j += 1;
      }
      const top = stack[stack.length - 1];
      if (top && top.type === "object" && jsonText[j] === ":") {
        const decodedKey = JSON.parse(rawStringLiteral);
        if (top.keys.has(decodedKey)) {
          throw new SyntaxError(`Duplicate JSON object key: ${decodedKey}`);
        }
        top.keys.add(decodedKey);
      }
      continue;
    }
    i += 1;
  }
}

function readBoundedJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const contentLengthHeader = req.headers["content-length"];
    if (contentLengthHeader !== undefined) {
      const declaredLen = Number(contentLengthHeader);
      if (!Number.isFinite(declaredLen) || declaredLen < 0 || declaredLen > maxBytes) {
        req.pause?.();
        reject(new PayloadTooLargeError(maxBytes));
        return;
      }
    }

    const chunks = [];
    let totalBytes = 0;
    let aborted = false;

    req.on("data", (chunk) => {
      if (aborted) return;
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        aborted = true;
        req.pause?.();
        reject(new PayloadTooLargeError(maxBytes));
        return;
      }
      chunks.push(chunk);
    });

    req.on("error", (err) => {
      if (!aborted) {
        aborted = true;
        reject(err);
      }
    });

    req.on("end", () => {
      if (aborted) return;
      if (totalBytes === 0) {
        reject(new SyntaxError("Empty JSON request body."));
        return;
      }
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        const parsed = JSON.parse(text);
        assertNoDuplicateJsonKeys(text);
        resolve(parsed);
      } catch {
        reject(new SyntaxError("Malformed JSON request body."));
      }
    });
  });
}

/**
 * Constant-time Bearer token check against `CORE_OPERATOR_TOKEN`.
 * Always fails closed when `CORE_OPERATOR_TOKEN` is unset or empty.
 */
export function verifyOperatorBearer(
  req,
  expectedSecret = process.env.CORE_OPERATOR_TOKEN,
) {
  if (typeof expectedSecret !== "string" || expectedSecret.length === 0) {
    return false;
  }
  const auth =
    typeof req?.headers?.authorization === "string"
      ? req.headers.authorization
      : "";
  if (!auth.startsWith("Bearer ")) {
    return false;
  }
  const candidate = auth.slice(7);
  if (candidate.length === 0) {
    return false;
  }
  const candDigest = crypto.createHash("sha256").update(candidate, "utf8").digest();
  const expDigest = crypto.createHash("sha256").update(expectedSecret, "utf8").digest();
  const digestsMatch = crypto.timingSafeEqual(candDigest, expDigest);
  return digestsMatch && candidate.length === expectedSecret.length;
}

const ALLOWED_PATHS = new Set([
  "/health",
  "/knowledge/corpus",
  "/agent/plan",
  "/transparency/sign-tree-head",
  "/keys",
]);

/**
 * Stateless request handler for `deroute-core`.
 * Never logs request bodies, headers, or caller IP addresses.
 */
export async function handleCoreRequest(req, res, deps = {}) {
  const originHeader = req.headers?.origin;
  const cors = buildCorsHeaders(originHeader);

  if (!cors.allowed) {
    sendJson(
      res,
      403,
      {
        ok: false,
        error: "origin_not_allowed",
        message: "Origin is not in the deroute-core CORS allowlist.",
      },
      cors.headers,
    );
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(req.url || "/", "http://localhost:8080");
  } catch {
    sendJson(res, 400, { ok: false, error: "invalid_url" }, cors.headers);
    return;
  }

  const pathname = parsedUrl.pathname;
  const method = (req.method || "GET").toUpperCase();

  if (method === "OPTIONS") {
    if (!ALLOWED_PATHS.has(pathname)) {
      sendJson(res, 404, { ok: false, error: "not_found" }, cors.headers);
      return;
    }
    res.writeHead(204, {
      "X-Content-Type-Options": "nosniff",
      ...cors.headers,
    });
    res.end();
    return;
  }

  if (!ALLOWED_PATHS.has(pathname)) {
    sendJson(res, 404, { ok: false, error: "not_found" }, cors.headers);
    return;
  }

  const keyRing =
    deps.keyRing ??
    getKeyRing({
      keySource: deps.keySource,
      keysDir: deps.keysDir,
    });

  if (pathname === "/health") {
    if (method !== "GET") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(res, 400, { ok: false, error: "query_parameters_forbidden" }, cors.headers);
      return;
    }
    sendJson(
      res,
      200,
      {
        ok: true,
        service: "deroute-core",
        version: "1.0.0",
        keySource: keyRing.keySource ?? keyRing["egress-signing"].keySource,
        enclaveKeys: {
          egressSigning: keyRing["egress-signing"].source,
          treeSigning: keyRing["tree-signing"].source,
        },
      },
      cors.headers,
    );
    return;
  }

  if (pathname === "/keys") {
    if (method !== "GET") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(res, 400, { ok: false, error: "query_parameters_forbidden" }, cors.headers);
      return;
    }
    sendJson(res, 200, getPublicKeysResponse(keyRing), cors.headers);
    return;
  }

  if (pathname === "/knowledge/corpus") {
    if (method !== "GET") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(
        res,
        400,
        {
          ok: false,
          error: "query_parameters_forbidden",
          message:
            "Whole-library retrieval accepts no query parameters so every caller receives the identical corpus.",
        },
        cors.headers,
      );
      return;
    }
    const corpus = await getWholeKnowledgeCorpus({ db: deps.db });
    sendJson(res, 200, corpus, {
      ...cors.headers,
      "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
    });
    return;
  }

  if (pathname === "/agent/plan") {
    if (method !== "POST") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(res, 400, { ok: false, error: "query_parameters_forbidden" }, cors.headers);
      return;
    }
    let body;
    try {
      body = await readBoundedJsonBody(req);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        res.once("finish", () => req.destroy());
        sendJson(
          res,
          413,
          { ok: false, error: "payload_too_large", message: err.message },
          { ...cors.headers, Connection: "close" },
        );
        return;
      }
      sendJson(
        res,
        400,
        { ok: false, error: "invalid_json", message: "Request body must be valid JSON." },
        cors.headers,
      );
      return;
    }

    try {
      const result = await planWithGemini({
        descriptor: body,
        apiKey: deps.geminiApiKey,
        genaiClient: deps.genaiClient,
        egressKeyPair: keyRing["egress-signing"],
        timestampSec: deps.timestampSec,
      });
      const { statusCode = 200, ...responseBody } = result;
      sendJson(res, statusCode, responseBody, cors.headers);
      return;
    } catch (err) {
      if (err instanceof TaskDescriptorValidationError) {
        sendJson(
          res,
          400,
          {
            ok: false,
            error: "invalid_task_descriptor",
            message: err.message,
            details: err.errors,
          },
          cors.headers,
        );
        return;
      }
      if (
        err instanceof ContentFreeEgressError ||
        err instanceof PrivacyInvariantViolationError
      ) {
        sendJson(
          res,
          400,
          {
            ok: false,
            error: "content_free_violation",
            message: err.message,
          },
          cors.headers,
        );
        return;
      }
      if (err instanceof ToolPolicyViolationError) {
        sendJson(
          res,
          422,
          {
            ok: false,
            error: "tool_policy_violation",
            toolName: err.toolName,
            message: err.message,
            details: err.validationErrors,
          },
          cors.headers,
        );
        return;
      }
      if (err instanceof PlannerBudgetExceededError) {
        sendJson(
          res,
          504,
          {
            ok: false,
            error: "planner_budget_exceeded",
            kind: err.kind,
            message: err.message,
          },
          cors.headers,
        );
        return;
      }
      sendJson(
        res,
        500,
        {
          ok: false,
          error: "internal_error",
          message: "Failed to process planning request.",
        },
        cors.headers,
      );
      return;
    }
  }

  if (pathname === "/transparency/sign-tree-head") {
    if (method !== "POST") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(res, 400, { ok: false, error: "query_parameters_forbidden" }, cors.headers);
      return;
    }
    const expectedToken =
      deps.operatorToken !== undefined
        ? deps.operatorToken
        : process.env.CORE_OPERATOR_TOKEN;
    if (!verifyOperatorBearer(req, expectedToken)) {
      sendJson(
        res,
        401,
        {
          ok: false,
          error: "unauthorized",
          message: "Valid CORE_OPERATOR_TOKEN Bearer authentication is required.",
        },
        cors.headers,
      );
      return;
    }

    let body;
    try {
      body = await readBoundedJsonBody(req);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        res.once("finish", () => req.destroy());
        sendJson(
          res,
          413,
          { ok: false, error: "payload_too_large", message: err.message },
          { ...cors.headers, Connection: "close" },
        );
        return;
      }
      sendJson(
        res,
        400,
        { ok: false, error: "invalid_json", message: "Request body must be valid JSON." },
        cors.headers,
      );
      return;
    }

    try {
      const signed = await verifyAndSignTreeHead(body, {
        keyPair: keyRing["tree-signing"],
        db: deps.db,
      });
      sendJson(
        res,
        200,
        {
          ok: true,
          sth: {
            treeSize: signed.treeSize,
            rootHash: signed.rootHash,
            timestampSec: signed.timestampSec,
            operatorPublicKey: signed.operatorPublicKey,
            signature: signed.signature,
            anchorTx: signed.anchorTx,
            anchoredAtSec: signed.anchoredAtSec,
          },
          ...signed,
        },
        cors.headers,
      );
      return;
    } catch (err) {
      if (err && err.name === "TreeHeadValidationError") {
        sendJson(
          res,
          400,
          {
            ok: false,
            error: "invalid_tree_head",
            message: err.message,
            details: err.errors ?? [],
          },
          cors.headers,
        );
        return;
      }
      if (err instanceof TreeHeadStateVerificationError) {
        sendJson(
          res,
          422,
          {
            ok: false,
            error: "tree_head_state_mismatch",
            message: err.message,
          },
          cors.headers,
        );
        return;
      }
      sendJson(
        res,
        500,
        {
          ok: false,
          error: "internal_error",
          message: "Failed to sign tree head.",
        },
        cors.headers,
      );
      return;
    }
  }
}

export function createCoreServer(deps = {}) {
  // Eagerly resolve keyRing at boot/creation so missing or unknown CORE_KEY_SOURCE refuses to start.
  const resolvedKeyRing =
    deps.keyRing ??
    getKeyRing({
      keySource: deps.keySource,
      keysDir: deps.keysDir,
    });
  const serverDeps = {
    ...deps,
    keyRing: resolvedKeyRing,
  };

  const server = http.createServer((req, res) => {
    handleCoreRequest(req, res, serverDeps).catch(() => {
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: "internal_error" });
      } else {
        res.end();
      }
    });
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 25_000;
  server.keepAliveTimeout = 5_000;
  server.timeout = 30_000;

  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.HOST || "0.0.0.0";
  const server = createCoreServer();
  server.listen(port, host, () => {
    process.stdout.write(
      JSON.stringify({
        service: "deroute-core",
        status: "listening",
        host,
        port,
      }) + "\n",
    );
  });

  const shutdown = () => {
    server.close(() => {
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
