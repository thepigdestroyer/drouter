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
import { signTreeHeadWithAttestedKey } from "./receipts.js";

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

function readBoundedJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const contentLengthHeader = req.headers["content-length"];
    if (contentLengthHeader !== undefined) {
      const declaredLen = Number(contentLengthHeader);
      if (!Number.isFinite(declaredLen) || declaredLen > maxBytes) {
        req.resume();
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
        req.resume();
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
        resolve(parsed);
      } catch {
        reject(new SyntaxError("Malformed JSON request body."));
      }
    });
  });
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

  const keyRing = deps.keyRing ?? getKeyRing();

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
        sendJson(
          res,
          413,
          { ok: false, error: "payload_too_large", message: err.message },
          cors.headers,
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
    let body;
    try {
      body = await readBoundedJsonBody(req);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        sendJson(
          res,
          413,
          { ok: false, error: "payload_too_large", message: err.message },
          cors.headers,
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
      const signed = signTreeHeadWithAttestedKey(body, keyRing["tree-signing"]);
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
  return http.createServer((req, res) => {
    handleCoreRequest(req, res, deps).catch(() => {
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: "internal_error" });
      } else {
        res.end();
      }
    });
  });
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
