import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { pathToFileURL } from "node:url";
import { MongoClient } from "mongodb";
import {
  configureAttestation,
  getAttestation,
  validateLauncherJwtClaims,
} from "./attestation-gcp.js";
import { ATLAS_DATABASE_NAME, getWholeKnowledgeCorpus } from "./corpus.js";
import {
  ContentFreeEgressError,
  PlannerBudgetExceededError,
  PrivacyInvariantViolationError,
  TaskDescriptorValidationError,
  ToolPolicyViolationError,
} from "./firewall.js";
import {
  computePublicKeysBindingSha256,
  getKeyRing,
  getPublicKeysResponse,
} from "./keys.js";
import { planWithGemini } from "./planner.js";
import {
  TreeHeadStateVerificationError,
  verifyAndSignTreeHead,
} from "./receipts.js";
import {
  getLoadedSecret,
  loadSecrets,
  resolveSecretsSource,
} from "./secrets-gcp.js";
import {
  getBootTlsMaterial,
  privateKey as bootTlsPrivateKey,
  tlsCertPem as bootTlsCertPem,
  tlsSpkiSha256 as bootTlsSpkiSha256,
  validateTlsCertAndKeyMatch,
} from "./tls.js";

export const ALLOWED_CORS_ORIGINS = new Set([
  "https://drouter-demo.vercel.app",
  "http://localhost:3000",
]);

export const MAX_BODY_BYTES = 16_384;
export const DEFAULT_BOOT_HTTPS_PORT = 8443;
export const DEFAULT_TINFOIL_HTTP_PORT = 8080;

function isAllowedCorsOrigin(cleanOrigin) {
  if (ALLOWED_CORS_ORIGINS.has(cleanOrigin)) {
    return true;
  }
  const configuredOrigin =
    typeof process.env.CORE_PUBLIC_ORIGIN === "string"
      ? process.env.CORE_PUBLIC_ORIGIN.trim()
      : "";
  if (configuredOrigin && cleanOrigin === configuredOrigin) {
    return true;
  }
  return false;
}

function buildCorsHeaders(originHeader) {
  if (!originHeader) {
    return { allowed: true, headers: {} };
  }
  const cleanOrigin = String(originHeader).trim();
  if (!isAllowedCorsOrigin(cleanOrigin)) {
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

function resolveDefaultOperatorSecret(explicitSecretsSource) {
  const loaded = getLoadedSecret("CORE_OPERATOR_TOKEN");
  if (loaded) {
    return loaded;
  }
  const source = resolveSecretsSource(
    explicitSecretsSource !== undefined ? explicitSecretsSource : process.env.CORE_SECRETS_SOURCE,
  );
  if (source === "gcp-secret-manager") {
    return undefined;
  }
  return process.env.CORE_OPERATOR_TOKEN;
}

/**
 * Constant-time Bearer token check against `CORE_OPERATOR_TOKEN`.
 * Always fails closed when `CORE_OPERATOR_TOKEN` is unset or empty, and never falls back
 * to `process.env` when `CORE_SECRETS_SOURCE=gcp-secret-manager`.
 */
export function verifyOperatorBearer(
  req,
  expectedSecret = resolveDefaultOperatorSecret(),
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
  "/attestation",
  "/health",
  "/knowledge/corpus",
  "/agent/plan",
  "/transparency/sign-tree-head",
  "/keys",
]);

function verifyAttestationMatchesServerState(att, {
  expectedEgress,
  expectedTree,
  expectedKeysDigest,
  expectedTlsSpkiSha256,
  expectedTlsCertPem,
  nowSec,
}) {
  const token = typeof att?.token === "string" ? att.token.trim() : "";
  const egress = typeof att?.keys?.egress === "string" ? att.keys.egress.trim() : "";
  const tree = typeof att?.keys?.tree === "string" ? att.keys.tree.trim() : "";
  const keysDigest = typeof att?.keysDigest === "string" ? att.keysDigest.trim() : "";
  const tlsSpkiSha256 =
    typeof att?.tlsSpkiSha256 === "string" ? att.tlsSpkiSha256.trim() : "";
  const tlsCertPem = typeof att?.tlsCertPem === "string" ? att.tlsCertPem.trim() : "";
  const refreshedAtSec =
    typeof att?.refreshedAtSec === "number" && Number.isFinite(att.refreshedAtSec)
      ? Math.floor(att.refreshedAtSec)
      : null;
  const expiresAtSec =
    typeof att?.expiresAtSec === "number" && Number.isFinite(att.expiresAtSec)
      ? Math.floor(att.expiresAtSec)
      : null;

  if (
    !token ||
    token.split(".").length !== 3 ||
    !egress ||
    !tree ||
    !keysDigest ||
    !tlsSpkiSha256 ||
    !tlsCertPem ||
    refreshedAtSec === null ||
    expiresAtSec === null ||
    expiresAtSec <= nowSec ||
    egress !== expectedEgress ||
    tree !== expectedTree ||
    keysDigest !== expectedKeysDigest ||
    tlsSpkiSha256 !== expectedTlsSpkiSha256 ||
    tlsCertPem !== expectedTlsCertPem
  ) {
    return null;
  }

  const { expiresAtSec: jwtExpSec } = validateLauncherJwtClaims(
    token,
    [expectedKeysDigest, expectedTlsSpkiSha256],
    nowSec,
  );
  if (jwtExpSec <= nowSec) {
    return null;
  }

  return {
    token,
    keys: {
      egress,
      tree,
    },
    keysDigest,
    tlsSpkiSha256,
    tlsCertPem,
    refreshedAtSec,
    expiresAtSec,
  };
}

let inMemoryMongoClientPromise = null;
let inMemoryMongoUri = null;

async function resolveDatabaseDep(explicitDb, explicitMongodbUri, explicitSecretsSource) {
  if (explicitDb !== undefined) {
    return explicitDb;
  }
  const source = resolveSecretsSource(
    explicitSecretsSource !== undefined ? explicitSecretsSource : process.env.CORE_SECRETS_SOURCE,
  );
  const secretUri =
    explicitMongodbUri !== undefined
      ? explicitMongodbUri
      : getLoadedSecret("MONGODB_URI") ??
        (source === "gcp-secret-manager" ? undefined : process.env.MONGODB_URI);
  if (!secretUri) {
    return undefined;
  }
  try {
    if (!inMemoryMongoClientPromise || inMemoryMongoUri !== secretUri) {
      inMemoryMongoUri = secretUri;
      const client = new MongoClient(secretUri, {
        appName: "deroute-core-enclave",
        maxPoolSize: 4,
        serverSelectionTimeoutMS: 4500,
      });
      inMemoryMongoClientPromise = client.connect();
    }
    const connected = await inMemoryMongoClientPromise;
    return connected.db(process.env.MONGODB_DB || ATLAS_DATABASE_NAME);
  } catch {
    inMemoryMongoClientPromise = null;
    return null;
  }
}

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

  if (pathname === "/attestation") {
    if (method !== "GET") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" }, cors.headers);
      return;
    }
    if (parsedUrl.search.length > 0) {
      sendJson(res, 400, { ok: false, error: "query_parameters_forbidden" }, cors.headers);
      return;
    }

    const effectiveKeySource = keyRing.keySource ?? keyRing["egress-signing"]?.keySource;
    if (effectiveKeySource !== "boot") {
      sendJson(
        res,
        503,
        {
          ok: false,
          error: "attestation_unavailable",
          message:
            "Confidential Space attestation token is only served in CORE_KEY_SOURCE=boot mode.",
        },
        cors.headers,
      );
      return;
    }

    const nowSec =
      typeof deps.nowSec === "function" ? deps.nowSec() : Math.floor(Date.now() / 1000);
    const expectedEgress = keyRing["egress-signing"].publicKeyHex;
    const expectedTree = keyRing["tree-signing"].publicKeyHex;
    const expectedKeysDigest = computePublicKeysBindingSha256(keyRing);
    const expectedTlsSpkiSha256 = (deps.tlsSpkiSha256 ?? bootTlsSpkiSha256).trim();
    const expectedTlsCertPem = (deps.tlsCertPem ?? bootTlsCertPem).trim();

    const triggerBackgroundRefresh = () => {
      try {
        if (typeof deps.refreshAttestation === "function") {
          Promise.resolve(deps.refreshAttestation()).catch(() => {});
        } else if (deps.attestationManager && typeof deps.attestationManager.refresh === "function") {
          Promise.resolve(deps.attestationManager.refresh()).catch(() => {});
        } else if (typeof deps.getAttestation === "function") {
          Promise.resolve(deps.getAttestation({ forceRefresh: true })).catch(() => {});
        } else {
          Promise.resolve(
            getAttestation({
              keyRing,
              tlsCertPem: expectedTlsCertPem,
              tlsSpkiSha256: expectedTlsSpkiSha256,
              forceRefresh: true,
            }),
          ).catch(() => {});
        }
      } catch {
        // Ignore synchronous errors from background refresh trigger
      }
    };

    try {
      const att = await (typeof deps.getAttestation === "function"
        ? deps.getAttestation()
        : deps.attestationManager && typeof deps.attestationManager.getAttestation === "function"
          ? deps.attestationManager.getAttestation()
          : getAttestation({
              keyRing,
              tlsCertPem: expectedTlsCertPem,
              tlsSpkiSha256: expectedTlsSpkiSha256,
            }));

      let verified = null;
      try {
        verified = verifyAttestationMatchesServerState(att, {
          expectedEgress,
          expectedTree,
          expectedKeysDigest,
          expectedTlsSpkiSha256,
          expectedTlsCertPem,
          nowSec,
        });
      } catch {
        verified = null;
      }

      if (!verified) {
        triggerBackgroundRefresh();
        sendJson(
          res,
          503,
          {
            ok: false,
            error: "attestation_unavailable",
            message:
              "Confidential Space attestation token is missing, expired, or does not match current keys and TLS certificate.",
          },
          cors.headers,
        );
        return;
      }

      sendJson(res, 200, verified, cors.headers);
      return;
    } catch {
      triggerBackgroundRefresh();
      sendJson(
        res,
        503,
        {
          ok: false,
          error: "attestation_unavailable",
          message:
            "Confidential Space attestation token is missing, expired, or unavailable.",
        },
        cors.headers,
      );
      return;
    }
  }

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
    sendJson(
      res,
      200,
      getPublicKeysResponse(keyRing, {
        tlsSpkiSha256: deps.tlsSpkiSha256 ?? bootTlsSpkiSha256,
      }),
      cors.headers,
    );
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
    const db = await resolveDatabaseDep(deps.db, deps.mongodbUri, deps.secretsSource);
    const corpus = await getWholeKnowledgeCorpus({ db });
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

    const effectiveGeminiKey =
      deps.geminiApiKey !== undefined ? deps.geminiApiKey : getLoadedSecret("GEMINI_API_KEY");

    try {
      const result = await planWithGemini({
        descriptor: body,
        apiKey: effectiveGeminiKey,
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
        : resolveDefaultOperatorSecret(deps.secretsSource);
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
      const db = await resolveDatabaseDep(deps.db, deps.mongodbUri, deps.secretsSource);
      const signed = await verifyAndSignTreeHead(body, {
        keyPair: keyRing["tree-signing"],
        db,
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

function applyServerHardeningTimeouts(srv) {
  srv.headersTimeout = 10_000;
  srv.requestTimeout = 25_000;
  srv.keepAliveTimeout = 5_000;
  srv.timeout = 30_000;
}

export function resolveServerPort(keySource, explicitPort = process.env.PORT) {
  if (explicitPort !== undefined && String(explicitPort).trim() !== "") {
    const parsed = Number(explicitPort);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
      return parsed;
    }
  }
  return keySource === "boot" ? DEFAULT_BOOT_HTTPS_PORT : DEFAULT_TINFOIL_HTTP_PORT;
}

export function createCoreServer(deps = {}) {
  // Eagerly validate CORE_SECRETS_SOURCE and CORE_KEY_SOURCE at creation so unknown values refuse to start.
  resolveSecretsSource(
    deps.secretsSource !== undefined ? deps.secretsSource : process.env.CORE_SECRETS_SOURCE,
  );
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

  const requestHandler = (req, res) => {
    handleCoreRequest(req, res, serverDeps).catch(() => {
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: "internal_error" });
      } else {
        res.end();
      }
    });
  };

  if (resolvedKeyRing.keySource === "boot") {
    const tlsMaterial = deps.tlsMaterial ?? getBootTlsMaterial();
    const rawCertPem = deps.tlsCertPem ?? tlsMaterial.tlsCertPem ?? bootTlsCertPem;
    const rawKeyPem = deps.tlsPrivateKey ?? tlsMaterial.privateKey ?? bootTlsPrivateKey;
    const validatedTls = validateTlsCertAndKeyMatch(
      rawCertPem,
      rawKeyPem,
      deps.tlsSpkiSha256,
    );
    const certPem = validatedTls.tlsCertPem;
    const keyPem = validatedTls.tlsPrivateKey;
    const spkiSha256 = validatedTls.tlsSpkiSha256;

    const attestationManager = configureAttestation({
      keyRing: resolvedKeyRing,
      tlsCertPem: certPem,
      tlsSpkiSha256: spkiSha256,
      ...(deps.socketPath ? { socketPath: deps.socketPath } : {}),
      ...(deps.audience ? { audience: deps.audience } : {}),
      ...(deps.refreshIntervalMs !== undefined
        ? { refreshIntervalMs: deps.refreshIntervalMs }
        : {}),
      ...(deps.nowSec ? { nowSec: deps.nowSec } : {}),
    });

    serverDeps.tlsCertPem = certPem;
    serverDeps.tlsSpkiSha256 = spkiSha256;
    serverDeps.attestationManager = attestationManager;

    const httpsServer = https.createServer(
      {
        key: keyPem,
        cert: certPem,
      },
      requestHandler,
    );
    applyServerHardeningTimeouts(httpsServer);
    httpsServer.tlsSpkiSha256 = spkiSha256;
    httpsServer.tlsCertPem = certPem;
    httpsServer.keySource = "boot";
    httpsServer.defaultPort = DEFAULT_BOOT_HTTPS_PORT;
    httpsServer.attestationManager = attestationManager;

    const origClose = httpsServer.close.bind(httpsServer);
    httpsServer.close = (cb) => {
      attestationManager.stop();
      return origClose(cb);
    };

    return httpsServer;
  }

  // CORE_KEY_SOURCE=tinfoil: plain HTTP server on 8080 behind Tinfoil enclave proxy shim
  const httpServer = http.createServer(requestHandler);
  applyServerHardeningTimeouts(httpServer);
  httpServer.keySource = "tinfoil";
  httpServer.defaultPort = DEFAULT_TINFOIL_HTTP_PORT;

  return httpServer;
}

/**
 * Loads secrets through `secrets-gcp.js` before creating and starting the server.
 * With `CORE_KEY_SOURCE=boot`, serves HTTPS on `0.0.0.0:8443` using the boot certificate.
 * With `CORE_KEY_SOURCE=tinfoil`, serves HTTP on `0.0.0.0:8080`.
 */
export async function startCoreServer(options = {}) {
  const secretsSource = resolveSecretsSource(
    options.secretsSource !== undefined ? options.secretsSource : process.env.CORE_SECRETS_SOURCE,
  );
  const loadedSecrets = await loadSecrets({
    source: secretsSource,
    allowPartialEnv: options.allowPartialEnv ?? false,
    ...(options.secretsOptions ?? {}),
  });

  const resolvedKeyRing =
    options.keyRing ??
    getKeyRing({
      keySource: options.keySource,
      keysDir: options.keysDir,
    });

  const host = options.host || process.env.HOST || "0.0.0.0";
  const port = resolveServerPort(
    resolvedKeyRing.keySource,
    options.port !== undefined ? options.port : process.env.PORT,
  );

  const server = createCoreServer({
    ...options,
    keyRing: resolvedKeyRing,
    secretsSource,
    mongodbUri: options.mongodbUri ?? loadedSecrets.MONGODB_URI,
    geminiApiKey: options.geminiApiKey ?? loadedSecrets.GEMINI_API_KEY,
    operatorToken: options.operatorToken ?? loadedSecrets.CORE_OPERATOR_TOKEN,
  });

  if (resolvedKeyRing.keySource === "boot") {
    const nowSec =
      typeof options.nowSec === "function" ? options.nowSec() : Math.floor(Date.now() / 1000);
    const expectedEgress = resolvedKeyRing["egress-signing"].publicKeyHex;
    const expectedTree = resolvedKeyRing["tree-signing"].publicKeyHex;
    const expectedKeysDigest = computePublicKeysBindingSha256(resolvedKeyRing);
    const expectedTlsSpkiSha256 = server.tlsSpkiSha256;
    const expectedTlsCertPem = server.tlsCertPem;

    try {
      const initialAtt = await (typeof options.getAttestation === "function"
        ? options.getAttestation()
        : server.attestationManager.getAttestation());

      const verified = verifyAttestationMatchesServerState(initialAtt, {
        expectedEgress,
        expectedTree,
        expectedKeysDigest,
        expectedTlsSpkiSha256,
        expectedTlsCertPem,
        nowSec,
      });

      if (!verified) {
        throw new Error(
          "Initial Confidential Space attestation token does not match server keys or TLS certificate.",
        );
      }
    } catch (err) {
      server.attestationManager?.stop?.();
      throw err;
    }
  }

  await new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener("listening", onListening);
      reject(err);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startCoreServer()
    .then((server) => {
      const addr = server.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : server.defaultPort;
      const host = process.env.HOST || "0.0.0.0";
      process.stdout.write(
        JSON.stringify({
          service: "deroute-core",
          status: "listening",
          protocol: server.keySource === "boot" ? "https" : "http",
          host,
          port: boundPort,
        }) + "\n",
      );

      const shutdown = () => {
        server.close(() => {
          process.exit(0);
        });
      };
      process.on("SIGTERM", shutdown);
      process.on("SIGINT", shutdown);
    })
    .catch((err) => {
      process.stderr.write(
        JSON.stringify({
          service: "deroute-core",
          status: "fatal",
          error: err instanceof Error ? err.message : "Failed to start deroute-core",
        }) + "\n",
      );
      process.exit(1);
    });
}
