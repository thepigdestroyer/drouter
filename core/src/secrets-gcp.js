import util from "node:util";

export const DEFAULT_GCP_METADATA_BASE_URL = "http://metadata.google.internal";
export const DEFAULT_SECRET_MANAGER_BASE_URL = "https://secretmanager.googleapis.com";
export const SECRETS_REQUEST_TIMEOUT_MS = 10_000;

export const VALID_SECRETS_SOURCES = ["env", "gcp-secret-manager"];

export const SECRET_DEFINITIONS = Object.freeze([
  Object.freeze({
    envKey: "MONGODB_URI",
    secretName: "MONGODB_URI",
  }),
  Object.freeze({
    envKey: "GEMINI_API_KEY",
    secretName: "GEMINI_API_KEY",
  }),
  Object.freeze({
    envKey: "CORE_OPERATOR_TOKEN",
    secretName: "CORE_OPERATOR_TOKEN",
  }),
]);

/**
 * Resolves `CORE_SECRETS_SOURCE`:
 * - Defaults to `"env"` when unset or empty (for Tinfoil compatibility).
 * - Accepts `"env"` or `"gcp-secret-manager"`.
 * - Throws and refuses to start on any unknown value.
 */
export function resolveSecretsSource(explicitSource = process.env.CORE_SECRETS_SOURCE) {
  if (explicitSource === undefined || explicitSource === null) {
    return "env";
  }
  const trimmed = typeof explicitSource === "string" ? explicitSource.trim() : String(explicitSource);
  if (trimmed === "") {
    return "env";
  }
  if (trimmed !== "env" && trimmed !== "gcp-secret-manager") {
    throw new Error(
      `Invalid CORE_SECRETS_SOURCE '${trimmed}': must be 'env' or 'gcp-secret-manager'.`,
    );
  }
  return trimmed;
}

function normalizeBaseUrl(rawUrl, label) {
  if (typeof rawUrl !== "string" || rawUrl.trim().length === 0) {
    throw new Error(`Invalid ${label}: must be a non-empty URL string.`);
  }
  const clean = rawUrl.trim().replace(/\/+$/, "");
  let parsed;
  try {
    parsed = new URL(clean);
  } catch {
    throw new Error(`Invalid ${label}: malformed URL.`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Invalid ${label}: unsupported protocol '${parsed.protocol}'.`);
  }
  return clean;
}

function resolveInjectableBaseUrls(options = {}) {
  const hasCustomMetadata = options.metadataBaseUrl !== undefined;
  const hasCustomSecretManager = options.secretManagerBaseUrl !== undefined;

  if ((hasCustomMetadata || hasCustomSecretManager) && process.env.NODE_ENV === "production") {
    throw new Error(
      "Custom metadataBaseUrl and secretManagerBaseUrl overrides are only permitted in tests.",
    );
  }

  const metadataBaseUrl = hasCustomMetadata
    ? normalizeBaseUrl(options.metadataBaseUrl, "metadataBaseUrl")
    : DEFAULT_GCP_METADATA_BASE_URL;
  const secretManagerBaseUrl = hasCustomSecretManager
    ? normalizeBaseUrl(options.secretManagerBaseUrl, "secretManagerBaseUrl")
    : DEFAULT_SECRET_MANAGER_BASE_URL;

  return { metadataBaseUrl, secretManagerBaseUrl };
}

async function fetchWithTimeout(url, init, timeoutMs = SECRETS_REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchGcpMetadataCredentials({ metadataBaseUrl, timeoutMs }) {
  const tokenUrl = `${metadataBaseUrl}/computeMetadata/v1/instance/service-accounts/default/token`;
  const projectUrl = `${metadataBaseUrl}/computeMetadata/v1/project/project-id`;
  const metadataHeaders = {
    "Metadata-Flavor": "Google",
  };

  let tokenRes;
  let projectRes;
  try {
    [tokenRes, projectRes] = await Promise.all([
      fetchWithTimeout(tokenUrl, { method: "GET", headers: metadataHeaders }, timeoutMs),
      fetchWithTimeout(projectUrl, { method: "GET", headers: metadataHeaders }, timeoutMs),
    ]);
  } catch {
    throw new Error("Failed to reach Google Compute Engine metadata server.");
  }

  if (!tokenRes.ok) {
    throw new Error(
      `GCE metadata server token endpoint returned HTTP ${tokenRes.status}.`,
    );
  }
  if (!projectRes.ok) {
    throw new Error(
      `GCE metadata server project-id endpoint returned HTTP ${projectRes.status}.`,
    );
  }

  let tokenJson;
  try {
    tokenJson = await tokenRes.json();
  } catch {
    throw new Error("GCE metadata server returned invalid JSON for service account token.");
  }

  const accessToken =
    typeof tokenJson?.access_token === "string" ? tokenJson.access_token.trim() : "";
  if (!accessToken) {
    throw new Error("GCE metadata server response did not contain a valid access_token.");
  }

  const rawProjectText = (await projectRes.text()).trim();
  if (!rawProjectText || !/^[A-Za-z0-9.:-]+$/.test(rawProjectText)) {
    throw new Error("GCE metadata server returned an empty or invalid project-id.");
  }

  return {
    accessToken,
    projectId: rawProjectText,
  };
}

function decodeStrictBase64Secret(b64String, secretLabel) {
  if (typeof b64String !== "string") {
    throw new Error(`Secret Manager payload for '${secretLabel}' is missing base64 data.`);
  }
  const cleaned = b64String.replace(/\s+/g, "");
  if (cleaned.length === 0 || cleaned.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    throw new Error(`Secret Manager payload for '${secretLabel}' contains invalid base64.`);
  }
  const decoded = Buffer.from(cleaned, "base64").toString("utf8").trim();
  if (!decoded) {
    throw new Error(`Secret Manager secret '${secretLabel}' decoded to an empty value.`);
  }
  return decoded;
}

async function accessSecretManagerLatestVersion({
  secretManagerBaseUrl,
  projectId,
  secretName,
  accessToken,
  timeoutMs,
}) {
  const buildUrl = (name) =>
    `${secretManagerBaseUrl}/v1/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(name)}/versions/latest:access`;

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/json",
  };

  let res;
  try {
    res = await fetchWithTimeout(buildUrl(secretName), { method: "GET", headers }, timeoutMs);
  } catch {
    throw new Error(`Failed to reach Google Cloud Secret Manager for secret '${secretName}'.`);
  }

  if (!res.ok) {
    throw new Error(
      `Secret Manager access failed for secret '${secretName}' with HTTP ${res.status}.`,
    );
  }

  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error(`Secret Manager returned invalid JSON for secret '${secretName}'.`);
  }

  const rawData = body?.payload?.data;
  return decodeStrictBase64Secret(rawData, secretName);
}

/**
 * Wraps the loaded secrets in an in-memory object where secret values are non-enumerable
 * and redacted under `util.inspect` and `JSON.stringify` so they are never accidentally logged.
 */
function createInMemorySecretsRecord(source, values) {
  const record = { source };
  for (const { envKey } of SECRET_DEFINITIONS) {
    const val = typeof values[envKey] === "string" ? values[envKey] : "";
    Object.defineProperty(record, envKey, {
      value: val,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
  Object.defineProperty(record, util.inspect.custom, {
    value: () => ({ source, secrets: "[REDACTED_IN_MEMORY]" }),
    enumerable: false,
  });
  return Object.freeze(record);
}

let inMemorySecrets = null;

/**
 * Loads `MONGODB_URI`, `GEMINI_API_KEY`, and `CORE_OPERATOR_TOKEN` according to `CORE_SECRETS_SOURCE`:
 * - `gcp-secret-manager`: fetches an access token and project ID from the GCE metadata server
 *   (`Metadata-Flavor: Google`), then reads `MONGODB_URI`, `GEMINI_API_KEY`, and `CORE_OPERATOR_TOKEN`
 *   from Secret Manager `versions/latest:access`. Holds values in memory only, never logs them,
 *   and fails closed if any secret is missing or empty.
 * - `env` (default for Tinfoil): reads `MONGODB_URI`, `GEMINI_API_KEY`, `CORE_OPERATOR_TOKEN`
 *   from the environment (`options.env ?? process.env`). Fails closed if any is missing unless
 *   `allowPartialEnv: true` is passed for unit tests.
 * - Unknown value: throws and refuses to start.
 */
export async function loadSecrets(options = {}) {
  const source = resolveSecretsSource(
    options.source !== undefined ? options.source : process.env.CORE_SECRETS_SOURCE,
  );
  const timeoutMs = options.timeoutMs ?? SECRETS_REQUEST_TIMEOUT_MS;

  if (source === "env") {
    const envObj = options.env ?? process.env;
    const allowPartialEnv = Boolean(options.allowPartialEnv);
    const values = {};
    for (const { envKey } of SECRET_DEFINITIONS) {
      const raw = typeof envObj[envKey] === "string" ? envObj[envKey].trim() : "";
      if (!raw && !allowPartialEnv) {
        throw new Error(
          `Missing required secret '${envKey}' in environment (CORE_SECRETS_SOURCE=env).`,
        );
      }
      values[envKey] = raw;
    }
    inMemorySecrets = createInMemorySecretsRecord("env", values);
    return inMemorySecrets;
  }

  // source === "gcp-secret-manager"
  const { metadataBaseUrl, secretManagerBaseUrl } = resolveInjectableBaseUrls(options);
  const { accessToken, projectId } = await fetchGcpMetadataCredentials({
    metadataBaseUrl,
    timeoutMs,
  });

  const values = {};
  for (const { envKey, secretName } of SECRET_DEFINITIONS) {
    values[envKey] = await accessSecretManagerLatestVersion({
      secretManagerBaseUrl,
      projectId,
      secretName,
      accessToken,
      timeoutMs,
    });
  }

  inMemorySecrets = createInMemorySecretsRecord("gcp-secret-manager", values);
  return inMemorySecrets;
}

export function getLoadedSecrets() {
  return inMemorySecrets;
}

export function getLoadedSecret(envKey) {
  if (inMemorySecrets && typeof inMemorySecrets[envKey] === "string" && inMemorySecrets[envKey]) {
    return inMemorySecrets[envKey];
  }
  return undefined;
}

export function resetLoadedSecretsForTests() {
  inMemorySecrets = null;
}
