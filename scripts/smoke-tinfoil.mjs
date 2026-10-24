// Smoke test: verify real Tinfoil router & model enclaves through the local dRouter relay.
// Usage: node --env-file=.env.local scripts/smoke-tinfoil.mjs [baseUrl] [--chat]
import { TinfoilAI } from "tinfoil";

const base = (process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "http://localhost:3000").replace(/\/+$/, "");
const runChat = process.env.SMOKE_CHAT === "1" || process.argv.includes("--chat");

// Tinfoil SDK requires https:// for attestationBundleURL; map virtual https origin to local http relay when testing localhost.
const virtualHttpsBase = base.startsWith("http://")
  ? "https://local-relay.drouter.internal"
  : base;

if (base.startsWith("http://")) {
  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (input, init) => {
    const urlStr =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    if (urlStr.startsWith(virtualHttpsBase)) {
      return origFetch(urlStr.replace(virtualHttpsBase, base), init);
    }
    return origFetch(input, init);
  };
}

const client = new TinfoilAI({
  bearerToken: "drouter-demo",
  baseURL: `${base}/api/relay/v1/`,
  attestationBundleURL: `${virtualHttpsBase}/api/relay`,
});

console.log(`=== 1. Tinfoil SDK Router Attestation (${base}/api/relay/attestation) ===`);
await client.ready();
const doc = await client.getVerificationDocument();
console.log("securityVerified:", doc.securityVerified);
console.log("enclaveHost:", doc.enclaveHost, "release:", doc.releaseTag ?? doc.releaseDigest);
console.log("measurement type:", doc.enclaveMeasurement?.measurement?.type);
for (const [name, step] of Object.entries(doc.steps)) {
  console.log(`  ${name}: ${step?.status}${step?.error ? ` (${step.error})` : ""}`);
}
if (!doc.securityVerified) {
  throw new Error("Router attestation verification failed");
}

console.log(`\n=== 2. Hop-Specific Attestation Relay (${base}/api/relay/relay-eu-zurich/attestation) ===`);
const hopRes = await fetch(`${base}/api/relay/relay-eu-zurich/attestation`);
const hopHeader = hopRes.headers.get("x-drouter-relay-hop");
const hopJson = await hopRes.json();
console.log("HTTP status:", hopRes.status, "X-DRouter-Relay-Hop:", hopHeader, "domain:", hopJson.domain);
if (hopRes.status !== 200 || hopHeader !== "relay-eu-zurich" || !hopJson.domain) {
  throw new Error("Hop-specific attestation relay check failed");
}

console.log(`\n=== 3. Deep Enclave Matrix & End-to-End Hardware/Sigstore Verification (${base}/api/relay/enclave-matrix) ===`);
const matrixRes = await fetch(`${base}/api/relay/enclave-matrix`);
if (!matrixRes.ok) {
  throw new Error(`enclave-matrix HTTP ${matrixRes.status}: ${await matrixRes.text()}`);
}
const matrix = await matrixRes.json();
console.log("Bundle status:", matrix.status, "routerHost:", matrix.routerHost, "releaseTag:", matrix.routerReleaseTag);
console.log("Router AMD SEV-SNP chain:", {
  verified: matrix.routerSnpChain?.verified,
  productName: matrix.routerSnpChain?.productName,
  arkSubject: matrix.routerSnpChain?.arkSubject,
  askSubject: matrix.routerSnpChain?.askSubject,
  vcekSubject: matrix.routerSnpChain?.vcekSubject,
  reportSignatureVerified: matrix.routerSnpChain?.reportSignatureVerified,
});
if (!matrix.routerSnpChain?.verified) {
  throw new Error(`Router AMD SEV-SNP chain failed: ${matrix.routerSnpChain?.error}`);
}

for (const [modelId, m] of Object.entries(matrix.models || {})) {
  console.log(`\nModel [${modelId}] (${m.repo}@${m.tag}) status=${m.status}:`);
  console.log(`  sigstoreVerified=${m.sigstoreVerified} registersMatchSigstore=${m.registersMatchSigstore}`);
  console.log(`  directQuoteVerified=${m.directQuoteVerified} host=${m.directQuoteHost ?? "n/a"} format=${m.directQuoteFormat ?? "n/a"}`);
  if (m.directQuoteError) {
    console.log(`  directQuoteNote: ${m.directQuoteError}`);
  }
  console.log(`  cryptographicallyVerified (${m.verificationBreakdown?.cryptographicallyVerified?.length ?? 0}):`);
  for (const item of m.verificationBreakdown?.cryptographicallyVerified ?? []) {
    console.log(`    + ${item}`);
  }
  console.log(`  trustedFromRouter (${m.verificationBreakdown?.trustedFromRouter?.length ?? 0}):`);
  for (const item of m.verificationBreakdown?.trustedFromRouter ?? []) {
    console.log(`    ~ ${item}`);
  }
}

if (runChat) {
  console.log(`\n=== 4. Live HPKE-Encrypted Chat Completion (${base}/api/relay/v1/chat/completions) ===`);
  const reply = await client.chat.completions.create(
    { model: "kimi-k3", messages: [{ role: "user", content: "Reply with exactly: enclave ok" }] },
    { headers: { "X-Tinfoil-Model": "kimi-k3" } },
  );
  console.log("chat:", reply.choices[0]?.message?.content);
}
