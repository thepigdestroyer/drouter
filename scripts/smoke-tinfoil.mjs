// Smoke test: verify a real Tinfoil enclave through the local dRouter relay.
// Usage: node scripts/smoke-tinfoil.mjs [baseUrl]
import { TinfoilAI } from "tinfoil";

const base = process.argv[2] ?? "http://localhost:3100";
const client = new TinfoilAI({
  bearerToken: "drouter-demo",
  baseURL: `${base}/api/relay/v1/`,
  attestationBundleURL: `${base}/api/relay`,
});

try {
  await client.ready();
} catch (error) {
  console.error("ready() failed:", error?.message ?? error);
}
const doc = await client.getVerificationDocument();
console.log("securityVerified:", doc.securityVerified);
console.log("enclaveHost:", doc.enclaveHost, "release:", doc.releaseTag ?? doc.releaseDigest);
console.log("measurement type:", doc.enclaveMeasurement?.measurement?.type);
for (const [name, step] of Object.entries(doc.steps)) console.log(`  ${name}: ${step?.status}${step?.error ? ` (${step.error})` : ""}`);

if (process.env.SMOKE_CHAT) {
  const reply = await client.chat.completions.create(
    { model: "kimi-k3", messages: [{ role: "user", content: "Reply with exactly: enclave ok" }] },
    { headers: { "X-Tinfoil-Model": "kimi-k3" } },
  );
  console.log("chat:", reply.choices[0]?.message?.content);
}
