import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/server", () => ({
  connection: async () => {},
}));

import { GET as getTransparencyRoute, POST as postTransparencyRoute } from "@/app/api/transparency/route";
import {
  GET as getVerificationsRoute,
  POST as postVerificationsRoute,
} from "@/app/api/transparency/verifications/route";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";
import {
  VERIFICATION_CLAIM_DOMAIN,
  coarsenEpochSecToHour,
  computeAuditPathFromLeaves,
  computeMerkleRootFromLeaves,
  computeNodeHash,
  computeRawLeafHash,
  computeVerifierFingerprint,
  getOperatorPublicKey,
  proveConsistencyFromLeaves,
  signTreeHead,
  signVerificationClaim,
  verifyConsistencyProofClient,
  verifyInclusionProofClient,
  verifySignedTreeHeadClient,
  verifyTransparencyProofBundleClient,
  verifyVerificationClaimSignature,
  type VerifierSubmissionClaim,
} from "@/lib/transparency/log";
import {
  appendVerificationEventToLog,
  getPersistedTransparencyLog,
  resetAnchorRateLimitState,
  setAnchorReceiptOverride,
  setLiveVerificationViewOverride,
  setTransparencyCollectionOverride,
  setVerifierSubmissionsCollectionOverride,
  type LiveVerificationView,
  type TransparencyCollectionLike,
} from "@/lib/transparency/store";
import {
  buildCanonicalVerificationClaim,
  loadOrCreateVerifierKey,
  parseDrouterCliArgs,
  signCliVerificationClaim,
  submitVerificationClaim,
} from "../../scripts/drouter-cli.mjs";

function createMockCollection(): {
  col: TransparencyCollectionLike;
  docs: Record<string, unknown>[];
} {
  const docs: Record<string, unknown>[] = [];

  const matches = (doc: Record<string, unknown>, filter: Record<string, unknown>): boolean => {
    return Object.entries(filter).every(([k, v]) => doc[k] === v);
  };

  const col: TransparencyCollectionLike = {
    find(filter: Record<string, unknown>) {
      const filtered = docs.filter((d) => matches(d, filter));
      return {
        sort(spec: Record<string, 1 | -1>) {
          const [field, dir] = Object.entries(spec)[0] ?? ["index", 1];
          const sorted = [...filtered].sort((a, b) => {
            const av = Number(a[field] ?? 0);
            const bv = Number(b[field] ?? 0);
            return dir === -1 ? bv - av : av - bv;
          });
          return {
            async toArray() {
              return sorted.map((d) => ({ ...d }));
            },
            limit(n: number) {
              return {
                async toArray() {
                  return sorted.slice(0, n).map((d) => ({ ...d }));
                },
              };
            },
          };
        },
        async toArray() {
          return filtered.map((d) => ({ ...d }));
        },
      };
    },
    async findOne(filter: Record<string, unknown>) {
      const found = docs.find((d) => matches(d, filter));
      return found ? { ...found } : null;
    },
    async insertOne(doc: Record<string, unknown>) {
      docs.push({ ...doc });
      return { acknowledged: true };
    },
    async insertMany(newDocs: Record<string, unknown>[]) {
      for (const d of newDocs) docs.push({ ...d });
      return { acknowledged: true };
    },
    async updateOne(filter: Record<string, unknown>, update: Record<string, unknown>, options?: Record<string, unknown>) {
      const idx = docs.findIndex((d) => matches(d, filter));
      const setFields = (update.$set ?? {}) as Record<string, unknown>;
      if (idx >= 0) {
        docs[idx] = { ...docs[idx], ...setFields };
      } else if (options?.upsert) {
        docs.push({ ...filter, ...setFields });
      }
      return { acknowledged: true };
    },
    async deleteMany(filter: Record<string, unknown>) {
      for (let i = docs.length - 1; i >= 0; i--) {
        if (matches(docs[i], filter)) {
          docs.splice(i, 1);
        }
      }
      return { acknowledged: true };
    },
    async countDocuments(filter: Record<string, unknown> = {}) {
      return docs.filter((d) => matches(d, filter)).length;
    },
  };

  return { col, docs };
}

function buildSampleLiveView(): LiveVerificationView {
  return {
    router: {
      nodeId: "tinfoil-router",
      enclaveHost: "router-0.tinfoil.sh",
      configRepo: "tinfoilsh/confidential-model-router",
      releaseDigest: "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
      measurement: "9134838da8aa4e1792566b2988820340356517c4db0c94261eb8154843e0357554ba72fcf185f950d9301fbede574c90",
    },
    models: {
      "kimi-k3": {
        id: "kimi-k3",
        repo: "tinfoilsh/confidential-kimi-k3",
        tag: "v0.0.15",
        measurement: "69c029108ac795b767e972858e926186c0e7b6a61f6c7fa9ce70ce1a6ee87f2c980bb51973cdf396404412ebb7c1a7b7",
        dmVerityRootHash: "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
        weightRepoCommit: "moonshotai/Kimi-K3@a590ce090cb049c93a33dfe8c208ec652aa20503",
        ok: true,
      },
      "glm-5-3": {
        id: "glm-5-3",
        repo: "tinfoilsh/confidential-glm5-3-nvfp4",
        tag: "v0.0.7",
        measurement: "b64eb23f1441a8f25e29d901782fbb82f894f434db70cb1658dd37c398715bfff070f3b732f2e623bf151e56d2699188",
        ok: true,
      },
    },
    checks: [
      { id: "C1", status: "pass" },
      { id: "C2", status: "pass" },
      { id: "C3", status: "pass" },
      { id: "C4", status: "pass" },
      { id: "C5", status: "pass" },
      { id: "C6", status: "pass" },
      { id: "C7", status: "pass" },
    ],
    overallOk: true,
  };
}

function buildValidClaim(epochHourSec = coarsenEpochSecToHour()): VerifierSubmissionClaim {
  const live = buildSampleLiveView();
  return {
    domain: VERIFICATION_CLAIM_DOMAIN,
    epochHourSec,
    router: { ...live.router },
    models: [live.models["glm-5-3"], live.models["kimi-k3"]],
    checks: live.checks.map((c) => ({ ...c })),
    overallOk: true,
  };
}

afterEach(() => {
  setTransparencyCollectionOverride(null);
  setVerifierSubmissionsCollectionOverride(null);
  setAnchorReceiptOverride(null);
  setLiveVerificationViewOverride(null);
  resetAnchorRateLimitState();
  resetRateLimitStateForTests();
});

describe("RFC 6962 Standard Test Vectors & Client Proof Verifiers", () => {
  it("matches official RFC 6962 / Certificate Transparency SHA-256 Merkle tree test vectors", () => {
    const emptyRoot = bytesToHex(computeMerkleRootFromLeaves([]));
    expect(emptyRoot).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const leaf0 = computeRawLeafHash(new Uint8Array(0));
    expect(bytesToHex(leaf0)).toBe("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    expect(bytesToHex(computeMerkleRootFromLeaves([leaf0]))).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );

    const leaves = Array.from({ length: 7 }, (_, i) => computeRawLeafHash(utf8ToBytes(`leaf-${i}`)));

    const h01 = computeNodeHash(leaves[0], leaves[1]);
    const h23 = computeNodeHash(leaves[2], leaves[3]);
    const h0123 = computeNodeHash(h01, h23);
    expect(bytesToHex(computeMerkleRootFromLeaves(leaves.slice(0, 4)))).toBe(bytesToHex(h0123));

    const h45 = computeNodeHash(leaves[4], leaves[5]);
    const h456 = computeNodeHash(h45, leaves[6]);
    const h0to6 = computeNodeHash(h0123, h456);
    const root7 = bytesToHex(computeMerkleRootFromLeaves(leaves));
    expect(root7).toBe(bytesToHex(h0to6));

    for (let i = 0; i < leaves.length; i++) {
      const auditPath = computeAuditPathFromLeaves(leaves, i);
      const res = verifyInclusionProofClient({
        leafHash: bytesToHex(leaves[i]),
        root: root7,
        auditPath,
        leafIndex: i,
        treeSize: leaves.length,
      });
      expect(res.ok).toBe(true);
      expect(res.computedRoot).toBe(root7);
    }

    for (let second = 1; second <= leaves.length; second++) {
      for (let first = 0; first <= second; first++) {
        const cProof = proveConsistencyFromLeaves(leaves, first, second);
        const cVerdict = verifyConsistencyProofClient(cProof);
        expect(cVerdict.ok).toBe(true);

        if (first > 0 && first < second) {
          const badRoot = verifyConsistencyProofClient({
            ...cProof,
            secondRoot: "aa".repeat(32),
          });
          expect(badRoot.ok).toBe(false);

          const badPath = verifyConsistencyProofClient({
            ...cProof,
            consistencyPath: cProof.consistencyPath.map((h, idx) => (idx === 0 ? "bb".repeat(32) : h)),
          });
          expect(badPath.ok).toBe(false);
        }
      }
    }
  });

  it("signs and verifies operator tree heads (STH) with hour-coarsened timestamps", () => {
    const rawRoot = bytesToHex(sha256(utf8ToBytes("test-merkle-root")));
    const uncoarsenedTime = 1761330123;
    const sth = signTreeHead({
      treeSize: 5,
      rootHash: rawRoot,
      timestampSec: uncoarsenedTime,
    });

    expect(sth.timestampSec).toBe(coarsenEpochSecToHour(uncoarsenedTime));
    expect(sth.timestampSec % 3600).toBe(0);
    expect(sth.operatorPublicKey).toBe(getOperatorPublicKey());

    const verified = verifySignedTreeHeadClient(sth, getOperatorPublicKey());
    expect(verified.ok).toBe(true);

    expect(verifySignedTreeHeadClient({ ...sth, treeSize: 6 }, getOperatorPublicKey()).ok).toBe(false);
    expect(verifySignedTreeHeadClient({ ...sth, timestampSec: sth.timestampSec + 15 }, getOperatorPublicKey()).ok).toBe(
      false,
    );
    expect(verifySignedTreeHeadClient(sth, "11".repeat(32)).ok).toBe(false);
  });
});

describe("MongoDB Persistence (`transparency_log`), Real Tinfoil Leaves & Hourly Arc Anchoring", () => {
  it("seeds only real Tinfoil enclave leaves (no sim nodes), rate-limits Arc anchoring to hourly, and rejects simulated nodes", async () => {
    const { col, docs } = createMockCollection();
    setTransparencyCollectionOverride(col);

    const anchorCalls: string[] = [];
    setAnchorReceiptOverride(async (receiptHash) => {
      anchorCalls.push(receiptHash);
      return `0x${"ab".repeat(32)}`;
    });

    const t0 = 1760000123;
    const initial = await getPersistedTransparencyLog({ nowSec: t0, anchorIfDue: true });
    expect(initial.persisted).toBe(true);
    expect(initial.events).toHaveLength(3);
    expect(initial.events.map((e) => e.nodeId)).toEqual(["tinfoil-router", "kimi-k3", "glm-5-3"]);
    expect(initial.events.every((e) => e.nodeKind === "tinfoil")).toBe(true);
    expect(initial.signedTreeHead.treeSize).toBe(3);
    expect(initial.signedTreeHead.timestampSec % 3600).toBe(0);
    expect(initial.signedTreeHead.anchorTx).toBe(`0x${"ab".repeat(32)}`);
    expect(anchorCalls).toHaveLength(1);

    const appended1 = await appendVerificationEventToLog({
      nodeId: "tinfoil-router",
      nodeKind: "tinfoil",
      ok: true,
      measurement: "aa".repeat(48),
      evidenceHash: "bb".repeat(32),
      enclaveHost: "router-0.tinfoil.sh",
      timestampSec: t0 + 600,
      anchorOnArc: true,
    });

    expect(appended1.persisted).toBe(true);
    expect(appended1.event.index).toBe(3);
    expect(appended1.event.epochHourSec % 3600).toBe(0);
    expect(appended1.signedTreeHead.treeSize).toBe(4);
    expect(anchorCalls).toHaveLength(1);

    const bundleVerdict = verifyTransparencyProofBundleClient({
      sth: appended1.signedTreeHead,
      expectedOperatorPublicKey: getOperatorPublicKey(),
      inclusionProof: appended1.inclusionProof,
      consistencyProof: appended1.consistencyProof,
    });
    expect(bundleVerdict.ok).toBe(true);

    const appended2 = await appendVerificationEventToLog({
      nodeId: "kimi-k3",
      nodeKind: "tinfoil",
      ok: true,
      measurement: "cc".repeat(48),
      evidenceHash: "dd".repeat(32),
      timestampSec: t0 + 3700,
      anchorOnArc: true,
    });
    expect(appended2.signedTreeHead.treeSize).toBe(5);
    expect(anchorCalls).toHaveLength(2);
    expect(docs.filter((d) => d.docType === "leaf")).toHaveLength(5);

    await expect(
      appendVerificationEventToLog({
        nodeId: "sim-1",
        nodeKind: "tinfoil",
        ok: true,
        measurement: "cc".repeat(48),
        evidenceHash: "dd".repeat(32),
      }),
    ).rejects.toThrow(/Simulated nodes are not permitted/);
  });

  it("removes simulated quorum, simulated release approvals, and simulated nodes from GET/POST /api/transparency", async () => {
    const { col } = createMockCollection();
    const { col: subCol } = createMockCollection();
    setTransparencyCollectionOverride(col);
    setVerifierSubmissionsCollectionOverride(subCol);

    const getRes = await getTransparencyRoute(new Request("http://localhost/api/transparency?first=1&second=3"));
    expect(getRes.status).toBe(200);
    const body = await getRes.json();

    expect(body.quorumSimulated).toBeUndefined();
    expect(body.verifierSet).toBeUndefined();
    expect(body.tickets).toBeUndefined();
    expect(body.log).toBeUndefined();
    expect(body.proofs).toBeUndefined();
    expect(body.releaseConsistencyProof).toBeUndefined();

    expect(body.operatorPublicKey).toBe(getOperatorPublicKey());
    expect(verifySignedTreeHeadClient(body.signedTreeHead, body.operatorPublicKey).ok).toBe(true);
    expect(verifyConsistencyProofClient(body.consistencyProof).ok).toBe(true);
    expect(body.verificationLog.events.every((e: { nodeKind: string }) => e.nodeKind === "tinfoil")).toBe(true);
    expect(body.distinctVerifierCount).toBe(0);
    expect(body.totalSubmissions).toBe(0);
    expect(body.recentSubmissions).toEqual([]);

    // Rejects sim node POST
    const simPostRes = await postTransparencyRoute(
      new Request("http://localhost/api/transparency", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          nodeId: "sim-1",
          nodeKind: "sim",
          ok: true,
          measurement: "12".repeat(48),
          evidenceHash: "34".repeat(32),
        }),
      }),
    );
    expect(simPostRes.status).toBe(400);

    // Accepts real tinfoil node POST
    const postRes = await postTransparencyRoute(
      new Request("http://localhost/api/transparency", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          nodeId: "tinfoil-router",
          nodeKind: "tinfoil",
          ok: true,
          measurement: "12".repeat(48),
          evidenceHash: "34".repeat(32),
          enclaveHost: "router-0.tinfoil.sh",
        }),
      }),
    );
    expect(postRes.status).toBe(200);
    const postBody = await postRes.json();
    expect(postBody.ok).toBe(true);
    expect(postBody.quorumSimulated).toBeUndefined();
    expect(postBody.event.index).toBe(3);
  });
});

describe("Permissionless Independent Verification (D8: CLI Key Gen, Canonical C1-C7 Signing & Server Re-Check)", () => {
  it("generates and persists a local Ed25519 verifier key via loadOrCreateVerifierKey and parses verify --submit CLI flags", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "deroute-verifier-test-"));
    const keyPath = path.join(tmpDir, "config", "deroute", "verifier-key");

    try {
      const k1 = loadOrCreateVerifierKey(keyPath);
      expect(k1.created).toBe(true);
      expect(fs.existsSync(keyPath)).toBe(true);
      expect(k1.secretKeyHex).toMatch(/^[0-9a-f]{64}$/);
      expect(k1.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
      expect(k1.fingerprint).toBe(computeVerifierFingerprint(k1.publicKey));

      // Second call reloads the exact same key from disk
      const k2 = loadOrCreateVerifierKey(keyPath);
      expect(k2.created).toBe(false);
      expect(k2.secretKeyHex).toBe(k1.secretKeyHex);
      expect(k2.publicKeyHex).toBe(k1.publicKeyHex);
      expect(k2.fingerprint).toBe(k1.fingerprint);

      const parsedArgs = parseDrouterCliArgs([
        "verify",
        "--submit",
        "--key-path",
        keyPath,
        "--upstream",
        "http://localhost:3000/",
      ]);
      expect(parsedArgs.command).toBe("verify");
      expect(parsedArgs.submit).toBe(true);
      expect(parsedArgs.keyPath).toBe(keyPath);
      expect(parsedArgs.upstream).toBe("http://localhost:3000");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("verifies valid signed C1-C7 claims, stores only fingerprint + result + coarse hour (no IP), appends to RFC 6962 log, and tracks distinctVerifierCount", async () => {
    const { col: logCol } = createMockCollection();
    const { col: subCol, docs: subDocs } = createMockCollection();
    setTransparencyCollectionOverride(logCol);
    setVerifierSubmissionsCollectionOverride(subCol);
    setLiveVerificationViewOverride(async () => buildSampleLiveView());

    const sk1 = new Uint8Array(32).fill(0x11);
    const sk2 = new Uint8Array(32).fill(0x22);
    const claim = buildValidClaim();

    const signed1 = signVerificationClaim(claim, sk1);
    expect(
      verifyVerificationClaimSignature({
        publicKey: signed1.publicKey,
        signature: signed1.signature,
        claim: signed1.claim,
      }).ok,
    ).toBe(true);

    // Submit from verifier 1
    const res1 = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "203.0.113.42",
        },
        body: JSON.stringify({
          publicKey: signed1.publicKey,
          signature: signed1.signature,
          claim: signed1.claim,
        }),
      }),
    );
    expect(res1.status).toBe(200);
    const body1 = await res1.json();
    expect(body1.ok).toBe(true);
    expect(body1.verifierFingerprint).toBe(signed1.verifierFingerprint);
    expect(body1.epochHourSec % 3600).toBe(0);
    expect(body1.distinctVerifierCount).toBe(1);
    expect(body1.totalSubmissions).toBe(1);
    expect(body1.event.index).toBe(3);
    expect(body1.event.verifierFingerprint).toBe(signed1.verifierFingerprint);
    expect(
      verifyTransparencyProofBundleClient({
        sth: body1.signedTreeHead,
        expectedOperatorPublicKey: body1.operatorPublicKey,
        inclusionProof: body1.inclusionProof,
        consistencyProof: body1.consistencyProof,
      }).ok,
    ).toBe(true);

    // Inspect raw stored MongoDB document in verifier_submissions: no IP, no raw publicKey, no signature
    expect(subDocs).toHaveLength(1);
    const storedDoc = subDocs[0];
    expect(storedDoc.verifierFingerprint).toBe(signed1.verifierFingerprint);
    expect(storedDoc.epochHourSec).toBe(claim.epochHourSec);
    expect(storedDoc.overallOk).toBe(true);
    expect(JSON.stringify(storedDoc)).not.toContain("203.0.113.42");
    expect(storedDoc.ip).toBeUndefined();
    expect(storedDoc.publicKey).toBeUndefined();
    expect(storedDoc.signature).toBeUndefined();

    // Second submission from the SAME verifier key keeps distinctVerifierCount === 1
    const res1b = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: signed1.publicKey,
          signature: signed1.signature,
          claim: signed1.claim,
        }),
      }),
    );
    expect(res1b.status).toBe(200);
    const body1b = await res1b.json();
    expect(body1b.distinctVerifierCount).toBe(1);
    expect(body1b.totalSubmissions).toBe(2);

    // Submission from a SECOND distinct verifier key increments distinctVerifierCount to 2
    const signed2 = signCliVerificationClaim(claim, bytesToHex(sk2));
    const res2 = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: signed2.publicKey,
          signature: signed2.signature,
          claim: signed2.claim,
        }),
      }),
    );
    expect(res2.status).toBe(200);
    const body2 = await res2.json();
    expect(body2.distinctVerifierCount).toBe(2);
    expect(body2.totalSubmissions).toBe(3);

    // GET /api/transparency/verifications exposes distinctVerifierCount and recentSubmissions
    const getVerRes = await getVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications?limit=10"),
    );
    expect(getVerRes.status).toBe(200);
    const getVerBody = await getVerRes.json();
    expect(getVerBody.ok).toBe(true);
    expect(getVerBody.distinctVerifierCount).toBe(2);
    expect(getVerBody.totalSubmissions).toBe(3);
    expect(getVerBody.recentSubmissions).toHaveLength(3);
  });

  it("rejects invalid signatures and rejects claims whose router, model, or C1-C7 facts mismatch the live view", async () => {
    const { col: logCol } = createMockCollection();
    const { col: subCol, docs: subDocs } = createMockCollection();
    setTransparencyCollectionOverride(logCol);
    setVerifierSubmissionsCollectionOverride(subCol);
    setLiveVerificationViewOverride(async () => buildSampleLiveView());

    const sk = new Uint8Array(32).fill(0x33);
    const validClaim = buildValidClaim();
    const signed = signVerificationClaim(validClaim, sk);

    // 1. Forged signature -> HTTP 400
    const badSigRes = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: signed.publicKey,
          signature: "00".repeat(64),
          claim: signed.claim,
        }),
      }),
    );
    expect(badSigRes.status).toBe(400);

    // 2. Valid signature over wrong router measurement -> HTTP 422
    const wrongRouterSigned = signVerificationClaim(
      {
        ...validClaim,
        router: {
          ...validClaim.router,
          measurement: "ff".repeat(48),
        },
      },
      sk,
    );
    const wrongRouterRes = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: wrongRouterSigned.publicKey,
          signature: wrongRouterSigned.signature,
          claim: wrongRouterSigned.claim,
        }),
      }),
    );
    expect(wrongRouterRes.status).toBe(422);
    const wrongRouterBody = await wrongRouterRes.json();
    expect(wrongRouterBody.ok).toBe(false);
    expect(wrongRouterBody.mismatches.join(" ")).toContain("router.measurement mismatch");

    // 3. Valid signature over wrong model tag -> HTTP 422
    const wrongModelSigned = signVerificationClaim(
      {
        ...validClaim,
        models: validClaim.models.map((m) => (m.id === "kimi-k3" ? { ...m, tag: "v9.9.9-backdoor" } : m)),
      },
      sk,
    );
    const wrongModelRes = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: wrongModelSigned.publicKey,
          signature: wrongModelSigned.signature,
          claim: wrongModelSigned.claim,
        }),
      }),
    );
    expect(wrongModelRes.status).toBe(422);
    const wrongModelBody = await wrongModelRes.json();
    expect(wrongModelBody.mismatches.join(" ")).toContain('Model "kimi-k3" tag mismatch');

    // 4. Valid signature over mismatched C4 check status -> HTTP 422
    const wrongCheckSigned = signVerificationClaim(
      {
        ...validClaim,
        checks: validClaim.checks.map((c) => (c.id === "C4" ? { ...c, status: "fail" as const } : c)),
        overallOk: false,
      },
      sk,
    );
    const wrongCheckRes = await postVerificationsRoute(
      new Request("http://localhost/api/transparency/verifications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicKey: wrongCheckSigned.publicKey,
          signature: wrongCheckSigned.signature,
          claim: wrongCheckSigned.claim,
        }),
      }),
    );
    expect(wrongCheckRes.status).toBe(422);
    expect(subDocs).toHaveLength(0);
  });

  it("builds a canonical C1-C7 claim via CLI helpers and submits end-to-end against POST /api/transparency/verifications", async () => {
    const { col: logCol } = createMockCollection();
    const { col: subCol } = createMockCollection();
    setTransparencyCollectionOverride(logCol);
    setVerifierSubmissionsCollectionOverride(subCol);
    const liveView = buildSampleLiveView();
    setLiveVerificationViewOverride(async () => liveView);

    const cliClaim = buildCanonicalVerificationClaim({
      doc: {
        enclaveHost: liveView.router.enclaveHost,
        configRepo: liveView.router.configRepo,
        releaseDigest: liveView.router.releaseDigest,
        codeFingerprint: liveView.router.measurement,
        securityVerified: true,
        steps: {
          verifyEnclave: { status: "success" },
          verifyCode: { status: "success" },
          verifyCertificate: { status: "success" },
          compareMeasurements: { status: "success" },
        },
      },
      matrix: {
        models: {
          "kimi-k3": {
            repo: liveView.models["kimi-k3"].repo,
            tag: liveView.models["kimi-k3"].tag,
            measurementRegisters: [liveView.models["kimi-k3"].measurement],
            dmVerityRootHash: liveView.models["kimi-k3"].dmVerityRootHash,
            weightRepoCommit: liveView.models["kimi-k3"].weightRepoCommit,
            healthyHosts: 1,
            configuredHosts: 1,
            status: "router-attested",
          },
          "glm-5-3": {
            repo: liveView.models["glm-5-3"].repo,
            tag: liveView.models["glm-5-3"].tag,
            measurementRegisters: [liveView.models["glm-5-3"].measurement],
            healthyHosts: 7,
            configuredHosts: 7,
            status: "router-attested",
          },
        },
      },
      proxyTable: { models: {} },
      registry: {
        source: "arc",
        nodes: [{ kind: "tinfoil", status: "active", stake: "100" }],
      },
    });

    const sk = ed25519.utils.randomSecretKey();
    const signed = signCliVerificationClaim(cliClaim, sk);
    const submitted = await submitVerificationClaim({
      upstream: "http://localhost",
      signedPayload: signed,
      fetchImpl: ((url: string, init: RequestInit) =>
        postVerificationsRoute(new Request(url, init))) as unknown as typeof fetch,
    });

    expect(submitted.ok).toBe(true);
    expect(submitted.status).toBe(200);
    expect(submitted.body.verifierFingerprint).toBe(signed.verifierFingerprint);
    expect(submitted.body.distinctVerifierCount).toBe(1);
  });
});
