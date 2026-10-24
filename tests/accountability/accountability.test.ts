import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  GET as getAccountability,
  POST as postAccountability,
  resetAccountabilityRateLimitForTests,
} from "@/app/api/accountability/route";
import {
  createCompromiseClaimForDemo,
  DEFAULT_OPERATOR_STAKE_USDC,
  FORBIDDEN_PREFIX_HEX,
  verifyKeyCompromiseBounty,
} from "@/lib/accountability/bounty";
import {
  computeCanaryCommitment,
  createCanarySession,
  verifyCanaryLeak,
} from "@/lib/accountability/canary";
import {
  defaultLatencyTriangulations,
  evaluateLatencyTriangulation,
} from "@/lib/accountability/latency";
import {
  defaultManifests,
  deriveNodeIdentityKey,
  detectManifestContradiction,
  signManifest,
  verifyManifest,
} from "@/lib/accountability/manifest";
import {
  CANARY_ONLY_MIN_HOURS,
  evaluateHeartbeatWindow,
  LINEAR_RAMP_HOURS,
} from "@/lib/accountability/ramp";
import { nodeIdFor, setArcClientDepsForTests } from "@/lib/arc/registry";
import { resetRateLimitStateForTests } from "@/lib/ratelimit";

vi.mock("next/server", () => ({
  connection: vi.fn(async () => undefined),
}));

beforeEach(() => {
  resetRateLimitStateForTests();
  resetAccountabilityRateLimitForTests();
});

afterEach(() => {
  setArcClientDepsForTests(null);
  vi.unstubAllEnvs();
});

describe("Subsystem 3 — Remote Accountability Layer (Spec §8.1–8.7)", () => {
  describe("§8.1 Hardware Manifests", () => {
    it("signs and verifies deterministic manifests for all 4 demo nodes", () => {
      const manifests = defaultManifests();
      expect(manifests).toHaveLength(4);
      expect(manifests.map((m) => m.nodeId)).toEqual([
        "tinfoil-router",
        "sim-1",
        "sim-2",
        "sim-3",
      ]);

      for (const m of manifests) {
        expect(verifyManifest(m)).toBe(true);
        expect(m.gpuIds).toHaveLength(8);
        expect(m.spdmDevices).toEqual([
          "spdm://nvidia-hgx-b200/0..7",
          "spdm://connectx-7/0",
          "spdm://nvme-raid/0",
        ]);
        expect(m.declared.board).toBe("AMD-Turin-HGX-8GPU");
        expect(m.declared.bmcFirmware).toBe("openbmc-2.16-caliptra");
        expect(m.declared.platformRot).toBe("Caliptra-1.1");
        expect(m.declared.dimmSlotsTotal).toBe(24);
        expect(m.declared.dimmSlotsPopulated).toBe(24);
        expect(m.declared.dimmSpeedMt).toBe(6400);
        expect(m.declared.pcieSlotsPopulated).toBe(10);
      }
    });

    it("detects contradictions when attested chipId, gpuIds, or signature differ", () => {
      const [m] = defaultManifests();
      expect(
        detectManifestContradiction(m, {
          chipId: m.chipId,
          gpuIds: m.gpuIds,
          region: m.declared.region,
        }),
      ).toEqual({
        contradicted: false,
        reasons: [],
      });

      // Mismatched chip ID
      const badChip = detectManifestContradiction(m, {
        chipId: "ff".repeat(64),
      });
      expect(badChip.contradicted).toBe(true);
      expect(badChip.reasons.some((r) => r.includes("chipId"))).toBe(true);

      // Mismatched GPU ID in slot 3
      const tamperedGpus = [...m.gpuIds];
      tamperedGpus[3] = "deadbeef".repeat(4);
      const badGpu = detectManifestContradiction(m, {
        gpuIds: tamperedGpus,
      });
      expect(badGpu.contradicted).toBe(true);
      expect(badGpu.reasons.some((r) => r.includes("GPU ID mismatch"))).toBe(true);

      // Tampered manifest body invalidates Ed25519 signature
      const { secretKey } = deriveNodeIdentityKey("sim-1");
      const signed = signManifest(
        {
          nodeId: m.nodeId,
          chipId: m.chipId,
          tcb: m.tcb,
          gpuIds: m.gpuIds,
          spdmDevices: m.spdmDevices,
          declared: m.declared,
          timestamp: m.timestamp,
        },
        secretKey,
      );
      expect(verifyManifest(signed)).toBe(true);
      expect(verifyManifest({ ...signed, tcb: "tampered-tcb" })).toBe(false);
    });
  });

  describe("§8.2 & §8.3 Heartbeats & Post-Restart Ramps", () => {
    const baseNow = 1760000000;

    it("awards 10000 bps in steady state with no restarts", () => {
      const res = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-steady", timestamp: baseNow - 30 },
          { nodeIdentityPk: "pk-steady", timestamp: baseNow - 20 },
          { nodeIdentityPk: "pk-steady", timestamp: baseNow - 10 },
          { nodeIdentityPk: "pk-steady", timestamp: baseNow },
        ],
        baseNow,
      );
      expect(res.status).toBe("full");
      expect(res.phase).toBe("steady");
      expect(res.weightBps).toBe(10000);
      expect(res.restartsIn30d).toBe(0);
      expect(res.dualIdentityDetected).toBe(false);
    });

    it("places a freshly restarted node into canary-only phase with 0 bps real traffic", () => {
      const restartTime = baseNow - 2 * 3600; // 2 hours ago (< 24h canary-only window)
      const res = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-old", timestamp: restartTime - 100 },
          { nodeIdentityPk: "pk-new", timestamp: restartTime },
        ],
        baseNow,
      );
      expect(res.status).toBe("ramp");
      expect(res.phase).toBe("canary-only");
      expect(res.weightBps).toBe(0);
      expect(res.restartsIn30d).toBe(1);
    });

    it("computes ~6667 bps at 48h into the 72h linear ramp", () => {
      const hoursSinceRestart = CANARY_ONLY_MIN_HOURS + 48; // 24h canary + 48h into 72h linear ramp
      const restartTime = baseNow - hoursSinceRestart * 3600;
      const res = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-1", timestamp: restartTime - 300 },
          { nodeIdentityPk: "pk-2", timestamp: restartTime },
        ],
        baseNow,
      );
      expect(res.status).toBe("ramp");
      expect(res.phase).toBe("linear-ramp");
      expect(res.restartsIn30d).toBe(1);
      expect(res.weightBps).toBe(6667);
    });

    it("halves traffic weight when restartsIn30d > 2", () => {
      const hoursSinceLatestRestart = CANARY_ONLY_MIN_HOURS + 48;
      const latestRestart = baseNow - hoursSinceLatestRestart * 3600;
      // 3 restarts in the 30-day window
      const resRamp = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-0", timestamp: latestRestart - 7200 },
          { nodeIdentityPk: "pk-1", timestamp: latestRestart - 5400 },
          { nodeIdentityPk: "pk-2", timestamp: latestRestart - 3600 },
          { nodeIdentityPk: "pk-3", timestamp: latestRestart },
        ],
        baseNow,
      );
      expect(resRamp.restartsIn30d).toBe(3);
      expect(resRamp.phase).toBe("linear-ramp");
      expect(resRamp.weightBps).toBe(Math.round(6667 / 2));

      // Also verify halving after full ramp completion (10000 -> 5000 bps)
      const postRampRestart =
        baseNow - (CANARY_ONLY_MIN_HOURS + LINEAR_RAMP_HOURS + 10) * 3600;
      const resPost = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-0", timestamp: postRampRestart - 7200 },
          { nodeIdentityPk: "pk-1", timestamp: postRampRestart - 5400 },
          { nodeIdentityPk: "pk-2", timestamp: postRampRestart - 3600 },
          { nodeIdentityPk: "pk-3", timestamp: postRampRestart },
        ],
        baseNow,
      );
      expect(resPost.restartsIn30d).toBe(3);
      expect(resPost.weightBps).toBe(5000);
    });

    it("immediately suspends a node (0 bps) if two distinct identity keys appear within 15s", () => {
      const res = evaluateHeartbeatWindow(
        [
          { nodeIdentityPk: "pk-alpha", timestamp: baseNow - 8 },
          { nodeIdentityPk: "pk-beta", timestamp: baseNow },
        ],
        baseNow,
      );
      expect(res.dualIdentityDetected).toBe(true);
      expect(res.status).toBe("suspended");
      expect(res.phase).toBe("suspended");
      expect(res.weightBps).toBe(0);
    });
  });

  describe("§8.4 Canary Honeytokens", () => {
    it("verifies a valid commitment reveal against real contract stake without fabricated percentage splits", () => {
      const nodeIdentityPk = deriveNodeIdentityKey("sim-1").publicKeyHex;
      const session = createCanarySession("sim-1", nodeIdentityPk, 42);

      expect(session.commitment).toBe(
        computeCanaryCommitment(session.honeytoken, session.salt, nodeIdentityPk, 42),
      );

      const verdict = verifyCanaryLeak({
        honeytoken: session.honeytoken,
        salt: session.salt,
        nodeIdentityPk,
        epoch: 42,
        commitment: session.commitment,
        stakeUsdc: 0.01,
      });

      expect(verdict.valid).toBe(true);
      expect(verdict.slashUsdc).toBe(0.01);
      expect(verdict.reporterBountyUsdc).toBe(0);
      expect(verdict.compensationPoolUsdc).toBe(0);
    });

    it("rejects canary reveals with wrong salt or wrong honeytoken", () => {
      const nodeIdentityPk = deriveNodeIdentityKey("sim-2").publicKeyHex;
      const session = createCanarySession("sim-2", nodeIdentityPk, 7);

      const badSalt = verifyCanaryLeak({
        honeytoken: session.honeytoken,
        salt: "00".repeat(32),
        nodeIdentityPk,
        epoch: 7,
        commitment: session.commitment,
        stakeUsdc: 0.01,
      });
      expect(badSalt.valid).toBe(false);
      expect(badSalt.slashUsdc).toBe(0);
      expect(badSalt.reporterBountyUsdc).toBe(0);

      const badToken = verifyCanaryLeak({
        honeytoken: "sk-live-drouter-forged-honeytoken",
        salt: session.salt,
        nodeIdentityPk,
        epoch: 7,
        commitment: session.commitment,
        stakeUsdc: 0.01,
      });
      expect(badToken.valid).toBe(false);
      expect(badToken.slashUsdc).toBe(0);
      expect(badToken.compensationPoolUsdc).toBe(0);
    });
  });

  describe("§8.5 Key-Compromise Bounty", () => {
    const approvedMeasurement = bytesToHex(
      sha384(utf8ToBytes("drouter-sim-node-image/v0.1.0")),
    );

    it("accepts a validly signed forbidden-prefix attestation report and uses contract stake without fabricated percentage splits", () => {
      const [manifest] = defaultManifests();
      const claim = createCompromiseClaimForDemo(
        manifest.nodeId,
        manifest.chipId,
        approvedMeasurement,
      );

      expect(claim.reportDataHex.startsWith(FORBIDDEN_PREFIX_HEX)).toBe(true);
      expect(FORBIDDEN_PREFIX_HEX).toHaveLength(64);
      expect(DEFAULT_OPERATOR_STAKE_USDC).toBe(0.01);

      const verdict = verifyKeyCompromiseBounty(claim, approvedMeasurement, 0.01);
      expect(verdict.valid).toBe(true);
      expect(verdict.slashUsdc).toBe(0.01);
      expect(verdict.submitterBountyUsdc).toBe(0);
    });

    it("rejects claims without FORBIDDEN_PREFIX_HEX, with wrong measurement, or with a bad signature", () => {
      const [manifest] = defaultManifests();
      const claim = createCompromiseClaimForDemo(
        manifest.nodeId,
        manifest.chipId,
        approvedMeasurement,
      );

      // 1. Wrong measurement
      const wrongMeasurement = verifyKeyCompromiseBounty(
        claim,
        "aa".repeat(48),
        0.01,
      );
      expect(wrongMeasurement.valid).toBe(false);
      expect(wrongMeasurement.submitterBountyUsdc).toBe(0);

      // 2. Missing FORBIDDEN_PREFIX_HEX
      const nonForbidden = verifyKeyCompromiseBounty(
        {
          ...claim,
          reportDataHex: "11".repeat(64),
        },
        approvedMeasurement,
        0.01,
      );
      expect(nonForbidden.valid).toBe(false);
      expect(nonForbidden.submitterBountyUsdc).toBe(0);

      // 3. Corrupted P-384 signature
      const badSigHex =
        (claim.signatureHex.startsWith("aa") ? "bb" : "aa") +
        claim.signatureHex.slice(2);
      const badSig = verifyKeyCompromiseBounty(
        {
          ...claim,
          signatureHex: badSigHex,
        },
        approvedMeasurement,
        0.01,
      );
      expect(badSig.valid).toBe(false);
      expect(badSig.submitterBountyUsdc).toBe(0);
    });
  });

  describe("§8.6 Latency Triangulation", () => {
    it("validates speed-of-light RTT bounds for the 4 demo nodes and flags relayed attestations", () => {
      const defaults = defaultLatencyTriangulations();
      expect(defaults).toHaveLength(4);
      for (const d of defaults) {
        expect(d.consistent).toBe(true);
        expect(d.relayedSuspected).toBe(false);
      }

      const relayed = evaluateLatencyTriangulation({
        nodeId: "sim-1",
        declaredRegion: "eu-west",
        measurements: [
          { vantageRegion: "eu-west", rttMs: 148.0 }, // Relayed across continents
          { vantageRegion: "us-east", rttMs: 210.0 },
          { vantageRegion: "ap-south", rttMs: 240.0 },
        ],
      });
      expect(relayed.consistent).toBe(false);
      expect(relayed.relayedSuspected).toBe(true);
      expect(relayed.reasons.length).toBeGreaterThan(0);
    });
  });

  describe("§8.7 On-Chain Arc Integration via /api/accountability (mocked viem)", () => {
    const registryAddr = "0xbc8085c2b6fe6e0db05f169925c0b841828f4481" as const;
    const operator = "0x1111111111111111111111111111111111111111" as const;

    it("records canary-leak, key-compromise, restart, and clone events on chain with real evidence hashes and live stake", async () => {
      vi.stubEnv("ARC_REGISTRY_ADDRESS", registryAddr);

      let txSeq = 0;
      const writeCalls: { functionName: string; args: readonly unknown[] }[] = [];

      setArcClientDepsForTests({
        readContract: vi.fn(async ({ functionName, args }) => {
          if (functionName === "nodeCount") return BigInt(1);
          if (functionName === "minStake") return BigInt(10_000_000_000_000_000);
          if (functionName === "nodeIdAt") return nodeIdFor("sim-1")!;
          if (functionName === "getNode") {
            return {
              operator,
              kind: "sim",
              name: "Simulated node",
              endpoint: "/api/sim/sim-1",
              measurement: `0x${"11".repeat(32)}`,
              region: "eu-west",
              stake: BigInt(10_000_000_000_000_000), // 0.01 USDC on chain
              status: 0,
              registeredAt: BigInt(1700000000),
              lastVerifiedAt: BigInt(0),
              lastVerifiedOk: false,
            };
          }
          throw new Error(`Unexpected readContract: ${functionName}`);
        }),
        writeContract: vi.fn(async ({ functionName, args }) => {
          txSeq += 1;
          writeCalls.push({ functionName, args });
          return `0x${String(txSeq).padStart(64, "0")}` as `0x${string}`;
        }),
      });

      const makePost = (action: string, nodeId: string) =>
        postAccountability(
          new Request("http://localhost/api/accountability", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": "198.51.100.42",
            },
            body: JSON.stringify({ action, nodeId }),
          }),
        );

      // 1. Canary leak on sim-1
      const res1 = await makePost("trigger-canary", "sim-1");
      expect(res1.status).toBe(200);
      const data1 = await res1.json();
      expect(data1.ok).toBe(true);
      expect(data1.onChain).toBe(true);
      expect(data1.txHash).toBe(`0x${"0".repeat(63)}1`);
      expect(data1.explorerUrl).toContain(data1.txHash);
      expect(data1.evidenceHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(data1.verdict.slashUsdc).toBe(0.01);
      expect(data1.verdict.reporterBountyUsdc).toBe(0);
      expect(writeCalls[0]).toEqual({
        functionName: "recordVerification",
        args: [nodeIdFor("sim-1"), false, data1.evidenceHash],
      });

      // 2. Key-compromise bounty on sim-2
      const res2 = await makePost("claim-key-bounty", "sim-2");
      expect(res2.status).toBe(200);
      const data2 = await res2.json();
      expect(data2.onChain).toBe(true);
      expect(data2.txHash).toBe(`0x${"0".repeat(63)}2`);
      expect(data2.verdict.slashUsdc).toBe(0.01);
      expect(data2.verdict.submitterBountyUsdc).toBe(0);
      expect(writeCalls[1]).toEqual({
        functionName: "recordVerification",
        args: [nodeIdFor("sim-2"), false, data2.evidenceHash],
      });

      // 3. Unannounced restart on sim-3
      const res3 = await makePost("simulate-restart", "sim-3");
      expect(res3.status).toBe(200);
      const data3 = await res3.json();
      expect(data3.onChain).toBe(true);
      expect(data3.txHash).toBe(`0x${"0".repeat(63)}3`);
      expect(data3.evaluation.phase).toBe("canary-only");
      expect(writeCalls[2]).toEqual({
        functionName: "recordVerification",
        args: [nodeIdFor("sim-3"), false, data3.evidenceHash],
      });

      // 4. Clone detection on sim-3
      const res4 = await makePost("simulate-clone", "sim-3");
      expect(res4.status).toBe(200);
      const data4 = await res4.json();
      expect(data4.onChain).toBe(true);
      expect(data4.txHash).toBe(`0x${"0".repeat(63)}4`);
      expect(data4.evaluation.dualIdentityDetected).toBe(true);
      expect(data4.event.slashUsdc).toBe(0.01);
      expect(writeCalls[3]).toEqual({
        functionName: "recordVerification",
        args: [nodeIdFor("sim-3"), false, data4.evidenceHash],
      });

      // 5. GET /api/accountability returns onChain, txHash, explorerUrl
      const getRes = await getAccountability();
      const getJson = await getRes.json();
      expect(getJson.onChain).toBe(true);
      expect(getJson.txHash).toBe(`0x${"0".repeat(63)}4`);
      expect(getJson.explorerUrl).toContain(getJson.txHash);
    });
  });
});
