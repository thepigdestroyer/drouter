import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  CipherSuite,
  AEAD_AES_256_GCM,
  KDF_HKDF_SHA256,
} from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  DEFAULT_HEART_GRID,
  blindEnvelopeRound,
  evaluateNodeChoice,
  fetchAndJudgeLiveAttestationNodes,
  judgeCandidateNodes,
  simulateSubpoenaPop,
  tapMemoryBus,
} from "@/lib/game/gauntlet";
import { preparePrompt } from "@/lib/pipeline";
import { padJsonPayloadToBucket } from "@/lib/relay";
import { sealEhbpHpkeFrame } from "@/components/packet-sniffer";

describe("The Enclave Gauntlet · 4 Interactive Security Exhibits", () => {
  describe("Exhibit 01: tapMemoryBus (AES-256-ECB vs AES-256-GCM with fresh nonces)", () => {
    it("leaks 100% of the 4x4 pattern under naive-cpu-xts due to identical 16-byte AES-ECB blocks", () => {
      const result = tapMemoryBus(DEFAULT_HEART_GRID, "naive-cpu-xts");
      expect(result.mode).toBe("naive-cpu-xts");
      expect(result.blocks).toHaveLength(16);
      expect(result.repeatedBlocks).toBe(14);
      expect(result.uniqueBlocks).toBe(2);
      expect(result.leakRatePct).toBe(100);
      expect(result.reconstructedGrid).toEqual(DEFAULT_HEART_GRID);
    });

    it("produces 0 repeated blocks, >7.8 bits/byte entropy, and 0% leak in drouter-gpu-hbm mode", () => {
      const result = tapMemoryBus(DEFAULT_HEART_GRID, "drouter-gpu-hbm");
      expect(result.mode).toBe("drouter-gpu-hbm");
      expect(result.blocks).toHaveLength(16);
      expect(result.repeatedBlocks).toBe(0);
      expect(result.uniqueBlocks).toBe(16);
      expect(result.entropyBitsPerByte).toBeGreaterThan(7.8);
      expect(result.leakRatePct).toBe(0);
      expect(result.reconstructedGrid.every((cell) => cell === null)).toBe(true);
    });
  });

  describe("Exhibit 02: blindEnvelopeRound (Real RSA-FDH Blind Signatures from src/lib/credits/blind.ts)", () => {
    it("blinds, signs, unblinds, and verifies a real >=1024-bit RSA blind signature while proving 6-way unlinkability", () => {
      const round = blindEnvelopeRound({ t: 42, r: 19 });
      expect(round.modulusBits).toBeGreaterThanOrEqual(1024);
      expect(round.signatureValid).toBe(true);
      expect(round.recomputedFromSignature).toBe(round.t);
      expect(round.nullifierHex).toMatch(/^[0-9a-f]{64}$/);
      expect(round.purchases).toHaveLength(3);
      expect(round.purchases[0].buyerWallet).toContain("Dana Reyes");
      expect(round.spentTokens).toHaveLength(3);
      expect(round.spentTokens.every((st) => st.signatureValid)).toBe(true);
      expect(round.permutations).toHaveLength(6);
      expect(round.validPermutationsCount).toBe(6);
      expect(round.unlinkable).toBe(true);
    });

    it("supports arbitrary player choices for token secret t and blinding factor r", () => {
      const round = blindEnvelopeRound(123, 57);
      expect(round.signatureValid).toBe(true);
      expect(round.unlinkable).toBe(true);
      expect(round.validPermutationsCount).toBe(6);
    });
  });

  describe("Exhibit 03: judgeCandidateNodes & evaluateNodeChoice (Spot the Forged Enclave)", () => {
    it("parses binary SEV-SNP reports with debug bit imposter, digest imposter, and 1 authentic node without fake locations", () => {
      const nodes = judgeCandidateNodes();
      expect(nodes).toHaveLength(3);

      for (const node of nodes) {
        expect(node.region).not.toContain("Ashburn");
        expect(node.region).not.toContain("Frankfurt");
        expect(node.region).not.toContain("Boardman");
        expect(node.region).toContain("router-0.tinfoil.sh");
      }

      const alpha = nodes.find((n) => n.id === "node-alpha")!;
      const bravo = nodes.find((n) => n.id === "node-bravo")!;
      const charlie = nodes.find((n) => n.id === "node-charlie")!;

      expect(alpha.policyDebugAllowed).toBe(true);
      expect(alpha.isAuthentic).toBe(false);

      expect(bravo.dmVerityMatchesSigstore).toBe(false);
      expect(bravo.isAuthentic).toBe(false);

      expect(charlie.policyDebugAllowed).toBe(false);
      expect(charlie.dmVerityMatchesSigstore).toBe(true);
      expect(charlie.isAuthentic).toBe(true);
    });

    it("scores player choices and identifies the exact register that caught each imposter", () => {
      const nodes = judgeCandidateNodes();

      const pickAlpha = evaluateNodeChoice("node-alpha", nodes);
      expect(pickAlpha.correct).toBe(false);
      expect(pickAlpha.caughtRegister).toBe("ATT_REPORT.POLICY[19]");

      const pickBravo = evaluateNodeChoice("node-bravo", nodes);
      expect(pickBravo.correct).toBe(false);
      expect(pickBravo.caughtRegister).toBe("INITRD.DM_VERITY_ROOT");

      const pickCharlie = evaluateNodeChoice("node-charlie", nodes);
      expect(pickCharlie.correct).toBe(true);
      expect(pickCharlie.authenticNodeId).toBe("node-charlie");
      expect(pickCharlie.caughtRegister).toBe("ALL_REGISTERS_CLEAN");
    });

    it("fetches a live attestation document from Tinfoil, tampers two copies, and verifies them with the real Verifier", async () => {
      const liveNodes = await fetchAndJudgeLiveAttestationNodes(
        "https://atc.tinfoil.sh/attestation"
      );
      expect(liveNodes).toHaveLength(3);
      expect(liveNodes[0].liveSource).toBe(true);
      expect(liveNodes[0].policyDebugAllowed).toBe(true);
      expect(liveNodes[0].isAuthentic).toBe(false);
      expect(liveNodes[0].verifierError).toBeTruthy();

      expect(liveNodes[1].liveSource).toBe(true);
      expect(liveNodes[1].dmVerityMatchesSigstore).toBe(false);
      expect(liveNodes[1].isAuthentic).toBe(false);
      expect(liveNodes[1].verifierError).toContain("digest");

      expect(liveNodes[2].liveSource).toBe(true);
      expect(liveNodes[2].isAuthentic).toBe(true);
      expect(liveNodes[2].verifierError).toBeUndefined();
    }, 15000);
  });

  describe("Exhibit 04: simulateSubpoenaPop (Real Key Destruction & AES-256-GCM Decryption Failure)", () => {
    it("decrypts before pop, zeroes the 256-bit key on pop, and proves AES-256-GCM decryption fails", () => {
      const live = simulateSubpoenaPop([]);
      expect(live.sessionDecryptable).toBe(true);
      expect(live.decryptionError).toBeNull();
      expect(live.sessionKeyHex).not.toBe("0".repeat(64));

      const frozenAndPopped = simulateSubpoenaPop(["freeze", "pop", "host-ram-dump"]);
      expect(frozenAndPopped.gpuPagesZeroed).toBe(true);
      expect(frozenAndPopped.gpuActiveBytesRemaining).toBe(0);
      expect(frozenAndPopped.sessionKeyHex).toBe("0".repeat(64));
      expect(frozenAndPopped.sessionDecryptable).toBe(false);
      expect(frozenAndPopped.decryptionError).toContain("AES-256-GCM decryption failed");
      expect(frozenAndPopped.hostDumpReadableBytes).toBe(0);
      expect(frozenAndPopped.cloudBlobDecryptableWithUserKey).toBe(true);
      expect(frozenAndPopped.cloudBlobDecryptableByServer).toBe(false);

      const shredded = simulateSubpoenaPop(["freeze", "pop", "shred-secret", "host-ram-dump"]);
      expect(shredded.gpuPagesZeroed).toBe(true);
      expect(shredded.sessionDecryptable).toBe(false);
      expect(shredded.hostDumpReadableBytes).toBe(0);
      expect(shredded.cloudBlobDecryptableWithUserKey).toBe(false);
      expect(shredded.cloudBlobDecryptableByServer).toBe(false);
    });
  });

  describe("Packet Sniffer: preparePrompt (I1) + RFC 9180 HPKE Encapsulation", () => {
    it("prepares prompt via preparePrompt, pads to 4096 bytes, and seals a valid RFC 9180 HPKE frame", async () => {
      const sample =
        "Send $125,000 to dana.reyes@acme.example using key sk-live-9876543210abcdef on 2026-11-04";
      const prepared = preparePrompt(sample, { normalizeStyle: true });
      expect(prepared.outboundText).not.toContain("dana.reyes@acme.example");
      expect(prepared.outboundText).not.toContain("sk-live-9876543210abcdef");
      expect(prepared.bucketBytes).toBe(4096);
      expect(prepared.report.redactions.length).toBeGreaterThanOrEqual(2);

      const { paddedJson, bucketBytes } = padJsonPayloadToBucket(
        JSON.stringify({
          model: "kimi-k3",
          stream: true,
          messages: [{ role: "user", content: prepared.outboundText }],
        }),
        prepared.bucketBytes
      );
      const paddedBytes = utf8ToBytes(paddedJson);
      expect(paddedBytes.byteLength).toBe(4096);
      expect(bucketBytes).toBe(4096);

      // Generate a real HPKE X25519 recipient keypair and verify our RFC 9180 HPKE frame opens cleanly
      const suite = new CipherSuite(
        KEM_DHKEM_X25519_HKDF_SHA256,
        KDF_HKDF_SHA256,
        AEAD_AES_256_GCM
      );
      const recipientKp = await suite.GenerateKeyPair(true);
      const recipientPubBytes = new Uint8Array(
        await suite.SerializePublicKey(recipientKp.publicKey)
      );
      const senderSk = new Uint8Array(32).fill(7);

      const sealed = sealEhbpHpkeFrame(paddedBytes, recipientPubBytes, senderSk);
      expect(sealed.encapsulatedKeyBytes.byteLength).toBe(32);
      expect(sealed.ciphertextBytes.byteLength).toBe(4096 + 16);
      expect(sealed.ehbpWireFrameBytes.byteLength).toBe(4 + 4096 + 16);

      const recipientCtx = await suite.SetupRecipient(
        recipientKp.privateKey,
        sealed.encapsulatedKeyBytes,
        { info: utf8ToBytes("ehbp request") }
      );
      const openedBytes = new Uint8Array(await recipientCtx.Open(sealed.ciphertextBytes));
      expect(openedBytes.byteLength).toBe(4096);
      const openedObj = JSON.parse(new TextDecoder().decode(openedBytes));
      expect(openedObj.messages[0].content).toBe(prepared.outboundText);
    });
  });

  describe("Wave 4 plain-language compliance & deRoute rename", () => {
    const BANNED_WORDS = [
      "attestation",
      "attested",
      "enclave",
      "TEE",
      "SEV-SNP",
      "SNP",
      "TDX",
      "HPKE",
      "RFC",
      "Merkle",
      "nullifier",
      "RSA",
      "quorum",
      "Sigstore",
      "Rekor",
      "VCEK",
      "CKKS",
      "FHE",
      "homomorphic",
      "dm-verity",
      "measurement",
      "ciphertext",
      "hash",
      "digest",
      "ECDSA",
      "X25519",
      "PII",
      "OHTTP",
      "SPRT",
      "Arc testnet",
      "relay hop",
      "bucket bytes",
    ];

    function getJsxOutsideTechDetails(relPath: string): string {
      const fullPath = path.resolve(process.cwd(), relPath);
      const src = fs.readFileSync(fullPath, "utf8");
      const returnIdx = src.lastIndexOf("return (");
      const jsx = returnIdx >= 0 ? src.slice(returnIdx) : src;
      return jsx.replace(/<TechDetails[\s\S]*?<\/TechDetails>/g, "");
    }

    it("keeps all banned technical jargon inside TechDetails across /explain, game, and packet-sniffer", () => {
      for (const relPath of [
        "src/app/explain/page.tsx",
        "src/components/game/enclave-gauntlet.tsx",
        "src/components/packet-sniffer.tsx",
      ]) {
        const defaultJsx = getJsxOutsideTechDetails(relPath)
          // Strip JSX comments and attribute/identifier tokens that are not user-visible text
          .replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
          .replace(/<[A-Za-z0-9_]+[^>]*>/g, " ")
          .replace(/<\/[A-Za-z0-9_]+>/g, " ")
          .replace(/\{[^}]*\}/g, " ");

        for (const word of BANNED_WORDS) {
          const re = new RegExp(`\\b${word.replace("-", "\\-")}\\b`, "i");
          expect(defaultJsx, `${relPath} leaked banned word "${word}" outside TechDetails`).not.toMatch(re);
        }
        expect(defaultJsx).not.toContain("—");
        expect(defaultJsx).not.toContain("dRouter");
      }
    });

    it("includes the 4 story scenes, 4 playful rounds, and 4 person cards with TechDetails ('What really happened')", () => {
      const explainSrc = fs.readFileSync(
        path.resolve(process.cwd(), "src/app/explain/page.tsx"),
        "utf8"
      );
      expect(explainSrc).toContain("How it works · deRoute");
      expect(explainSrc).toContain("Scene One");
      expect(explainSrc).toContain("Scene Two");
      expect(explainSrc).toContain("Scene Three");
      expect(explainSrc).toContain("Scene Four");

      const gameSrc = fs.readFileSync(
        path.resolve(process.cwd(), "src/components/game/enclave-gauntlet.tsx"),
        "utf8"
      );
      expect(gameSrc).toContain("Spy on the wire");
      expect(gameSrc).toContain("Pay without a name");
      expect(gameSrc).toContain("Spot the fake");
      expect(gameSrc).toContain("Vanish");
      expect(gameSrc).toContain('label="What really happened"');

      const snifferSrc = fs.readFileSync(
        path.resolve(process.cwd(), "src/components/packet-sniffer.tsx"),
        "utf8"
      );
      expect(snifferSrc).toContain("What each person can see");
      expect(snifferSrc).toContain("Your internet provider");
      expect(snifferSrc).toContain("Our server");
      expect(snifferSrc).toContain("The sealed computer");
      expect(snifferSrc).toContain('label="What really happened"');
    });
  });
});
