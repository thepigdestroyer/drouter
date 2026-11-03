# Pin update, 3 November 2026

From 28 October 2026 the hourly monitor reported 3 of 6 sealed computers as failing check C7 (manifest-pinned model and dm-verity root): `kimi-k3`, `glm-5-3` and `deepseek-v4-1-flash`. This note records why, and what changed.

## Cause

Tinfoil published new signed releases on 28 October 2026:

| Model | Pinned before | Signed release now | New dm-verity root |
|---|---|---|---|
| kimi-k3 | `confidential-kimi-k3@v0.0.15` | `v0.0.16` | `b1902527b8cd0b9be8753052b9c28a114cabe57286ed2b65928e78647afd7936` |
| glm-5-3 | `confidential-glm5-3-nvfp4@v0.0.7` | `v0.0.10` | same |
| deepseek-v4-1-flash | `confidential-deepseek-v4-1-flash@v0.0.8+b200` | `v0.0.10+b300` (b200 still rolling out on some hosts, same root) | same |

All three moved to a new shared base image, so their dm-verity root changed. deRoute's catalog in `src/lib/weights/open-shards.ts` still pinned the 25 October values, so the cross-source dm-verity comparison failed. Everything else the monitor checks still matched: the hardware attestation chain, the Hugging Face commit, the weight MPK hash and the shard Merkle root.

## Evidence checked before re-pinning

- Each new `tinfoil-deployment.json` was fetched from the tinfoilsh GitHub release. Its `hashes.root` equals the `roothash=` on its own kernel command line, and `sha256(config)` equals its `tinfoil-config-hash`.
- The live enclaves report exactly these release measurements (for example kimi-k3 `snp_measurement` `7fb2b796...` and RTMR1 `758adac4...`).
- The weights are unchanged: `moonshotai/Kimi-K3@a590ce09`, `Inferact/GLM-5.3-NVFP4@ce67b36f` and `deepseek-ai/DeepSeek-V4.1-Flash-1017@1bae0e10`, with the same MPK hashes as before. kimi-k3 additionally loads a speculative-decoding draft model (`RedHatAI/Kimi-K3-speculator.dspark@38a88101`), and deepseek's VM grew from 32 to 56 vCPUs.

## What changed

- The three catalog entries now pin the new tag, dm-verity root, container image digest, config hash and measurement registers, all copied from the signed releases above.
- `/api/ashi` returned HTTP 500: it assumed the first deepseek host serves an Intel TDX quote, but Tinfoil now runs that model on a mixed AMD SEV-SNP and Intel TDX fleet. It now picks a host that actually serves a TDX quote, compares RTMRs against the release that host runs, and leaves a tier unmeasured instead of failing the whole response if a format changes again.
- Two live tests made the same single-host assumptions and now pick hosts the same way.
