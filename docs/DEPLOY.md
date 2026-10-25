# Deployment & Operations Runbook (`docs/DEPLOY.md`)

- **Product Name**: deRoute
- **Production URL**: `https://drouter-demo.vercel.app`
- **Repository**: `https://github.com/thepigdestroyer/drouter`
- **Google Cloud Confidential Space Guide**: [docs/confidential-space.md](confidential-space.md)
- **Transparency Log Restart Record**: [docs/transparency-log-restart.md](transparency-log-restart.md)

---

## 1. Vercel Environment Variables (By Name Only)

Configure the following environment variables in the Vercel project settings (`Production` and `Preview` environments as appropriate). Never commit secret values to Git. See `.env.example` for a template.

### Required in Production (`/api/health` checks presence by name only)

| Variable Name | Scope | Purpose |
| :--- | :--- | :--- |
| `TINFOIL_API_KEY` | Server | Authenticates the oblivious HPKE relay (`/api/relay/**`), attested second-pass PII filter (`attestedPiiFilter`), attested 768-d embeddings (`nomic-embed-text`), OpenAI-compatible gateway (`/api/v1/chat/completions`), and daily mystery-shopper SPRT auditor (`/api/cron/auditor`). |
| `MONGODB_URI` | Server | MongoDB Atlas connection string (`mongodb+srv://...`) for the `drouter-app` user (`readWrite` on database `drouter` only). |
| `ARC_RPC_URL` | Server | Circle Arc Testnet JSON-RPC endpoint URL (chain ID `5042002`). |
| `ARC_REGISTRY_ADDRESS` | Server | Deployed `DRouterRegistry` smart contract address on Circle Arc Testnet (`0xbc8085c2b6fe6e0db05f169925c0b841828f4481`). |
| `ARC_VERIFIER_PRIVATE_KEY` | Server | Private key for the authorised Circle Arc Testnet verifier wallet used by `/api/anchor`, `/api/cron/monitor`, and `scripts/publish-filter-fingerprint.mjs` to call `recordVerification` and `anchorReceipt`. |
| `SIM_HARDWARE_SEED` | Server | 32-byte (64-hex-char) secret seed used to derive the server's Ed25519 transparency log tree-head signing key (`src/lib/transparency/log.ts`). |
| `CREDITS_ISSUER_RSA_PQ` | Server | 2,048-bit RSA prime pair (`p_hex:q_hex`) for signing unlinkable Chaumian blind credit tokens (`e_1=65537`, `e_5=65539`, `e_20=65543`). |

### Additional Production & Feature Variables

| Variable Name | Scope | Purpose |
| :--- | :--- | :--- |
| `CREDITS_DEPOSIT_XPUB` | Server | BIP32 extended public key at `m/44'/60'/0'/0` used by `POST /api/credits/invoice` (`deriveDepositAddress`) to derive a fresh, one-time USDC deposit address on Circle Arc Testnet for each credit invoice while keeping the spending private key offline. |
| `CRON_SECRET` | Server + GitHub Actions | Bearer token (`Authorization: Bearer <CRON_SECRET>`) authenticating hourly runs of `GET /api/cron/monitor` (triggered by `.github/workflows/monitor.yml` and daily fallback in `vercel.json`) and daily runs of `GET /api/cron/auditor`. |
| `NEXT_PUBLIC_ARC_REGISTRY_ADDRESS` | Client + Server | Public `DRouterRegistry` contract address (`0xbc8085c2b6fe6e0db05f169925c0b841828f4481`) exposed to the browser for explorer links and verification badges. |
| `GEMINI_API_KEY` | Server | Google Gemini API key for live `gemini-4-argon` control-plane planning in `POST /api/gemini/plan` when `deroute-core` is not deployed. When unset (and `CORE_HOST` is unset), `POST /api/gemini/plan` returns HTTP `503` with `planner: "unavailable"` and `plan: null` (never a fake or simulated plan). |
| `CORE_HOST` | Server | Host and port (`<VM_PUBLIC_IP>:8443`) of the `deroute-core` Google Cloud Confidential Space VM behind `/api/core/[...path]`. Currently unset because the Confidential Space VM is built and reviewed but not yet deployed; while unset, `/api/core/*` returns HTTP `503 { "core": "not-deployed" }`. |
| `CORE_IMAGE_DIGESTS` / `NEXT_PUBLIC_CORE_IMAGE_DIGESTS` | Client + Server | Optional comma-separated `sha256:<64-hex>` allowlist narrowing the committed digest list in `src/lib/attestation/expected-core-digests.json` (`sha256:220578e0d103bfb6969cffde67e332cfaac278a4affc9eba7e84c96253f03207`). Can only narrow, never widen, the committed list. |
| `MONGODB_DB` | Server | Database name override (defaults to `drouter` in production; tests automatically isolate to a separate database). |
| `ATLAS_INGEST_TOKEN` | Server | Shared secret verified in constant time against `X-Atlas-Ingest-Token` on `POST /api/atlas` (`action: "ingest"`). If unset, external document ingestion is disabled (`403`). |
| `ARC_DEPLOYER_PRIVATE_KEY` | Local CLI only | Deployer/owner private key used offline by `scripts/arc-deploy.mjs` and `scripts/arc-seed.mjs`. Never needed on Vercel. |

### Post-Deployment Health Check

After deploying, verify all subsystems and required environment variable names (without exposing values):

```bash
curl -s https://drouter-demo.vercel.app/api/health | jq .
```

Expected response shape:

```json
{
  "ok": true,
  "checks": {
    "mongodb": { "ok": true, "detail": "MongoDB ping succeeded on database drouter" },
    "arcRpc": { "ok": true, "detail": "Arc Testnet RPC reachable at block ..." },
    "tinfoilAttestation": { "ok": true, "detail": "Tinfoil attestation endpoint reachable (HTTP 200)" },
    "env": { "ok": true, "detail": "All 7 required variables present (TINFOIL_API_KEY, MONGODB_URI, ARC_RPC_URL, ARC_REGISTRY_ADDRESS, ARC_VERIFIER_PRIVATE_KEY, SIM_HARDWARE_SEED, CREDITS_ISSUER_RSA_PQ); optional present: ..." }
  }
}
```

---

## 2. MongoDB Atlas Setup & Search Index Script

deRoute uses a MongoDB Atlas M0 cluster running MongoDB 8.0.34 (`drouter` database). The database user `drouter-app` is scoped to `readWrite@drouter`. Because Vercel serverless functions do not have fixed outbound IP addresses, the Atlas network access list is open (`0.0.0.0/0`); authentication is enforced via SCRAM-SHA-256 credentials and zero prompts or PII are stored in the database.

### Initial Cluster Provisioning (One-Time)

If setting up a new Atlas project and M0 cluster from scratch using the Atlas CLI:

```bash
bash scripts/atlas-setup.sh
```

### Seeding the 16-Document Knowledge Corpus & Creating 768-d Search Indexes

Run `scripts/atlas-indexes.mjs` against `.env.local` to upsert the 16 curated confidential-computing provider, hardware advisory, and cryptographic architecture documents (with 768-dimensional L2-normalized embeddings computed via Tinfoil's attested `nomic-embed-text` enclave) into `drouter.enclave_intelligence` and ensure both search indexes are created:

```bash
node --env-file=.env.local scripts/atlas-indexes.mjs
```

This script ensures:
1. Unique B-tree indexes on `enclave_intelligence.docId` and `agent_verification_receipts.receiptId`.
2. **Atlas Search Index (`drouter_text_search`)**: Lucene `standard` analyzer on `title`, `summary`, and `tags`, plus `keyword` analyzer on `category`.
3. **Atlas Vector Search Index (`drouter_vector_index`)**: 768-dimension `cosine` similarity vector index on `embedding` with pre-filtering on `category`.

Wait until both indexes report `status: "READY"` at 768 dimensions so MongoDB 8.0 native `$rankFusion` (`$vectorSearch` + `$search`) executes on Atlas.

---

## 3. Circle Arc Testnet Registry & Mechanical Filter Fingerprint

The on-chain node and receipt registry (`DRouterRegistry`) is deployed on Circle Arc Testnet:
- **Chain ID**: `5042002`
- **Contract Address**: `0xbc8085c2b6fe6e0db05f169925c0b841828f4481`
- **Testnet ERC-20 USDC Contract**: `0x3600000000000000000000000000000000000000` (6 decimals)
- **Block Explorers**: `https://testnet.arcscan.app` and `https://explorer.testnet.arc.io`

### Registered Real Enclave Nodes

`scripts/arc-seed.mjs` revokes any legacy simulated practice nodes (`sim-1`, `sim-2`, `sim-3`) and registers the 6 real Tinfoil enclaves from `https://inference.tinfoil.sh/.well-known/tinfoil-proxy`:
1. `tinfoil-router` (`inference.tinfoil.sh` / `router-0.tinfoil.sh`, `tinfoilsh/confidential-model-router`)
2. `tinfoil-kimi-k3` (`kimi-k3-inf14.tinfoil.containers.tinfoil.dev`, `tinfoilsh/confidential-kimi-k3`)
3. `tinfoil-glm-5-3` (`glm-5-3-inf19-0.tinfoil.containers.tinfoil.dev`, `tinfoilsh/confidential-glm5-3-nvfp4`)
4. `tinfoil-deepseek-v4-1-flash` (`deepseek-v4-1-flash-inf15-0.tinfoil.containers.tinfoil.dev`, `tinfoilsh/confidential-deepseek-v4-1-flash`)
5. `tinfoil-gpt-oss-120b` (`gpt-oss-120b-inf12-0.tinfoil.containers.tinfoil.dev`, `tinfoilsh/confidential-gpt-oss-120b`)
6. `tinfoil-llama3-3-70b` (`llama3-3-70b-inf12.tinfoil.containers.tinfoil.dev`, `tinfoilsh/confidential-llama3-3-70b`)

```bash
node scripts/arc-compile.mjs
node --env-file=.env.local scripts/arc-seed.mjs
```

### Publishing a Mechanical Filter Fingerprint on Circle Arc Testnet

Whenever `MECHANICAL_RULESET` in `src/lib/privacy/mechanical-ruleset.ts` is updated, bump its `version` and anchor the new fingerprint on Circle Arc Testnet:

```bash
# 1. Dry-run: print version, SHA-256 fingerprint, and keccak256 receipt hash without transacting
node scripts/publish-filter-fingerprint.mjs

# 2. Anchor on Circle Arc Testnet and update src/lib/privacy/published-fingerprint.json
node --env-file=.env.local scripts/publish-filter-fingerprint.mjs --confirm
```

Current published filter anchor (`src/lib/privacy/published-fingerprint.json`):
- **Version**: `1.0.1`
- **Fingerprint**: `0x0928121dfa0558ab8e59af0298aa76c5b9a3674012d2ff162b66df79bba20f28`
- **Anchor Transaction**: `0x09055dc1b5d6a79de9d96824ee76213b2c238a8bfd744ab143405d30db1fe730`

---

## 4. Hourly Monitoring Cron & Independent CLI Verification

### Hourly Enclave Monitor (`.github/workflows/monitor.yml`)

Because Vercel Hobby only supports daily cron schedules in `vercel.json`, hourly monitoring of all 6 real Tinfoil enclaves is triggered by GitHub Actions (`.github/workflows/monitor.yml` at `17 * * * *` and backup slot `47 * * * *`) using the `CRON_SECRET` repository secret:

```bash
curl -sS -H "Authorization: Bearer ${CRON_SECRET}" https://drouter-demo.vercel.app/api/cron/monitor | jq .
```

### Independent CLI Verification (`scripts/drouter-cli.mjs`)

Anyone can verify the live enclaves and submit a signed Ed25519 verification claim to `POST /api/transparency/verifications`:

```bash
node scripts/drouter-cli.mjs verify --submit --upstream https://drouter-demo.vercel.app
```

---

## 5. `deroute-core` on Google Cloud Confidential Space (Live)

The `deroute-core` enclave workload (`core/`, image `ghcr.io/thepigdestroyer/deroute-core@sha256:220578e0d103bfb6969cffde67e332cfaac278a4affc9eba7e84c96253f03207` in `src/lib/attestation/expected-core-digests.json`) and its operational scripts in `scripts/gcp/` are deployed on an AMD SEV Confidential Space VM (`n2d-standard-2`, us-central1-a). Production sets `CORE_HOST` and `CORE_IMAGE_DIGESTS`, so `/api/core/*` and `POST /api/gemini/plan` route through the attested VM; `node scripts/gcp/verify-core.mjs` passes all 11 checks.

Once ready to deploy:

```bash
# 1. Deploy or update the Confidential Space VM (sev or tdx) and Secret Manager secrets
PROJECT_ID=<gcp-project-id> \
REGION=us-central1 \
ZONE=us-central1-a \
CHIP=sev \
IMAGE_DIGEST=sha256:220578e0d103bfb6969cffde67e332cfaac278a4affc9eba7e84c96253f03207 \
bash scripts/gcp/deploy-core.sh

# 2. Independently verify the VM's Google Confidential Space PKI token and nonces
CORE_HOST=<VM_PUBLIC_IP>:8443 \
CORE_IMAGE_DIGESTS=sha256:220578e0d103bfb6969cffde67e332cfaac278a4affc9eba7e84c96253f03207 \
node scripts/gcp/verify-core.mjs

# 3. Lifecycle management scripts
PROJECT_ID=<gcp-project-id> ZONE=us-central1-a bash scripts/gcp/stop-core.sh
PROJECT_ID=<gcp-project-id> ZONE=us-central1-a bash scripts/gcp/start-core.sh
PROJECT_ID=<gcp-project-id> REGION=us-central1 ZONE=us-central1-a bash scripts/gcp/destroy-core.sh
```

After `verify-core.mjs` passes, set `CORE_HOST=<VM_PUBLIC_IP>:8443` in Vercel environment variables and redeploy so `/api/core/*` and `POST /api/gemini/plan` route through the attested Confidential Space VM. See [docs/confidential-space.md](confidential-space.md) for the complete 10-check verification specification.

---

## 6. Rotating Secrets & Rollback Procedure

### Rotating Secrets

1. **`TINFOIL_API_KEY`**: Generate a new key in the Tinfoil dashboard, update `TINFOIL_API_KEY` in Vercel, and redeploy.
2. **`MONGODB_URI`**: Rotate the `drouter-app` password in MongoDB Atlas, update `MONGODB_URI` in Vercel (and in Google Cloud Secret Manager if `deroute-core` is deployed), and redeploy.
3. **`ARC_VERIFIER_PRIVATE_KEY`**: Generate a new secp256k1 wallet, fund it with Arc Testnet USDC at `https://faucet.circle.com`, authorise the new verifier on `DRouterRegistry` (`setVerifier(newAddress, true)` and `setVerifier(oldAddress, false)`), update `ARC_VERIFIER_PRIVATE_KEY` in Vercel, and redeploy.
4. **`CREDITS_ISSUER_RSA_PQ`**: Generate two new 1,024-bit primes `p` and `q` coprime to `65537`, `65539`, and `65543` such that `p * q` is 2,048 bits, update `CREDITS_ISSUER_RSA_PQ` (`p_hex:q_hex`) in Vercel, and redeploy (rotating the modulus invalidates previously minted unspent tokens).
5. **`CREDITS_DEPOSIT_XPUB`**: Derive a new BIP32 account extended public key (`m/44'/60'/<account>'/0`) from your offline hardware wallet, update `CREDITS_DEPOSIT_XPUB` in Vercel, and redeploy.
6. **`CRON_SECRET` & `ATLAS_INGEST_TOKEN`**: Generate a new 32-byte hex secret (`openssl rand -hex 32`), update in Vercel (and GitHub Actions repository secrets for `CRON_SECRET`), and redeploy.

### Instant Rollback

```bash
# List recent deployments and roll back production alias immediately
vercel ls
vercel rollback <deployment-id-or-url>

# Verify post-rollback health and enclave attestation
curl -s https://drouter-demo.vercel.app/api/health | jq .
node scripts/drouter-cli.mjs verify --upstream https://drouter-demo.vercel.app
```
