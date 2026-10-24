# Deployment & Operations Runbook (`docs/DEPLOY.md`)

Production URL: `https://drouter-demo.vercel.app`
Repository: `https://github.com/thepigdestroyer/drouter`

---

## 1. Vercel Environment Variables (By Name Only)

Configure the following environment variables in the Vercel project settings (`Production` and `Preview` environments as appropriate). Never commit secret values to Git. See `.env.example` for a complete template.

### Required in Production

| Variable Name | Scope | Purpose |
|---|---|---|
| `TINFOIL_API_KEY` | Server | Authenticates oblivious relay (`/api/relay/**`), OpenAI-compatible gateway (`/api/v1/chat/completions`), and daily mystery-shopper auditor (`/api/cron/auditor`) requests to Tinfoil enclaves. |
| `MONGODB_URI` | Server | MongoDB Atlas connection string (`mongodb+srv://...`) for the `drouter-app` user (`readWrite` on database `drouter` only). |
| `ARC_RPC_URL` | Server | Circle Arc Testnet JSON-RPC endpoint URL (chain ID `5042002`). |
| `ARC_REGISTRY_ADDRESS` | Server | Deployed `DRouterRegistry` smart contract address on Circle Arc Testnet (`0xbc8085c2b6fe6e0db05f169925c0b841828f4481`). |
| `NEXT_PUBLIC_ARC_REGISTRY_ADDRESS` | Client + Server | Public `DRouterRegistry` contract address exposed to the browser for explorer links and verification badges. |
| `ARC_VERIFIER_PRIVATE_KEY` | Server | Private key for the authorised Circle Arc Testnet verifier wallet used by `/api/anchor` to call `recordVerification` and `anchorReceipt`. |
| `SIM_HARDWARE_SEED` | Server | 32-byte hex seed used to derive deterministic simulated hardware roots and node keys (`sim-1`, `sim-2`, `sim-3`). |
| `CREDITS_ISSUER_RSA_PQ` | Server | 2,048-bit RSA prime pair (`p_hex:q_hex`) for signing unlinkable blind credit tokens. |
| `CRON_SECRET` | Server | Secret token sent by Vercel Cron (`Authorization: Bearer <CRON_SECRET>`) to authenticate daily runs of `GET /api/cron/auditor`. |

### Optional in Production

| Variable Name | Scope | Purpose |
|---|---|---|
| `MONGODB_DB` | Server | Database name override (defaults to `drouter`). |
| `ATLAS_INGEST_TOKEN` | Server | Shared secret verified against the `X-Atlas-Ingest-Token` header on `POST /api/atlas` (`action: "ingest"`). If unset, external document ingestion is disabled (`403`). |
| `GEMINI_API_KEY` | Server | Google Gemini API key for live Gemini 4 Argon (`gemini-4-argon`, `gemini-3.8-flash`, `gemini-3.5-flash-lite`) Interactions API calls. When unset, `/api/gemini` runs all local and Tinfoil/Atlas verifiers for real and labels Gemini model synthesis as `mode: "simulated"`. |
| `VOYAGE_API_KEY` | Server | Voyage AI API key for live 128-dimensional query embeddings in `/api/atlas`. When unset, dRouter uses the deterministic `local-hashed-128 (stand-in)` embedding engine. |
| `VOYAGE_MODEL` | Server | Voyage AI model name override (defaults to `voyage-3-lite`). |
| `CREDITS_ISSUER_SEED` | Server | Optional hex seed fallback for local/test RSA credit key derivation when `CREDITS_ISSUER_RSA_PQ` is unset. |
| `ARC_DEPLOYER_PRIVATE_KEY` | Local CLI only | Deployer/operator private key used by `scripts/arc-deploy.mjs` and `scripts/arc-seed.mjs`. Not needed at runtime on Vercel. |

### Post-Deployment Health Check

After deploying, verify all subsystems and required environment variable names (without exposing values) via Interface I4:

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
    "env": { "ok": true, "detail": "All 7 required variables present (...)" }
  }
}
```

---

## 2. MongoDB Atlas Setup & Search Index Script

dRouter uses a MongoDB Atlas cluster running MongoDB 8.0 (`drouter` database). The database user `drouter-app` is scoped to `readWrite@drouter`.

### Initial Cluster Provisioning (One-Time)

If setting up a new Atlas project and M0 cluster from scratch using the Atlas CLI:

```bash
bash scripts/atlas-setup.sh
```

### Seeding Knowledge Documents & Creating Search Indexes

Run `scripts/atlas-indexes.mjs` against `.env.local` to upsert the 16 curated confidential provider and hardware advisory documents (with 128-dimensional unit-normalized embeddings) into `drouter.enclave_intelligence` and ensure the search indexes are created:

```bash
node --env-file=.env.local scripts/atlas-indexes.mjs
```

This script ensures:
1. Unique B-tree indexes on `enclave_intelligence.docId` and `agent_verification_receipts.receiptId`.
2. **Atlas Search Index (`drouter_text_search`)**: Lucene `standard` analyzer on `title`, `summary`, and `tags`, plus `keyword` analyzer on `category`.
3. **Atlas Vector Search Index (`drouter_vector_index`)**: 128-dimension `cosine` similarity vector index on `embedding` with pre-filtering on `category`.

Wait until both indexes report `status: "READY"` in the script output so MongoDB 8.0 native `$rankFusion` (`$vectorSearch` + `$search`) executes on Atlas.

---

## 3. Circle Arc Testnet Registry

The on-chain node and receipt registry (`DRouterRegistry`) is deployed on Circle Arc Testnet:
- **Chain ID**: `5042002`
- **Contract Address**: `0xbc8085c2b6fe6e0db05f169925c0b841828f4481`
- **Block Explorers**: `https://testnet.arcscan.app` and `https://explorer.testnet.arc.io`

**Important**: Do not redeploy the registry contract in normal operations; point `ARC_REGISTRY_ADDRESS` and `NEXT_PUBLIC_ARC_REGISTRY_ADDRESS` to `0xbc8085c2b6fe6e0db05f169925c0b841828f4481`.

If you ever need to compile or seed nodes on a fresh contract:
1. Compile `contracts/DRouterRegistry.sol` to `src/lib/arc/artifact.json`:
   ```bash
   node scripts/arc-compile.mjs
   ```
2. Ensure `ARC_DEPLOYER_PRIVATE_KEY` is funded with Arc Testnet USDC from `https://faucet.circle.com` (minimum gas fee on Arc is 20 gwei).
3. Seed the 4 demo nodes (`tinfoil-router`, `sim-1`, `sim-2`, `sim-3`):
   ```bash
   node --env-file=.env.local scripts/arc-seed.mjs
   ```

---

## 4. Rotating Secrets

All secrets can be rotated without downtime by updating the Vercel environment variable and triggering a redeploy.

1. **`TINFOIL_API_KEY`**:
   - Generate a new API key in the Tinfoil dashboard.
   - Update in Vercel: `printf '%s' "$NEW_KEY" | vercel env add TINFOIL_API_KEY production --force`
   - Redeploy production.
2. **`MONGODB_URI` (Database Password Rotation)**:
   - Generate a new random password (`openssl rand -hex 24`) and update the `drouter-app` user in MongoDB Atlas (`atlas dbusers update drouter-app --password ...`).
   - Update `MONGODB_URI` in Vercel (`vercel env add MONGODB_URI production --force`) and redeploy.
3. **`ARC_VERIFIER_PRIVATE_KEY`**:
   - Generate a new secp256k1 wallet and fund it with Arc Testnet USDC at `https://faucet.circle.com`.
   - Using the deployer key (`owner` of `DRouterRegistry`), authorise the new verifier (`setVerifier(newAddress, true)`) and revoke the old verifier (`setVerifier(oldAddress, false)`).
   - Update `ARC_VERIFIER_PRIVATE_KEY` in Vercel and redeploy.
4. **`CREDITS_ISSUER_RSA_PQ`**:
   - Generate two new 1,024-bit primes `p` and `q` coprime to `65537`, `65539`, and `65543` such that `p * q` is 2,048 bits.
   - Update `CREDITS_ISSUER_RSA_PQ` (`p_hex:q_hex`) in Vercel and redeploy. Note: rotating the issuer modulus invalidates previously minted unspent client credit tokens.
5. **`CRON_SECRET` & `ATLAS_INGEST_TOKEN`**:
   - Generate a new 32-byte hex secret (`openssl rand -hex 32`), update in Vercel (`vercel env add CRON_SECRET production --force`), and redeploy. Vercel Cron automatically sends `Authorization: Bearer <CRON_SECRET>` on scheduled `/api/cron/auditor` invocations.

---

## 5. Rollback Procedure

If a production deployment introduces a regression or fails `/api/health`:

1. **Instant Rollback via Vercel CLI**:
   ```bash
   # List recent deployments and identify the last known-good deployment URL or ID
   vercel ls

   # Roll back production alias immediately (zero rebuild time)
   vercel rollback <deployment-id-or-url>
   ```
2. **Rollback via Vercel Dashboard**:
   - Navigate to the project's **Deployments** tab, open the menu on the previous healthy production deployment, and select **Instant Rollback**.
3. **Verify Post-Rollback State**:
   - Confirm `/api/health` returns `{"ok": true}`:
     ```bash
     curl -s https://drouter-demo.vercel.app/api/health | jq .
     ```
   - Run the CLI attestation verifier against production:
     ```bash
     node scripts/drouter-cli.mjs verify --upstream https://drouter-demo.vercel.app
     ```
