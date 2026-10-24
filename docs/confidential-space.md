# deRoute Core on Google Cloud Confidential Space

## Plain Explanation

### What Runs in the Sealed Google Computer

In deRoute, all private document work happens locally inside your browser first: your browser scrubs personal identifiers (names, emails, account numbers, secrets) and builds a **content-free task descriptor** containing only bucketed token counts, redaction category counts (0 to 5), and opaque handles (`$INPUT`). Your raw prompt text never leaves your device.

The sealed Google computer (`deroute-core`, running inside **Google Cloud Confidential Space**) handles the public, verifiable coordination steps:
1. **Whole-library knowledge corpus (`GET /knowledge/corpus`)**: Serves the identical 16-document public reference library to every caller so your topic of interest cannot be inferred from a search query.
2. **Content-free control-plane planning (`POST /agent/plan`)**: Inspects the content-free task descriptor, verifies that zero free text or smuggled strings are present, calls the `gemini-4-argon` control plane with only that content-free descriptor, and signs an Ed25519 **egress receipt** proving the exact bytes sent to Gemini.
3. **Transparency log tree-head signing (`POST /transparency/sign-tree-head`)**: Verifies the append-only Merkle tree state and signs hourly tree heads with an attested Ed25519 key.

At boot time, the sealed computer generates three keys in hardware-encrypted RAM that are never written to disk and never exported:
- `egress-signing` (Ed25519) for signing Gemini control-plane egress receipts,
- `tree-signing` (Ed25519) for signing Merkle transparency tree heads,
- an ephemeral ECDSA P-256 TLS key and self-signed certificate for port `8443`.

### What Google and the Operator Can and Cannot See

| Party | What They Can See | What They Cannot See |
| :--- | :--- | :--- |
| **Your Browser** | Your raw prompt, redacted prompt, local RAG history, and all cryptographic signatures and attestation tokens. | Cloud operator secrets (`GEMINI_API_KEY`, `MONGODB_URI`, `CORE_OPERATOR_TOKEN`). |
| **Vercel Proxy (`/api/core/*`)** | Your request to fetch the public corpus or submit a content-free task descriptor. | Your raw or scrubbed prompt text (which never leaves your browser), or the private keys inside the Confidential Space VM. |
| **Google Cloud / Confidential Space VM** | The public container image (`ghcr.io/thepigdestroyer/deroute-core@sha256:<digest>`), the content-free task descriptor, and Vercel's outbound IP address. | **Your IP address, cookies, or browser User-Agent** (stripped by the Vercel proxy), your raw or scrubbed prompt, and the in-memory signing keys (protected by AMD SEV or Intel TDX memory encryption). Container stdout/stderr log redirection and memory monitoring are locked to `never` in the image launch policy. |

### Why User IP Addresses Never Reach the VM or Google

Your browser never connects directly to the Confidential Space VM. Instead, requests go to the Next.js route `/api/core/[...path]` on Vercel, which enforces a strict 5-path allowlist (`attestation`, `keys`, `health`, `knowledge/corpus`, `agent/plan`) and strips `X-Forwarded-For`, `X-Real-IP`, `Cookie`, and `User-Agent` before opening a pinned TLS connection to the VM.

Because every critical artifact (the Google PKI attestation token, the Ed25519 egress receipt, and the Merkle tree head) is cryptographically signed inside the sealed VM and re-verified in your browser using `@peculiar/x509` and WebCrypto, the Vercel proxy cannot tamper with responses undetected.

---

## Technical Verification Steps

Anyone can verify the live Confidential Space workload either in the browser or from the command line using `scripts/gcp/verify-core.mjs` or `verifyConfidentialSpaceAttestation()` in `src/lib/attestation/confidential-space.ts`.

### Command-Line Verification

```bash
CORE_HOST=<VM_PUBLIC_IP>:8443 \
CORE_IMAGE_DIGESTS=sha256:<PUBLISHED_IMAGE_DIGEST> \
node scripts/gcp/verify-core.mjs
```

### Exact Cryptographic and Claim Checks (G4)

The shared verifier (`src/lib/attestation/confidential-space.ts`) runs the following 10 checks on the PKI JWT returned by `GET /attestation`:

1. **`jwt_header_and_x5c`**: Splits the compact JWS (`header.payload.signature`), verifies `header.alg === "RS256"`, and checks that `header.x5c` contains exactly 3 DER certificates (`[leaf, intermediate, root]`).
2. **`pinned_root_ca`**: Parses `x5c[2]` and verifies that its raw DER bytes and SHA-256 fingerprint equal the pinned Google Confidential Space Root CA:
   - SHA-256: `148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39`
   - SHA-1: `B95120742C24E3AA34042E1C3BA3AAD28B212321` (matches Google's published digest at `https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources#request`).
3. **`x5c_chain_and_validity`**: Verifies that the leaf certificate is signed by the intermediate CA, the intermediate CA is signed by the root CA, the root CA is self-signed, CA basic constraints hold, and all three certificates are within their `notBefore` .. `notAfter` validity window at verification time.
4. **`jwt_rs256_signature`**: Verifies the `RSASSA-PKCS1-v1_5` SHA-256 signature over the ASCII `header.payload` bytes using the leaf certificate's public key via WebCrypto.
5. **`issuer_and_audience`**: Confirms `iss === "https://confidentialcomputing.googleapis.com"` and `aud === "https://drouter-demo.vercel.app/deroute-core"`.
6. **`token_lifetime`**: Validates numeric `nbf`, `iat`, and `exp` claims against the current Unix timestamp with a 60-second clock-skew tolerance.
7. **`confidential_space_posture`**: Requires `swname === "CONFIDENTIAL_SPACE"`, `dbgstat === "disabled-since-boot"` (rejecting `confidential-space-debug`), `secboot === true`, and `submods.confidential_space.support_attributes` containing `"STABLE"`.
8. **`hardware_tee_model`**: Requires `hwmodel` to be in `["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"]` and reports the active hardware isolation technology.
9. **`container_image_digest`**: Requires `submods.container.image_digest` to match one of the expected `sha256:<64-hex>` digests configured in `CORE_IMAGE_DIGESTS`.
10. **`container_env_override` & `eat_nonce_binding`**:
    - Requires `Object.keys(submods.container.env_override ?? {})` to be a subset of `["CORE_KEY_SOURCE", "CORE_PUBLIC_ORIGIN"]` (conforming to Dockerfile label `tee.launch_policy.allow_env_override`).
    - Recomputes `keysDigest = sha256(canonicalJson({ egress, tree }))` and `tlsSpkiDigest = sha256(tlsCert.publicKey.rawData)` and requires `eat_nonce` to contain both 64-character lowercase hex digests.

### Verify-Then-Pin TLS in `/api/core/[...path]` (G5)

1. When a request arrives at `/api/core/<path>`, the proxy first checks if it holds a cached attestation for `CORE_HOST` that is at least 5 minutes (`300 s`) away from `exp`.
2. On a cold cache, the proxy connects to `https://<CORE_HOST>:8443/attestation`, captures the peer TLS certificate's raw DER bytes from the TLS socket, and runs `verifyConfidentialSpaceAttestation()` with those exact certificate bytes.
3. Once verified, the proxy caches `tlsSpkiSha256` until `exp - 300` seconds and pins all subsequent `node:https` requests using a `checkServerIdentity` and `secureConnect` callback that computes `sha256(peerCert.publicKey.spkiDer)` and aborts the connection if it differs from the attested `tlsSpkiSha256`.

### Official Google Cloud References

- [Access resources not managed by Google Cloud IAM (PKI tokens & unix socket)](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)
- [Confidential Space attestation token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Confidential Space launch policies](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies)
- [Confidential Space workload metadata variables](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables)
- [Deploy Confidential Space workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)
- [Create and customize Confidential Space workloads](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-customize-workloads)
