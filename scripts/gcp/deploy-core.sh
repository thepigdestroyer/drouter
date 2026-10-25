#!/usr/bin/env bash
# Deploy or update the deRoute core workload on Google Cloud Confidential Space (G7).
#
# Official references:
# - Deploy workloads: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads
# - Metadata variables: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables
# - Launch policies: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies
#
# Security invariants:
# - Uses the production `confidential-space` image family from `confidential-space-images` (never `confidential-space-debug`).
# - Secrets (`MONGODB_URI`, `GEMINI_API_KEY`, `CORE_OPERATOR_TOKEN`) are stored in Secret Manager via stdin
#   (`printf %s "$v" | gcloud secrets versions add NAME --data-file=-`) and never passed via `tee-env-*` metadata
#   or echoed to stdout/stderr.
# - `roles/secretmanager.secretAccessor` is granted per secret only (never project-wide).

set -euo pipefail
set +x

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
CHIP="${CHIP:-sev}"
INSTANCE_NAME="${INSTANCE_NAME:-deroute-core}"
SA_NAME="${SA_NAME:-deroute-core}"
ADDRESS_NAME="${ADDRESS_NAME:-deroute-core-ip}"
FIREWALL_RULE_NAME="${FIREWALL_RULE_NAME:-deroute-core-allow-8443}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/thepigdestroyer/deroute-core}"
IMAGE_DIGEST="${IMAGE_DIGEST:-}"
CORE_PUBLIC_ORIGIN="${CORE_PUBLIC_ORIGIN:-https://drouter-demo.vercel.app}"
ENV_FILE="${ENV_FILE:-.env.local}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is required (set PROJECT_ID=<gcp-project-id>)." >&2
  exit 1
fi

if [[ -z "${IMAGE_DIGEST}" || ! "${IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Error: IMAGE_DIGEST must be set to a full sha256:<64-hex> digest." >&2
  exit 1
fi

case "${CHIP}" in
  sev)
    MACHINE_TYPE="n2d-standard-2"
    CONFIDENTIAL_COMPUTE_TYPE="SEV"
    MAINTENANCE_POLICY="MIGRATE"
    MIN_CPU_PLATFORM="AMD Milan"
    ;;
  tdx)
    MACHINE_TYPE="c3-standard-4"
    CONFIDENTIAL_COMPUTE_TYPE="TDX"
    MAINTENANCE_POLICY="TERMINATE"
    MIN_CPU_PLATFORM=""
    ;;
  *)
    echo "Error: CHIP must be 'sev' or 'tdx' (got '${CHIP}')." >&2
    exit 1
    ;;
esac

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
IMAGE_REF="${IMAGE_REPO}@${IMAGE_DIGEST}"

# 1. Enable required Google Cloud APIs
gcloud services enable \
  compute.googleapis.com \
  confidentialcomputing.googleapis.com \
  secretmanager.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

# 2. Ensure dedicated workload service account exists
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="deRoute Confidential Space Workload" \
    --description="Least-privilege service account for deroute-core Confidential Space VM" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

# Grant only workloadUser and logWriter at project scope
for ROLE in "roles/confidentialcomputing.workloadUser" "roles/logging.logWriter"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None \
    --quiet >/dev/null
done

# Helper to read a secret from macOS Keychain first, then .env.local, without printing
read_secret_value() {
  local env_name="$1"
  local keychain_service="$2"
  local val=""

  if [[ -n "${!env_name:-}" ]]; then
    printf '%s' "${!env_name}"
    return 0
  fi

  if command -v security >/dev/null 2>&1 && [[ -n "${keychain_service}" ]]; then
    val="$(security find-generic-password -a "${USER}" -s "${keychain_service}" -w 2>/dev/null || true)"
    if [[ -n "${val}" ]]; then
      printf '%s' "${val}"
      return 0
    fi
  fi

  if [[ -f "${ENV_FILE}" ]]; then
    val="$(grep -E "^${env_name}=" "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2- || true)"
    val="${val#\"}"
    val="${val%\"}"
    val="${val#\'}"
    val="${val%\'}"
    if [[ -n "${val}" ]]; then
      printf '%s' "${val}"
      return 0
    fi
  fi

  return 1
}

upsert_secret() {
  local secret_name="$1"
  local keychain_service="$2"
  local v=""
  local existing=""

  if ! v="$(read_secret_value "${secret_name}" "${keychain_service}")" || [[ -z "${v}" ]]; then
    echo "Error: Secret ${secret_name} not found in environment, macOS Keychain (${keychain_service}), or ${ENV_FILE}." >&2
    exit 1
  fi

  if ! gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud secrets create "${secret_name}" \
      --replication-policy="automatic" \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null
  else
    existing="$(gcloud secrets versions access latest --secret="${secret_name}" --project="${PROJECT_ID}" 2>/dev/null || true)"
  fi

  # Only add a new version if no version exists or the secret value changed
  if [[ -z "${existing}" || "${existing}" != "${v}" ]]; then
    printf %s "$v" | gcloud secrets versions add "${secret_name}" \
      --data-file=- \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null
  fi
  unset existing
  unset v

  # Grant secretAccessor on this individual secret only
  gcloud secrets add-iam-policy-binding "${secret_name}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
}

# 3. Provision secrets in Secret Manager via stdin and bind per-secret IAM
upsert_secret "MONGODB_URI" "mongodb-uri"
upsert_secret "GEMINI_API_KEY" "gemini-api-key"
upsert_secret "CORE_OPERATOR_TOKEN" "core-operator-token"

# 4. Reserve static regional external IPv4 address
if ! gcloud compute addresses describe "${ADDRESS_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute addresses create "${ADDRESS_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

PUBLIC_IP="$(gcloud compute addresses describe "${ADDRESS_NAME}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --format='value(address)')"

# 5. Ensure VPC firewall rule allows TCP:8443 to network tag deroute-core
if ! gcloud compute firewall-rules describe "${FIREWALL_RULE_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute firewall-rules create "${FIREWALL_RULE_NAME}" \
    --allow="tcp:8443" \
    --direction="INGRESS" \
    --source-ranges="0.0.0.0/0" \
    --target-tags="deroute-core" \
    --description="Allow inbound HTTPS (8443) to deRoute Confidential Space workload" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

# 6. Create or update the Confidential Space VM
# Non-secret metadata only; tee-container-log-redirect is omitted (defaults to false, enforced by launch_policy.log_redirect=never).
METADATA="^~^tee-image-reference=${IMAGE_REF}~tee-restart-policy=Always~tee-env-CORE_KEY_SOURCE=boot~tee-env-CORE_PUBLIC_ORIGIN=${CORE_PUBLIC_ORIGIN}~tee-env-CORE_SECRETS_SOURCE=gcp-secret-manager"

if gcloud compute instances describe "${INSTANCE_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  INSTANCE_STATUS="$(gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT_ID}" \
    --format='value(status)')"
  gcloud compute instances add-metadata "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT_ID}" \
    --metadata="${METADATA}" \
    --quiet >/dev/null
  if [[ "${INSTANCE_STATUS}" == "RUNNING" ]]; then
    gcloud compute instances stop "${INSTANCE_NAME}" \
      --zone="${ZONE}" \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null
  fi
  gcloud compute instances start "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
else
  CREATE_ARGS=(
    compute instances create "${INSTANCE_NAME}"
    --confidential-compute-type="${CONFIDENTIAL_COMPUTE_TYPE}"
    --machine-type="${MACHINE_TYPE}"
    --maintenance-policy="${MAINTENANCE_POLICY}"
    --shielded-secure-boot
    --image-project="confidential-space-images"
    --image-family="confidential-space"
    --metadata="${METADATA}"
    --service-account="${SA_EMAIL}"
    --scopes="cloud-platform"
    --tags="deroute-core"
    --address="${PUBLIC_IP}"
    --zone="${ZONE}"
    --project="${PROJECT_ID}"
    --quiet
  )
  if [[ -n "${MIN_CPU_PLATFORM}" ]]; then
    CREATE_ARGS+=(--min-cpu-platform="${MIN_CPU_PLATFORM}")
  fi
  gcloud "${CREATE_ARGS[@]}" >/dev/null
fi

printf 'PUBLIC_IP=%s\n' "${PUBLIC_IP}"
printf 'IMAGE_DIGEST=%s\n' "${IMAGE_DIGEST}"
printf 'VERIFY_COMMAND=CORE_HOST=%s:8443 CORE_IMAGE_DIGESTS=%s node scripts/gcp/verify-core.mjs\n' "${PUBLIC_IP}" "${IMAGE_DIGEST}"
