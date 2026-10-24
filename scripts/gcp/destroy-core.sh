#!/usr/bin/env bash
# Tear down the deRoute Confidential Space VM, firewall rule, and static IP (G7).
# Pass PURGE_ALL=1 to also delete the Secret Manager secrets and workload service account.

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
INSTANCE_NAME="${INSTANCE_NAME:-deroute-core}"
SA_NAME="${SA_NAME:-deroute-core}"
ADDRESS_NAME="${ADDRESS_NAME:-deroute-core-ip}"
FIREWALL_RULE_NAME="${FIREWALL_RULE_NAME:-deroute-core-allow-8443}"
PURGE_ALL="${PURGE_ALL:-0}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is required (set PROJECT_ID=<gcp-project-id>)." >&2
  exit 1
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud compute instances describe "${INSTANCE_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute instances delete "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --delete-disks="all" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

if gcloud compute firewall-rules describe "${FIREWALL_RULE_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute firewall-rules delete "${FIREWALL_RULE_NAME}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

if gcloud compute addresses describe "${ADDRESS_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute addresses delete "${ADDRESS_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
fi

if [[ "${PURGE_ALL}" == "1" ]]; then
  for SECRET_NAME in "MONGODB_URI" "GEMINI_API_KEY" "CORE_OPERATOR_TOKEN"; do
    if gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      gcloud secrets delete "${SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --quiet >/dev/null
    fi
  done

  if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts delete "${SA_EMAIL}" \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null
  fi
fi

printf 'DESTROYED=%s\n' "${INSTANCE_NAME}"
