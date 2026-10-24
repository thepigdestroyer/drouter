#!/usr/bin/env bash
# Start a stopped deRoute Confidential Space VM instance and print its public IP (G7).

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
INSTANCE_NAME="${INSTANCE_NAME:-deroute-core}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is required (set PROJECT_ID=<gcp-project-id>)." >&2
  exit 1
fi

gcloud compute instances start "${INSTANCE_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

PUBLIC_IP="$(gcloud compute instances describe "${INSTANCE_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT_ID}" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"

printf 'STARTED=%s\n' "${INSTANCE_NAME}"
printf 'PUBLIC_IP=%s\n' "${PUBLIC_IP}"
