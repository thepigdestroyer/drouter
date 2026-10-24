#!/usr/bin/env bash
# Stop a running deRoute Confidential Space VM instance to pause compute billing (G7).

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
INSTANCE_NAME="${INSTANCE_NAME:-deroute-core}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is required (set PROJECT_ID=<gcp-project-id>)." >&2
  exit 1
fi

gcloud compute instances stop "${INSTANCE_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

printf 'STOPPED=%s\n' "${INSTANCE_NAME}"
