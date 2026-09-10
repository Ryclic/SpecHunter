#!/usr/bin/env bash
set -euo pipefail

project=${SPECHUNTER_GCP_PROJECT:-spechunter}
zone=${SPECHUNTER_GCP_ZONE:-us-central1-a}
name=${SPECHUNTER_GCP_WORKER:-spechunter-boom-build-1}

case "${1:-}" in
  create)
    gcloud compute instances create "$name" \
      --project="$project" \
      --zone="$zone" \
      --machine-type=e2-standard-8 \
      --image-family=rocky-linux-9-optimized-gcp \
      --image-project=rocky-linux-cloud \
      --boot-disk-size=200GB \
      --boot-disk-type=pd-balanced \
      --max-run-duration=6h \
      --instance-termination-action=DELETE \
      --no-service-account \
      --no-scopes \
      --labels=purpose=spechunter-boom,autodelete=true
    ;;
  status)
    gcloud compute instances describe "$name" --project="$project" --zone="$zone" \
      --format='yaml(name,status,machineType,disks,networkInterfaces,resourceStatus)'
    ;;
  delete)
    gcloud compute instances delete "$name" --project="$project" --zone="$zone"
    ;;
  *)
    echo "usage: $0 {create|status|delete}" >&2
    exit 2
    ;;
esac
