#!/bin/bash
# ==============================================================================
# Google Cloud Run ClamAV Deployment Script
# ==============================================================================
set -e

PROJECT_ID=$(gcloud config get-value project)
REGION=${GCP_REGION:-"us-central1"}
SERVICE_NAME="clamav-malware-scanner"

echo "========================================================================"
echo " 🛡️ Deploying ClamAV Scanner Microservice to Google Cloud Run"
echo " Target Project: ${PROJECT_ID}"
echo " Region:         ${REGION}"
echo "========================================================================"

if [ -z "$PROJECT_ID" ]; then
    echo "[-] Error: No active GCP project configured. Run 'gcloud config set project <PROJECT_ID>' first."
    exit 1
fi

echo "[1/4] Enabling required Google Cloud APIs..."
gcloud services enable \
    run.googleapis.com \
    storage.googleapis.com \
    eventarc.googleapis.com \
    firestore.googleapis.com \
    pubsub.googleapis.com \
    cloudbuild.googleapis.com

echo "[2/4] Provisioning isolated Google Cloud Storage buckets..."
UNTRUSTED_BUCKET="${PROJECT_ID}-untrusted-landing"
CLEAN_BUCKET="${PROJECT_ID}-clean-safe"
QUARANTINE_BUCKET="${PROJECT_ID}-quarantined-malware"

gcloud storage buckets create "gs://${UNTRUSTED_BUCKET}" --location="${REGION}" --uniform-bucket-level-access || true
gcloud storage buckets create "gs://${CLEAN_BUCKET}" --location="${REGION}" --uniform-bucket-level-access || true
gcloud storage buckets create "gs://${QUARANTINE_BUCKET}" --location="${REGION}" --uniform-bucket-level-access || true

echo "[3/4] Building container and deploying to Google Cloud Run..."
gcloud builds submit --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

gcloud run deploy "${SERVICE_NAME}" \
    --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest" \
    --platform managed \
    --region "${REGION}" \
    --memory 2Gi \
    --cpu 2 \
    --concurrency 10 \
    --timeout 300 \
    --set-env-vars "CLEAN_BUCKET=${CLEAN_BUCKET},QUARANTINE_BUCKET=${QUARANTINE_BUCKET}" \
    --no-allow-unauthenticated

echo "[4/4] Configuring Eventarc trigger for Cloud Storage upload events..."
gcloud eventarc triggers create "${SERVICE_NAME}-trigger" \
    --location="${REGION}" \
    --destination-run-service="${SERVICE_NAME}" \
    --destination-run-path="/scan" \
    --event-filters="type=google.cloud.storage.object.v1.finalized" \
    --event-filters="bucket=${UNTRUSTED_BUCKET}" || true

echo "========================================================================"
echo " ✅ Deployment Complete!"
echo " Upload files to: gs://${UNTRUSTED_BUCKET}/"
echo " Clean files ->   gs://${CLEAN_BUCKET}/"
echo " Quarantine ->    gs://${QUARANTINE_BUCKET}/"
echo "========================================================================"
