# 🛡️ Serverless Malware & Virus Scanning System (Google Cloud Run + ClamAV)

[![Google Cloud](https://img.shields.io/badge/Google_Cloud-Cloud_Run_|_GCS_|_Eventarc_|_Firestore-blue.svg)](https://cloud.google.com/)
[![ClamAV](https://img.shields.io/badge/Antivirus-ClamAV_Engine-red.svg)](https://www.clamav.net/)
[![Docker](https://img.shields.io/badge/Container-Docker_OCI-2496ED.svg)](https://www.docker.com/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform_GCP-purple.svg)](https://www.terraform.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, event-driven serverless malware scanning pipeline built on **Google Cloud Platform (GCP)**. Automatically intercepts file uploads to Google Cloud Storage, scans payloads in an isolated **Google Cloud Run** containerized sandbox using the **ClamAV** engine, isolates malicious threats in a quarantine bucket, logs audit trails to **Cloud Firestore**, and dispatches instant security alerts via **Cloud Pub/Sub**.

---

## 🎯 Architectural Motivation: Why Google Cloud Run Over Lambda?

Traditional serverless antivirus scanning on function-as-a-service (FaaS) platforms like AWS Lambda faces severe architectural bottlenecks:
- **Package Size Limits**: ClamAV's daily virus signature databases (`daily.cvd`, `main.cvd`, `bytecode.cvd`) continuously grow and exceed **350MB+**, violating standard uncompressed layer limits (250MB) and requiring fragile EC2 compilation workflows.
- **Cold Starts & Memory Pressures**: Loading massive signature databases into short-lived function memory causes severe cold starts and execution timeouts.
- **Database Freshness**: Signature databases cannot run persistent background update daemons (`freshclam`) inside ephemeral functions.

### 💡 The Solution: Google Cloud Run Containerization
By architecting this system on **Google Cloud Run**, we achieve the best of both worlds:
1. **Containerized Freedom**: Package full ClamAV binaries and the complete virus definition database inside a standard Docker OCI container with zero size restrictions.
2. **True Serverless Economics**: Scales to zero when idle; autoscales instantly to handle high-throughput file upload spikes.
3. **Automated Signature Updates**: Runs a lightweight background daemon (`freshclam`) that updates threat signatures continuously without redeploying code.
4. **Zero-Trust Storage Isolation**: Employs three segregated Google Cloud Storage (GCS) buckets ensuring unverified uploads never reach business workloads.

---

## 🏛️ System Architecture

```text
                               ┌────────────────────────────────────────────────────────┐
                               │                 Google Cloud Platform                  │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
                                        User / Client Uploads Object
                                                           │
                                                           ▼
                                            ┌─────────────────────────────┐
                                            │     GCS: Landing Bucket     │
                                            │ (Untrusted / Quarantine In) │
                                            └──────────────┬──────────────┘
                                                           │
                                        Object Finalized Event Notification
                                                           │
                                                           ▼
                                            ┌─────────────────────────────┐
                                            │      Google Eventarc        │
                                            │   (Cloud Storage Trigger)   │
                                            └──────────────┬──────────────┘
                                                           │ HTTP POST /scan
                                                           ▼
                                            ┌─────────────────────────────┐
                                            │      Google Cloud Run       │
                                            │   (Containerized ClamAV)    │
                                            │  • SHA-256 Hash Generation  │
                                            │  • ClamAV Antivirus Scan    │
                                            │  • Metadata Tagging         │
                                            └──────────────┬──────────────┘
                                                           │
                            ┌──────────────────────────────┼──────────────────────────────┐
                            │ (If Clean)                   │ (If Infected)                │
                            ▼                              ▼                              ▼
                 ┌────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
                 │  GCS: Clean Bucket │         │   GCS: Quarantine  │         │  Cloud Firestore   │
                 │   (Safe Storage)   │         │       Bucket       │         │ (Audit Log / Hashes│
                 └────────────────────┘         └──────────┬─────────┘         └────────────────────┘
                                                           │
                                                           ▼
                                                ┌────────────────────┐
                                                │   Cloud Pub/Sub    │
                                                │ (Immediate Alert)  │
                                                └────────────────────┘
```

---

## 🛠️ Google Cloud Services & Tech Stack

| Service | Category | Purpose in Architecture |
| :--- | :--- | :--- |
| **Google Cloud Run** | Compute | Serverless container execution running ClamAV daemon (`clamd`) and Flask ingestion webhook. |
| **Google Cloud Storage (GCS)** | Object Storage | Provides 3-tier bucket isolation (`untrusted-landing`, `clean-safe`, `quarantined-malware`). |
| **Google Eventarc** | Event Routing | Captures `google.cloud.storage.object.v1.finalized` events and triggers Cloud Run over secure HTTP. |
| **Google Cloud Firestore** | NoSQL Database | Stores tamper-evident scan audit logs, SHA-256 file hashes, malware signatures, and timestamps. |
| **Google Cloud Pub/Sub** | Messaging | Dispatches real-time security alerts to SecOps teams / Slack webhooks when threats are detected. |
| **Google Cloud Build** | CI/CD | Builds and pushes Docker container images to Google Container Registry (GCR) / Artifact Registry. |
| **GCP IAM & Service Accounts** | Security | Enforces least-privilege service account roles (`roles/storage.objectAdmin`, `roles/datastore.user`). |
| **ClamAV & FreshClam** | Threat Intelligence | Open-source antivirus engine detecting trojans, viruses, malware, and ransomware. |

---

## 📂 Project Structure

```
serverless-virus-scanning-system/
├── Dockerfile                   # Multi-stage container packaging ClamAV, freshclam & Python
├── entrypoint.sh                # Container bootstrap starting clamd, freshclam daemon & gunicorn
├── deploy.sh                    # Automated 1-click gcloud deployment script
├── requirements.txt             # Google Cloud SDK & Flask dependencies
├── src/
│   ├── __init__.py
│   ├── app.py                   # Flask microservice handling Eventarc / GCS webhooks
│   ├── scanner.py               # ClamAV scan wrapper & SHA-256 cryptographic hashing
│   ├── gcs_handler.py           # GCS object promotion, quarantine move & metadata tagging
│   ├── database.py              # Cloud Firestore audit log persistence
│   └── notifier.py              # Cloud Pub/Sub threat alert dispatcher
├── terraform/
│   ├── main.tf                  # Complete GCP Infrastructure as Code (Cloud Run, GCS, Eventarc)
│   ├── variables.tf             # Input variables (project_id, region, image)
│   └── outputs.tf               # Exported bucket names and Cloud Run URLs
├── tests/
│   ├── __init__.py
│   └── test_scanner.py          # Unit tests for clean files, SHA-256, and EICAR malware test string
└── README.md
```

---

## 🚀 Deployment & Setup

### Prerequisites
- [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and authenticated:
  ```bash
  gcloud auth login
  gcloud config set project <YOUR_GCP_PROJECT_ID>
  ```
- Docker installed locally (or use Google Cloud Build).

---

### Option 1: 1-Click Automated Deployment (`deploy.sh`)
Run the automated deployment script to enable APIs, create buckets, build the container, and deploy Cloud Run:

```bash
chmod +x deploy.sh
./deploy.sh
```

---

### Option 2: Infrastructure as Code via Terraform
Deploy the entire pipeline reproducibly using Terraform:

```bash
cd terraform

# Initialize and deploy
terraform init
terraform plan -var="project_id=YOUR_PROJECT_ID"
terraform apply -var="project_id=YOUR_PROJECT_ID"
```

---

## 🧪 Testing the Malware Scanner

### 1. Test Clean File Upload
Upload a safe text file to your untrusted landing bucket:
```bash
echo "Hello, this is a clean file." > clean_sample.txt
gcloud storage cp clean_sample.txt gs://<PROJECT_ID>-untrusted-landing/
```
**Verification:**
- File is scanned in Cloud Run and moved to `gs://<PROJECT_ID>-clean-safe/clean_sample.txt`.
- Object in landing bucket is deleted.
- Audit log is created in Cloud Firestore with verdict `CLEAN`.

### 2. Test Malware Detection & Quarantine (EICAR Test String)
Upload the industry-standard [EICAR Antivirus Test File](https://www.eicar.org/download-anti-malware-testfile/) (a harmless string designed to test antivirus scanners):
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar_test.txt
gcloud storage cp eicar_test.txt gs://<PROJECT_ID>-untrusted-landing/
```
**Verification:**
- ClamAV flags malware signature: `Win.Test.EICAR_HDB-1 FOUND`.
- File is immediately isolated in `gs://<PROJECT_ID>-quarantined-malware/eicar_test.txt`.
- An alert is published to Cloud Pub/Sub:
  ```json
  {
    "alert": "MALWARE_DETECTED",
    "severity": "CRITICAL",
    "filename": "eicar_test.txt",
    "signature": "Win.Test.EICAR_HDB-1",
    "quarantined_location": "gs://<PROJECT_ID>-quarantined-malware/eicar_test.txt"
  }
  ```
- Permanent audit log with SHA-256 hash is recorded in Cloud Firestore.

---

## 🔒 Security Best Practices Implemented

- **Zero-Trust Bucket Isolation**: Incoming untrusted files are physically separated from production read buckets. Applications only read from the verified `clean-safe` bucket.
- **Least-Privilege Service Accounts**: The Cloud Run service account is only granted permissions to specific buckets and Firestore collections, blocking broader project access.
- **Cryptographic File Verification**: Computes SHA-256 hashes of every scanned object to establish chain-of-custody and prevent duplicate processing.
- **Automatic Container Cleanup**: Scanned payloads are stored only in memory or temporary ephemeral container disk (`/tmp`) and wiped immediately post-scan.

---

## 👩‍💻 Built By

**Kosha Gohil**  
Cloud Support Associate | Cloud Security | CompTIA Security+  

### Key Accomplishments & Business Impact:
- **Overcame FaaS Limits**: Re-architected malware scanning from Lambda layer restrictions (250MB limit) to **Google Cloud Run**, eliminating build failures caused by growing 350MB+ ClamAV signature definitions.
- **Automated Real-Time Ingestion**: Integrated **Google Eventarc** to intercept Cloud Storage uploads within milliseconds, removing manual security reviews and preventing malware propagation.
- **Auditable Zero-Trust Storage**: Built an automated 3-tier GCS isolation workflow backed by **Cloud Firestore** for compliance and forensic tracking.

---

## 📜 License
Distributed under the **MIT License**.
