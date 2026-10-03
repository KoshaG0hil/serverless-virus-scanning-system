terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ==============================================================================
# GOOGLE CLOUD STORAGE BUCKETS (ISOLATION ARCHITECTURE)
# ==============================================================================
resource "google_storage_bucket" "untrusted" {
  name                        = "${var.project_id}-untrusted-landing"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket" "clean" {
  name                        = "${var.project_id}-clean-safe"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket" "quarantine" {
  name                        = "${var.project_id}-quarantined-malware"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

# ==============================================================================
# CLOUD PUB/SUB SECURITY ALERT TOPIC
# ==============================================================================
resource "google_pubsub_topic" "malware_alerts" {
  name = "malware-scan-alerts"
}

# ==============================================================================
# LEAST-PRIVILEGE SERVICE ACCOUNT
# ==============================================================================
resource "google_service_account" "scanner_sa" {
  account_id   = "clamav-scanner-sa"
  display_name = "ClamAV Cloud Run Scanner Service Account"
}

# Grant Cloud Storage access
resource "google_project_iam_member" "storage_admin" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.scanner_sa.email}"
}

# Grant Firestore access
resource "google_project_iam_member" "datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.scanner_sa.email}"
}

# Grant Pub/Sub publish access
resource "google_pubsub_topic_iam_member" "pubsub_publisher" {
  topic  = google_pubsub_topic.malware_alerts.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.scanner_sa.email}"
}

# ==============================================================================
# GOOGLE CLOUD RUN V2 SERVICE (CONTAINERIZED CLAMAV)
# ==============================================================================
resource "google_cloud_run_v2_service" "scanner" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.scanner_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 20
    }

    containers {
      image = var.container_image

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "CLEAN_BUCKET"
        value = google_storage_bucket.clean.name
      }
      env {
        name  = "QUARANTINE_BUCKET"
        value = google_storage_bucket.quarantine.name
      }
      env {
        name  = "PUBSUB_TOPIC"
        value = google_pubsub_topic.malware_alerts.id
      }
    }
  }
}

# ==============================================================================
# EVENTARC TRIGGER: CLOUD STORAGE TO CLOUD RUN
# ==============================================================================
resource "google_eventarc_trigger" "gcs_trigger" {
  name     = "${var.service_name}-gcs-trigger"
  location = var.region

  matching_criteria {
    attribute = "type"
    value     = "google.cloud.storage.object.v1.finalized"
  }
  matching_criteria {
    attribute = "bucket"
    value     = google_storage_bucket.untrusted.name
  }

  destination {
    cloud_run_service {
      service = google_cloud_run_v2_service.scanner.name
      region  = var.region
      path    = "/scan"
    }
  }

  service_account = google_service_account.scanner_sa.email
}
