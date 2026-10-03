output "cloud_run_service_url" {
  description = "URL of the deployed Cloud Run ClamAV scanner service"
  value       = google_cloud_run_v2_service.scanner.uri
}

output "untrusted_upload_bucket" {
  description = "GCS bucket for incoming untrusted uploads"
  value       = google_storage_bucket.untrusted.name
}

output "clean_files_bucket" {
  description = "GCS bucket for verified safe files"
  value       = google_storage_bucket.clean.name
}

output "quarantined_files_bucket" {
  description = "GCS bucket for isolated malware"
  value       = google_storage_bucket.quarantine.name
}
