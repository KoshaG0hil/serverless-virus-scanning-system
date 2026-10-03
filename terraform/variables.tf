variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
  default     = "my-gcp-project"
}

variable "region" {
  type        = string
  description = "Google Cloud Region"
  default     = "us-central1"
}

variable "service_name" {
  type        = string
  description = "Cloud Run service name"
  default     = "clamav-malware-scanner"
}

variable "container_image" {
  type        = string
  description = "Container image URL"
  default     = "gcr.io/my-gcp-project/clamav-malware-scanner:latest"
}
