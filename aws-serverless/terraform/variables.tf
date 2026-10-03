variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "serverless-malware-scanner"
}

variable "alert_email" {
  type        = string
  description = "Email address for malware detection alerts"
  default     = "security-alerts@example.com"
}
