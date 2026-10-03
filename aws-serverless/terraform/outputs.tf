output "lambda_arn" {
  description = "ARN of the ClamAV scanning Lambda function"
  value       = aws_lambda_function.scanner.arn
}

output "untrusted_upload_bucket" {
  description = "S3 bucket for incoming unverified uploads"
  value       = aws_s3_bucket.untrusted.id
}

output "clean_files_bucket" {
  description = "S3 bucket for verified clean files"
  value       = aws_s3_bucket.clean.id
}

output "quarantined_files_bucket" {
  description = "S3 bucket for quarantined malware"
  value       = aws_s3_bucket.quarantine.id
}

output "sns_topic_arn" {
  description = "SNS Topic ARN for malware alerts"
  value       = aws_sns_topic.malware_alerts.arn
}
