terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ==============================================================================
# S3 3-TIER ISOLATION BUCKETS
# ==============================================================================
resource "aws_s3_bucket" "untrusted" {
  bucket        = "${var.project_name}-untrusted-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket" "clean" {
  bucket        = "${var.project_name}-clean-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket" "quarantine" {
  bucket        = "${var.project_name}-quarantine-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Block public access across all buckets
resource "aws_s3_bucket_public_access_block" "block_untrusted" {
  bucket                  = aws_s3_bucket.untrusted.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "block_clean" {
  bucket                  = aws_s3_bucket.clean.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "block_quarantine" {
  bucket                  = aws_s3_bucket.quarantine.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==============================================================================
# DYNAMODB AUDIT LOG TABLE
# ==============================================================================
resource "aws_dynamodb_table" "scan_logs" {
  name         = "VirusScanLogs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "filename"
  range_key    = "timestamp"

  attribute {
    name = "filename"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }
}

# ==============================================================================
# SNS SECURITY ALERT TOPIC
# ==============================================================================
resource "aws_sns_topic" "malware_alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.malware_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ==============================================================================
# IAM EXECUTION ROLE FOR LAMBDA
# ==============================================================================
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "S3IsolationBucketAccess"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = [
          "${aws_s3_bucket.untrusted.arn}/*",
          "${aws_s3_bucket.clean.arn}/*",
          "${aws_s3_bucket.quarantine.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBLogging"
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = aws_dynamodb_table.scan_logs.arn
      },
      {
        Sid    = "SNSPublishAlerts"
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.malware_alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_perms" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}

# ==============================================================================
# LAMBDA FUNCTION
# ==============================================================================
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "scanner" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-scanner"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 2048

  environment {
    variables = {
      CLEAN_BUCKET      = aws_s3_bucket.clean.id
      QUARANTINE_BUCKET = aws_s3_bucket.quarantine.id
      DYNAMODB_TABLE    = aws_dynamodb_table.scan_logs.name
      SNS_TOPIC_ARN     = aws_sns_topic.malware_alerts.arn
    }
  }
}

# ==============================================================================
# S3 BUCKET NOTIFICATION TRIGGER
# ==============================================================================
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Untrusted"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.untrusted.arn
}

resource "aws_s3_bucket_notification" "untrusted_notification" {
  bucket = aws_s3_bucket.untrusted.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.scanner.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
