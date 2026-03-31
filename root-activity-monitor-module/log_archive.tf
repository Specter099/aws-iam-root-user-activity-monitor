// S3 Log Archive Bucket + Kinesis Data Firehose pipeline for Lambda log export.
// Gated by var.enable_log_archive (default: true).

locals {
  log_archive_bucket_name = var.log_archive_bucket_name != "" ? var.log_archive_bucket_name : "security-monitor-logs-${data.aws_caller_identity.current.account_id}-${var.region}"
}

data "aws_caller_identity" "current" {}

// ── S3 Bucket ─────────────────────────────────────────────────────────────────

// NOTE: The CDK stack sets bucket_namespace = "account-regional" via CfnBucket L1
// override. The Terraform AWS provider does not yet support this attribute.
// When provider support is added, set it here to match CDK parity.
resource "aws_s3_bucket" "SecurityMonitorLogsBucket" {
  count  = var.enable_log_archive ? 1 : 0
  bucket = local.log_archive_bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "SecurityMonitorLogsBucketVersioning" {
  count  = var.enable_log_archive ? 1 : 0
  bucket = aws_s3_bucket.SecurityMonitorLogsBucket[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "SecurityMonitorLogsBucketEncryption" {
  count  = var.enable_log_archive ? 1 : 0
  bucket = aws_s3_bucket.SecurityMonitorLogsBucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "SecurityMonitorLogsBucketPublicAccess" {
  count  = var.enable_log_archive ? 1 : 0
  bucket = aws_s3_bucket.SecurityMonitorLogsBucket[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "SecurityMonitorLogsBucketLifecycle" {
  count  = var.enable_log_archive ? 1 : 0
  bucket = aws_s3_bucket.SecurityMonitorLogsBucket[0].id

  rule {
    id     = "expire-after-365-days"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

// ── Kinesis Data Firehose → S3 ────────────────────────────────────────────────

resource "aws_iam_role" "FirehoseDeliveryRole" {
  count = var.enable_log_archive ? 1 : 0
  name  = "SecurityMonitorFirehoseRole${var.name_suffix}"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "FirehoseDeliveryPolicy" {
  count = var.enable_log_archive ? 1 : 0
  name  = "FirehoseS3DeliveryPolicy"
  role  = aws_iam_role.FirehoseDeliveryRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "S3Access"
      Effect = "Allow"
      Action = [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:PutObject"
      ]
      Resource = [
        aws_s3_bucket.SecurityMonitorLogsBucket[0].arn,
        "${aws_s3_bucket.SecurityMonitorLogsBucket[0].arn}/*"
      ]
    }]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "SecurityMonitorFirehose" {
  count       = var.enable_log_archive ? 1 : 0
  name        = "security-monitor-logs-firehose${var.name_suffix}"
  destination = "extended_s3"
  tags        = var.tags

  extended_s3_configuration {
    role_arn   = aws_iam_role.FirehoseDeliveryRole[0].arn
    bucket_arn = aws_s3_bucket.SecurityMonitorLogsBucket[0].arn

    prefix              = "logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

    buffering_size     = 64
    buffering_interval = 300
    compression_format = "GZIP"
  }
}

// ── CloudWatch Logs → Firehose subscription ───────────────────────────────────

resource "aws_iam_role" "CWLogsFirehoseRole" {
  count = var.enable_log_archive ? 1 : 0
  name  = "CWLogsFirehoseRole${var.name_suffix}"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringLike = {
          "aws:SourceArn" = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "CWLogsFirehosePolicy" {
  count = var.enable_log_archive ? 1 : 0
  name  = "PutToFirehose"
  role  = aws_iam_role.CWLogsFirehoseRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "PutToFirehose"
      Effect = "Allow"
      Action = [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ]
      Resource = [aws_kinesis_firehose_delivery_stream.SecurityMonitorFirehose[0].arn]
    }]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "LambdaLogsToFirehose" {
  count           = var.enable_log_archive ? 1 : 0
  name            = "all-events-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.RootActivityLambdaLogs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.SecurityMonitorFirehose[0].arn
  role_arn        = aws_iam_role.CWLogsFirehoseRole[0].role_arn

  depends_on = [aws_iam_role_policy.CWLogsFirehosePolicy]
}
