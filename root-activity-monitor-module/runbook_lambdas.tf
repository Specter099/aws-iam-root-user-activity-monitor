// Incident response runbook Lambda functions.
// Gated by var.enable_incident_response (default: true).
//
// 13 functions across 4 runbooks, with per-function IAM roles (least privilege).
// All functions use the runbooks/ directory as their code asset.

locals {
  runbook_lambdas = {
    log-incident = {
      handler     = "log_incident.lambda_handler"
      description = "Log incident to DynamoDB"
    }
    send-incident-report = {
      handler     = "send_incident_report.lambda_handler"
      description = "Send incident report via SNS"
    }
    root-check-cloudtrail = {
      handler     = "root_check_cloudtrail.lambda_handler"
      description = "Check CloudTrail for recent root activity"
    }
    root-check-access-keys = {
      handler     = "root_check_access_keys.lambda_handler"
      description = "Check for root access key creation"
    }
    root-deactivate-keys = {
      handler     = "root_deactivate_keys.lambda_handler"
      description = "Deactivate suspicious root access keys"
    }
    cred-check-key-creation = {
      handler     = "cred_check_key_creation.lambda_handler"
      description = "Evaluate access key creation for suspicious patterns"
    }
    cred-deactivate-key = {
      handler     = "cred_deactivate_key.lambda_handler"
      description = "Deactivate suspicious access key"
    }
    cred-check-trust-policy = {
      handler     = "cred_check_trust_policy.lambda_handler"
      description = "Check role trust policy for external accounts"
    }
    cred-revert-trust-policy = {
      handler     = "cred_revert_trust_policy.lambda_handler"
      description = "Revert role trust policy to remove external accounts"
    }
    exfil-revoke-snapshot = {
      handler     = "exfil_revoke_snapshot.lambda_handler"
      description = "Revoke shared EBS snapshot permissions"
    }
    exfil-check-bucket = {
      handler     = "exfil_check_bucket.lambda_handler"
      description = "Check S3 bucket for public access"
    }
    exfil-revert-bucket-policy = {
      handler     = "exfil_revert_bucket_policy.lambda_handler"
      description = "Revert S3 bucket policy to remove public access"
    }
    login-query-failures = {
      handler     = "login_query_failures.lambda_handler"
      description = "Query CloudTrail for failed login attempts"
    }
  }

  // IAM actions each runbook Lambda needs beyond the base permissions
  runbook_extra_actions = {
    log-incident             = []
    send-incident-report     = []
    root-check-cloudtrail    = ["cloudtrail:LookupEvents"]
    root-check-access-keys   = ["iam:ListAccessKeys"]
    root-deactivate-keys     = ["iam:UpdateAccessKey"]
    cred-check-key-creation  = []
    cred-deactivate-key      = ["iam:UpdateAccessKey"]
    cred-check-trust-policy  = []
    cred-revert-trust-policy = ["iam:UpdateAssumeRolePolicy", "iam:GetRole", "cloudtrail:LookupEvents"]
    exfil-revoke-snapshot    = ["ec2:ModifySnapshotAttribute", "ec2:DescribeSnapshotAttribute"]
    exfil-check-bucket       = ["s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock"]
    exfil-revert-bucket-policy = ["s3:DeleteBucketPolicy", "s3:PutBucketAcl"]
    login-query-failures     = ["cloudtrail:LookupEvents"]
  }
}

data "archive_file" "RunbookLambda" {
  count       = var.enable_incident_response ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/../runbooks"
  output_path = "${path.module}/outputs/RunbookLambda.zip"
}

// Per-function IAM roles (least privilege, matching CDK per-function role behavior)
resource "aws_iam_role" "RunbookLambdaRole" {
  for_each = var.enable_incident_response ? local.runbook_lambdas : {}

  name               = "sec-runbook-${each.key}-role${var.name_suffix}"
  assume_role_policy = file("${path.module}/iam/lambda-assume-policy.json")
  tags               = var.tags
}

resource "aws_iam_role_policy" "RunbookLambdaBasePolicy" {
  for_each = var.enable_incident_response ? local.runbook_lambdas : {}

  name = "RunbookLambdaBasePolicy"
  role = aws_iam_role.RunbookLambdaRole[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LogAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/sec-runbook-${each.key}${var.name_suffix}",
          "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/sec-runbook-${each.key}${var.name_suffix}:*"
        ]
      },
      {
        Sid    = "DynamoDBWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [aws_dynamodb_table.IncidentsTable[0].arn]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.root-activity-sns-topic.arn]
      }
    ]
  })
}

// Per-function extra policy (only for functions that need additional AWS API access)
resource "aws_iam_role_policy" "RunbookLambdaExtraPolicy" {
  for_each = var.enable_incident_response ? {
    for k, v in local.runbook_extra_actions : k => v if length(v) > 0
  } : {}

  name = "RunbookExtraPolicy"
  role = aws_iam_role.RunbookLambdaRole[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ExtraPermissions"
      Effect   = "Allow"
      Action   = each.value
      Resource = "*"
    }]
  })
}

// CloudWatch Log Groups for each runbook Lambda
resource "aws_cloudwatch_log_group" "RunbookLambdaLogs" {
  for_each = var.enable_incident_response ? local.runbook_lambdas : {}

  name              = "/aws/lambda/sec-runbook-${each.key}${var.name_suffix}"
  retention_in_days = 90
  tags              = var.tags
}

// Lambda functions
resource "aws_lambda_function" "RunbookLambda" {
  #checkov:skip=CKV_AWS_117:Serverless implementation, VPC not required.
  #checkov:skip=CKV_AWS_173:Using AWS Lambda owned key for env var encryption.
  #checkov:skip=CKV_AWS_50:Relies on CloudWatch Logs, X-Ray not required.

  for_each = var.enable_incident_response ? local.runbook_lambdas : {}

  filename         = data.archive_file.RunbookLambda[0].output_path
  source_code_hash = data.archive_file.RunbookLambda[0].output_base64sha256
  function_name    = "sec-runbook-${each.key}${var.name_suffix}"
  description      = each.value.description
  role             = aws_iam_role.RunbookLambdaRole[each.key].arn
  handler          = each.value.handler
  runtime          = "python3.12"
  timeout          = 60

  environment {
    variables = {
      INCIDENTS_TABLE = aws_dynamodb_table.IncidentsTable[0].name
      SNS_TOPIC_ARN   = aws_sns_topic.root-activity-sns-topic.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.RunbookLambdaLogs]
}
