// Local values for parameterized resource names (multi-region safe)
locals {
  function_name  = "root-activity-monitor${var.name_suffix}"
  dlq_name       = "root-activity-monitor-dlq${var.name_suffix}"
  event_bus_name = "hub-root-activity${var.name_suffix}"
  rule_name      = "hub-capture-root-activity${var.name_suffix}"
  log_group_name = "/aws/lambda/root-activity-monitor${var.name_suffix}"
}

// Lambda function resources

resource "aws_iam_role_policy" "LambdaRootAPIMonitorPolicy" {
  name = "LambdaRootAPIMonitorPolicy"
  role = aws_iam_role.LambdaRootAPIMonitorRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LogStreamAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          aws_cloudwatch_log_group.RootActivityLambdaLogs.arn,
          "${aws_cloudwatch_log_group.RootActivityLambdaLogs.arn}:*"
        ]
      },
      {
        Sid      = "SNSPublishAllow"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.root-activity-sns-topic.arn]
      },
      {
        Sid      = "ListAccountAlias"
        Effect   = "Allow"
        Action   = ["iam:ListAccountAliases"]
        Resource = "*"
      },
      {
        Sid      = "OrganizationsDescribeAccount"
        Effect   = "Allow"
        Action   = ["organizations:DescribeAccount"]
        Resource = "*"
      },
      {
        Sid      = "DLQAccess"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.RootActivityDLQ.arn]
      }
    ]
  })
}

resource "aws_iam_role" "LambdaRootAPIMonitorRole" {
  name               = "LambdaRootAPIMonitorRole${var.name_suffix}"
  assume_role_policy = file("${path.module}/iam/lambda-assume-policy.json")
  tags               = var.tags
}

resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.RootActivityLambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hub-root-activity-rule.arn
  depends_on = [
    aws_lambda_function.RootActivityLambda
  ]
}

data "archive_file" "RootActivityLambda" {
  type        = "zip"
  source_file = "${path.module}/RootActivityLambda.py"
  output_path = "${path.module}/outputs/RootActivityLambda.zip"
}

// Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "RootActivityDLQ" {
  name                      = local.dlq_name
  message_retention_seconds = 1209600 // 14 days
  kms_master_key_id         = "alias/aws/sqs"
  tags                      = var.tags
}

// CloudWatch Log Group with retention
resource "aws_cloudwatch_log_group" "RootActivityLambdaLogs" {
  name              = local.log_group_name
  retention_in_days = 90
  tags              = var.tags
}

resource "aws_lambda_function" "RootActivityLambda" {
  #checkov:skip=CKV_AWS_117:The Lambda function is part of a serverless implementation.
  #checkov:skip=CKV_AWS_173:No AWS KMS key provided to encrypt environment variables. Using AWS Lambda owned key.
  #checkov:skip=CKV_AWS_50:The Lambda function does not require X-Ray tracing and relies on CloudWatch Logs.

  filename      = "${path.module}/outputs/RootActivityLambda.zip"
  function_name = local.function_name
  role          = aws_iam_role.LambdaRootAPIMonitorRole.arn
  handler       = "RootActivityLambda.lambda_handler"
  timeout       = 30

  source_code_hash               = data.archive_file.RootActivityLambda.output_base64sha256
  runtime                        = "python3.12"
  reserved_concurrent_executions = 50

  dead_letter_config {
    target_arn = aws_sqs_queue.RootActivityDLQ.arn
  }

  environment {
    variables = {
      SNSARN = aws_sns_topic.root-activity-sns-topic.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.RootActivityLambdaLogs]
}

// CloudWatch alarm for DLQ messages (failed invocations)
resource "aws_cloudwatch_metric_alarm" "DLQMessagesAlarm" {
  alarm_name          = "root-activity-monitor-dlq-alarm${var.name_suffix}"
  alarm_description   = "Alert when root activity monitor Lambda fails and sends messages to DLQ"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.RootActivityDLQ.name
  }

  alarm_actions = [aws_sns_topic.root-activity-sns-topic.arn]
  tags          = var.tags
}

// CloudWatch alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "LambdaErrorsAlarm" {
  alarm_name          = "root-activity-monitor-lambda-errors${var.name_suffix}"
  alarm_description   = "Alert when root activity monitor Lambda encounters errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.RootActivityLambda.function_name
  }

  alarm_actions = [aws_sns_topic.root-activity-sns-topic.arn]
  tags          = var.tags
}

// Event Bus Resources
resource "aws_cloudwatch_event_bus" "hub-root-activity-eventbus" {
  name = local.event_bus_name
}

resource "aws_cloudwatch_event_bus_policy" "hub-root-activity-eventbus-OrgAccess" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OrganizationAccess"
        Effect    = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action    = "events:PutEvents"
        Resource  = aws_cloudwatch_event_bus.hub-root-activity-eventbus.arn
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = data.aws_organizations_organization.myorg.id
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "hub-root-activity-rule" {
  name           = local.rule_name
  description    = "Capture root user AWS Console Sign In, API calls, and credential changes."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail",
    "AWS Console Sign In via CloudTrail",
    "AWS Service Event via CloudTrail"
  ],
  "detail": {
      "userIdentity": {
          "type": [
              "Root"
          ]
      }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "root-activity-event-target" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-root-activity-rule.name
  arn            = aws_lambda_function.RootActivityLambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

// ── Category 1: Console sign-in anomalies (non-root) ───────────────────
resource "aws_cloudwatch_event_rule" "hub-console-signin-anomaly-rule" {
  name           = "hub-capture-console-signin-anomalies${var.name_suffix}"
  description    = "Detect console logins without MFA or failed login attempts (non-root)."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS Console Sign In via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [{ "anything-but": "Root" }]
    },
    "$or": [
      {
        "additionalEventData": {
          "MFAUsed": [{ "anything-but": "Yes" }]
        }
      },
      {
        "responseElements": {
          "ConsoleLogin": ["Failure"]
        }
      }
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "console-signin-anomaly-target" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-console-signin-anomaly-rule.name
  arn            = aws_lambda_function.RootActivityLambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

resource "aws_lambda_permission" "allow_console_signin_anomaly_events" {
  statement_id  = "AllowExecutionFromConsoleSignInAnomalyEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.RootActivityLambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hub-console-signin-anomaly-rule.arn
}

// ── Category 2: IAM credential abuse (non-root) ────────────────────────
resource "aws_cloudwatch_event_rule" "hub-iam-credential-abuse-rule" {
  name           = "hub-capture-iam-credential-abuse${var.name_suffix}"
  description    = "Detect credential retrieval and reconnaissance calls (non-root)."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [{ "anything-but": "Root" }]
    },
    "eventName": [
      "GetSessionToken",
      "AssumeRole",
      "GetFederationToken",
      "GetCallerIdentity"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "iam-credential-abuse-target" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-iam-credential-abuse-rule.name
  arn            = aws_lambda_function.RootActivityLambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

resource "aws_lambda_permission" "allow_iam_credential_abuse_events" {
  statement_id  = "AllowExecutionFromIAMCredentialAbuseEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.RootActivityLambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hub-iam-credential-abuse-rule.arn
}

// ── Category 3: Privilege escalation (non-root) ────────────────────────
resource "aws_cloudwatch_event_rule" "hub-privilege-escalation-rule" {
  name           = "hub-capture-privilege-escalation${var.name_suffix}"
  description    = "Detect IAM policy changes and identity creation that could grant elevated access (non-root)."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [{ "anything-but": "Root" }]
    },
    "eventName": [
      "CreateAccessKey",
      "AttachUserPolicy",
      "AttachRolePolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "CreateLoginProfile",
      "UpdateLoginProfile",
      "UpdateAssumeRolePolicy",
      "CreateRole",
      "CreateUser"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "privilege-escalation-target" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-privilege-escalation-rule.name
  arn            = aws_lambda_function.RootActivityLambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

resource "aws_lambda_permission" "allow_privilege_escalation_events" {
  statement_id  = "AllowExecutionFromPrivilegeEscalationEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.RootActivityLambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hub-privilege-escalation-rule.arn
}

// ── Category 4: Data exfiltration signals (non-root) ───────────────────
resource "aws_cloudwatch_event_rule" "hub-data-exfiltration-rule" {
  name           = "hub-capture-data-exfiltration${var.name_suffix}"
  description    = "Detect EBS/RDS snapshot sharing and S3 bucket exposure (non-root)."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [{ "anything-but": "Root" }]
    },
    "eventName": [
      "CreateSnapshot",
      "ModifySnapshotAttribute",
      "PutBucketPolicy",
      "PutBucketAcl",
      "ModifyDBSnapshotAttribute",
      "CreateDBSnapshot"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "data-exfiltration-target" {
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-data-exfiltration-rule.name
  arn            = aws_lambda_function.RootActivityLambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
}

resource "aws_lambda_permission" "allow_data_exfiltration_events" {
  statement_id  = "AllowExecutionFromDataExfiltrationEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.RootActivityLambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hub-data-exfiltration-rule.arn
}

// SNS resources
resource "aws_sns_topic" "root-activity-sns-topic" {
  name              = var.SNSTopicName
  display_name      = "AWS IAM Root User Activity Monitor"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "root-activity-sns-topic-sub" {
  endpoint  = var.SNSSubscriptions
  protocol  = "email-json"
  topic_arn = aws_sns_topic.root-activity-sns-topic.arn
}
