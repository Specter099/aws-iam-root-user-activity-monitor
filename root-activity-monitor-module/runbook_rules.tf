// EventBridge rules that trigger incident response Step Functions.
// These run in parallel with the existing Lambda-based alerting rules.
// Gated by var.enable_incident_response (default: true).

// IAM role for EventBridge to start Step Functions executions
resource "aws_iam_role" "EventBridgeSfnRole" {
  count = var.enable_incident_response ? 1 : 0
  name  = "EventBridgeSfnRole${var.name_suffix}"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "EventBridgeSfnPolicy" {
  count = var.enable_incident_response ? 1 : 0
  name  = "EventBridgeSfnPolicy"
  role  = aws_iam_role.EventBridgeSfnRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "StartExecution"
      Effect = "Allow"
      Action = ["states:StartExecution"]
      Resource = [
        aws_sfn_state_machine.RootActivityResponseSM[0].arn,
        aws_sfn_state_machine.CredentialCompromiseResponseSM[0].arn,
        aws_sfn_state_machine.DataExfiltrationResponseSM[0].arn,
        aws_sfn_state_machine.FailedLoginInvestigationSM[0].arn,
      ]
    }]
  })
}

// ── Rule 1: Root Activity → RootActivityResponseSM ────────────────────────────

resource "aws_cloudwatch_event_rule" "hub-runbook-root-activity" {
  count          = var.enable_incident_response ? 1 : 0
  name           = "hub-runbook-root-activity${var.name_suffix}"
  description    = "Trigger Root Activity Runbook for root user events (parallel to Lambda alerting)."
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
      "type": ["Root"]
    }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "runbook-root-activity-target" {
  count          = var.enable_incident_response ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-runbook-root-activity[0].name
  arn            = aws_sfn_state_machine.RootActivityResponseSM[0].arn
  role_arn       = aws_iam_role.EventBridgeSfnRole[0].arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

// ── Rule 2: Credential Compromise → CredentialCompromiseResponseSM ────────────

resource "aws_cloudwatch_event_rule" "hub-runbook-cred-compromise" {
  count          = var.enable_incident_response ? 1 : 0
  name           = "hub-runbook-cred-compromise${var.name_suffix}"
  description    = "Trigger Credential Compromise Runbook for key creation and role trust policy changes."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventName": [
      "CreateAccessKey",
      "UpdateAssumeRolePolicy"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "runbook-cred-compromise-target" {
  count          = var.enable_incident_response ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-runbook-cred-compromise[0].name
  arn            = aws_sfn_state_machine.CredentialCompromiseResponseSM[0].arn
  role_arn       = aws_iam_role.EventBridgeSfnRole[0].arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

// ── Rule 3: Data Exfiltration → DataExfiltrationResponseSM ────────────────────

resource "aws_cloudwatch_event_rule" "hub-runbook-data-exfil" {
  count          = var.enable_incident_response ? 1 : 0
  name           = "hub-runbook-data-exfil${var.name_suffix}"
  description    = "Trigger Data Exfiltration Runbook for snapshot sharing and S3 bucket exposure."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventName": [
      "ModifySnapshotAttribute",
      "PutBucketPolicy",
      "PutBucketAcl"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "runbook-data-exfil-target" {
  count          = var.enable_incident_response ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-runbook-data-exfil[0].name
  arn            = aws_sfn_state_machine.DataExfiltrationResponseSM[0].arn
  role_arn       = aws_iam_role.EventBridgeSfnRole[0].arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

// ── Rule 4: Failed Login → FailedLoginInvestigationSM ─────────────────────────

resource "aws_cloudwatch_event_rule" "hub-runbook-failed-login" {
  count          = var.enable_incident_response ? 1 : 0
  name           = "hub-runbook-failed-login${var.name_suffix}"
  description    = "Trigger Failed Login Investigation Runbook for failed console login attempts."
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name

  event_pattern = <<EOF
{
  "detail-type": [
    "AWS Console Sign In via CloudTrail"
  ],
  "detail": {
    "responseElements": {
      "ConsoleLogin": ["Failure"]
    }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "runbook-failed-login-target" {
  count          = var.enable_incident_response ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.hub-root-activity-eventbus.name
  rule           = aws_cloudwatch_event_rule.hub-runbook-failed-login[0].name
  arn            = aws_sfn_state_machine.FailedLoginInvestigationSM[0].arn
  role_arn       = aws_iam_role.EventBridgeSfnRole[0].arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}
