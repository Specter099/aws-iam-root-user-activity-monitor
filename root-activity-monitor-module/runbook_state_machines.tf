// Incident response Step Functions state machines.
// Gated by var.enable_incident_response (default: true).
//
// 4 state machines matching the CDK IncidentResponseRunbooks construct:
//   1. Root Activity Response
//   2. Credential Compromise Response
//   3. Data Exfiltration Response
//   4. Failed Login Investigation

locals {
  state_machines = {
    "sec-incident-root-activity"   = "Root Activity Response"
    "sec-incident-cred-compromise" = "Credential Compromise Response"
    "sec-incident-data-exfil"      = "Data Exfiltration Response"
    "sec-incident-failed-login"    = "Failed Login Investigation"
  }
}

// ── IAM Role for Step Functions ───────────────────────────────────────────────

resource "aws_iam_role" "RunbookStateMachineRole" {
  count = var.enable_incident_response ? 1 : 0
  name  = "RunbookStateMachineRole${var.name_suffix}"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "RunbookStateMachinePolicy" {
  count = var.enable_incident_response ? 1 : 0
  name  = "RunbookStateMachinePolicy"
  role  = aws_iam_role.RunbookStateMachineRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [for k, v in local.runbook_lambdas : aws_lambda_function.RunbookLambda[k].arn]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "*"
      },
      {
        Sid      = "XRayAccess"
        Effect   = "Allow"
        Action   = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

// ── CloudWatch Log Groups for state machines ──────────────────────────────────

resource "aws_cloudwatch_log_group" "RunbookStateMachineLogs" {
  for_each = var.enable_incident_response ? local.state_machines : {}

  name              = "/aws/states/${each.key}${var.name_suffix}"
  retention_in_days = 90
  tags              = var.tags
}

// ── State Machine 1: Root Activity Response ───────────────────────────────────

resource "aws_sfn_state_machine" "RootActivityResponseSM" {
  count    = var.enable_incident_response ? 1 : 0
  name     = "sec-incident-root-activity${var.name_suffix}"
  role_arn = aws_iam_role.RunbookStateMachineRole[0].arn
  tags     = var.tags

  tracing_configuration {
    enabled = true
  }

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.RunbookStateMachineLogs["sec-incident-root-activity"].arn}:*"
    level                  = "ERROR"
    include_execution_data = false
  }

  definition = jsonencode({
    Comment = "Root Activity Response Runbook"
    StartAt = "Log"
    States = {
      Log = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["log-incident"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.log_result"
        Next           = "CheckCloudTrail"
      }
      CheckCloudTrail = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["root-check-cloudtrail"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.cloudtrail_result"
        Next           = "CheckKeys"
      }
      CheckKeys = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["root-check-access-keys"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.keys_result"
        Next           = "NewKeysFound"
      }
      NewKeysFound = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.keys_result.new_keys_found"
          BooleanEquals = true
          Next          = "DeactivateKeys"
        }]
        Default = "SendReport"
      }
      DeactivateKeys = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["root-deactivate-keys"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.deactivate_result"
        Next           = "SendReport"
      }
      SendReport = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["send-incident-report"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.report_result"
        End            = true
      }
    }
  })
}

// ── State Machine 2: Credential Compromise Response ───────────────────────────

resource "aws_sfn_state_machine" "CredentialCompromiseResponseSM" {
  count    = var.enable_incident_response ? 1 : 0
  name     = "sec-incident-cred-compromise${var.name_suffix}"
  role_arn = aws_iam_role.RunbookStateMachineRole[0].arn
  tags     = var.tags

  tracing_configuration {
    enabled = true
  }

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.RunbookStateMachineLogs["sec-incident-cred-compromise"].arn}:*"
    level                  = "ERROR"
    include_execution_data = false
  }

  definition = jsonencode({
    Comment = "Credential Compromise Response Runbook"
    StartAt = "Log"
    States = {
      Log = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["log-incident"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.log_result"
        Next           = "EventType"
      }
      EventType = {
        Type = "Choice"
        Choices = [
          {
            Variable         = "$.detail.eventName"
            StringEquals     = "CreateAccessKey"
            Next             = "CheckKeyCreation"
          },
          {
            Variable         = "$.detail.eventName"
            StringEquals     = "UpdateAssumeRolePolicy"
            Next             = "CheckTrustPolicy"
          }
        ]
        Default = "SendReport"
      }
      CheckKeyCreation = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["cred-check-key-creation"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.key_creation_result"
        Next           = "Suspicious"
      }
      Suspicious = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.key_creation_result.is_suspicious"
          BooleanEquals = true
          Next          = "DeactivateKey"
        }]
        Default = "SendReport"
      }
      DeactivateKey = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["cred-deactivate-key"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.cred_deactivate_result"
        Next           = "SendReport"
      }
      CheckTrustPolicy = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["cred-check-trust-policy"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.trust_policy_result"
        Next           = "ExternalAccounts"
      }
      ExternalAccounts = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.trust_policy_result.external_accounts_found"
          BooleanEquals = true
          Next          = "RevertTrustPolicy"
        }]
        Default = "SendReport"
      }
      RevertTrustPolicy = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["cred-revert-trust-policy"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.revert_trust_result"
        Next           = "SendReport"
      }
      SendReport = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["send-incident-report"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.report_result"
        End            = true
      }
    }
  })
}

// ── State Machine 3: Data Exfiltration Response ───────────────────────────────

resource "aws_sfn_state_machine" "DataExfiltrationResponseSM" {
  count    = var.enable_incident_response ? 1 : 0
  name     = "sec-incident-data-exfil${var.name_suffix}"
  role_arn = aws_iam_role.RunbookStateMachineRole[0].arn
  tags     = var.tags

  tracing_configuration {
    enabled = true
  }

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.RunbookStateMachineLogs["sec-incident-data-exfil"].arn}:*"
    level                  = "ERROR"
    include_execution_data = false
  }

  definition = jsonencode({
    Comment = "Data Exfiltration Response Runbook"
    StartAt = "Log"
    States = {
      Log = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["log-incident"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.log_result"
        Next           = "EventType"
      }
      EventType = {
        Type = "Choice"
        Choices = [
          {
            Variable     = "$.detail.eventName"
            StringEquals = "ModifySnapshotAttribute"
            Next         = "RevokeSnapshot"
          },
          {
            Or = [
              {
                Variable     = "$.detail.eventName"
                StringEquals = "PutBucketPolicy"
              },
              {
                Variable     = "$.detail.eventName"
                StringEquals = "PutBucketAcl"
              }
            ]
            Next = "CheckBucket"
          }
        ]
        Default = "SendReport"
      }
      RevokeSnapshot = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["exfil-revoke-snapshot"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.revoke_snapshot_result"
        Next           = "SendReport"
      }
      CheckBucket = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["exfil-check-bucket"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.bucket_check_result"
        Next           = "BucketPublic"
      }
      BucketPublic = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.bucket_check_result.is_public"
          BooleanEquals = true
          Next          = "RevertBucketPolicy"
        }]
        Default = "SendReport"
      }
      RevertBucketPolicy = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["exfil-revert-bucket-policy"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.revert_policy_result"
        Next           = "SendReport"
      }
      SendReport = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["send-incident-report"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.report_result"
        End            = true
      }
    }
  })
}

// ── State Machine 4: Failed Login Investigation ──────────────────────────────

resource "aws_sfn_state_machine" "FailedLoginInvestigationSM" {
  count    = var.enable_incident_response ? 1 : 0
  name     = "sec-incident-failed-login${var.name_suffix}"
  role_arn = aws_iam_role.RunbookStateMachineRole[0].arn
  tags     = var.tags

  tracing_configuration {
    enabled = true
  }

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.RunbookStateMachineLogs["sec-incident-failed-login"].arn}:*"
    level                  = "ERROR"
    include_execution_data = false
  }

  definition = jsonencode({
    Comment = "Failed Login Investigation Runbook"
    StartAt = "Log"
    States = {
      Log = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["log-incident"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.log_result"
        Next           = "QueryFailures"
      }
      QueryFailures = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["login-query-failures"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.login_query_result"
        Next           = "SendReport"
      }
      SendReport = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.RunbookLambda["send-incident-report"].arn
          "Payload.$"  = "$"
        }
        ResultSelector = { ".$" = "$.Payload" }
        ResultPath     = "$.report_result"
        End            = true
      }
    }
  })
}
