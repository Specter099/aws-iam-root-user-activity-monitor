output "orgid" {
  value = data.aws_organizations_organization.myorg.id
}

output "dlq_arn" {
  description = "ARN of the Dead Letter Queue for failed Lambda invocations"
  value       = aws_sqs_queue.RootActivityDLQ.arn
}

output "lambda_function_arn" {
  description = "ARN of the root activity monitor Lambda function"
  value       = aws_lambda_function.RootActivityLambda.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for root activity notifications"
  value       = aws_sns_topic.root-activity-sns-topic.arn
}

output "event_bus_arn" {
  description = "ARN of the hub EventBridge event bus"
  value       = aws_cloudwatch_event_bus.hub-root-activity-eventbus.arn
}

output "log_archive_bucket_name" {
  description = "S3 bucket for long-term security log archival"
  value       = var.enable_log_archive ? aws_s3_bucket.SecurityMonitorLogsBucket[0].bucket : ""
}

output "firehose_delivery_stream_arn" {
  description = "Kinesis Data Firehose delivery stream ARN"
  value       = var.enable_log_archive ? aws_kinesis_firehose_delivery_stream.SecurityMonitorFirehose[0].arn : ""
}

output "incidents_table_arn" {
  description = "DynamoDB incidents table ARN"
  value       = var.enable_incident_response ? aws_dynamodb_table.IncidentsTable[0].arn : ""
}

output "root_activity_runbook_arn" {
  description = "Root Activity incident response Step Function ARN"
  value       = var.enable_incident_response ? aws_sfn_state_machine.RootActivityResponseSM[0].arn : ""
}

output "credential_compromise_runbook_arn" {
  description = "Credential Compromise incident response Step Function ARN"
  value       = var.enable_incident_response ? aws_sfn_state_machine.CredentialCompromiseResponseSM[0].arn : ""
}

output "data_exfiltration_runbook_arn" {
  description = "Data Exfiltration incident response Step Function ARN"
  value       = var.enable_incident_response ? aws_sfn_state_machine.DataExfiltrationResponseSM[0].arn : ""
}

output "failed_login_runbook_arn" {
  description = "Failed Login Investigation Step Function ARN"
  value       = var.enable_incident_response ? aws_sfn_state_machine.FailedLoginInvestigationSM[0].arn : ""
}
