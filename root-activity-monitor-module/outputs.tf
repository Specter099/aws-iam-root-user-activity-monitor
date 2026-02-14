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
