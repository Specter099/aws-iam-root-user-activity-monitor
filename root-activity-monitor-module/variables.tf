variable "tags" {
  description = "Add tags to set on module resources."
  type        = map(string)
  default     = {}
}

variable "region" {
  description = "Add the region code where resources will be deployed."
  type        = string
  default     = "eu-west-1"
}

variable "SNSTopicName" {
  description = "Add SNS topic name."
  type        = string
  default     = "aws-iam-root-user-activity-monitor"
}

variable "SNSSubscriptions" {
  description = "Add your email here to be able to receive notifications"
  type        = string
  default     = "__REPLACE_EMAIL_ADDRESS__"
}

variable "name_suffix" {
  description = "Optional suffix appended to resource names for multi-region deployments (e.g., '-euw1')."
  type        = string
  default     = ""
}

variable "log_archive_bucket_name" {
  description = "S3 bucket name for long-term security log archival. Defaults to security-monitor-logs-{account_id}-{region}."
  type        = string
  default     = ""
}

variable "enable_log_archive" {
  description = "Enable S3 log archive bucket and Firehose pipeline for Lambda log export."
  type        = bool
  default     = true
}

variable "enable_incident_response" {
  description = "Enable incident response runbooks (Step Functions, DynamoDB, runbook Lambdas)."
  type        = bool
  default     = true
}
