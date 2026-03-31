// DynamoDB table for incident response tracking.
// Gated by var.enable_incident_response (default: true).

resource "aws_dynamodb_table" "IncidentsTable" {
  count        = var.enable_incident_response ? 1 : 0
  name         = "security-monitor-incidents${var.name_suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"
  range_key    = "timestamp"

  attribute {
    name = "incident_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}
