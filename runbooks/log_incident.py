"""
Step 1 (shared): Log an incident to the DynamoDB incidents table.
Called as the first state in every runbook state machine.

Input:  full EventBridge / CloudTrail event (state machine input)
Output: {incident_id, timestamp}  → stored at $.log_result
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3


def lambda_handler(event, context):
    table = boto3.resource("dynamodb").Table(os.environ["INCIDENTS_TABLE"])

    incident_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()
    ttl = int(time.time()) + (90 * 24 * 60 * 60)  # 90 days

    detail = event.get("detail", {})
    user_identity = detail.get("userIdentity", {})

    item = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "event_name": detail.get("eventName", "Unknown"),
        "event_account": event.get("account", "Unknown"),
        "event_region": event.get("region", "Unknown"),
        "detail_type": event.get("detail-type", "Unknown"),
        "user_type": user_identity.get("type", "Unknown"),
        "user_arn": user_identity.get("arn", "Unknown"),
        "source_ip": detail.get("sourceIPAddress", "Unknown"),
        "event_time": detail.get("eventTime", timestamp),
        "ttl": ttl,
    }

    table.put_item(Item=item)
    print(f"Logged incident {incident_id} for event {item['event_name']}")

    return {"incident_id": incident_id, "timestamp": timestamp}
