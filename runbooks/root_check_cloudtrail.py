"""
Runbook 1 – Root Activity Response, Step 2:
Query CloudTrail for all root user actions in the last 24 hours.

Input:  full state (EventBridge event + $.log_result)
Output: {root_actions: [...], action_count: N}  → stored at $.cloudtrail_result
"""
import os
from datetime import datetime, timedelta, timezone

import boto3


def lambda_handler(event, context):
    cloudtrail = boto3.client("cloudtrail")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    root_actions = []
    paginator = cloudtrail.get_paginator("lookup_events")

    pages = paginator.paginate(
        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"MaxItems": 200, "PageSize": 50},
    )

    for page in pages:
        for evt in page.get("Events", []):
            root_actions.append(
                {
                    "eventName": evt.get("EventName", "Unknown"),
                    "eventTime": evt.get("EventTime", "").isoformat()
                    if hasattr(evt.get("EventTime", ""), "isoformat")
                    else str(evt.get("EventTime", "")),
                    "sourceIPAddress": evt.get("CloudTrailEvent")
                    and __import__("json").loads(evt["CloudTrailEvent"]).get(
                        "sourceIPAddress", "Unknown"
                    )
                    or "Unknown",
                    "awsRegion": evt.get("CloudTrailEvent")
                    and __import__("json").loads(evt["CloudTrailEvent"]).get(
                        "awsRegion", "Unknown"
                    )
                    or "Unknown",
                }
            )

    print(f"Found {len(root_actions)} root actions in the last 24 hours")
    return {"root_actions": root_actions, "action_count": len(root_actions)}
