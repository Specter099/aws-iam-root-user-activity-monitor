"""
Runbook 4 – Failed Login Investigation, Step 2:
Query CloudTrail for all failed console logins from the same source IP
in the last hour. Flag as brute force if > 5 failures.

Input:  full state (EventBridge event + $.log_result)
Output: {source_ip, failure_count, brute_force_detected,
         first_failure_time, last_failure_time, sample_events}
        → stored at $.login_query_result
"""
import json
from datetime import datetime, timedelta, timezone

import boto3


_BRUTE_FORCE_THRESHOLD = 5


def lambda_handler(event, context):
    cloudtrail = boto3.client("cloudtrail")

    detail = event.get("detail", {})
    source_ip = detail.get("sourceIPAddress", "Unknown")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)

    failures = []

    if source_ip and source_ip != "Unknown":
        try:
            resp = cloudtrail.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            for evt in resp.get("Events", []):
                raw = json.loads(evt.get("CloudTrailEvent", "{}"))
                if (
                    raw.get("sourceIPAddress") == source_ip
                    and raw.get("responseElements", {}).get("ConsoleLogin") == "Failure"
                ):
                    failures.append(
                        {
                            "eventTime": raw.get("eventTime", ""),
                            "userAgent": raw.get("userAgent", ""),
                            "userType": raw.get("userIdentity", {}).get("type", ""),
                        }
                    )
        except Exception as e:
            print(f"Warning: CloudTrail lookup failed: {e}")

    failure_count = len(failures)
    brute_force = failure_count > _BRUTE_FORCE_THRESHOLD

    times = [f["eventTime"] for f in failures if f["eventTime"]]
    times.sort()

    print(
        f"Source IP {source_ip}: {failure_count} failed login(s) in last 1h, "
        f"brute_force={brute_force}"
    )

    return {
        "source_ip": source_ip,
        "failure_count": failure_count,
        "brute_force_detected": brute_force,
        "first_failure_time": times[0] if times else "Unknown",
        "last_failure_time": times[-1] if times else "Unknown",
        "sample_events": failures[:5],
    }
