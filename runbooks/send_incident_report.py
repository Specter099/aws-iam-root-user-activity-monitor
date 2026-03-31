"""
Final step (shared): Format and publish an incident report via SNS.
Receives the full state machine state; adapts message based on which
runbook keys are present.

Input:  full state (EventBridge event + all previous $.xxx_result keys)
Output: {message_id}
"""
import json
import os
from datetime import datetime, timezone

import boto3


def lambda_handler(event, context):
    sns = boto3.client("sns")
    topic_arn = os.environ["SNS_TOPIC_ARN"]

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    account_id = event.get("account", "Unknown")
    region = event.get("region", "Unknown")
    source_ip = detail.get("sourceIPAddress", "Unknown")
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())

    log_result = event.get("log_result", {})
    incident_id = log_result.get("incident_id", "Unknown")[:8]

    lines = [
        "=" * 60,
        "AUTOMATED INCIDENT RESPONSE REPORT",
        "=" * 60,
        f"Incident ID  : {log_result.get('incident_id', 'Unknown')}",
        f"Event        : {event_name}",
        f"Account      : {account_id}",
        f"Region       : {region}",
        f"Source IP    : {source_ip}",
        f"Event Time   : {event_time}",
        f"User Type    : {detail.get('userIdentity', {}).get('type', 'Unknown')}",
        f"User ARN     : {detail.get('userIdentity', {}).get('arn', 'Unknown')}",
        "",
    ]

    # Runbook 1: Root Activity
    if "cloudtrail_result" in event:
        ct = event["cloudtrail_result"]
        lines += [
            "ROOT ACTIVITY ANALYSIS (last 24 hours)",
            "-" * 40,
            f"Total root actions found : {ct.get('action_count', 0)}",
        ]
        for action in ct.get("root_actions", [])[:10]:
            lines.append(f"  - {action.get('eventName','?')} at {action.get('eventTime','?')} from {action.get('sourceIPAddress','?')}")
        lines.append("")

    if "keys_result" in event:
        kr = event["keys_result"]
        if kr.get("new_keys_found"):
            lines += [
                "NEW ACCESS KEYS CREATED BY ROOT",
                "-" * 40,
            ]
            for k in kr.get("new_keys", []):
                lines.append(f"  Key ID: {k.get('key_id','?')}  Username: {k.get('username','?')}")
            lines.append("")

    if "deactivate_result" in event:
        dr = event["deactivate_result"]
        lines += [
            "AUTOMATED REMEDIATION: KEY DEACTIVATION",
            "-" * 40,
            f"Keys deactivated : {dr.get('deactivated_count', 0)}",
        ]
        for k in dr.get("deactivated_keys", []):
            lines.append(f"  - {k}")
        lines.append("")

    # Runbook 2: Credential Compromise
    if "key_creation_result" in event:
        kcr = event["key_creation_result"]
        lines += [
            "CREDENTIAL COMPROMISE ANALYSIS",
            "-" * 40,
            f"Key ID       : {kcr.get('key_id', 'Unknown')}",
            f"Key Owner    : {kcr.get('key_owner', 'Unknown')}",
            f"Created By   : {kcr.get('created_by', 'Unknown')}",
            f"Suspicious   : {kcr.get('is_suspicious', False)}",
            "",
        ]

    if "cred_deactivate_result" in event:
        cdr = event["cred_deactivate_result"]
        lines += [
            "AUTOMATED REMEDIATION: SUSPICIOUS KEY DEACTIVATED",
            "-" * 40,
            f"Key ID: {cdr.get('key_id', 'Unknown')}  Status: {cdr.get('status', 'Unknown')}",
            "",
        ]

    if "trust_policy_result" in event:
        tpr = event["trust_policy_result"]
        lines += [
            "TRUST POLICY ANALYSIS",
            "-" * 40,
            f"Role Name            : {tpr.get('role_name', 'Unknown')}",
            f"External Accounts    : {tpr.get('external_accounts_found', False)}",
        ]
        for acct in tpr.get("external_account_ids", []):
            lines.append(f"  - External Account: {acct}")
        lines.append("")

    if "revert_trust_result" in event:
        rtr = event["revert_trust_result"]
        lines += [
            "AUTOMATED REMEDIATION: TRUST POLICY REVERTED",
            "-" * 40,
            f"Role Name : {rtr.get('role_name', 'Unknown')}",
            f"Status    : {rtr.get('status', 'Unknown')}",
            "",
        ]

    # Runbook 3: Data Exfiltration
    if "revoke_snapshot_result" in event:
        rsr = event["revoke_snapshot_result"]
        lines += [
            "AUTOMATED REMEDIATION: SNAPSHOT SHARE REVOKED",
            "-" * 40,
            f"Snapshot ID       : {rsr.get('snapshot_id', 'Unknown')}",
            f"External Accounts : {rsr.get('revoked_accounts', [])}",
            f"Status            : {rsr.get('status', 'Unknown')}",
            "",
        ]

    if "bucket_check_result" in event:
        bcr = event["bucket_check_result"]
        lines += [
            "S3 BUCKET EXPOSURE ANALYSIS",
            "-" * 40,
            f"Bucket Name  : {bcr.get('bucket_name', 'Unknown')}",
            f"Is Public    : {bcr.get('is_public', False)}",
            f"Reason       : {bcr.get('public_reason', 'N/A')}",
            "",
        ]

    if "revert_policy_result" in event:
        rpr = event["revert_policy_result"]
        lines += [
            "AUTOMATED REMEDIATION: BUCKET POLICY REVERTED",
            "-" * 40,
            f"Bucket Name : {rpr.get('bucket_name', 'Unknown')}",
            f"Action      : {rpr.get('action', 'Unknown')}",
            f"Status      : {rpr.get('status', 'Unknown')}",
            "",
        ]

    # Runbook 4: Failed Login
    if "login_query_result" in event:
        lqr = event["login_query_result"]
        lines += [
            "FAILED LOGIN INVESTIGATION",
            "-" * 40,
            f"Source IP          : {lqr.get('source_ip', 'Unknown')}",
            f"Failures (1h)      : {lqr.get('failure_count', 0)}",
            f"Brute Force Flag   : {lqr.get('brute_force_detected', False)}",
            f"First Seen         : {lqr.get('first_failure_time', 'Unknown')}",
            f"Last Seen          : {lqr.get('last_failure_time', 'Unknown')}",
        ]
        if lqr.get("brute_force_detected"):
            lines += [
                "",
                "RECOMMENDATION: Block source IP at WAF/Security Group.",
                "Consider enabling AWS Shield Advanced if attacks persist.",
            ]
        lines.append("")

    lines += [
        "=" * 60,
        "This report was generated automatically by the Security",
        "Monitoring Hub incident response runbooks.",
        "Review and take manual action as required.",
        "=" * 60,
    ]

    message = "\n".join(lines)
    subject = f"[AUTO-REMEDIATION] {event_name} | Incident {incident_id} | Account {account_id}"

    response = sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=message,
    )
    print(f"Published incident report, message ID: {response['MessageId']}")
    return {"message_id": response["MessageId"]}
