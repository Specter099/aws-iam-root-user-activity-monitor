"""
Runbook 2 – Credential Compromise Response, Step 3b (conditional):
Revert the trust policy of a role that had external accounts added.
Strategy: fetch the previous UpdateAssumeRolePolicy event from CloudTrail
to obtain the prior policy; fall back to removing all external principals.

Input:  full state including $.trust_policy_result
Output: {role_name, status, action_taken, error}  → stored at $.revert_trust_result
"""
import json
import re
from datetime import datetime, timedelta, timezone

import boto3


def lambda_handler(event, context):
    iam = boto3.client("iam")
    cloudtrail = boto3.client("cloudtrail")

    tpr = event.get("trust_policy_result", {})
    role_name = tpr.get("role_name", "")
    account_id = tpr.get("account_id", "")
    external_ids = tpr.get("external_account_ids", [])

    if not role_name or role_name == "Unknown":
        return {"role_name": role_name, "status": "skipped_no_role_name", "action_taken": "none", "error": None}

    previous_policy = _find_previous_trust_policy(cloudtrail, role_name)

    if previous_policy:
        try:
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(previous_policy))
            print(f"Reverted trust policy for {role_name} to previous version")
            return {
                "role_name": role_name,
                "status": "reverted",
                "action_taken": "restored_previous_policy",
                "error": None,
            }
        except Exception as e:
            return {"role_name": role_name, "status": "failed", "action_taken": "attempted_revert", "error": str(e)}

    # Fallback: get current policy and strip external principals
    try:
        role_resp = iam.get_role(RoleName=role_name)
        current_policy = role_resp["Role"]["AssumeRolePolicyDocument"]
        cleaned = _strip_external_principals(current_policy, account_id)
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(cleaned))
        print(f"Stripped {len(external_ids)} external principal(s) from {role_name} trust policy")
        return {
            "role_name": role_name,
            "status": "remediated",
            "action_taken": "stripped_external_principals",
            "error": None,
        }
    except Exception as e:
        return {"role_name": role_name, "status": "failed", "action_taken": "attempted_strip", "error": str(e)}


def _find_previous_trust_policy(cloudtrail, role_name: str) -> dict | None:
    """Return the policy document from the second-most-recent UpdateAssumeRolePolicy
    event for this role, or None if unavailable."""
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=90)
        resp = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "UpdateAssumeRolePolicy"}
            ],
            StartTime=start,
            EndTime=end,
            MaxResults=50,
        )
        events_for_role = []
        for evt in resp.get("Events", []):
            raw = json.loads(evt.get("CloudTrailEvent", "{}"))
            if raw.get("requestParameters", {}).get("roleName") == role_name:
                events_for_role.append(raw)

        # Sort newest-first; the second entry has the policy that was in place
        # before the suspicious update (the first entry)
        events_for_role.sort(
            key=lambda e: e.get("eventTime", ""), reverse=True
        )
        if len(events_for_role) >= 2:
            prev_doc_str = events_for_role[1].get("requestParameters", {}).get("policyDocument", "")
            if prev_doc_str:
                return json.loads(prev_doc_str) if isinstance(prev_doc_str, str) else prev_doc_str
    except Exception as e:
        print(f"Warning: could not retrieve previous trust policy from CloudTrail: {e}")
    return None


def _strip_external_principals(policy: dict, account_id: str) -> dict:
    """Remove any Principal entries that reference accounts other than account_id."""
    cleaned_statements = []
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            aws = principal.get("AWS", [])
            if isinstance(aws, str):
                aws = [aws]
            filtered = [p for p in aws if account_id in p or not re.search(r"\d{12}", p)]
            if filtered:
                stmt["Principal"]["AWS"] = filtered
                cleaned_statements.append(stmt)
            elif set(principal.keys()) - {"AWS"}:
                cleaned_statements.append(stmt)
        else:
            cleaned_statements.append(stmt)
    policy["Statement"] = cleaned_statements
    return policy
