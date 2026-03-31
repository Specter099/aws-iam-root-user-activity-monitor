"""
Runbook 2 – Credential Compromise Response, Step 2b:
For an UpdateAssumeRolePolicy event, parse the new trust policy and check
whether any external (non-org) account IDs were added as principals.

Input:  full state (EventBridge event + $.log_result)
Output: {role_name, external_accounts_found, external_account_ids,
         new_policy_document, account_id}
        → stored at $.trust_policy_result
"""
import json
import re

import boto3


_ACCOUNT_PRINCIPAL_RE = re.compile(r'"arn:aws:iam::(\d{12}):')


def _extract_account_ids_from_policy(policy_doc: dict) -> list:
    """Return all 12-digit account IDs referenced as principals in the policy."""
    policy_str = json.dumps(policy_doc)
    return list(set(_ACCOUNT_PRINCIPAL_RE.findall(policy_str)))


def lambda_handler(event, context):
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})

    role_name = request_params.get("roleName", "Unknown")
    hub_account_id = event.get("account", "")

    new_policy_str = request_params.get("policyDocument", "{}")
    try:
        new_policy_doc = json.loads(new_policy_str) if isinstance(new_policy_str, str) else new_policy_str
    except json.JSONDecodeError:
        new_policy_doc = {}

    all_account_ids = _extract_account_ids_from_policy(new_policy_doc)
    external_account_ids = [a for a in all_account_ids if a != hub_account_id]

    print(
        f"Role {role_name}: new trust policy references "
        f"{len(all_account_ids)} account(s), {len(external_account_ids)} external"
    )

    return {
        "role_name": role_name,
        "external_accounts_found": len(external_account_ids) > 0,
        "external_account_ids": external_account_ids,
        "new_policy_document": json.dumps(new_policy_doc),
        "account_id": hub_account_id,
    }
