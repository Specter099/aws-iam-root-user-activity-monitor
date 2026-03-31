"""
Runbook 2 – Credential Compromise Response, Step 3a (conditional):
Deactivate the suspicious access key identified in cred_check_key_creation.

Input:  full state including $.key_creation_result
Output: {key_id, username, status, error}  → stored at $.cred_deactivate_result
"""
import boto3


def lambda_handler(event, context):
    iam = boto3.client("iam")

    kcr = event.get("key_creation_result", {})
    key_id = kcr.get("key_id", "")
    key_owner = kcr.get("key_owner", "")

    if not key_id:
        return {"key_id": key_id, "username": key_owner, "status": "skipped_no_key_id", "error": None}

    try:
        kwargs = {"AccessKeyId": key_id, "Status": "Inactive"}
        if key_owner and key_owner.lower() not in ("unknown", "root", ""):
            kwargs["UserName"] = key_owner
        iam.update_access_key(**kwargs)
        print(f"Deactivated suspicious key {key_id} owned by {key_owner}")
        return {"key_id": key_id, "username": key_owner, "status": "deactivated", "error": None}
    except Exception as e:
        err = str(e)
        print(f"Failed to deactivate key {key_id}: {err}")
        return {"key_id": key_id, "username": key_owner, "status": "failed", "error": err}
