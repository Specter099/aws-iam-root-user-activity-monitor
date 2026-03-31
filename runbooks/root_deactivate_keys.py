"""
Runbook 1 – Root Activity Response, Step 4 (conditional):
Deactivate all root access keys found in the previous step.

Input:  full state including $.keys_result.new_keys
Output: {deactivated_keys: [...], deactivated_count: N, errors: [...]}
        → stored at $.deactivate_result
"""
import boto3


def lambda_handler(event, context):
    iam = boto3.client("iam")

    keys_result = event.get("keys_result", {})
    new_keys = keys_result.get("new_keys", [])

    deactivated = []
    errors = []

    for key_info in new_keys:
        key_id = key_info.get("key_id")
        username = key_info.get("username", "root")
        if not key_id:
            continue
        try:
            kwargs = {"AccessKeyId": key_id, "Status": "Inactive"}
            # UserName is required for IAM users; omit for root
            if username and username.lower() != "root":
                kwargs["UserName"] = username
            iam.update_access_key(**kwargs)
            deactivated.append(key_id)
            print(f"Deactivated access key {key_id} for user {username}")
        except Exception as e:
            err = f"Failed to deactivate {key_id}: {e}"
            errors.append(err)
            print(err)

    return {
        "deactivated_keys": deactivated,
        "deactivated_count": len(deactivated),
        "errors": errors,
    }
