"""
Runbook 1 – Root Activity Response, Step 3:
Check whether new IAM access keys were created by root in this session
by inspecting the triggering event and listing active root keys.

Input:  full state (EventBridge event + $.log_result + $.cloudtrail_result)
Output: {new_keys_found: bool, new_keys: [{key_id, username, created_date}]}
        → stored at $.keys_result
"""
import os

import boto3


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    new_keys = []

    # If this event itself is a CreateAccessKey, capture the key directly
    if event_name == "CreateAccessKey":
        resp_elements = detail.get("responseElements", {})
        access_key = resp_elements.get("accessKey", {})
        key_id = access_key.get("accessKeyId")
        username = access_key.get("userName", "root")
        if key_id:
            new_keys.append(
                {
                    "key_id": key_id,
                    "username": username,
                    "source": "triggering_event",
                }
            )

    # Also check whether root currently has any active keys
    iam = boto3.client("iam")
    try:
        # No UserName param → returns keys for the root account credential
        response = iam.list_access_keys()
        for key_meta in response.get("AccessKeyMetadata", []):
            kid = key_meta.get("AccessKeyId", "")
            # Include keys not already in new_keys list
            if kid and not any(k["key_id"] == kid for k in new_keys):
                new_keys.append(
                    {
                        "key_id": kid,
                        "username": key_meta.get("UserName", "root"),
                        "source": "iam_list",
                        "status": key_meta.get("Status", "Unknown"),
                        "created_date": key_meta.get("CreateDate", "").isoformat()
                        if hasattr(key_meta.get("CreateDate", ""), "isoformat")
                        else str(key_meta.get("CreateDate", "")),
                    }
                )
    except Exception as e:
        print(f"Warning: could not list access keys: {e}")

    print(f"Found {len(new_keys)} new/active root access key(s)")
    return {"new_keys_found": len(new_keys) > 0, "new_keys": new_keys}
