"""
Runbook 2 – Credential Compromise Response, Step 2a:
For a CreateAccessKey event, determine whether the creating principal
is different from the key owner (suspicious cross-principal key creation).

Input:  full state (EventBridge event + $.log_result)
Output: {key_id, key_owner, created_by, is_suspicious}
        → stored at $.key_creation_result
"""
import boto3


def lambda_handler(event, context):
    detail = event.get("detail", {})
    user_identity = detail.get("userIdentity", {})
    response_elements = detail.get("responseElements", {})

    access_key = response_elements.get("accessKey", {})
    key_id = access_key.get("accessKeyId", "Unknown")
    key_owner = access_key.get("userName", "Unknown")

    # The creating principal
    created_by_arn = user_identity.get("arn", "Unknown")
    created_by_type = user_identity.get("type", "Unknown")
    # For assumed-role sessions, the principalId encodes the actual caller
    created_by = user_identity.get("principalId", created_by_arn)

    # Suspicious if: root created a key for an IAM user, or a different IAM
    # user created a key for another user (cross-user key creation)
    is_suspicious = False
    reason = "none"

    if created_by_type == "Root":
        is_suspicious = True
        reason = "root_user_created_key"
    elif key_owner != "Unknown":
        # Extract the username from the ARN of the creator
        creator_username = created_by_arn.split("/")[-1] if "/" in created_by_arn else created_by_arn
        if creator_username != key_owner:
            is_suspicious = True
            reason = f"key_creator_{creator_username}_differs_from_key_owner_{key_owner}"

    print(
        f"Key {key_id}: owner={key_owner}, created_by={created_by_arn}, "
        f"suspicious={is_suspicious}, reason={reason}"
    )

    return {
        "key_id": key_id,
        "key_owner": key_owner,
        "created_by": created_by_arn,
        "created_by_type": created_by_type,
        "is_suspicious": is_suspicious,
        "reason": reason,
    }
