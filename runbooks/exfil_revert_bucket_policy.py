"""
Runbook 3 – Data Exfiltration Response, Step 3b (conditional):
Revert a public-exposing S3 bucket policy or ACL to a safe state.
For bucket policy events: delete the policy (removes public access).
For ACL events: reset ACL to private.

Input:  full state including $.bucket_check_result
Output: {bucket_name, action, status, error}  → stored at $.revert_policy_result
"""
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    s3 = boto3.client("s3")

    bcr = event.get("bucket_check_result", {})
    bucket_name = bcr.get("bucket_name", "")
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if not bucket_name:
        return {"bucket_name": bucket_name, "action": "skipped", "status": "no_bucket_name", "error": None}

    if event_name == "PutBucketAcl":
        # Reset ACL to private
        try:
            s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
            print(f"Reset ACL to private for bucket {bucket_name}")
            return {"bucket_name": bucket_name, "action": "reset_acl_to_private", "status": "reverted", "error": None}
        except Exception as e:
            return {"bucket_name": bucket_name, "action": "reset_acl_to_private", "status": "failed", "error": str(e)}

    # Default: PutBucketPolicy — delete the offending policy
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
        print(f"Deleted public bucket policy for {bucket_name}")
        return {"bucket_name": bucket_name, "action": "deleted_bucket_policy", "status": "reverted", "error": None}
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return {"bucket_name": bucket_name, "action": "delete_bucket_policy", "status": "already_no_policy", "error": None}
        return {"bucket_name": bucket_name, "action": "delete_bucket_policy", "status": "failed", "error": str(e)}
