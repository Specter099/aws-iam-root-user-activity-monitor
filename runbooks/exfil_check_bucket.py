"""
Runbook 3 – Data Exfiltration Response, Step 2b:
For a PutBucketPolicy or PutBucketAcl event, check whether the bucket is
now publicly accessible.

Input:  full state (EventBridge event + $.log_result)
Output: {bucket_name, is_public, public_reason, current_policy}
        → stored at $.bucket_check_result
"""
import json

import boto3
from botocore.exceptions import ClientError


_PUBLIC_PRINCIPALS = {"*", "arn:aws:iam::*:root"}


def _policy_allows_public_access(policy_doc: dict) -> tuple[bool, str]:
    """Return (is_public, reason) by scanning for Allow * Principal statements."""
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True, "policy_allows_all_principals"
        if isinstance(principal, dict):
            aws = principal.get("AWS", [])
            if isinstance(aws, str):
                aws = [aws]
            if any(p in _PUBLIC_PRINCIPALS for p in aws):
                return True, "policy_allows_public_principal"
    return False, ""


def lambda_handler(event, context):
    s3 = boto3.client("s3")

    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})

    bucket_name = request_params.get("bucketName", "")
    if not bucket_name:
        return {"bucket_name": "", "is_public": False, "public_reason": "no_bucket_name", "current_policy": ""}

    is_public = False
    public_reason = ""
    current_policy = ""

    # Check bucket policy
    try:
        policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
        current_policy = policy_resp.get("Policy", "{}")
        policy_doc = json.loads(current_policy)
        is_public, public_reason = _policy_allows_public_access(policy_doc)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            current_policy = "{}"
        else:
            print(f"Warning: could not get bucket policy: {e}")

    # Check ACL if not already flagged as public
    if not is_public:
        try:
            acl_resp = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl_resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ):
                    is_public = True
                    public_reason = f"acl_grants_{grantee['URI']}"
                    break
        except Exception as e:
            print(f"Warning: could not get bucket ACL: {e}")

    # Check Block Public Access settings
    try:
        bpa_resp = s3.get_public_access_block(Bucket=bucket_name)
        bpa = bpa_resp.get("PublicAccessBlockConfiguration", {})
        if bpa.get("BlockPublicPolicy") and bpa.get("BlockPublicAcls"):
            is_public = False
            public_reason = "block_public_access_active"
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            print(f"Warning: could not get public access block: {e}")

    print(f"Bucket {bucket_name}: is_public={is_public}, reason={public_reason}")

    return {
        "bucket_name": bucket_name,
        "is_public": is_public,
        "public_reason": public_reason,
        "current_policy": current_policy,
    }
