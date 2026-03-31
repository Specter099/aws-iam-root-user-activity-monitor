"""
Runbook 3 – Data Exfiltration Response, Step 2a:
For a ModifySnapshotAttribute event, identify the external accounts that
the snapshot was shared with and revoke the share.

Input:  full state (EventBridge event + $.log_result)
Output: {snapshot_id, revoked_accounts, status, error}
        → stored at $.revoke_snapshot_result
"""
import boto3


def lambda_handler(event, context):
    ec2 = boto3.client("ec2")

    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    hub_account_id = event.get("account", "")

    snapshot_id = request_params.get("snapshotId", "")
    if not snapshot_id:
        return {"snapshot_id": snapshot_id, "revoked_accounts": [], "status": "skipped_no_snapshot_id", "error": None}

    # Determine which accounts were granted permission in this event
    # requestParameters.createVolumePermission.add contains new grants
    create_volume_permission = request_params.get("createVolumePermission", {})
    add_permissions = create_volume_permission.get("add", {}).get("items", [])

    external_accounts = [
        item.get("userId", item.get("group", ""))
        for item in add_permissions
        if item.get("userId", item.get("group", "")) != hub_account_id
        and item.get("userId", item.get("group", "")) != ""
    ]

    if not external_accounts:
        # Fall back: describe current permissions and revoke anything external
        try:
            resp = ec2.describe_snapshot_attribute(
                SnapshotId=snapshot_id, Attribute="createVolumePermission"
            )
            for perm in resp.get("CreateVolumePermissions", []):
                user_id = perm.get("UserId", perm.get("Group", ""))
                if user_id and user_id != hub_account_id:
                    external_accounts.append(user_id)
        except Exception as e:
            print(f"Warning: could not describe snapshot permissions: {e}")

    revoked = []
    errors = []
    for account in external_accounts:
        try:
            remove_item = {"UserId": account} if account.isdigit() else {"Group": account}
            ec2.modify_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute="createVolumePermission",
                OperationType="remove",
                UserIds=[account] if account.isdigit() else [],
                GroupNames=[] if account.isdigit() else [account],
            )
            revoked.append(account)
            print(f"Revoked snapshot {snapshot_id} share from {account}")
        except Exception as e:
            err = f"Failed to revoke {account}: {e}"
            errors.append(err)
            print(err)

    return {
        "snapshot_id": snapshot_id,
        "revoked_accounts": revoked,
        "status": "revoked" if revoked else ("no_external_shares" if not errors else "failed"),
        "error": errors if errors else None,
    }
