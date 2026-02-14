import json
import boto3
import logging
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

snsclient = boto3.client('sns')
iamclient = boto3.client('iam')
snsARN = os.environ['SNSARN']

# Root API actions classified by severity
CRITICAL_ACTIONS = {
    'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
    'CreateLoginProfile', 'UpdateLoginProfile', 'DeleteLoginProfile',
    'EnableMFADevice', 'DeactivateMFADevice', 'DeleteVirtualMFADevice',
    'CreateVirtualMFADevice', 'ResyncMFADevice',
    'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy', 'DeleteUserPolicy',
    'CreateUser', 'DeleteUser',
    'CreateRole', 'DeleteRole', 'AttachRolePolicy', 'DetachRolePolicy',
    'UpdateAssumeRolePolicy', 'PutRolePolicy',
    'CreatePolicy', 'CreatePolicyVersion',
    'PasswordRecoveryRequested', 'PasswordUpdated',
    'ConsoleLogin',
}

HIGH_ACTIONS = {
    'StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors',
    'DeleteFlowLogs', 'DeleteVpcPeeringConnection',
    'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
    'CreateSecurityGroup', 'DeleteSecurityGroup',
    'RunInstances', 'TerminateInstances',
    'CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy',
    'PutBucketPublicAccessBlock',
    'CreateStack', 'DeleteStack', 'UpdateStack',
}


def classify_severity(event_name, detail_type):
    """Classify the severity of a root user action."""
    if 'Console Sign In' in detail_type:
        return 'CRITICAL'
    if event_name in CRITICAL_ACTIONS:
        return 'CRITICAL'
    if event_name in HIGH_ACTIONS:
        return 'HIGH'
    return 'MEDIUM'


def get_account_alias(account_id):
    """Attempt to resolve the account alias. Falls back to account ID."""
    try:
        response = iamclient.list_account_aliases()
        aliases = response.get('AccountAliases', [])
        if aliases:
            return aliases[0]
    except ClientError:
        pass
    return account_id


def extract_event_details(event):
    """Extract and structure relevant fields from the CloudTrail event."""
    detail = event.get('detail', {})
    user_identity = detail.get('userIdentity', {})

    return {
        'eventName': detail.get('eventName', 'Unknown'),
        'eventTime': detail.get('eventTime', event.get('time', 'Unknown')),
        'awsRegion': detail.get('awsRegion', event.get('region', 'Unknown')),
        'sourceIPAddress': detail.get('sourceIPAddress', 'Unknown'),
        'userAgent': detail.get('userAgent', 'Unknown'),
        'accountId': event.get('account', 'Unknown'),
        'userType': user_identity.get('type', 'Unknown'),
        'arn': user_identity.get('arn', 'Unknown'),
        'errorCode': detail.get('errorCode'),
        'errorMessage': detail.get('errorMessage'),
        'detailType': event.get('detail-type', 'Unknown'),
        'requestParameters': detail.get('requestParameters'),
        'responseElements': detail.get('responseElements'),
    }


def format_notification(details, severity, account_alias):
    """Build a human-readable notification message."""
    lines = [
        f"{'=' * 60}",
        f"  ROOT USER ACTIVITY DETECTED - Severity: {severity}",
        f"{'=' * 60}",
        "",
        f"Account:       {account_alias} ({details['accountId']})",
        f"Action:        {details['eventName']}",
        f"Event Type:    {details['detailType']}",
        f"Time (UTC):    {details['eventTime']}",
        f"Region:        {details['awsRegion']}",
        f"Source IP:     {details['sourceIPAddress']}",
        f"User Agent:    {details['userAgent']}",
    ]

    if details['errorCode']:
        lines.append(f"Error Code:    {details['errorCode']}")
    if details['errorMessage']:
        lines.append(f"Error Message: {details['errorMessage']}")

    lines.extend([
        "",
        "--- Recommended Actions ---",
    ])

    if severity == 'CRITICAL':
        lines.extend([
            "1. Verify this activity was authorized immediately",
            "2. If unauthorized, rotate root credentials and enable MFA",
            "3. Review CloudTrail logs for related activity",
            "4. Consider enabling AWS Organizations SCP to deny root actions",
        ])
    elif severity == 'HIGH':
        lines.extend([
            "1. Confirm the action was performed by an authorized operator",
            "2. Review CloudTrail for the full session activity",
            "3. Validate no security controls were weakened",
        ])
    else:
        lines.extend([
            "1. Review whether root usage was necessary",
            "2. Consider using IAM roles with least-privilege instead",
        ])

    lines.extend([
        "",
        "--- Raw Event ---",
        json.dumps(details.get('requestParameters') or {}, indent=2, default=str),
    ])

    return "\n".join(lines)


def lambda_handler(event, context):
    """Process root user activity events and send SNS notifications."""
    logger.debug("Received event: %s", json.dumps(event, default=str))

    details = extract_event_details(event)
    severity = classify_severity(details['eventName'], details['detailType'])
    account_alias = get_account_alias(details['accountId'])

    logger.info(
        "Root activity detected: action=%s severity=%s account=%s region=%s source_ip=%s",
        details['eventName'], severity, details['accountId'],
        details['awsRegion'], details['sourceIPAddress'],
    )

    subject = "[{0}] Root: {1} in {2}".format(
        severity, details['eventName'], account_alias
    )[:100]

    message_body = format_notification(details, severity, account_alias)

    try:
        response = snsclient.publish(
            TargetArn=snsARN,
            Subject=subject,
            Message=json.dumps({
                'default': json.dumps(event, default=str),
                'email': message_body,
                'email-json': json.dumps({
                    'severity': severity,
                    'account': details['accountId'],
                    'accountAlias': account_alias,
                    'action': details['eventName'],
                    'sourceIP': details['sourceIPAddress'],
                    'region': details['awsRegion'],
                    'time': details['eventTime'],
                    'rawEvent': event,
                }, default=str),
            }),
            MessageStructure='json',
        )
        logger.info("SNS publish successful: MessageId=%s", response.get('MessageId'))
    except ClientError as e:
        logger.error(
            "Failed to publish to SNS: %s (action=%s, account=%s)",
            e, details['eventName'], details['accountId'],
        )
        raise
