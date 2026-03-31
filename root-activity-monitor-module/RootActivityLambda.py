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
orgclient = boto3.client('organizations')
snsARN = os.environ['SNSARN']

# ── Detection categories ───────────────────────────────────────────────────
CATEGORY_ROOT = 'ROOT_ACTIVITY'
CATEGORY_CONSOLE_ANOMALY = 'CONSOLE_SIGNIN_ANOMALY'
CATEGORY_IAM_ABUSE = 'IAM_CREDENTIAL_ABUSE'
CATEGORY_PRIV_ESC = 'PRIVILEGE_ESCALATION'
CATEGORY_DATA_EXFIL = 'DATA_EXFILTRATION'

# Short labels used in SNS subjects (kept under ~20 chars for subject budget)
CATEGORY_LABELS = {
    CATEGORY_ROOT: 'Root',
    CATEGORY_CONSOLE_ANOMALY: 'Console-Anomaly',
    CATEGORY_IAM_ABUSE: 'IAM-Abuse',
    CATEGORY_PRIV_ESC: 'Priv-Esc',
    CATEGORY_DATA_EXFIL: 'Data-Exfil',
}

# ── Severity sets for root activity ───────────────────────────────────────
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

# ── Action sets for the four new detection categories ─────────────────────
# These apply only to non-root principals; root events use CATEGORY_ROOT.

# Category 2: IAM credential abuse — credential retrieval and reconnaissance.
# CreateAccessKey is omitted here; it belongs to PRIVILEGE_ESCALATION_ACTIONS.
IAM_CREDENTIAL_ABUSE_ACTIONS = {
    'GetSessionToken',
    'AssumeRole',
    'GetFederationToken',
    'GetCallerIdentity',
}

# Category 3: Privilege escalation — granting or expanding access.
PRIVILEGE_ESCALATION_ACTIONS = {
    'CreateAccessKey',
    'AttachUserPolicy', 'AttachRolePolicy',
    'PutUserPolicy', 'PutRolePolicy',
    'CreateLoginProfile', 'UpdateLoginProfile',
    'UpdateAssumeRolePolicy',
    'CreateRole', 'CreateUser',
}

# Category 4: Data exfiltration signals — storage sharing / exposure.
DATA_EXFILTRATION_ACTIONS = {
    'CreateSnapshot', 'ModifySnapshotAttribute',
    'PutBucketPolicy', 'PutBucketAcl',
    'ModifyDBSnapshotAttribute', 'CreateDBSnapshot',
}


def classify_category(event_name, user_type, mfa_used, console_login_result):
    """Return the detection category for an event.

    Root user events always map to ROOT_ACTIVITY.  For non-root principals the
    category is resolved by action set membership (priority: data-exfil >
    priv-esc > iam-abuse > console-anomaly).
    """
    if user_type == 'Root':
        return CATEGORY_ROOT

    # Console sign-in anomaly: MFA absent/disabled or login failed
    if event_name == 'ConsoleLogin':
        if mfa_used != 'Yes' or console_login_result == 'Failure':
            return CATEGORY_CONSOLE_ANOMALY

    if event_name in DATA_EXFILTRATION_ACTIONS:
        return CATEGORY_DATA_EXFIL

    if event_name in PRIVILEGE_ESCALATION_ACTIONS:
        return CATEGORY_PRIV_ESC

    if event_name in IAM_CREDENTIAL_ABUSE_ACTIONS:
        return CATEGORY_IAM_ABUSE

    # Non-root event that doesn't match any new category — treat as root-parity
    return CATEGORY_ROOT


def classify_severity(event_name, detail_type, category):
    """Classify the severity of an event given its category.

    ROOT_ACTIVITY uses the existing CRITICAL_ACTIONS / HIGH_ACTIONS sets.
    New categories use per-category severity rules.
    """
    if category == CATEGORY_ROOT:
        if 'Console Sign In' in detail_type:
            return 'CRITICAL'
        if event_name in CRITICAL_ACTIONS:
            return 'CRITICAL'
        if event_name in HIGH_ACTIONS:
            return 'HIGH'
        return 'MEDIUM'

    if category == CATEGORY_CONSOLE_ANOMALY:
        return 'HIGH'

    if category == CATEGORY_PRIV_ESC:
        # Policy attachment and role/user creation carry higher risk
        if event_name in {
            'AttachUserPolicy', 'AttachRolePolicy',
            'PutUserPolicy', 'PutRolePolicy',
            'UpdateAssumeRolePolicy', 'CreateAccessKey',
        }:
            return 'CRITICAL'
        return 'HIGH'

    if category == CATEGORY_IAM_ABUSE:
        # Reconnaissance calls are lower severity than active abuse
        if event_name in {'GetCallerIdentity', 'GetFederationToken'}:
            return 'MEDIUM'
        return 'HIGH'

    if category == CATEGORY_DATA_EXFIL:
        # Modifying snapshot attributes (sharing externally) is most critical
        if event_name in {'ModifySnapshotAttribute', 'ModifyDBSnapshotAttribute'}:
            return 'CRITICAL'
        return 'HIGH'

    return 'MEDIUM'


def get_account_name(account_id):
    """Resolve the account name for the source account via Organizations API.

    Falls back to the hub account alias, then to the raw account ID.
    """
    # First, try Organizations API to get the spoke account's name
    try:
        response = orgclient.describe_account(AccountId=account_id)
        name = response.get('Account', {}).get('Name')
        if name:
            return name
    except ClientError as e:
        logger.debug("organizations:DescribeAccount failed for %s: %s", account_id, e)

    # Fallback: hub account alias (useful when the event originates in the hub)
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
    additional_data = detail.get('additionalEventData', {})
    response_elements = detail.get('responseElements') or {}

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
        'responseElements': response_elements,
        # Fields used for console sign-in anomaly classification
        'mfaUsed': additional_data.get('MFAUsed', 'Unknown'),
        'consoleLoginResult': response_elements.get('ConsoleLogin', 'Unknown'),
    }


def format_notification(details, severity, category, account_alias):
    """Build a human-readable notification message."""
    category_label = CATEGORY_LABELS.get(category, category)

    lines = [
        f"{'=' * 60}",
        f"  SECURITY ALERT - Category: {category_label} | Severity: {severity}",
        f"{'=' * 60}",
        "",
        f"Account:       {account_alias} ({details['accountId']})",
        f"Action:        {details['eventName']}",
        f"Event Type:    {details['detailType']}",
        f"Time (UTC):    {details['eventTime']}",
        f"Region:        {details['awsRegion']}",
        f"Source IP:     {details['sourceIPAddress']}",
        f"User Agent:    {details['userAgent']}",
        f"User Type:     {details['userType']}",
    ]

    if details['userType'] != 'Root':
        lines.append(f"Principal ARN: {details['arn']}")

    if category == CATEGORY_CONSOLE_ANOMALY:
        lines.append(f"MFA Used:      {details['mfaUsed']}")
        lines.append(f"Login Result:  {details['consoleLoginResult']}")

    if details['errorCode']:
        lines.append(f"Error Code:    {details['errorCode']}")
    if details['errorMessage']:
        lines.append(f"Error Message: {details['errorMessage']}")

    lines.extend([
        "",
        "--- Recommended Actions ---",
    ])

    if category == CATEGORY_ROOT:
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
    elif category == CATEGORY_CONSOLE_ANOMALY:
        lines.extend([
            "1. Confirm the login was performed by an authorized user",
            "2. If MFA was not used, enforce MFA via IAM policy or SCP",
            "3. If the login failed, check for credential stuffing or brute-force",
            "4. Review CloudTrail for subsequent activity from this principal",
        ])
    elif category == CATEGORY_PRIV_ESC:
        lines.extend([
            "1. Verify the IAM change was authorized and follows least-privilege",
            "2. Review the permissions granted and assess blast radius",
            "3. Check whether the principal performing the change should have this ability",
            "4. Consider implementing IAM Access Analyzer to flag overly-permissive policies",
        ])
    elif category == CATEGORY_IAM_ABUSE:
        lines.extend([
            "1. Confirm the credential operation was expected for this principal",
            "2. Review CloudTrail for the full session and subsequent API calls",
            "3. Check for unusual source IPs or user agents",
            "4. If unauthorized, revoke the session and rotate credentials",
        ])
    elif category == CATEGORY_DATA_EXFIL:
        lines.extend([
            "1. Verify the storage change was authorized",
            "2. Inspect snapshot attributes or bucket policies for external sharing",
            "3. If unauthorized, revert the policy/attribute change immediately",
            "4. Review CloudTrail for related data access events",
        ])

    lines.extend([
        "",
        "--- Raw Event ---",
        json.dumps(details.get('requestParameters') or {}, indent=2, default=str),
    ])

    return "\n".join(lines)


def lambda_handler(event, context):
    """Process security events and send categorized SNS notifications."""
    logger.debug("Received event: %s", json.dumps(event, default=str))

    details = extract_event_details(event)
    category = classify_category(
        details['eventName'],
        details['userType'],
        details['mfaUsed'],
        details['consoleLoginResult'],
    )
    severity = classify_severity(details['eventName'], details['detailType'], category)
    account_alias = get_account_name(details['accountId'])

    category_label = CATEGORY_LABELS.get(category, category)
    logger.info(
        "Security event detected: action=%s category=%s severity=%s account=%s region=%s source_ip=%s",
        details['eventName'], category, severity, details['accountId'],
        details['awsRegion'], details['sourceIPAddress'],
    )

    subject = "[{0}] [{1}] {2} in {3}".format(
        severity, category_label, details['eventName'], account_alias
    )[:100]

    message_body = format_notification(details, severity, category, account_alias)

    try:
        response = snsclient.publish(
            TargetArn=snsARN,
            Subject=subject,
            Message=json.dumps({
                'default': json.dumps(event, default=str),
                'email': message_body,
                'email-json': json.dumps({
                    'severity': severity,
                    'category': category,
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
