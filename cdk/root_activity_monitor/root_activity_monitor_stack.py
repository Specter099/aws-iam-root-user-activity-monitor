import os

import aws_cdk as cdk
import aws_cdk.aws_cloudwatch as cloudwatch
import aws_cdk.aws_cloudwatch_actions as cw_actions
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kinesisfirehose as firehose
import aws_cdk.aws_kms as kms
import aws_cdk.aws_lambda as _lambda
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_sns as sns
import aws_cdk.aws_sns_subscriptions as subscriptions
import aws_cdk.aws_sqs as sqs
from constructs import Construct

# Event names forwarded by the spoke's new detection rules.
# Used to build hub EventBridge rule patterns that mirror the spoke.
_CONSOLE_SIGNIN_ANOMALY_NAMES = ["ConsoleLogin"]

_IAM_CREDENTIAL_ABUSE_NAMES = [
    "GetSessionToken",
    "AssumeRole",
    "GetFederationToken",
    "GetCallerIdentity",
]

_PRIVILEGE_ESCALATION_NAMES = [
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "CreateUser",
]

_DATA_EXFILTRATION_NAMES = [
    "CreateSnapshot",
    "ModifySnapshotAttribute",
    "PutBucketPolicy",
    "PutBucketAcl",
    "ModifyDBSnapshotAttribute",
    "CreateDBSnapshot",
]

# EventBridge pattern fragment that excludes root principals, keeping new
# category rules mutually exclusive with the existing root-activity rule.
_NON_ROOT_IDENTITY = {"userIdentity": {"type": [{"anything-but": "Root"}]}}


class RootActivityMonitorStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        notification_email: str,
        organization_id: str | None = None,
        sns_topic_name: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        sns_topic_name = sns_topic_name or "aws-iam-root-user-activity-monitor"

        # --- SNS Topic ---
        self.sns_topic = sns.Topic(
            self,
            "RootActivitySnsTopic",
            topic_name=sns_topic_name,
            display_name="AWS IAM Root User Activity Monitor",
            master_key=kms.Alias.from_alias_name(
                self, "SnsKmsKey", "alias/aws/sns"
            ),
        )

        self.sns_topic.add_subscription(
            subscriptions.EmailSubscription(notification_email, json=True)
        )

        # --- Dead Letter Queue ---
        self.dead_letter_queue = sqs.Queue(
            self,
            "RootActivityDLQ",
            queue_name="root-activity-monitor-dlq",
            retention_period=cdk.Duration.days(14),
            encryption=sqs.QueueEncryption.KMS_MANAGED,
        )

        # --- CloudWatch Log Group ---
        log_group = logs.LogGroup(
            self,
            "RootActivityLambdaLogs",
            log_group_name="/aws/lambda/root-activity-monitor",
            retention=logs.RetentionDays.THREE_MONTHS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # --- Lambda Function ---
        self.lambda_function = _lambda.Function(
            self,
            "RootActivityLambda",
            function_name="root-activity-monitor",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="RootActivityLambda.lambda_handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "..", "..", "root-activity-monitor-module"
                ),
                exclude=[
                    "*.tf",
                    "*.json",
                    "outputs",
                    "iam",
                    "README.md",
                    "LICENSE",
                ],
            ),
            timeout=cdk.Duration.seconds(30),
            reserved_concurrent_executions=5,
            dead_letter_queue=self.dead_letter_queue,
            environment={
                "SNSARN": self.sns_topic.topic_arn,
            },
            log_group=log_group,
        )

        # Grant Lambda permissions to publish to SNS
        self.sns_topic.grant_publish(self.lambda_function)

        # Grant Lambda permission to list account aliases
        self.lambda_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="ListAccountAlias",
                actions=["iam:ListAccountAliases"],
                resources=["*"],
            )
        )

        # Grant Lambda permission to resolve spoke account names via Organizations
        self.lambda_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="OrganizationsDescribeAccount",
                actions=["organizations:DescribeAccount"],
                resources=["*"],
            )
        )

        # --- EventBridge Event Bus ---
        self.event_bus = events.EventBus(
            self,
            "HubRootActivityEventBus",
            event_bus_name="hub-root-activity",
        )

        # Organization-scoped access to the event bus
        if organization_id:
            events.CfnEventBusPolicy(
                self,
                "OrgAccessPolicy",
                event_bus_name=self.event_bus.event_bus_name,
                statement_id="OrganizationAccess",
                action="events:PutEvents",
                principal="*",
                condition=events.CfnEventBusPolicy.ConditionProperty(
                    type="StringEquals",
                    key="aws:PrincipalOrgID",
                    value=organization_id,
                ),
            )

        # Shared helper: add a rule → Lambda target on the hub event bus
        def _add_hub_rule(construct_id, rule_name, description, event_pattern):
            rule = events.Rule(
                self,
                construct_id,
                rule_name=rule_name,
                description=description,
                event_bus=self.event_bus,
                event_pattern=event_pattern,
            )
            rule.add_target(
                targets.LambdaFunction(
                    self.lambda_function,
                    retry_attempts=3,
                    max_event_age=cdk.Duration.hours(1),
                )
            )
            return rule

        # ── Existing rule: root user activity ─────────────────────────────
        _add_hub_rule(
            "HubRootActivityRule",
            "hub-capture-root-activity",
            "Capture root user AWS Console Sign In, API calls, and credential changes.",
            events.EventPattern(
                detail_type=[
                    "AWS API Call via CloudTrail",
                    "AWS Console Sign In via CloudTrail",
                    "AWS Service Event via CloudTrail",
                ],
                detail={
                    "userIdentity": {
                        "type": ["Root"],
                    },
                },
            ),
        )

        # ── Category 1: Console sign-in anomalies (non-root) ──────────────
        # Matches ConsoleLogin where MFA was not used OR the login failed.
        # Uses EventBridge $or content-based filtering.
        _add_hub_rule(
            "HubConsoleSignInAnomalyRule",
            "hub-capture-console-signin-anomalies",
            "Detect console logins without MFA or failed login attempts (non-root).",
            events.EventPattern(
                detail_type=["AWS Console Sign In via CloudTrail"],
                detail={
                    **_NON_ROOT_IDENTITY,
                    "$or": [
                        {
                            "additionalEventData": {
                                "MFAUsed": [{"anything-but": "Yes"}],
                            },
                        },
                        {
                            "responseElements": {
                                "ConsoleLogin": ["Failure"],
                            },
                        },
                    ],
                },
            ),
        )

        # ── Category 2: IAM credential abuse (non-root) ───────────────────
        _add_hub_rule(
            "HubIAMCredentialAbuseRule",
            "hub-capture-iam-credential-abuse",
            "Detect credential retrieval and reconnaissance calls (non-root).",
            events.EventPattern(
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    **_NON_ROOT_IDENTITY,
                    "eventName": _IAM_CREDENTIAL_ABUSE_NAMES,
                },
            ),
        )

        # ── Category 3: Privilege escalation (non-root) ───────────────────
        _add_hub_rule(
            "HubPrivilegeEscalationRule",
            "hub-capture-privilege-escalation",
            "Detect IAM policy changes and identity creation that could grant elevated access (non-root).",
            events.EventPattern(
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    **_NON_ROOT_IDENTITY,
                    "eventName": _PRIVILEGE_ESCALATION_NAMES,
                },
            ),
        )

        # ── Category 4: Data exfiltration signals (non-root) ──────────────
        _add_hub_rule(
            "HubDataExfiltrationRule",
            "hub-capture-data-exfiltration",
            "Detect EBS/RDS snapshot sharing and S3 bucket exposure (non-root).",
            events.EventPattern(
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    **_NON_ROOT_IDENTITY,
                    "eventName": _DATA_EXFILTRATION_NAMES,
                },
            ),
        )

        # --- S3 Log Archive Bucket ---
        log_archive_bucket = s3.Bucket(
            self,
            "SecurityMonitorLogsBucket",
            bucket_name="security-monitor-logs-124307364559-us-east-1-an",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    enabled=True,
                    expiration=cdk.Duration.days(365),
                )
            ],
        )

        # --- Kinesis Data Firehose → S3 ---

        # IAM role that Firehose assumes to write to S3
        firehose_role = iam.Role(
            self,
            "FirehoseDeliveryRole",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
            description="Allows Kinesis Data Firehose to deliver log events to S3",
        )
        log_archive_bucket.grant_read_write(firehose_role)

        delivery_stream = firehose.CfnDeliveryStream(
            self,
            "SecurityMonitorFirehose",
            delivery_stream_name="security-monitor-logs-firehose",
            delivery_stream_type="DirectPut",
            extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=log_archive_bucket.bucket_arn,
                role_arn=firehose_role.role_arn,
                prefix="logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
                error_output_prefix="errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    interval_in_seconds=300,
                    size_in_m_bs=64,
                ),
                compression_format="GZIP",
            ),
        )

        # IAM role that CloudWatch Logs assumes to put records into Firehose
        cw_logs_role = iam.Role(
            self,
            "CWLogsFirehoseRole",
            assumed_by=iam.ServicePrincipal(
                "logs.amazonaws.com",
                conditions={
                    "StringLike": {
                        "aws:SourceArn": f"arn:aws:logs:{self.region}:{self.account}:*"
                    }
                },
            ),
            description="Allows CloudWatch Logs to deliver log events to Kinesis Data Firehose",
        )
        cw_logs_role.add_to_policy(
            iam.PolicyStatement(
                sid="PutToFirehose",
                actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
                resources=[delivery_stream.attr_arn],
            )
        )

        # Subscription filter: export ALL Lambda log events to Firehose
        logs.CfnSubscriptionFilter(
            self,
            "LambdaLogsToFirehose",
            log_group_name=log_group.log_group_name,
            filter_name="all-events-to-firehose",
            filter_pattern="",
            destination_arn=delivery_stream.attr_arn,
            role_arn=cw_logs_role.role_arn,
        )

        # --- CloudWatch Alarms ---
        dlq_alarm = cloudwatch.Alarm(
            self,
            "DLQMessagesAlarm",
            alarm_name="root-activity-monitor-dlq-alarm",
            alarm_description="Alert when root activity monitor Lambda fails and sends messages to DLQ",
            metric=self.dead_letter_queue.metric_approximate_number_of_messages_visible(
                period=cdk.Duration.minutes(5),
                statistic="Sum",
            ),
            threshold=0,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        dlq_alarm.add_alarm_action(cw_actions.SnsAction(self.sns_topic))

        lambda_errors_alarm = cloudwatch.Alarm(
            self,
            "LambdaErrorsAlarm",
            alarm_name="root-activity-monitor-lambda-errors",
            alarm_description="Alert when root activity monitor Lambda encounters errors",
            metric=self.lambda_function.metric_errors(
                period=cdk.Duration.minutes(5),
                statistic="Sum",
            ),
            threshold=0,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        lambda_errors_alarm.add_alarm_action(cw_actions.SnsAction(self.sns_topic))

        # --- Outputs ---
        cdk.CfnOutput(
            self,
            "SnsTopicArn",
            value=self.sns_topic.topic_arn,
            description="SNS topic ARN for root activity notifications",
        )

        cdk.CfnOutput(
            self,
            "DlqArn",
            value=self.dead_letter_queue.queue_arn,
            description="Dead Letter Queue ARN for failed Lambda invocations",
        )

        cdk.CfnOutput(
            self,
            "LambdaFunctionArn",
            value=self.lambda_function.function_arn,
            description="Root activity monitor Lambda function ARN",
        )

        cdk.CfnOutput(
            self,
            "EventBusArn",
            value=self.event_bus.event_bus_arn,
            description="Hub EventBridge event bus ARN",
        )

        cdk.CfnOutput(
            self,
            "LogArchiveBucketName",
            value=log_archive_bucket.bucket_name,
            description="S3 bucket for long-term security log archival",
        )

        cdk.CfnOutput(
            self,
            "FirehoseDeliveryStreamArn",
            value=delivery_stream.attr_arn,
            description="Kinesis Data Firehose delivery stream ARN",
        )
