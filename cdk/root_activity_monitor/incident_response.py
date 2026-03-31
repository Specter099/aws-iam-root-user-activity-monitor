"""
IncidentResponseRunbooks CDK Construct
--------------------------------------
Creates 4 Step Functions state machines that auto-remediate security incidents
detected by the hub EventBridge bus. Each state machine runs in *parallel*
with (not replacing) the existing Lambda-based alerting pipeline.

Runbooks:
  1. Root Activity Response         (CRITICAL)
  2. Credential Compromise Response (HIGH)
  3. Data Exfiltration Response     (CRITICAL)
  4. Failed Login Investigation     (CRITICAL)
"""
from __future__ import annotations

import os

import aws_cdk as cdk
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as _lambda
import aws_cdk.aws_logs as logs
import aws_cdk.aws_sns as sns
import aws_cdk.aws_stepfunctions as sfn
import aws_cdk.aws_stepfunctions_tasks as sfn_tasks
from constructs import Construct

# Path to the runbooks/ directory at repo root
_RUNBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "runbooks")

# Privilege-escalation event names that trigger Runbook 2
_CRED_COMPROMISE_EVENTS = ["CreateAccessKey", "UpdateAssumeRolePolicy"]

# Data-exfiltration event names that trigger Runbook 3
_DATA_EXFIL_EVENTS = ["ModifySnapshotAttribute", "PutBucketPolicy", "PutBucketAcl"]


class IncidentResponseRunbooks(Construct):
    """
    Deploys the DynamoDB incidents table, all runbook Lambda functions,
    4 Step Functions state machines, and the EventBridge rules that trigger them.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        sns_topic: sns.Topic,
        event_bus: events.EventBus,
    ) -> None:
        super().__init__(scope, construct_id)

        self._sns_topic = sns_topic

        # ── DynamoDB Incidents Table ──────────────────────────────────────────
        self.incidents_table = dynamodb.Table(
            self,
            "IncidentsTable",
            table_name="security-monitor-incidents",
            partition_key=dynamodb.Attribute(
                name="incident_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # ── Shared Lambda functions ───────────────────────────────────────────
        self._log_fn = self._create_lambda("LogIncident", "log_incident")
        self._send_report_fn = self._create_lambda(
            "SendIncidentReport", "send_incident_report"
        )

        self.incidents_table.grant_write_data(self._log_fn)
        sns_topic.grant_publish(self._send_report_fn)

        # ── Runbook-specific Lambdas + State Machines ─────────────────────────
        self.root_activity_sm = self._build_root_activity_sm()
        self.credential_compromise_sm = self._build_credential_compromise_sm()
        self.data_exfiltration_sm = self._build_data_exfiltration_sm()
        self.failed_login_sm = self._build_failed_login_sm()

        # ── EventBridge rules (parallel to existing Lambda alerting) ──────────
        self._add_sfn_rules(event_bus)

        # ── Stack outputs ─────────────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "IncidentsTableArn",
            value=self.incidents_table.table_arn,
            description="DynamoDB incidents table ARN",
        )
        cdk.CfnOutput(
            self,
            "RootActivityRunbookArn",
            value=self.root_activity_sm.state_machine_arn,
            description="Root Activity incident response Step Function ARN",
        )
        cdk.CfnOutput(
            self,
            "CredentialCompromiseRunbookArn",
            value=self.credential_compromise_sm.state_machine_arn,
            description="Credential Compromise incident response Step Function ARN",
        )
        cdk.CfnOutput(
            self,
            "DataExfiltrationRunbookArn",
            value=self.data_exfiltration_sm.state_machine_arn,
            description="Data Exfiltration incident response Step Function ARN",
        )
        cdk.CfnOutput(
            self,
            "FailedLoginRunbookArn",
            value=self.failed_login_sm.state_machine_arn,
            description="Failed Login Investigation Step Function ARN",
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _create_lambda(
        self,
        construct_id: str,
        handler_module: str,
        extra_policies: list[iam.PolicyStatement] | None = None,
    ) -> _lambda.Function:
        """Create a runbook Lambda pointing at the shared runbooks/ asset directory."""
        fn = _lambda.Function(
            self,
            construct_id,
            function_name=f"sec-runbook-{handler_module.replace('_', '-')}",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler=f"{handler_module}.lambda_handler",
            code=_lambda.Code.from_asset(_RUNBOOKS_DIR),
            timeout=cdk.Duration.seconds(60),
            environment={
                "INCIDENTS_TABLE": self.incidents_table.table_name,
                "SNS_TOPIC_ARN": self._sns_topic.topic_arn,
            },
        )
        for policy in extra_policies or []:
            fn.add_to_role_policy(policy)
        return fn

    def _sfn_log_group(self, name: str) -> logs.LogGroup:
        return logs.LogGroup(
            self,
            f"{name}Logs",
            log_group_name=f"/aws/states/{name}",
            retention=logs.RetentionDays.THREE_MONTHS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def _make_state_machine(
        self,
        construct_id: str,
        name: str,
        chain: sfn.IChainable,
    ) -> sfn.StateMachine:
        """Wrap a chain in a StandardWorkflow StateMachine with CloudWatch logging."""
        lg = self._sfn_log_group(name)
        return sfn.StateMachine(
            self,
            construct_id,
            state_machine_name=name,
            definition_body=sfn.DefinitionBody.from_chainable(chain),
            tracing_enabled=True,
            logs=sfn.LogOptions(
                destination=lg,
                level=sfn.LogLevel.ERROR,
                include_execution_data=False,
            ),
        )

    def _log_task(self, prefix: str) -> sfn_tasks.LambdaInvoke:
        return sfn_tasks.LambdaInvoke(
            self,
            f"{prefix}-Log",
            lambda_function=self._log_fn,
            payload_response_only=True,
            result_path="$.log_result",
        )

    def _send_report_task(self, prefix: str) -> sfn_tasks.LambdaInvoke:
        return sfn_tasks.LambdaInvoke(
            self,
            f"{prefix}-SendReport",
            lambda_function=self._send_report_fn,
            payload_response_only=True,
            result_path="$.report_result",
        )

    # ── Runbook 1: Root Activity Response ─────────────────────────────────────

    def _build_root_activity_sm(self) -> sfn.StateMachine:
        # Lambdas
        cloudtrail_fn = self._create_lambda(
            "RootCheckCloudTrail",
            "root_check_cloudtrail",
            [iam.PolicyStatement(actions=["cloudtrail:LookupEvents"], resources=["*"])],
        )
        check_keys_fn = self._create_lambda(
            "RootCheckAccessKeys",
            "root_check_access_keys",
            [iam.PolicyStatement(actions=["iam:ListAccessKeys"], resources=["*"])],
        )
        deactivate_keys_fn = self._create_lambda(
            "RootDeactivateKeys",
            "root_deactivate_keys",
            [iam.PolicyStatement(actions=["iam:UpdateAccessKey"], resources=["*"])],
        )

        # States
        log = self._log_task("Root")
        send = self._send_report_task("Root")

        check_ct = sfn_tasks.LambdaInvoke(
            self,
            "Root-CheckCloudTrail",
            lambda_function=cloudtrail_fn,
            payload_response_only=True,
            result_path="$.cloudtrail_result",
        )
        check_keys = sfn_tasks.LambdaInvoke(
            self,
            "Root-CheckKeys",
            lambda_function=check_keys_fn,
            payload_response_only=True,
            result_path="$.keys_result",
        )
        deactivate = sfn_tasks.LambdaInvoke(
            self,
            "Root-DeactivateKeys",
            lambda_function=deactivate_keys_fn,
            payload_response_only=True,
            result_path="$.deactivate_result",
        )
        deactivate.next(send)

        keys_choice = sfn.Choice(self, "Root-NewKeysFound?")
        keys_choice.when(
            sfn.Condition.boolean_equals("$.keys_result.new_keys_found", True),
            deactivate,
        )
        keys_choice.otherwise(send)

        chain = log.next(check_ct).next(check_keys).next(keys_choice)
        return self._make_state_machine(
            "RootActivityResponseSM",
            "sec-incident-root-activity",
            chain,
        )

    # ── Runbook 2: Credential Compromise Response ─────────────────────────────

    def _build_credential_compromise_sm(self) -> sfn.StateMachine:
        # Lambdas
        check_key_fn = self._create_lambda(
            "CredCheckKeyCreation",
            "cred_check_key_creation",
        )
        cred_deactivate_fn = self._create_lambda(
            "CredDeactivateKey",
            "cred_deactivate_key",
            [iam.PolicyStatement(actions=["iam:UpdateAccessKey"], resources=["*"])],
        )
        check_trust_fn = self._create_lambda(
            "CredCheckTrustPolicy",
            "cred_check_trust_policy",
        )
        revert_trust_fn = self._create_lambda(
            "CredRevertTrustPolicy",
            "cred_revert_trust_policy",
            [
                iam.PolicyStatement(
                    actions=["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=["cloudtrail:LookupEvents"], resources=["*"]
                ),
            ],
        )

        # States
        log = self._log_task("Cred")
        send = self._send_report_task("Cred")

        check_key = sfn_tasks.LambdaInvoke(
            self,
            "Cred-CheckKeyCreation",
            lambda_function=check_key_fn,
            payload_response_only=True,
            result_path="$.key_creation_result",
        )
        cred_deactivate = sfn_tasks.LambdaInvoke(
            self,
            "Cred-DeactivateKey",
            lambda_function=cred_deactivate_fn,
            payload_response_only=True,
            result_path="$.cred_deactivate_result",
        )
        check_trust = sfn_tasks.LambdaInvoke(
            self,
            "Cred-CheckTrustPolicy",
            lambda_function=check_trust_fn,
            payload_response_only=True,
            result_path="$.trust_policy_result",
        )
        revert_trust = sfn_tasks.LambdaInvoke(
            self,
            "Cred-RevertTrustPolicy",
            lambda_function=revert_trust_fn,
            payload_response_only=True,
            result_path="$.revert_trust_result",
        )

        cred_deactivate.next(send)
        revert_trust.next(send)

        suspicious_choice = sfn.Choice(self, "Cred-Suspicious?")
        suspicious_choice.when(
            sfn.Condition.boolean_equals("$.key_creation_result.is_suspicious", True),
            cred_deactivate,
        )
        suspicious_choice.otherwise(send)

        external_choice = sfn.Choice(self, "Cred-ExternalAccounts?")
        external_choice.when(
            sfn.Condition.boolean_equals(
                "$.trust_policy_result.external_accounts_found", True
            ),
            revert_trust,
        )
        external_choice.otherwise(send)

        event_type_choice = sfn.Choice(self, "Cred-EventType?")
        event_type_choice.when(
            sfn.Condition.string_equals("$.detail.eventName", "CreateAccessKey"),
            check_key.next(suspicious_choice),
        )
        event_type_choice.when(
            sfn.Condition.string_equals(
                "$.detail.eventName", "UpdateAssumeRolePolicy"
            ),
            check_trust.next(external_choice),
        )
        event_type_choice.otherwise(send)

        chain = log.next(event_type_choice)
        return self._make_state_machine(
            "CredentialCompromiseResponseSM",
            "sec-incident-cred-compromise",
            chain,
        )

    # ── Runbook 3: Data Exfiltration Response ─────────────────────────────────

    def _build_data_exfiltration_sm(self) -> sfn.StateMachine:
        # Lambdas
        revoke_snap_fn = self._create_lambda(
            "ExfilRevokeSnapshot",
            "exfil_revoke_snapshot",
            [
                iam.PolicyStatement(
                    actions=[
                        "ec2:ModifySnapshotAttribute",
                        "ec2:DescribeSnapshotAttribute",
                    ],
                    resources=["*"],
                )
            ],
        )
        check_bucket_fn = self._create_lambda(
            "ExfilCheckBucket",
            "exfil_check_bucket",
            [
                iam.PolicyStatement(
                    actions=[
                        "s3:GetBucketPolicy",
                        "s3:GetBucketAcl",
                        "s3:GetBucketPublicAccessBlock",
                    ],
                    resources=["*"],
                )
            ],
        )
        revert_policy_fn = self._create_lambda(
            "ExfilRevertBucketPolicy",
            "exfil_revert_bucket_policy",
            [
                iam.PolicyStatement(
                    actions=[
                        "s3:DeleteBucketPolicy",
                        "s3:PutBucketAcl",
                    ],
                    resources=["*"],
                )
            ],
        )

        # States
        log = self._log_task("Exfil")
        send = self._send_report_task("Exfil")

        revoke_snap = sfn_tasks.LambdaInvoke(
            self,
            "Exfil-RevokeSnapshot",
            lambda_function=revoke_snap_fn,
            payload_response_only=True,
            result_path="$.revoke_snapshot_result",
        )
        check_bucket = sfn_tasks.LambdaInvoke(
            self,
            "Exfil-CheckBucket",
            lambda_function=check_bucket_fn,
            payload_response_only=True,
            result_path="$.bucket_check_result",
        )
        revert_policy = sfn_tasks.LambdaInvoke(
            self,
            "Exfil-RevertBucketPolicy",
            lambda_function=revert_policy_fn,
            payload_response_only=True,
            result_path="$.revert_policy_result",
        )

        revoke_snap.next(send)
        revert_policy.next(send)

        bucket_public_choice = sfn.Choice(self, "Exfil-BucketPublic?")
        bucket_public_choice.when(
            sfn.Condition.boolean_equals("$.bucket_check_result.is_public", True),
            revert_policy,
        )
        bucket_public_choice.otherwise(send)

        event_type_choice = sfn.Choice(self, "Exfil-EventType?")
        event_type_choice.when(
            sfn.Condition.string_equals(
                "$.detail.eventName", "ModifySnapshotAttribute"
            ),
            revoke_snap,
        )
        event_type_choice.when(
            sfn.Condition.or_(
                sfn.Condition.string_equals("$.detail.eventName", "PutBucketPolicy"),
                sfn.Condition.string_equals("$.detail.eventName", "PutBucketAcl"),
            ),
            check_bucket.next(bucket_public_choice),
        )
        event_type_choice.otherwise(send)

        chain = log.next(event_type_choice)
        return self._make_state_machine(
            "DataExfiltrationResponseSM",
            "sec-incident-data-exfil",
            chain,
        )

    # ── Runbook 4: Failed Login Investigation ─────────────────────────────────

    def _build_failed_login_sm(self) -> sfn.StateMachine:
        query_fn = self._create_lambda(
            "LoginQueryFailures",
            "login_query_failures",
            [iam.PolicyStatement(actions=["cloudtrail:LookupEvents"], resources=["*"])],
        )

        log = self._log_task("Login")
        send = self._send_report_task("Login")

        query = sfn_tasks.LambdaInvoke(
            self,
            "Login-QueryFailures",
            lambda_function=query_fn,
            payload_response_only=True,
            result_path="$.login_query_result",
        )

        chain = log.next(query).next(send)
        return self._make_state_machine(
            "FailedLoginInvestigationSM",
            "sec-incident-failed-login",
            chain,
        )

    # ── EventBridge Rules ─────────────────────────────────────────────────────

    def _add_sfn_rules(self, event_bus: events.EventBus) -> None:
        """Add 4 EventBridge rules on the hub bus, each targeting a Step Function.
        These run in parallel with the existing Lambda-based alerting rules."""

        def _rule(construct_id, rule_name, description, event_pattern, sm):
            rule = events.Rule(
                self,
                construct_id,
                rule_name=rule_name,
                description=description,
                event_bus=event_bus,
                event_pattern=event_pattern,
            )
            rule.add_target(
                targets.SfnStateMachine(
                    sm,
                    retry_attempts=2,
                    max_event_age=cdk.Duration.hours(1),
                )
            )

        # Runbook 1: all root user activity
        _rule(
            "HubRunbookRootActivityRule",
            "hub-runbook-root-activity",
            "Trigger Root Activity Runbook for root user events (parallel to Lambda alerting).",
            events.EventPattern(
                detail_type=[
                    "AWS API Call via CloudTrail",
                    "AWS Console Sign In via CloudTrail",
                    "AWS Service Event via CloudTrail",
                ],
                detail={"userIdentity": {"type": ["Root"]}},
            ),
            self.root_activity_sm,
        )

        # Runbook 2: CreateAccessKey and UpdateAssumeRolePolicy
        _rule(
            "HubRunbookCredCompromiseRule",
            "hub-runbook-cred-compromise",
            "Trigger Credential Compromise Runbook for key creation and role trust policy changes.",
            events.EventPattern(
                detail_type=["AWS API Call via CloudTrail"],
                detail={"eventName": _CRED_COMPROMISE_EVENTS},
            ),
            self.credential_compromise_sm,
        )

        # Runbook 3: snapshot sharing and bucket exposure
        _rule(
            "HubRunbookDataExfilRule",
            "hub-runbook-data-exfil",
            "Trigger Data Exfiltration Runbook for snapshot sharing and S3 bucket exposure.",
            events.EventPattern(
                detail_type=["AWS API Call via CloudTrail"],
                detail={"eventName": _DATA_EXFIL_EVENTS},
            ),
            self.data_exfiltration_sm,
        )

        # Runbook 4: failed console login
        _rule(
            "HubRunbookFailedLoginRule",
            "hub-runbook-failed-login",
            "Trigger Failed Login Investigation Runbook for failed console login attempts.",
            events.EventPattern(
                detail_type=["AWS Console Sign In via CloudTrail"],
                detail={
                    "responseElements": {"ConsoleLogin": ["Failure"]},
                },
            ),
            self.failed_login_sm,
        )
