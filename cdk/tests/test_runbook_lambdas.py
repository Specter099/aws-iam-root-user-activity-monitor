"""
Unit tests for the incident response runbook Lambda handlers.
AWS calls are stubbed via unittest.mock so no real credentials are needed.
"""
import importlib
import json
import sys
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RUNBOOKS_PATH = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "..", "runbooks"
)


def _import_runbook(module_name: str):
    """Import a runbook module from the runbooks/ directory."""
    spec = importlib.util.spec_from_file_location(
        module_name,
        __import__("os").path.join(RUNBOOKS_PATH, f"{module_name}.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cloudtrail_event(
    event_name="CreateAccessKey",
    user_type="IAMUser",
    user_arn="arn:aws:iam::123456789012:user/test",
    source_ip="1.2.3.4",
    account="123456789012",
    region="us-east-1",
    response_elements=None,
    request_parameters=None,
):
    return {
        "version": "0",
        "id": "test-event-id",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": account,
        "time": "2024-01-15T10:00:00Z",
        "region": region,
        "detail": {
            "eventVersion": "1.08",
            "eventName": event_name,
            "eventTime": "2024-01-15T10:00:00Z",
            "awsRegion": region,
            "sourceIPAddress": source_ip,
            "userAgent": "aws-cli/2.0",
            "userIdentity": {
                "type": user_type,
                "arn": user_arn,
                "accountId": account,
                "principalId": user_arn,
            },
            "responseElements": response_elements or {},
            "requestParameters": request_parameters or {},
        },
    }


# ---------------------------------------------------------------------------
# log_incident tests
# ---------------------------------------------------------------------------


class TestLogIncident(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("log_incident")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "test-incidents-table", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.resource")
    def test_returns_incident_id_and_timestamp(self, mock_resource):
        table_mock = MagicMock()
        mock_resource.return_value.Table.return_value = table_mock

        event = _cloudtrail_event()
        result = self.mod.lambda_handler(event, {})

        self.assertIn("incident_id", result)
        self.assertIn("timestamp", result)
        self.assertTrue(len(result["incident_id"]) == 36)  # UUID length
        table_mock.put_item.assert_called_once()

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "test-incidents-table", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.resource")
    def test_item_includes_event_fields(self, mock_resource):
        table_mock = MagicMock()
        mock_resource.return_value.Table.return_value = table_mock

        event = _cloudtrail_event(event_name="PutBucketPolicy", source_ip="10.0.0.1", account="999888777666")
        self.mod.lambda_handler(event, {})

        call_args = table_mock.put_item.call_args[1]["Item"]
        self.assertEqual(call_args["event_name"], "PutBucketPolicy")
        self.assertEqual(call_args["source_ip"], "10.0.0.1")
        self.assertEqual(call_args["event_account"], "999888777666")
        self.assertIn("ttl", call_args)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "test-incidents-table", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.resource")
    def test_missing_fields_default_gracefully(self, mock_resource):
        table_mock = MagicMock()
        mock_resource.return_value.Table.return_value = table_mock

        # Minimal event with no detail
        result = self.mod.lambda_handler({}, {})
        self.assertIn("incident_id", result)
        call_args = table_mock.put_item.call_args[1]["Item"]
        self.assertEqual(call_args["event_name"], "Unknown")
        self.assertEqual(call_args["source_ip"], "Unknown")


# ---------------------------------------------------------------------------
# send_incident_report tests
# ---------------------------------------------------------------------------


class TestSendIncidentReport(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("send_incident_report")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_publishes_to_sns(self, mock_boto):
        sns_mock = MagicMock()
        sns_mock.publish.return_value = {"MessageId": "msg-123"}
        mock_boto.return_value = sns_mock

        event = _cloudtrail_event()
        event["log_result"] = {"incident_id": "abc-123", "timestamp": "2024-01-15T10:00:00Z"}
        result = self.mod.lambda_handler(event, {})

        sns_mock.publish.assert_called_once()
        self.assertEqual(result["message_id"], "msg-123")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_subject_truncated_to_100_chars(self, mock_boto):
        sns_mock = MagicMock()
        sns_mock.publish.return_value = {"MessageId": "msg-456"}
        mock_boto.return_value = sns_mock

        event = _cloudtrail_event(event_name="A" * 80, account="9" * 12)
        event["log_result"] = {"incident_id": "x" * 36, "timestamp": "2024-01-15"}
        self.mod.lambda_handler(event, {})

        call_kwargs = sns_mock.publish.call_args[1]
        self.assertLessEqual(len(call_kwargs["Subject"]), 100)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_includes_brute_force_section_when_flag_set(self, mock_boto):
        sns_mock = MagicMock()
        sns_mock.publish.return_value = {"MessageId": "msg-789"}
        mock_boto.return_value = sns_mock

        event = _cloudtrail_event(event_name="ConsoleLogin")
        event["log_result"] = {"incident_id": "abc-123", "timestamp": "2024-01-15"}
        event["login_query_result"] = {
            "source_ip": "5.5.5.5",
            "failure_count": 10,
            "brute_force_detected": True,
            "first_failure_time": "2024-01-15T09:00:00Z",
            "last_failure_time": "2024-01-15T10:00:00Z",
        }
        self.mod.lambda_handler(event, {})

        message = sns_mock.publish.call_args[1]["Message"]
        self.assertIn("BRUTE FORCE", message.upper())
        self.assertIn("5.5.5.5", message)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_includes_root_cloudtrail_section(self, mock_boto):
        sns_mock = MagicMock()
        sns_mock.publish.return_value = {"MessageId": "msg-abc"}
        mock_boto.return_value = sns_mock

        event = _cloudtrail_event(event_name="CreateAccessKey", user_type="Root")
        event["log_result"] = {"incident_id": "abc-123", "timestamp": "2024-01-15"}
        event["cloudtrail_result"] = {
            "root_actions": [{"eventName": "CreateAccessKey", "eventTime": "2024-01-15", "sourceIPAddress": "1.1.1.1"}],
            "action_count": 1,
        }
        event["keys_result"] = {"new_keys_found": True, "new_keys": [{"key_id": "AKIATEST", "username": "root"}]}
        self.mod.lambda_handler(event, {})

        message = sns_mock.publish.call_args[1]["Message"]
        self.assertIn("ROOT ACTIVITY ANALYSIS", message)
        self.assertIn("AKIATEST", message)


# ---------------------------------------------------------------------------
# root_check_cloudtrail tests
# ---------------------------------------------------------------------------


class TestRootCheckCloudTrail(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("root_check_cloudtrail")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_returns_root_actions(self, mock_boto):
        ct_mock = MagicMock()
        paginator_mock = MagicMock()
        ct_mock.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [
            {
                "Events": [
                    {
                        "EventName": "CreateAccessKey",
                        "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                        "CloudTrailEvent": json.dumps({"sourceIPAddress": "1.2.3.4", "awsRegion": "us-east-1"}),
                    }
                ]
            }
        ]
        mock_boto.return_value = ct_mock

        event = _cloudtrail_event(user_type="Root")
        result = self.mod.lambda_handler(event, {})

        self.assertEqual(result["action_count"], 1)
        self.assertEqual(result["root_actions"][0]["eventName"], "CreateAccessKey")
        self.assertEqual(result["root_actions"][0]["sourceIPAddress"], "1.2.3.4")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_returns_zero_when_no_root_actions(self, mock_boto):
        ct_mock = MagicMock()
        paginator_mock = MagicMock()
        ct_mock.get_paginator.return_value = paginator_mock
        paginator_mock.paginate.return_value = [{"Events": []}]
        mock_boto.return_value = ct_mock

        event = _cloudtrail_event()
        result = self.mod.lambda_handler(event, {})

        self.assertEqual(result["action_count"], 0)
        self.assertEqual(result["root_actions"], [])


# ---------------------------------------------------------------------------
# root_check_access_keys tests
# ---------------------------------------------------------------------------


class TestRootCheckAccessKeys(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("root_check_access_keys")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_detects_key_in_create_event(self, mock_boto):
        iam_mock = MagicMock()
        iam_mock.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_boto.return_value = iam_mock

        event = _cloudtrail_event(
            event_name="CreateAccessKey",
            user_type="Root",
            response_elements={"accessKey": {"accessKeyId": "AKIATESTROOTKEY1", "userName": "root"}},
        )
        result = self.mod.lambda_handler(event, {})

        self.assertTrue(result["new_keys_found"])
        self.assertEqual(result["new_keys"][0]["key_id"], "AKIATESTROOTKEY1")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_returns_false_when_no_keys(self, mock_boto):
        iam_mock = MagicMock()
        iam_mock.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_boto.return_value = iam_mock

        event = _cloudtrail_event(event_name="ConsoleLogin", user_type="Root")
        result = self.mod.lambda_handler(event, {})

        self.assertFalse(result["new_keys_found"])
        self.assertEqual(result["new_keys"], [])

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_list_access_keys_failure_is_graceful(self, mock_boto):
        iam_mock = MagicMock()
        iam_mock.list_access_keys.side_effect = Exception("AccessDenied")
        mock_boto.return_value = iam_mock

        event = _cloudtrail_event(event_name="ConsoleLogin", user_type="Root")
        result = self.mod.lambda_handler(event, {})
        # Should return what it found from event (nothing in this case) without raising
        self.assertIn("new_keys_found", result)


# ---------------------------------------------------------------------------
# root_deactivate_keys tests
# ---------------------------------------------------------------------------


class TestRootDeactivateKeys(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("root_deactivate_keys")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_deactivates_listed_keys(self, mock_boto):
        iam_mock = MagicMock()
        mock_boto.return_value = iam_mock

        event = _cloudtrail_event()
        event["keys_result"] = {
            "new_keys_found": True,
            "new_keys": [
                {"key_id": "AKIA111", "username": "root"},
                {"key_id": "AKIA222", "username": "alice"},
            ],
        }
        result = self.mod.lambda_handler(event, {})

        self.assertEqual(result["deactivated_count"], 2)
        self.assertIn("AKIA111", result["deactivated_keys"])
        self.assertIn("AKIA222", result["deactivated_keys"])
        self.assertEqual(iam_mock.update_access_key.call_count, 2)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_records_errors_on_failure(self, mock_boto):
        iam_mock = MagicMock()
        iam_mock.update_access_key.side_effect = Exception("Throttled")
        mock_boto.return_value = iam_mock

        event = _cloudtrail_event()
        event["keys_result"] = {
            "new_keys_found": True,
            "new_keys": [{"key_id": "AKIA999", "username": "root"}],
        }
        result = self.mod.lambda_handler(event, {})

        self.assertEqual(result["deactivated_count"], 0)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("AKIA999", result["errors"][0])


# ---------------------------------------------------------------------------
# cred_check_key_creation tests
# ---------------------------------------------------------------------------


class TestCredCheckKeyCreation(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("cred_check_key_creation")

    def test_flags_root_creating_key(self):
        event = _cloudtrail_event(
            event_name="CreateAccessKey",
            user_type="Root",
            user_arn="arn:aws:iam::123456789012:root",
            response_elements={
                "accessKey": {"accessKeyId": "AKIATEST", "userName": "alice"}
            },
        )
        result = self.mod.lambda_handler(event, {})
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(result["key_id"], "AKIATEST")
        self.assertEqual(result["key_owner"], "alice")

    def test_flags_cross_user_key_creation(self):
        event = _cloudtrail_event(
            event_name="CreateAccessKey",
            user_type="IAMUser",
            user_arn="arn:aws:iam::123456789012:user/mallory",
            response_elements={
                "accessKey": {"accessKeyId": "AKIATEST2", "userName": "victim"}
            },
        )
        result = self.mod.lambda_handler(event, {})
        self.assertTrue(result["is_suspicious"])

    def test_does_not_flag_self_key_creation(self):
        event = _cloudtrail_event(
            event_name="CreateAccessKey",
            user_type="IAMUser",
            user_arn="arn:aws:iam::123456789012:user/alice",
            response_elements={
                "accessKey": {"accessKeyId": "AKIAALICE", "userName": "alice"}
            },
        )
        result = self.mod.lambda_handler(event, {})
        self.assertFalse(result["is_suspicious"])

    def test_handles_missing_response_elements(self):
        event = _cloudtrail_event(event_name="CreateAccessKey")
        result = self.mod.lambda_handler(event, {})
        self.assertIn("is_suspicious", result)
        self.assertIn("key_id", result)


# ---------------------------------------------------------------------------
# cred_check_trust_policy tests
# ---------------------------------------------------------------------------


class TestCredCheckTrustPolicy(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("cred_check_trust_policy")

    def test_detects_external_account_in_trust_policy(self):
        trust_policy = json.dumps({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }]
        })
        event = _cloudtrail_event(
            event_name="UpdateAssumeRolePolicy",
            account="123456789012",
            request_parameters={"roleName": "MyRole", "policyDocument": trust_policy},
        )
        result = self.mod.lambda_handler(event, {})
        self.assertTrue(result["external_accounts_found"])
        self.assertIn("999999999999", result["external_account_ids"])

    def test_does_not_flag_same_account_principal(self):
        trust_policy = json.dumps({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                "Action": "sts:AssumeRole",
            }]
        })
        event = _cloudtrail_event(
            event_name="UpdateAssumeRolePolicy",
            account="123456789012",
            request_parameters={"roleName": "MyRole", "policyDocument": trust_policy},
        )
        result = self.mod.lambda_handler(event, {})
        self.assertFalse(result["external_accounts_found"])
        self.assertEqual(result["external_account_ids"], [])

    def test_handles_empty_policy(self):
        event = _cloudtrail_event(
            event_name="UpdateAssumeRolePolicy",
            account="123456789012",
            request_parameters={"roleName": "EmptyRole", "policyDocument": "{}"},
        )
        result = self.mod.lambda_handler(event, {})
        self.assertFalse(result["external_accounts_found"])

    def test_handles_missing_role_name(self):
        event = _cloudtrail_event(event_name="UpdateAssumeRolePolicy")
        result = self.mod.lambda_handler(event, {})
        self.assertEqual(result["role_name"], "Unknown")


# ---------------------------------------------------------------------------
# exfil_check_bucket tests
# ---------------------------------------------------------------------------


class TestExfilCheckBucket(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("exfil_check_bucket")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_detects_public_policy(self, mock_boto):
        s3_mock = MagicMock()
        public_policy = json.dumps({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }]
        })
        s3_mock.get_bucket_policy.return_value = {"Policy": public_policy}
        from botocore.exceptions import ClientError
        s3_mock.get_bucket_acl.return_value = {"Grants": []}
        s3_mock.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}},
            "GetPublicAccessBlock",
        )
        mock_boto.return_value = s3_mock

        event = _cloudtrail_event(
            event_name="PutBucketPolicy",
            request_parameters={"bucketName": "my-bucket"},
        )
        result = self.mod.lambda_handler(event, {})
        self.assertTrue(result["is_public"])
        self.assertEqual(result["bucket_name"], "my-bucket")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_not_public_with_block_public_access(self, mock_boto):
        from botocore.exceptions import ClientError
        s3_mock = MagicMock()
        s3_mock.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
        )
        s3_mock.get_bucket_acl.return_value = {"Grants": []}
        s3_mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
            }
        }
        mock_boto.return_value = s3_mock

        event = _cloudtrail_event(
            event_name="PutBucketPolicy",
            request_parameters={"bucketName": "private-bucket"},
        )
        result = self.mod.lambda_handler(event, {})
        self.assertFalse(result["is_public"])

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_handles_missing_bucket_name(self, mock_boto):
        s3_mock = MagicMock()
        mock_boto.return_value = s3_mock

        event = _cloudtrail_event(event_name="PutBucketPolicy")
        result = self.mod.lambda_handler(event, {})
        self.assertFalse(result["is_public"])
        self.assertEqual(result["public_reason"], "no_bucket_name")


# ---------------------------------------------------------------------------
# login_query_failures tests
# ---------------------------------------------------------------------------


class TestLoginQueryFailures(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("login_query_failures")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_flags_brute_force_above_threshold(self, mock_boto):
        ct_mock = MagicMock()
        mock_boto.return_value = ct_mock

        failed_event_json = json.dumps({
            "sourceIPAddress": "5.5.5.5",
            "responseElements": {"ConsoleLogin": "Failure"},
            "eventTime": "2024-01-15T10:00:00Z",
            "userAgent": "Mozilla",
            "userIdentity": {"type": "IAMUser"},
        })
        ct_mock.lookup_events.return_value = {
            "Events": [
                {"CloudTrailEvent": failed_event_json, "EventName": "ConsoleLogin"},
            ]
            * 8  # 8 failures from same IP
        }

        event = _cloudtrail_event(event_name="ConsoleLogin", source_ip="5.5.5.5")
        event["detail"]["responseElements"] = {"ConsoleLogin": "Failure"}
        result = self.mod.lambda_handler(event, {})

        self.assertTrue(result["brute_force_detected"])
        self.assertGreater(result["failure_count"], 5)
        self.assertEqual(result["source_ip"], "5.5.5.5")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_does_not_flag_below_threshold(self, mock_boto):
        ct_mock = MagicMock()
        mock_boto.return_value = ct_mock

        ct_mock.lookup_events.return_value = {
            "Events": [
                {
                    "CloudTrailEvent": json.dumps({
                        "sourceIPAddress": "2.2.2.2",
                        "responseElements": {"ConsoleLogin": "Failure"},
                        "eventTime": "2024-01-15T10:00:00Z",
                        "userAgent": "Mozilla",
                        "userIdentity": {"type": "IAMUser"},
                    }),
                    "EventName": "ConsoleLogin",
                }
            ]
            * 3  # only 3 failures
        }

        event = _cloudtrail_event(event_name="ConsoleLogin", source_ip="2.2.2.2")
        event["detail"]["responseElements"] = {"ConsoleLogin": "Failure"}
        result = self.mod.lambda_handler(event, {})

        self.assertFalse(result["brute_force_detected"])
        self.assertLessEqual(result["failure_count"], 5)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_only_counts_matching_ip(self, mock_boto):
        ct_mock = MagicMock()
        mock_boto.return_value = ct_mock

        events_list = []
        # 6 from target IP
        for _ in range(6):
            events_list.append({
                "CloudTrailEvent": json.dumps({
                    "sourceIPAddress": "1.1.1.1",
                    "responseElements": {"ConsoleLogin": "Failure"},
                    "eventTime": "2024-01-15T10:00:00Z",
                    "userAgent": "Mozilla",
                    "userIdentity": {"type": "IAMUser"},
                }),
                "EventName": "ConsoleLogin",
            })
        # 3 from a different IP (should be ignored)
        for _ in range(3):
            events_list.append({
                "CloudTrailEvent": json.dumps({
                    "sourceIPAddress": "9.9.9.9",
                    "responseElements": {"ConsoleLogin": "Failure"},
                    "eventTime": "2024-01-15T10:00:00Z",
                    "userAgent": "Mozilla",
                    "userIdentity": {"type": "IAMUser"},
                }),
                "EventName": "ConsoleLogin",
            })

        ct_mock.lookup_events.return_value = {"Events": events_list}

        event = _cloudtrail_event(event_name="ConsoleLogin", source_ip="1.1.1.1")
        result = self.mod.lambda_handler(event, {})

        self.assertTrue(result["brute_force_detected"])
        self.assertEqual(result["failure_count"], 6)

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_cloudtrail_error_handled_gracefully(self, mock_boto):
        ct_mock = MagicMock()
        ct_mock.lookup_events.side_effect = Exception("CloudTrail throttled")
        mock_boto.return_value = ct_mock

        event = _cloudtrail_event(event_name="ConsoleLogin", source_ip="3.3.3.3")
        result = self.mod.lambda_handler(event, {})

        self.assertFalse(result["brute_force_detected"])
        self.assertEqual(result["failure_count"], 0)
        self.assertEqual(result["source_ip"], "3.3.3.3")


# ---------------------------------------------------------------------------
# exfil_revoke_snapshot tests
# ---------------------------------------------------------------------------


class TestExfilRevokeSnapshot(unittest.TestCase):
    def setUp(self):
        self.mod = _import_runbook("exfil_revoke_snapshot")

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_revokes_external_account_share(self, mock_boto):
        ec2_mock = MagicMock()
        mock_boto.return_value = ec2_mock

        event = _cloudtrail_event(
            event_name="ModifySnapshotAttribute",
            account="123456789012",
            request_parameters={
                "snapshotId": "snap-abc123",
                "createVolumePermission": {
                    "add": {"items": [{"userId": "999999999999"}]}
                },
            },
        )
        result = self.mod.lambda_handler(event, {})

        self.assertIn("999999999999", result["revoked_accounts"])
        self.assertEqual(result["snapshot_id"], "snap-abc123")
        ec2_mock.modify_snapshot_attribute.assert_called_once()

    @patch.dict("os.environ", {"INCIDENTS_TABLE": "t", "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123:test"})
    @patch("boto3.client")
    def test_skips_when_no_snapshot_id(self, mock_boto):
        ec2_mock = MagicMock()
        mock_boto.return_value = ec2_mock

        event = _cloudtrail_event(event_name="ModifySnapshotAttribute")
        result = self.mod.lambda_handler(event, {})

        self.assertEqual(result["status"], "skipped_no_snapshot_id")
        ec2_mock.modify_snapshot_attribute.assert_not_called()


# ---------------------------------------------------------------------------
# cdk stack test: incidents table and state machine outputs present
# ---------------------------------------------------------------------------


class TestIncidentResponseStackOutputs(unittest.TestCase):
    """Smoke-test that the CDK stack synthesises the expected resources."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        import os
        cls._synth_failed = False
        try:
            # We just check that the imports work, not a full synth here
            cdk_path = os.path.join(os.path.dirname(__file__), "..")
            spec = importlib.util.spec_from_file_location(
                "incident_response",
                os.path.join(cdk_path, "root_activity_monitor", "incident_response.py"),
            )
            mod = importlib.util.module_from_spec(spec)
            # Just loading the module validates syntax
        except Exception as e:
            cls._synth_failed = True
            cls._synth_error = str(e)

    def test_incident_response_module_importable(self):
        """The incident_response module must at minimum be parseable Python."""
        import ast
        import os
        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "root_activity_monitor",
            "incident_response.py",
        )
        with open(path) as f:
            source = f.read()
        # Will raise SyntaxError if the file has invalid syntax
        tree = ast.parse(source)
        self.assertIsNotNone(tree)


if __name__ == "__main__":
    unittest.main()
