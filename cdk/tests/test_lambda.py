"""Tests for RootActivityLambda classification logic.

Only the pure functions (classify_category, classify_severity,
extract_event_details, format_notification) are tested here — no AWS SDK
calls are made.  The module-level boto3 clients and SNSARN env-var are
patched out before import so the tests can run without AWS credentials.
"""

import importlib
import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Patch AWS SDK and env var so the module can be imported in unit tests
# ---------------------------------------------------------------------------

def _make_mock_boto3():
    """Return a minimal boto3 mock that satisfies module-level client() calls."""
    mock = MagicMock()
    mock.client.return_value = MagicMock()
    return mock


@patch.dict(os.environ, {"SNSARN": "arn:aws:sns:us-east-1:123456789012:test"})
@patch("boto3.client", return_value=MagicMock())
def _import_lambda(mock_client):
    """Import the Lambda module with boto3 stubbed out."""
    # Ensure a fresh import if the module was already loaded
    module_path = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "root-activity-monitor-module",
    )
    sys.path.insert(0, os.path.abspath(module_path))
    if "RootActivityLambda" in sys.modules:
        del sys.modules["RootActivityLambda"]
    with patch.dict(os.environ, {"SNSARN": "arn:aws:sns:us-east-1:123456789012:test"}):
        module = importlib.import_module("RootActivityLambda")
    return module


lam = _import_lambda()

classify_category = lam.classify_category
classify_severity = lam.classify_severity
extract_event_details = lam.extract_event_details
format_notification = lam.format_notification

CATEGORY_ROOT = lam.CATEGORY_ROOT
CATEGORY_CONSOLE_ANOMALY = lam.CATEGORY_CONSOLE_ANOMALY
CATEGORY_IAM_ABUSE = lam.CATEGORY_IAM_ABUSE
CATEGORY_PRIV_ESC = lam.CATEGORY_PRIV_ESC
CATEGORY_DATA_EXFIL = lam.CATEGORY_DATA_EXFIL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cloudtrail_event(
    event_name="DescribeInstances",
    user_type="IAMUser",
    detail_type="AWS API Call via CloudTrail",
    mfa_used=None,
    console_login_result=None,
    error_code=None,
    request_params=None,
):
    """Build a minimal EventBridge / CloudTrail event dict."""
    detail = {
        "eventName": event_name,
        "eventTime": "2024-01-01T00:00:00Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {"type": user_type, "arn": f"arn:aws:iam::123456789012:user/test"},
        "requestParameters": request_params or {},
    }
    if mfa_used is not None:
        detail["additionalEventData"] = {"MFAUsed": mfa_used}
    if console_login_result is not None:
        detail["responseElements"] = {"ConsoleLogin": console_login_result}
    if error_code:
        detail["errorCode"] = error_code

    return {
        "detail-type": detail_type,
        "account": "123456789012",
        "region": "us-east-1",
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# classify_category
# ---------------------------------------------------------------------------

class TestClassifyCategory(unittest.TestCase):

    # Root user always maps to ROOT_ACTIVITY regardless of event name
    def test_root_user_api_call(self):
        self.assertEqual(
            classify_category("CreateAccessKey", "Root", "Unknown", "Unknown"),
            CATEGORY_ROOT,
        )

    def test_root_user_console_login(self):
        self.assertEqual(
            classify_category("ConsoleLogin", "Root", "No", "Success"),
            CATEGORY_ROOT,
        )

    # Console sign-in anomalies
    def test_console_login_no_mfa(self):
        self.assertEqual(
            classify_category("ConsoleLogin", "IAMUser", "No", "Success"),
            CATEGORY_CONSOLE_ANOMALY,
        )

    def test_console_login_mfa_unknown(self):
        self.assertEqual(
            classify_category("ConsoleLogin", "IAMUser", "Unknown", "Success"),
            CATEGORY_CONSOLE_ANOMALY,
        )

    def test_console_login_failure(self):
        self.assertEqual(
            classify_category("ConsoleLogin", "IAMUser", "Yes", "Failure"),
            CATEGORY_CONSOLE_ANOMALY,
        )

    def test_console_login_with_mfa_success_is_not_anomaly(self):
        # A successful MFA-protected login is not an anomaly and falls through
        # to CATEGORY_ROOT (default for unmatched non-root events)
        result = classify_category("ConsoleLogin", "IAMUser", "Yes", "Success")
        self.assertNotEqual(result, CATEGORY_CONSOLE_ANOMALY)

    # Data exfiltration (checked before priv-esc in priority order)
    def test_modify_snapshot_attribute(self):
        self.assertEqual(
            classify_category("ModifySnapshotAttribute", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_DATA_EXFIL,
        )

    def test_put_bucket_policy(self):
        self.assertEqual(
            classify_category("PutBucketPolicy", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_DATA_EXFIL,
        )

    def test_create_db_snapshot(self):
        self.assertEqual(
            classify_category("CreateDBSnapshot", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_DATA_EXFIL,
        )

    # Privilege escalation
    def test_attach_user_policy(self):
        self.assertEqual(
            classify_category("AttachUserPolicy", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_PRIV_ESC,
        )

    def test_create_access_key_non_root(self):
        self.assertEqual(
            classify_category("CreateAccessKey", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_PRIV_ESC,
        )

    def test_update_assume_role_policy(self):
        self.assertEqual(
            classify_category("UpdateAssumeRolePolicy", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_PRIV_ESC,
        )

    def test_create_login_profile(self):
        self.assertEqual(
            classify_category("CreateLoginProfile", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_PRIV_ESC,
        )

    # IAM credential abuse
    def test_get_session_token(self):
        self.assertEqual(
            classify_category("GetSessionToken", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_IAM_ABUSE,
        )

    def test_assume_role(self):
        self.assertEqual(
            classify_category("AssumeRole", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_IAM_ABUSE,
        )

    def test_get_caller_identity(self):
        self.assertEqual(
            classify_category("GetCallerIdentity", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_IAM_ABUSE,
        )

    def test_get_federation_token(self):
        self.assertEqual(
            classify_category("GetFederationToken", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_IAM_ABUSE,
        )

    # Unclassified non-root events default to ROOT (catch-all)
    def test_unclassified_event(self):
        self.assertEqual(
            classify_category("DescribeInstances", "IAMUser", "Unknown", "Unknown"),
            CATEGORY_ROOT,
        )


# ---------------------------------------------------------------------------
# classify_severity
# ---------------------------------------------------------------------------

class TestClassifySeverity(unittest.TestCase):

    # Root activity — existing logic preserved
    def test_root_console_sign_in_is_critical(self):
        self.assertEqual(
            classify_severity("ConsoleLogin", "AWS Console Sign In via CloudTrail", CATEGORY_ROOT),
            "CRITICAL",
        )

    def test_root_create_access_key_is_critical(self):
        self.assertEqual(
            classify_severity("CreateAccessKey", "AWS API Call via CloudTrail", CATEGORY_ROOT),
            "CRITICAL",
        )

    def test_root_stop_logging_is_high(self):
        self.assertEqual(
            classify_severity("StopLogging", "AWS API Call via CloudTrail", CATEGORY_ROOT),
            "HIGH",
        )

    def test_root_unknown_action_is_medium(self):
        self.assertEqual(
            classify_severity("DescribeInstances", "AWS API Call via CloudTrail", CATEGORY_ROOT),
            "MEDIUM",
        )

    # Console anomaly
    def test_console_anomaly_is_high(self):
        self.assertEqual(
            classify_severity("ConsoleLogin", "AWS Console Sign In via CloudTrail", CATEGORY_CONSOLE_ANOMALY),
            "HIGH",
        )

    # Privilege escalation
    def test_attach_user_policy_is_critical(self):
        self.assertEqual(
            classify_severity("AttachUserPolicy", "AWS API Call via CloudTrail", CATEGORY_PRIV_ESC),
            "CRITICAL",
        )

    def test_put_role_policy_is_critical(self):
        self.assertEqual(
            classify_severity("PutRolePolicy", "AWS API Call via CloudTrail", CATEGORY_PRIV_ESC),
            "CRITICAL",
        )

    def test_create_login_profile_is_high(self):
        self.assertEqual(
            classify_severity("CreateLoginProfile", "AWS API Call via CloudTrail", CATEGORY_PRIV_ESC),
            "HIGH",
        )

    def test_create_role_is_high(self):
        self.assertEqual(
            classify_severity("CreateRole", "AWS API Call via CloudTrail", CATEGORY_PRIV_ESC),
            "HIGH",
        )

    # IAM credential abuse
    def test_get_caller_identity_is_medium(self):
        self.assertEqual(
            classify_severity("GetCallerIdentity", "AWS API Call via CloudTrail", CATEGORY_IAM_ABUSE),
            "MEDIUM",
        )

    def test_assume_role_is_high(self):
        self.assertEqual(
            classify_severity("AssumeRole", "AWS API Call via CloudTrail", CATEGORY_IAM_ABUSE),
            "HIGH",
        )

    def test_get_session_token_is_high(self):
        self.assertEqual(
            classify_severity("GetSessionToken", "AWS API Call via CloudTrail", CATEGORY_IAM_ABUSE),
            "HIGH",
        )

    # Data exfiltration
    def test_modify_snapshot_attribute_is_critical(self):
        self.assertEqual(
            classify_severity("ModifySnapshotAttribute", "AWS API Call via CloudTrail", CATEGORY_DATA_EXFIL),
            "CRITICAL",
        )

    def test_modify_db_snapshot_attribute_is_critical(self):
        self.assertEqual(
            classify_severity("ModifyDBSnapshotAttribute", "AWS API Call via CloudTrail", CATEGORY_DATA_EXFIL),
            "CRITICAL",
        )

    def test_put_bucket_policy_is_high(self):
        self.assertEqual(
            classify_severity("PutBucketPolicy", "AWS API Call via CloudTrail", CATEGORY_DATA_EXFIL),
            "HIGH",
        )

    def test_create_snapshot_is_high(self):
        self.assertEqual(
            classify_severity("CreateSnapshot", "AWS API Call via CloudTrail", CATEGORY_DATA_EXFIL),
            "HIGH",
        )


# ---------------------------------------------------------------------------
# extract_event_details
# ---------------------------------------------------------------------------

class TestExtractEventDetails(unittest.TestCase):

    def test_basic_fields(self):
        event = _make_cloudtrail_event(event_name="GetCallerIdentity")
        details = extract_event_details(event)
        self.assertEqual(details["eventName"], "GetCallerIdentity")
        self.assertEqual(details["accountId"], "123456789012")
        self.assertEqual(details["awsRegion"], "us-east-1")
        self.assertEqual(details["sourceIPAddress"], "1.2.3.4")

    def test_mfa_used_extracted(self):
        event = _make_cloudtrail_event(mfa_used="Yes")
        details = extract_event_details(event)
        self.assertEqual(details["mfaUsed"], "Yes")

    def test_mfa_absent_defaults_to_unknown(self):
        event = _make_cloudtrail_event()
        details = extract_event_details(event)
        self.assertEqual(details["mfaUsed"], "Unknown")

    def test_console_login_result_extracted(self):
        event = _make_cloudtrail_event(console_login_result="Failure")
        details = extract_event_details(event)
        self.assertEqual(details["consoleLoginResult"], "Failure")

    def test_console_login_result_absent_defaults_to_unknown(self):
        event = _make_cloudtrail_event()
        details = extract_event_details(event)
        self.assertEqual(details["consoleLoginResult"], "Unknown")

    def test_error_code_extracted(self):
        event = _make_cloudtrail_event(error_code="AccessDenied")
        details = extract_event_details(event)
        self.assertEqual(details["errorCode"], "AccessDenied")


# ---------------------------------------------------------------------------
# format_notification
# ---------------------------------------------------------------------------

class TestFormatNotification(unittest.TestCase):

    def _details(self, event_name="CreateAccessKey", user_type="IAMUser", category=CATEGORY_PRIV_ESC):
        event = _make_cloudtrail_event(event_name=event_name, user_type=user_type)
        return extract_event_details(event)

    def test_root_notification_contains_category_label(self):
        details = self._details(user_type="Root", category=CATEGORY_ROOT)
        msg = format_notification(details, "CRITICAL", CATEGORY_ROOT, "my-account")
        self.assertIn("Root", msg)
        self.assertIn("CRITICAL", msg)

    def test_priv_esc_notification_contains_category_label(self):
        details = self._details()
        msg = format_notification(details, "CRITICAL", CATEGORY_PRIV_ESC, "my-account")
        self.assertIn("Priv-Esc", msg)

    def test_console_anomaly_includes_mfa_field(self):
        event = _make_cloudtrail_event(
            event_name="ConsoleLogin",
            detail_type="AWS Console Sign In via CloudTrail",
            mfa_used="No",
            console_login_result="Success",
        )
        details = extract_event_details(event)
        msg = format_notification(details, "HIGH", CATEGORY_CONSOLE_ANOMALY, "my-account")
        self.assertIn("MFA Used", msg)
        self.assertIn("Login Result", msg)

    def test_data_exfil_includes_category_label(self):
        details = self._details(event_name="ModifySnapshotAttribute")
        msg = format_notification(details, "CRITICAL", CATEGORY_DATA_EXFIL, "my-account")
        self.assertIn("Data-Exfil", msg)

    def test_iam_abuse_includes_category_label(self):
        details = self._details(event_name="AssumeRole", category=CATEGORY_IAM_ABUSE)
        msg = format_notification(details, "HIGH", CATEGORY_IAM_ABUSE, "my-account")
        self.assertIn("IAM-Abuse", msg)

    def test_non_root_notification_includes_principal_arn(self):
        details = self._details(user_type="IAMUser")
        msg = format_notification(details, "HIGH", CATEGORY_PRIV_ESC, "my-account")
        self.assertIn("Principal ARN", msg)

    def test_root_notification_omits_principal_arn(self):
        details = self._details(user_type="Root", category=CATEGORY_ROOT)
        msg = format_notification(details, "CRITICAL", CATEGORY_ROOT, "my-account")
        self.assertNotIn("Principal ARN", msg)


if __name__ == "__main__":
    unittest.main()
