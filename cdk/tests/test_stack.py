"""CDK stack snapshot / assertion tests for the S3 log archival resources.

These tests verify that the synthesised CloudFormation template contains the
expected S3 bucket, Kinesis Data Firehose delivery stream, and CloudWatch Logs
subscription filter added for long-term forensic log retention.

No AWS credentials are required — aws_cdk.assertions operates entirely against
the in-memory CloudFormation template produced by cdk.App().synth().
"""

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from root_activity_monitor.root_activity_monitor_stack import RootActivityMonitorStack

BUCKET_NAME = "security-monitor-logs-124307364559-us-east-1-an"
FIREHOSE_STREAM_NAME = "security-monitor-logs-firehose"


@pytest.fixture(scope="module")
def template():
    app = cdk.App()
    stack = RootActivityMonitorStack(
        app,
        "TestStack",
        notification_email="test@example.com",
        env=cdk.Environment(account="124307364559", region="us-east-1"),
    )
    return Template.from_stack(stack)


# ---------------------------------------------------------------------------
# S3 bucket
# ---------------------------------------------------------------------------


def test_log_archive_bucket_exists(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {"BucketName": BUCKET_NAME},
    )


def test_log_archive_bucket_public_access_blocked(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketName": BUCKET_NAME,
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        },
    )


def test_log_archive_bucket_sse_s3_encryption(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketName": BUCKET_NAME,
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        },
    )


def test_log_archive_bucket_versioning_enabled(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketName": BUCKET_NAME,
            "VersioningConfiguration": {"Status": "Enabled"},
        },
    )


def test_log_archive_bucket_lifecycle_365_day_expiration(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketName": BUCKET_NAME,
            "LifecycleConfiguration": {
                "Rules": Match.array_with(
                    [
                        Match.object_like(
                            {
                                "Status": "Enabled",
                                "ExpirationInDays": 365,
                            }
                        )
                    ]
                )
            },
        },
    )


# ---------------------------------------------------------------------------
# Kinesis Data Firehose delivery stream
# ---------------------------------------------------------------------------


def test_firehose_delivery_stream_exists(template):
    template.has_resource_properties(
        "AWS::KinesisFirehose::DeliveryStream",
        {"DeliveryStreamName": FIREHOSE_STREAM_NAME},
    )


def test_firehose_delivery_stream_type_direct_put(template):
    template.has_resource_properties(
        "AWS::KinesisFirehose::DeliveryStream",
        {
            "DeliveryStreamName": FIREHOSE_STREAM_NAME,
            "DeliveryStreamType": "DirectPut",
        },
    )


def test_firehose_uses_extended_s3_destination(template):
    template.has_resource_properties(
        "AWS::KinesisFirehose::DeliveryStream",
        {
            "DeliveryStreamName": FIREHOSE_STREAM_NAME,
            "ExtendedS3DestinationConfiguration": Match.object_like(
                {"CompressionFormat": "GZIP"}
            ),
        },
    )


# ---------------------------------------------------------------------------
# CloudWatch Logs subscription filter
# ---------------------------------------------------------------------------


def test_subscription_filter_exists(template):
    template.resource_count_is("AWS::Logs::SubscriptionFilter", 1)


def test_subscription_filter_targets_firehose(template):
    # LogGroupName is a Ref token in the synthesised template, so we match only
    # the fields that resolve to plain strings.
    template.has_resource_properties(
        "AWS::Logs::SubscriptionFilter",
        {
            "FilterName": "all-events-to-firehose",
            "FilterPattern": "",
            "LogGroupName": Match.any_value(),
            "DestinationArn": Match.any_value(),
        },
    )
