#!/usr/bin/env python3
import os
import re

import aws_cdk as cdk

from root_activity_monitor.root_activity_monitor_stack import RootActivityMonitorStack

app = cdk.App()

# Read configuration from CDK context or environment
notification_email = app.node.try_get_context("notificationEmail") or os.environ.get(
    "NOTIFICATION_EMAIL"
)

if not notification_email:
    raise ValueError(
        "Notification email is required. Provide via context "
        "(-c notificationEmail=you@example.com) "
        "or NOTIFICATION_EMAIL environment variable."
    )

organization_id = app.node.try_get_context("organizationId") or os.environ.get(
    "ORGANIZATION_ID"
)

if organization_id and not re.match(r"^o-[a-z0-9]{10,32}$", organization_id):
    raise ValueError(
        f'Invalid organizationId "{organization_id}". '
        "Must match the format o-xxxxxxxxxx (e.g., o-abc123def4)."
    )

sns_topic_name = app.node.try_get_context("snsTopicName") or None

RootActivityMonitorStack(
    app,
    "RootActivityMonitorStack",
    notification_email=notification_email,
    organization_id=organization_id,
    sns_topic_name=sns_topic_name,
    env=cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=os.environ.get("CDK_DEFAULT_REGION", "eu-west-1"),
    ),
)

app.synth()
