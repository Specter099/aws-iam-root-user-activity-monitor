#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { RootActivityMonitorStack } from '../lib/root-activity-monitor-stack';

const app = new cdk.App();

// Read configuration from CDK context or environment
const notificationEmail = app.node.tryGetContext('notificationEmail')
  || process.env.NOTIFICATION_EMAIL;

if (!notificationEmail) {
  throw new Error(
    'Notification email is required. Provide via context (-c notificationEmail=you@example.com) '
    + 'or NOTIFICATION_EMAIL environment variable.',
  );
}

const organizationId = app.node.tryGetContext('organizationId')
  || process.env.ORGANIZATION_ID;

const snsTopicName = app.node.tryGetContext('snsTopicName') || undefined;

new RootActivityMonitorStack(app, 'RootActivityMonitorStack', {
  notificationEmail,
  organizationId,
  snsTopicName,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'eu-west-1',
  },
});
