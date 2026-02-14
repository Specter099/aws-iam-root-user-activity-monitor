import * as path from 'path';
import {
  Stack,
  StackProps,
  Duration,
  RemovalPolicy,
  aws_lambda as lambda,
  aws_events as events,
  aws_events_targets as targets,
  aws_sns as sns,
  aws_sns_subscriptions as subs,
  aws_sqs as sqs,
  aws_iam as iam,
  aws_cloudwatch as cloudwatch,
  aws_cloudwatch_actions as cw_actions,
  aws_logs as logs,
  aws_kms as kms,
  CfnOutput,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface RootActivityMonitorStackProps extends StackProps {
  /**
   * SNS topic name for root activity notifications.
   * @default 'aws-iam-root-user-activity-monitor'
   */
  readonly snsTopicName?: string;

  /**
   * Email address to receive root activity notifications.
   */
  readonly notificationEmail: string;

  /**
   * AWS Organization ID for cross-account EventBridge permissions.
   * If not provided, the event bus will not have org-scoped permissions.
   */
  readonly organizationId?: string;
}

export class RootActivityMonitorStack extends Stack {
  public readonly snsTopic: sns.Topic;
  public readonly lambdaFunction: lambda.Function;
  public readonly deadLetterQueue: sqs.Queue;
  public readonly eventBus: events.EventBus;

  constructor(scope: Construct, id: string, props: RootActivityMonitorStackProps) {
    super(scope, id, props);

    const snsTopicName = props.snsTopicName ?? 'aws-iam-root-user-activity-monitor';

    // --- SNS Topic ---
    this.snsTopic = new sns.Topic(this, 'RootActivitySnsTopic', {
      topicName: snsTopicName,
      displayName: 'AWS IAM Root User Activity Monitor',
      masterKey: kms.Alias.fromAliasName(this, 'SnsKmsKey', 'alias/aws/sns'),
    });

    this.snsTopic.addSubscription(
      new subs.EmailSubscription(props.notificationEmail, {
        json: true,
      }),
    );

    // --- Dead Letter Queue ---
    this.deadLetterQueue = new sqs.Queue(this, 'RootActivityDLQ', {
      queueName: 'root-activity-monitor-dlq',
      retentionPeriod: Duration.days(14),
      encryption: sqs.QueueEncryption.KMS_MANAGED,
    });

    // --- CloudWatch Log Group ---
    const logGroup = new logs.LogGroup(this, 'RootActivityLambdaLogs', {
      logGroupName: '/aws/lambda/root-activity-monitor',
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // --- Lambda Function ---
    this.lambdaFunction = new lambda.Function(this, 'RootActivityLambda', {
      functionName: 'root-activity-monitor',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'RootActivityLambda.lambda_handler',
      code: lambda.Code.fromAsset(
        path.join(__dirname, '..', '..', 'root-activity-monitor-module'),
        { exclude: ['*.tf', '*.json', 'outputs', 'iam', 'README.md', 'LICENSE'] },
      ),
      timeout: Duration.seconds(30),
      reservedConcurrentExecutions: 5,
      deadLetterQueue: this.deadLetterQueue,
      environment: {
        SNSARN: this.snsTopic.topicArn,
      },
      logGroup,
    });

    // Grant Lambda permissions to publish to SNS
    this.snsTopic.grantPublish(this.lambdaFunction);

    // Grant Lambda permission to list account aliases
    this.lambdaFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ListAccountAlias',
        actions: ['iam:ListAccountAliases'],
        resources: ['*'],
      }),
    );

    // --- EventBridge Event Bus ---
    this.eventBus = new events.EventBus(this, 'HubRootActivityEventBus', {
      eventBusName: 'hub-root-activity',
    });

    // Organization-scoped access to the event bus
    if (props.organizationId) {
      new events.CfnEventBusPolicy(this, 'OrgAccessPolicy', {
        eventBusName: this.eventBus.eventBusName,
        statementId: 'OrganizationAccess',
        action: 'events:PutEvents',
        principal: '*',
        condition: {
          type: 'StringEquals',
          key: 'aws:PrincipalOrgID',
          value: props.organizationId,
        },
      });
    }

    // --- EventBridge Rule ---
    const rule = new events.Rule(this, 'HubRootActivityRule', {
      ruleName: 'hub-capture-root-activity',
      description: 'Capture root user AWS Console Sign In, API calls, and credential changes.',
      eventBus: this.eventBus,
      eventPattern: {
        detailType: [
          'AWS API Call via CloudTrail',
          'AWS Console Sign In via CloudTrail',
          'AWS Service Event via CloudTrail',
        ],
        detail: {
          userIdentity: {
            type: ['Root'],
          },
        },
      },
    });

    rule.addTarget(new targets.LambdaFunction(this.lambdaFunction));

    // --- CloudWatch Alarms ---
    const dlqAlarm = new cloudwatch.Alarm(this, 'DLQMessagesAlarm', {
      alarmName: 'root-activity-monitor-dlq-alarm',
      alarmDescription: 'Alert when root activity monitor Lambda fails and sends messages to DLQ',
      metric: this.deadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dlqAlarm.addAlarmAction(new cw_actions.SnsAction(this.snsTopic));

    const lambdaErrorsAlarm = new cloudwatch.Alarm(this, 'LambdaErrorsAlarm', {
      alarmName: 'root-activity-monitor-lambda-errors',
      alarmDescription: 'Alert when root activity monitor Lambda encounters errors',
      metric: this.lambdaFunction.metricErrors({
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    lambdaErrorsAlarm.addAlarmAction(new cw_actions.SnsAction(this.snsTopic));

    // --- Outputs ---
    new CfnOutput(this, 'SnsTopicArn', {
      value: this.snsTopic.topicArn,
      description: 'SNS topic ARN for root activity notifications',
    });

    new CfnOutput(this, 'DlqArn', {
      value: this.deadLetterQueue.queueArn,
      description: 'Dead Letter Queue ARN for failed Lambda invocations',
    });

    new CfnOutput(this, 'LambdaFunctionArn', {
      value: this.lambdaFunction.functionArn,
      description: 'Root activity monitor Lambda function ARN',
    });

    new CfnOutput(this, 'EventBusArn', {
      value: this.eventBus.eventBusArn,
      description: 'Hub EventBridge event bus ARN',
    });
  }
}
