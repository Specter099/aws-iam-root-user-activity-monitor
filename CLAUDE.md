# CLAUDE.md - AI Assistant Guide

This document provides AI assistants with comprehensive guidance for working with the AWS IAM Root User Activity Monitor codebase.

## Project Overview

This is an **AWS Prescriptive Guidance pattern** implementing event-driven monitoring of IAM root user activity across multiple AWS accounts. It follows AWS security best practices by detecting and alerting when root user credentials are used — a key security risk indicator.

The system classifies root activity by **severity level** (CRITICAL / HIGH / MEDIUM) and delivers enriched notifications with incident context and recommended response actions.

### Architecture: Hub-and-Spoke Model

```
Spoke Accounts                           Hub Account
┌─────────────────────┐                 ┌──────────────────────────────────────────┐
│ Root User Activity  │                 │                                          │
│         ↓           │                 │  EventBridge       Lambda                │
│   CloudTrail Logs   │                 │  Event Bus    →    Function              │
│         ↓           │   EventBridge   │      ↑          ↙        ↘              │
│ EventBridge Rule    │ ──────────────→ │      └──── SNS Topic    SQS DLQ         │
│ (RootActivityRule)  │   (cross-acct)  │               ↓            ↓             │
└─────────────────────┘                 │    Email Notification  CW Alarm → SNS   │
                                        │                                          │
                                        │  CloudWatch Alarms (errors + DLQ)        │
                                        └──────────────────────────────────────────┘
```

- **Spoke Accounts**: Detect root user activity via CloudTrail and forward events
- **Hub Account**: Centrally process events, classify severity, and send notifications via SNS
- **Dead Letter Queue**: Captures failed Lambda invocations with CloudWatch alarm monitoring

## Directory Structure

```
/
├── provider.tf                    # Root Terraform provider config (multi-region)
├── hub.tf                         # Hub account module instantiation
├── spoke-stackset.yaml            # CloudFormation StackSet for spoke accounts
├── README.md                      # Project documentation
├── CLAUDE.md                      # AI assistant guide (this file)
├── CONTRIBUTING.md                # Contribution guidelines
├── CODE_OF_CONDUCT.md             # Amazon Open Source Code of Conduct
├── LICENSE                        # MIT-0 License
├── RootActivityMonitor.png        # Architecture diagram
├── iam-root-activity-monitor-source.drawio  # Draw.io diagram source
├── cdk/                           # AWS CDK deployment (TypeScript alternative)
│   ├── bin/app.ts                 # CDK app entry point
│   ├── lib/root-activity-monitor-stack.ts  # Hub stack definition
│   ├── package.json               # Node.js dependencies
│   ├── tsconfig.json              # TypeScript configuration
│   └── cdk.json                   # CDK app configuration
└── root-activity-monitor-module/  # Reusable Terraform module
    ├── main.tf                    # Core infrastructure definitions
    ├── variables.tf               # Input variables
    ├── outputs.tf                 # Output values (orgid, dlq_arn, lambda_arn, sns_arn)
    ├── data.tf                    # Data source definitions
    ├── provider.tf                # Module provider config
    ├── RootActivityLambda.py      # Python Lambda function (incident detection)
    ├── LICENSE                    # MIT-0 License (module copy)
    ├── README.md                  # Module documentation
    └── iam/
        ├── lambda-policy.json     # Lambda execution policy
        └── lambda-assume-policy.json  # Lambda assume role policy
```

## Technologies

| Category | Technology | Version/Details |
|----------|-----------|-----------------|
| IaC (Hub) | Terraform | ~> 5.0 AWS provider |
| IaC (Hub alt.) | AWS CDK | v2 (TypeScript) |
| IaC (Spokes) | CloudFormation | StackSet deployment (2010-09-09) |
| Runtime | Python | 3.12 |
| Cloud Platform | AWS | EventBridge, Lambda, SNS, SQS, CloudWatch, CloudTrail, IAM |

## Key Files Reference

### Infrastructure Code

| File | Purpose |
|------|---------|
| `hub.tf` | Instantiates the Terraform module for hub account. Contains email placeholder `__REPLACE_EMAIL_ADDRESS__` |
| `spoke-stackset.yaml` | CloudFormation for spoke accounts. Requires `HubAccount` parameter (12-digit account ID) |
| `root-activity-monitor-module/main.tf` | Core resources: Lambda, EventBridge, SNS, SQS DLQ, CloudWatch Alarms, IAM roles |
| `root-activity-monitor-module/variables.tf` | Module inputs: `SNSTopicName`, `SNSSubscriptions`, `region`, `tags` |
| `root-activity-monitor-module/outputs.tf` | Module outputs: `orgid`, `dlq_arn`, `lambda_function_arn`, `sns_topic_arn` |

### CDK Infrastructure Code

| File | Purpose |
|------|---------|
| `cdk/bin/app.ts` | CDK app entry point. Reads `notificationEmail` from context or env var |
| `cdk/lib/root-activity-monitor-stack.ts` | Full hub stack: Lambda, EventBridge, SNS, SQS DLQ, CloudWatch Alarms |

### Lambda Function — Incident Detection Engine

**File**: `root-activity-monitor-module/RootActivityLambda.py`

The Lambda function provides:
- **Severity classification**: Actions categorized as CRITICAL, HIGH, or MEDIUM
- **Incident context enrichment**: Source IP, user agent, region, timestamps, error details
- **Account alias resolution**: Human-readable account names via `iam:ListAccountAliases`
- **Structured notifications**: Separate message formats for email and JSON consumers
- **Recommended response actions**: Severity-appropriate remediation guidance in each alert

```python
# Severity tiers
CRITICAL_ACTIONS = {
    'CreateAccessKey', 'ConsoleLogin', 'PasswordRecoveryRequested',
    'EnableMFADevice', 'DeactivateMFADevice', 'AttachUserPolicy', ...
}
HIGH_ACTIONS = {
    'StopLogging', 'DeleteTrail', 'RunInstances', 'DeleteBucket', ...
}
# Everything else → MEDIUM
```

**Entry point**: `lambda_handler(event, context)`
**Environment Variable**: `SNSARN` — Injected by Terraform or CDK

### Reliability Infrastructure

| Resource | Purpose |
|----------|---------|
| `aws_sqs_queue.RootActivityDLQ` | Dead Letter Queue — captures failed Lambda invocations (14-day retention, KMS encrypted) |
| `aws_cloudwatch_metric_alarm.DLQMessagesAlarm` | Alerts when messages land in the DLQ |
| `aws_cloudwatch_metric_alarm.LambdaErrorsAlarm` | Alerts on any Lambda execution errors |
| `aws_cloudwatch_log_group.RootActivityLambdaLogs` | Log retention set to 90 days |

## Development Workflow

### Prerequisites
- AWS Organization set up
- AWS CLI configured with appropriate credentials
- Access to hub and spoke AWS accounts
- **Terraform path**: Terraform with AWS provider ~> 5.0
- **CDK path**: Node.js >= 18, npm, AWS CDK v2 (`npm install -g aws-cdk`)

### Option A: Deploy Hub with Terraform

1. **Configure Hub Account** (`hub.tf`):
   - Replace `__REPLACE_EMAIL_ADDRESS__` with notification email
   - Adjust region via provider alias if needed

2. **Deploy Hub Infrastructure**:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

### Option B: Deploy Hub with CDK

1. **Install dependencies**:
   ```bash
   cd cdk
   npm install
   ```

2. **Deploy** (email is required, org ID is optional but recommended):
   ```bash
   npx cdk deploy \
     -c notificationEmail=security-team@example.com \
     -c organizationId=o-abc123def4
   ```

   Or use environment variables:
   ```bash
   export NOTIFICATION_EMAIL=security-team@example.com
   export ORGANIZATION_ID=o-abc123def4
   npx cdk deploy
   ```

3. **Other CDK commands**:
   ```bash
   npx cdk diff                  # Preview changes
   npx cdk synth                 # Synthesize CloudFormation template
   npx cdk destroy               # Tear down stack
   ```

### Deploy Spoke Accounts (required for both options)

- Use CloudFormation StackSets with `spoke-stackset.yaml`
- Provide `HubAccount` parameter (12-digit AWS account ID)
- Note: The template prevents deployment in the hub account itself (condition check)

### Multi-Region Support

**Terraform**: The root `provider.tf` configures aliases for:
- `aws.euw1` → eu-west-1 (currently active in hub.tf)
- `aws.use1` → us-east-1

**CDK**: Set the region via `CDK_DEFAULT_REGION` environment variable or by modifying `env.region` in `cdk/bin/app.ts`. For multi-region, instantiate additional stacks in `app.ts` with different region values.

## Code Conventions

### Terraform
- **Resource Naming**: PascalCase for resource logical names
  - Example: `aws_iam_role_policy "LambdaRootAPIMonitorPolicy"`, `aws_sqs_queue "RootActivityDLQ"`
- **AWS Resource Names**: Kebab-case
  - Example: `hub-root-activity-eventbus`, `root-activity-monitor-dlq`
- **Variables**: PascalCase
  - Example: `SNSTopicName`, `SNSSubscriptions`
- **Tags**: Apply via `var.tags` map
- **Inline policies**: Use `jsonencode()` for dynamic policies (e.g., DLQ policy)
- **File-based policies**: Use `file()` for static JSON policies in `iam/` directory

### CDK (TypeScript)
- **Construct naming**: PascalCase matching Terraform logical names
  - Example: `RootActivityDLQ`, `HubRootActivityEventBus`
- **Stack props**: Use a dedicated `Props` interface extending `StackProps`
- **Configuration**: Pass via CDK context (`-c key=value`) or environment variables
- **Permissions**: Use CDK grant methods (`topic.grantPublish(fn)`) over raw policy statements
- **Lambda code**: References `root-activity-monitor-module/RootActivityLambda.py` via `Code.fromAsset`

### Python (Lambda)
- **Runtime**: Python 3.12
- **Logging**: Use `logging` module — DEBUG for detailed traces, INFO for operational events
- **Error Handling**: Catch `ClientError` from boto3; re-raise on SNS publish failures to trigger DLQ
- **Environment Variables**: Access via `os.environ`
- **SNS Subject**: Truncate to 100 characters (AWS SNS limit)
- **Severity Classification**: Maintain `CRITICAL_ACTIONS` and `HIGH_ACTIONS` sets at module level

### EventBridge Patterns
Event pattern for root user detection (hub and spoke):
```json
{
  "detail-type": [
    "AWS API Call via CloudTrail",
    "AWS Console Sign In via CloudTrail",
    "AWS Service Event via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": ["Root"]
    }
  }
}
```

## Security Considerations

### IAM Best Practices
- Lambda role follows least privilege:
  - CloudWatch Logs: Create log groups/streams, put log events
  - SNS: Publish to topic
  - IAM: ListAccountAliases only
  - SQS: SendMessage to the specific DLQ
- EventBridge permissions scoped to AWS Organization via `aws:PrincipalOrgID`

### Security Check Suppressions
The Lambda resource includes Checkov skip comments for:
- `CKV_AWS_117`: VPC deployment (not required for this use case)
- `CKV_AWS_173`: Environment variable encryption (using AWS Lambda owned key)
- `CKV_AWS_50`: X-Ray tracing (relies on CloudWatch Logs)

Note: `CKV_AWS_116` (Dead Letter Queue) is now resolved — DLQ is configured.

### Encryption
- SNS Topic: KMS encryption with AWS managed key (`alias/aws/sns`)
- SQS DLQ: KMS encryption with AWS managed key (`alias/aws/sqs`)

### Security Issues
Report security vulnerabilities via [AWS vulnerability reporting](http://aws.amazon.com/security/vulnerability-reporting/), NOT public GitHub issues.

## Incident Detection and Response

### Severity Classification

| Severity | Trigger | Examples |
|----------|---------|---------|
| **CRITICAL** | Console sign-ins, credential/MFA changes, IAM modifications | `ConsoleLogin`, `CreateAccessKey`, `DeactivateMFADevice`, `AttachUserPolicy` |
| **HIGH** | Security control changes, infrastructure modifications | `StopLogging`, `DeleteTrail`, `RunInstances`, `DeleteBucket` |
| **MEDIUM** | All other root API activity | Any root API call not in CRITICAL or HIGH sets |

### Notification Format

Email notifications include:
- Severity level prominently in subject line: `[CRITICAL] Root: ConsoleLogin in my-account`
- Account name (resolved alias) and ID
- Action performed, event type, timestamp
- Source IP address and user agent
- Error codes (if the action failed)
- Severity-appropriate recommended response actions
- Raw request parameters for forensic context

### Adding New Severity Classifications
Edit `CRITICAL_ACTIONS` or `HIGH_ACTIONS` sets in `root-activity-monitor-module/RootActivityLambda.py`.

## Common Tasks

### Modifying the Lambda Function
1. Edit `root-activity-monitor-module/RootActivityLambda.py`
2. Redeploy:
   - **Terraform**: `terraform apply` (auto-repackages via `archive_file`)
   - **CDK**: `cd cdk && npx cdk deploy` (auto-bundles via `Code.fromAsset`)

### Adding New Regions
1. Add provider alias in root `provider.tf`
2. Add new module instantiation in `hub.tf` referencing the new alias

### Changing Notification Email
**Terraform** — edit `hub.tf`:
```hcl
module "root-activity-monitor-euw1" {
  SNSSubscriptions = "your-email@example.com"
  # ...
}
```

**CDK** — pass a different context value:
```bash
npx cdk deploy -c notificationEmail=new-email@example.com
```

### Updating Event Patterns
Hub and spoke patterns must stay in sync across all IaC:
- **Terraform**: `aws_cloudwatch_event_rule` in `root-activity-monitor-module/main.tf`
- **CDK**: `eventPattern` in `cdk/lib/root-activity-monitor-stack.ts`
- **Spokes**: `EventPattern` in `spoke-stackset.yaml`

### Monitoring the Dead Letter Queue
Failed Lambda invocations are sent to the SQS DLQ (`root-activity-monitor-dlq`). A CloudWatch alarm triggers SNS notification when messages appear. To inspect failed events:
```bash
aws sqs receive-message --queue-url <DLQ_URL> --max-number-of-messages 10
```

## Testing Considerations

- **Local Testing**: Lambda function can be tested with sample CloudTrail events
- **Integration Testing**: Requires actual root user activity in spoke accounts
- **Validate Templates**:
  ```bash
  terraform validate
  aws cloudformation validate-template --template-body file://spoke-stackset.yaml
  cd cdk && npx cdk synth   # validates CDK stack
  ```
- **Test Severity Classification**: Invoke Lambda with events containing different `eventName` values to verify CRITICAL/HIGH/MEDIUM routing

## Git Workflow

- **Main Branch**: `main`
- **Contribution**: Fork → branch → PR workflow
- **Commit Messages**: Clear, descriptive messages focused on the change
- See `CONTRIBUTING.md` for full guidelines

## Important Notes for AI Assistants

1. **Email Placeholder**: `hub.tf` contains `__REPLACE_EMAIL_ADDRESS__` — always remind users to replace this
2. **Organization Requirement**: This solution requires AWS Organizations for cross-account event delivery
3. **Reserved Concurrency**: Lambda is set to 5 concurrent executions
4. **Hub Account ID**: Required as CloudFormation parameter (`HubAccount`) when deploying spoke-stackset.yaml
5. **Event Bus Name**: Must match between hub (`hub-root-activity`) and spoke configurations
6. **Event Pattern Sync**: Hub (Terraform or CDK) and spoke (CloudFormation) event patterns must stay aligned
7. **CDK and Terraform Parity**: The CDK stack deploys identical resources to Terraform. Changes to one should be mirrored in the other
8. **DLQ Monitoring**: Failed events are preserved in SQS for 14 days — advise users to check the DLQ if notifications are missing
9. **Severity Sets**: When adding new monitored actions, update the appropriate severity set in `RootActivityLambda.py`
10. **License**: MIT-0 (no attribution required)
