# CLAUDE.md - AI Assistant Guide

This document provides AI assistants with comprehensive guidance for working with the AWS IAM Root User Activity Monitor codebase.

## Project Overview

This is an **AWS Prescriptive Guidance pattern** implementing event-driven monitoring of IAM root user activity across multiple AWS accounts. It follows AWS security best practices by detecting and alerting when root user credentials are used—a key security risk indicator.

### Architecture: Hub-and-Spoke Model

```
Spoke Accounts                           Hub Account
┌─────────────────────┐                 ┌─────────────────────────────────┐
│ Root User Activity  │                 │                                 │
│         ↓           │                 │   EventBridge      Lambda       │
│   CloudTrail Logs   │                 │   Event Bus    →   Function     │
│         ↓           │   EventBridge   │       ↑               ↓         │
│ EventBridge Rule    │ ──────────────→ │       └───────── SNS Topic      │
│ (RootActivityRule)  │   (cross-acct)  │                       ↓         │
└─────────────────────┘                 │              Email Notification │
                                        └─────────────────────────────────┘
```

- **Spoke Accounts**: Detect root user activity via CloudTrail and forward events
- **Hub Account**: Centrally process events and send notifications via SNS

## Directory Structure

```
/
├── provider.tf                    # Root Terraform provider config (multi-region)
├── hub.tf                         # Hub account module instantiation
├── spoke-stackset.yaml            # CloudFormation StackSet for spoke accounts
├── README.md                      # Project documentation
├── CONTRIBUTING.md                # Contribution guidelines
├── CODE_OF_CONDUCT.md             # Amazon Open Source Code of Conduct
├── LICENSE                        # MIT-0 License
├── RootActivityMonitor.png        # Architecture diagram
└── root-activity-monitor-module/  # Reusable Terraform module
    ├── main.tf                    # Core infrastructure definitions
    ├── variables.tf               # Input variables
    ├── outputs.tf                 # Output values
    ├── data.tf                    # Data source definitions
    ├── provider.tf                # Module provider config
    ├── RootActivityLambda.py      # Python Lambda function
    └── iam/
        ├── lambda-policy.json     # Lambda execution policy
        └── lambda-assume-policy.json  # Lambda assume role policy
```

## Technologies

| Category | Technology | Version/Details |
|----------|-----------|-----------------|
| IaC (Hub) | Terraform | ~3.0 provider |
| IaC (Spokes) | CloudFormation | StackSet deployment |
| Runtime | Python | 3.8 |
| Cloud Platform | AWS | EventBridge, Lambda, SNS, CloudTrail, IAM |

## Key Files Reference

### Infrastructure Code

| File | Purpose |
|------|---------|
| `hub.tf` | Instantiates the Terraform module for hub account. Contains email placeholder `__REPLACE_EMAIL_ADDRESS__` |
| `spoke-stackset.yaml` | CloudFormation for spoke accounts. Requires `HubAccountId` parameter |
| `root-activity-monitor-module/main.tf` | Core resources: Lambda, EventBridge, SNS, IAM roles |
| `root-activity-monitor-module/variables.tf` | Module inputs: `SNSTopicName`, `SNSSubscriptions`, `region`, `tags` |

### Lambda Function

**File**: `root-activity-monitor-module/RootActivityLambda.py`

```python
# Entry point
def lambda_handler(event, context):
    # Extracts: eventName, userIdentity.type, account
    # Publishes to SNS with subject (truncated to 100 chars)
```

**Environment Variable**: `SNSARN` - Injected by Terraform

## Development Workflow

### Prerequisites
- AWS Organization set up
- Terraform ~3.0
- AWS CLI configured with appropriate credentials
- Access to hub and spoke AWS accounts

### Deployment Steps

1. **Configure Hub Account** (`hub.tf`):
   - Replace `__REPLACE_EMAIL_ADDRESS__` with notification email
   - Adjust region via provider alias if needed

2. **Deploy Hub Infrastructure**:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

3. **Deploy Spoke Accounts**:
   - Use CloudFormation StackSets with `spoke-stackset.yaml`
   - Provide `HubAccountId` parameter (12-digit AWS account ID)

### Multi-Region Support
The root `provider.tf` configures aliases for:
- `aws.euw1` → eu-west-1
- `aws.use1` → us-east-1

## Code Conventions

### Terraform
- **Resource Naming**: PascalCase for resource logical names
  - Example: `aws_iam_role_policy "LambdaRootAPIMonitorPolicy"`
- **AWS Resource Names**: Kebab-case
  - Example: `hub-root-activity-eventbus`
- **Variables**: PascalCase
  - Example: `SNSTopicName`, `SNSSubscriptions`
- **Tags**: Apply via `var.tags` map

### Python (Lambda)
- **Logging**: Use `logging` module with DEBUG level
- **Error Handling**: Catch `ClientError` exceptions from boto3
- **Environment Variables**: Access via `os.environ`
- **SNS Subject**: Truncate to 100 characters

### EventBridge Patterns
Event pattern for root user detection:
```json
{
  "detail-type": ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"],
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
  - CloudWatch Logs: Create log streams, put log events
  - SNS: Publish to specific topic
  - IAM: ListAccountAliases only
- EventBridge permissions scoped to AWS Organization via `aws:PrincipalOrgID`

### Security Check Suppressions
The Lambda resource includes Checkov skip comments for:
- `CKV_AWS_116`: Dead Letter Queue (not needed for notifications)
- `CKV_AWS_117`: VPC deployment (not required for this use case)
- `CKV_AWS_173`: Environment variable encryption
- `CKV_AWS_50`: X-Ray tracing

### Encryption
- SNS Topic uses KMS encryption with AWS managed key (`alias/aws/sns`)

### Security Issues
Report security vulnerabilities via [AWS vulnerability reporting](http://aws.amazon.com/security/vulnerability-reporting/), NOT public GitHub issues.

## Common Tasks

### Modifying the Lambda Function
1. Edit `root-activity-monitor-module/RootActivityLambda.py`
2. Terraform will automatically repackage via `archive_file` data source
3. Run `terraform apply`

### Adding New Regions
1. Add provider alias in root `provider.tf`
2. Reference new alias in module instantiation in `hub.tf`

### Changing Notification Email
Edit `hub.tf`:
```hcl
module "root-activity-monitor" {
  SNSSubscriptions = "your-email@example.com"
  # ...
}
```

### Updating Event Patterns
- Hub: Modify `aws_cloudwatch_event_rule` in `root-activity-monitor-module/main.tf`
- Spoke: Modify `EventPattern` in `spoke-stackset.yaml`

## Testing Considerations

- **Local Testing**: Lambda function can be tested with sample CloudTrail events
- **Integration Testing**: Requires actual root user activity in spoke accounts
- **Validate Templates**:
  ```bash
  terraform validate
  aws cloudformation validate-template --template-body file://spoke-stackset.yaml
  ```

## Git Workflow

- **Main Branch**: `main`
- **Contribution**: Fork → branch → PR workflow
- **Commit Messages**: Clear, descriptive messages focused on the change
- See `CONTRIBUTING.md` for full guidelines

## Important Notes for AI Assistants

1. **Email Placeholder**: `hub.tf` contains `__REPLACE_EMAIL_ADDRESS__` - always remind users to replace this
2. **Organization Requirement**: This solution requires AWS Organizations for cross-account event delivery
3. **Reserved Concurrency**: Lambda is set to 1 concurrent execution - suitable for notification workloads
4. **Hub Account ID**: Required as CloudFormation parameter when deploying spoke-stackset.yaml
5. **Event Bus Name**: Must match between hub (`hub-root-activity`) and spoke configurations
6. **License**: MIT-0 (no attribution required)
