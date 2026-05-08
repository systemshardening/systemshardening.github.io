---
title: "Serverless Security Observability: AWS Lambda, GCP Cloud Functions, Azure Functions"
description: "Serverless and FaaS workloads present unique security observability challenges: no persistent agents, ephemeral execution environments, and platform-managed runtimes with limited introspection. This article covers structured security logging, abuse detection, layer integrity, secret management, VPC controls, and exfiltration detection for AWS Lambda, GCP Cloud Functions, and Azure Functions."
slug: serverless-security-observability
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - serverless
  - aws-lambda
  - cloud-functions
  - runtime-monitoring
  - function-security
personas:
  - security-engineer
  - platform-engineer
article_number: 563
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/serverless-security-observability/
---

# Serverless Security Observability: AWS Lambda, GCP Cloud Functions, Azure Functions

## Problem

Serverless and Function-as-a-Service (FaaS) workloads fundamentally break the assumptions that most security observability tooling is built on. Traditional endpoint security relies on persistent agents running in the operating system. Traditional network monitoring relies on long-lived connections that can be tracked across sessions. Traditional log aggregation relies on syslog or journal daemons that survive the lifetime of a request.

None of those primitives exist in serverless.

A Lambda function runs for 100 milliseconds, processes a message, and its execution environment is frozen or destroyed. The next invocation may run in a fresh environment or a recycled one — and the function has no way to know which. The platform manages the runtime, the OS, and the network namespace. There is no filesystem to persist agent state to. eBPF programs cannot be loaded because the underlying host is not accessible. Container escape detection does not apply because there is no container to escape from.

The security observability model for serverless must be:

- **Platform-native first.** CloudTrail, CloudWatch Logs, Cloud Audit Logs, and Application Insights are the primary signal sources — not host agents.
- **Code-level instrumentation.** Structured logging within the function code, using libraries like AWS Lambda Powertools, is the only reliable way to emit security-relevant events.
- **Invocation-level telemetry.** Anomaly detection must work at the granularity of individual function invocations, not long-running processes.
- **Control-plane aware.** Unauthorised changes to function configuration — updating environment variables, attaching new layers, changing IAM roles — are often more important to detect than runtime behaviour.

Common security problems in serverless environments:

- **Secrets in environment variables.** Lambda environment variables are stored in plaintext in the Lambda configuration and visible to anyone with `lambda:GetFunction` permissions. They are also included in CloudTrail events when functions are updated.
- **Third-party Lambda layers executing unreviewed code.** Lambda layers are code packages attached to functions. A compromised or malicious layer executes with the same permissions as the function itself — including access to attached secrets and the function's IAM role.
- **Invocation from unexpected principals.** A function intended for internal event processing receives direct invocations from external AWS accounts, or from IAM principals that should not have access. CloudTrail captures this — but only if someone is watching.
- **Crypto mining within execution time limits.** Functions with generous memory and timeout settings (15 minutes is the Lambda maximum) are attractive for crypto mining. Attackers who gain code execution attempt to maximise compute within the billing window.
- **Exfiltration via outbound HTTP.** Functions typically have unrestricted egress by default. Compromised function code can exfiltrate secrets or data via HTTP calls to attacker-controlled endpoints, with no network-level detection if the function is not in a VPC.

**Target systems:** AWS Lambda (all runtimes); GCP Cloud Functions (1st and 2nd gen); Azure Functions (Consumption and Premium plans).

## Threat Model

- **Adversary 1 — Secrets extraction via `lambda:GetFunction`:** An attacker compromises an IAM credential with broad read permissions. They call `lambda:GetFunction` on production functions and retrieve plaintext database passwords, API keys, and signing secrets from environment variables. No runtime access required.
- **Adversary 2 — Malicious Lambda layer supply chain attack:** A popular open-source Lambda layer for observability instrumentation is compromised. The next deploy of any function using that layer executes the attacker's code, which exfiltrates the function's IAM temporary credentials to an external endpoint. All functions using the layer are affected simultaneously.
- **Adversary 3 — Crypto mining via code injection:** An attacker gains the ability to update Lambda function code (via a compromised CI/CD pipeline or stolen IAM key with `lambda:UpdateFunctionCode`). They inject a crypto miner that runs until the function times out, maximising compute usage. The attack repeats on every invocation.
- **Adversary 4 — Privilege escalation via Lambda IAM role:** A Lambda function is assigned an overly permissive IAM role. An attacker who achieves code execution in the function (through injection or logic flaws) calls `sts:AssumeRole` or uses the metadata endpoint to retrieve temporary credentials for the role, then uses those credentials to move laterally in the AWS account.
- **Adversary 5 — Unauthorised direct invocation:** A Lambda function is intended to be invoked only by an internal EventBridge rule. An external party discovers the function ARN and invokes it directly via `lambda:InvokeFunction`, bypassing application-layer access controls. The function processes arbitrary attacker-supplied input.
- **Access level:** Adversaries 1, 3, 5 require IAM credentials. Adversary 2 requires supply-chain compromise of a layer dependency. Adversary 4 requires code execution in the function.
- **Objective:** Exfiltrate secrets; gain persistent account access; consume compute; bypass access controls.
- **Blast radius:** A single compromised IAM key with Lambda permissions across a production account can extract secrets from all functions simultaneously.

## Configuration

### Step 1: Enable CloudTrail for Lambda Control-Plane Events

CloudTrail is the authoritative source for Lambda control-plane events: who deployed what code, who changed which environment variable, who invoked which function from which principal.

```bash
# Verify CloudTrail is logging Lambda data events.
# Data events (InvokeFunction) are not logged by default — must be enabled explicitly.
aws cloudtrail get-event-selectors --trail-name production-trail

# Enable Lambda data event logging (InvokeFunction calls).
aws cloudtrail put-event-selectors \
  --trail-name production-trail \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::Lambda::Function",
          "Values": ["arn:aws:lambda:us-east-1:123456789012:function:*"]
        }
      ]
    }
  ]'
```

CloudTrail events to alert on:

| Event | Security Signal |
|-------|----------------|
| `UpdateFunctionCode` | New function code deployed — verify this matches an expected CI/CD invocation |
| `UpdateFunctionConfiguration` | Environment variables, layers, timeout, or memory changed |
| `AddLayerVersionPermission` | Lambda layer shared with another account |
| `AddPermission` | Resource-based policy modified — new principal can invoke the function |
| `InvokeFunction` | Direct invocation from unexpected principal or AWS account |
| `CreateFunction` | New function created — not from expected automation |
| `DeleteFunction` | Function deleted — potential evidence destruction |

### Step 2: AWS Lambda Structured Security Logging with Powertools

Lambda Powertools provides structured logging, tracing, and metrics in a consistent format. Security-relevant events should be emitted as structured log records — not print statements — so they can be queried in CloudWatch Logs Insights.

```python
# Python Lambda with AWS Lambda Powertools structured logging.
# Install: pip install aws-lambda-powertools
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext
import json, os

logger = Logger(service="payment-processor")
tracer = Tracer(service="payment-processor")
metrics = Metrics(namespace="SecurityMetrics", service="payment-processor")

@logger.inject_lambda_context(log_event=False)  # log_event=False: don't log raw input (may contain PII).
@tracer.capture_lambda_handler
def handler(event: dict, context: LambdaContext) -> dict:
    # Log the invocation source for audit purposes.
    # event_source is safe to log; do not log raw event payload without scrubbing.
    logger.info(
        "function_invoked",
        extra={
            "event_source": event.get("source", "direct"),
            "request_id": context.aws_request_id,
            "function_version": context.function_version,
            # DO NOT log: event body, tokens, payment card data.
        }
    )

    try:
        result = process_payment(event)
        logger.info("payment_processed", extra={"result": "success"})
        return result
    except PermissionError as e:
        # Security-relevant: log authorisation failures as security events.
        logger.warning(
            "authorisation_failure",
            extra={
                "error_type": type(e).__name__,
                # Avoid logging e.args which may include sensitive context.
                "request_id": context.aws_request_id,
            }
        )
        metrics.add_metric(name="AuthorisationFailure", unit=MetricUnit.Count, value=1)
        raise
    except Exception as e:
        logger.exception("unexpected_error")
        raise
```

```typescript
// TypeScript Lambda with Powertools.
// Install: npm install @aws-lambda-powertools/logger @aws-lambda-powertools/tracer
import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import type { Context } from 'aws-lambda';

const logger = new Logger({ serviceName: 'api-gateway-handler' });
const tracer = new Tracer({ serviceName: 'api-gateway-handler' });

export const handler = async (event: APIGatewayEvent, context: Context) => {
  // Inject Lambda context into all log records automatically.
  logger.addContext(context);

  // Log security-relevant request metadata — not request body.
  logger.info('request_received', {
    sourceIp: event.requestContext?.identity?.sourceIp,
    httpMethod: event.httpMethod,
    path: event.path,
    // NOT: event.body, event.headers['Authorization'].
  });

  // Detect and log unexpected caller identity.
  const callerId = event.requestContext?.identity?.caller;
  if (callerId && !callerId.startsWith('arn:aws:iam::123456789012:')) {
    logger.warn('cross_account_invocation', {
      caller: callerId,
      sourceIp: event.requestContext?.identity?.sourceIp,
    });
  }
};
```

### Step 3: Lambda Insights for Process-Level Telemetry

Lambda Insights is a CloudWatch feature that collects enhanced metrics from within the execution environment, including CPU usage, memory usage, network activity, and — critically — per-invocation cold start indicators. Enable it via the Lambda Insights managed layer.

```bash
# Enable Lambda Insights on a function.
aws lambda update-function-configuration \
  --function-name payment-processor \
  --layers "arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:38"

# Grant CloudWatch Logs write permission to the execution role.
aws iam attach-role-policy \
  --role-name payment-processor-execution-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLambdaInsightsExecutionRolePolicy
```

Lambda Insights emits the `LambdaInsights` log group with structured performance records. The fields useful for security detection:

| Field | Security Use |
|-------|-------------|
| `cold_start` | Unexpectedly high cold start rate may indicate function version churn (code being redeployed frequently) |
| `memory_utilisation` | Sustained high memory usage across all invocations suggests injected workload (crypto miner) |
| `cpu_total_time` | CPU time approaching the timeout limit on every invocation is a strong crypto mining signal |
| `init_duration` | Large init duration from a new layer version — layer has significant new code |
| `total_network` | Abnormally high outbound network bytes relative to function purpose |

### Step 4: Detecting Lambda Abuse — CloudWatch Logs Insights Queries

```sql
-- Detect crypto mining pattern: invocations consistently approaching timeout.
-- Run against /aws/lambda/<function-name> log group.
fields @timestamp, @requestId, @duration, @maxMemoryUsed, @initDuration
| filter @duration > 800000  -- 800 seconds; adjust to 80% of configured timeout.
| stats count() as timeout_approaches by bin(1h)
| sort @timestamp desc

-- Detect unusual invocation volume (possible abuse or data exfiltration loop).
fields @timestamp, @requestId
| stats count() as invocation_count by bin(5m)
| sort invocation_count desc
| limit 20

-- Detect cold starts with unexpected init duration (large new layer or code).
fields @timestamp, @requestId, @initDuration
| filter @initDuration > 5000  -- 5-second init; investigate new layer or heavy dependency.
| sort @timestamp desc

-- Find invocations that logged security events (structured log search).
fields @timestamp, message, event_source, request_id
| filter level = "WARNING" and message like /authorisation_failure|cross_account|unexpected_caller/
| sort @timestamp desc
```

CloudWatch metric filter for crypto mining detection:

```bash
# Create a metric filter that counts invocations above 90% of configured timeout.
aws cloudwatch put-metric-filter \
  --log-group-name /aws/lambda/payment-processor \
  --filter-name NearTimeoutInvocations \
  --filter-pattern '[timestamp, requestId, level="REPORT", label1, label2, duration, "ms", label3, label4, billed, "ms", label5, label6, memory_size, "MB", label7, label8, max_memory, "MB", ...]' \
  --metric-transformations \
    metricName=NearTimeoutInvocations,metricNamespace=LambdaSecurity,metricValue=1

# Alert when near-timeout invocations exceed threshold.
aws cloudwatch put-metric-alarm \
  --alarm-name LambdaCryptoMiningDetection \
  --metric-name NearTimeoutInvocations \
  --namespace LambdaSecurity \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
```

### Step 5: CloudTrail Alert — Unexpected InvokeFunction Principal

```python
# EventBridge rule matching CloudTrail InvokeFunction events from unexpected principals.
# Deploy this as a CloudFormation or Terraform resource.
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["Invoke"],
    "userIdentity": {
      "accountId": [{"anything-but": ["123456789012"]}]  # Flag cross-account invocations.
    }
  }
}
```

```bash
# Query CloudTrail directly for unexpected InvokeFunction callers.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Invoke \
  --start-time 2026-05-06T00:00:00Z \
  --end-time 2026-05-07T00:00:00Z \
  --query 'Events[?contains(CloudTrailEvent, `"userIdentity"`) == `true`].[EventTime,Username,CloudTrailEvent]' \
  --output table
```

### Step 6: Lambda Layer Security — Verifying Integrity

Third-party Lambda layers execute arbitrary code with the full permissions of the function's IAM role. They are a significant supply-chain risk: a compromised layer publisher can push a malicious layer version that is automatically picked up by functions configured to use `$LATEST` or unpinned ARNs.

```bash
# BAD: unpinned layer ARN — always uses latest version.
# arn:aws:lambda:us-east-1:580247275435:layer:SomeLayer:$LATEST

# GOOD: pin to a specific layer version ARN.
aws lambda update-function-configuration \
  --function-name payment-processor \
  --layers "arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:38"
# The :38 is the version number — this is immutable.
```

```bash
# Audit all Lambda functions for third-party layers.
# A third-party layer has a different account ID in the ARN.
aws lambda list-functions --query 'Functions[*].[FunctionName,Layers]' --output json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
account_id = '123456789012'
for fn_name, layers in data:
    if layers:
        for layer in layers:
            arn = layer['Arn']
            layer_account = arn.split(':')[4]
            if layer_account != account_id:
                print(f'EXTERNAL LAYER: {fn_name} uses {arn} from account {layer_account}')
"
```

```bash
# Detect layer version changes in CloudTrail.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionConfiguration \
  --query 'Events[*].CloudTrailEvent' --output text | \
  python3 -c "
import json, sys
for line in sys.stdin:
    try:
        event = json.loads(line)
        layers = event.get('requestParameters', {}).get('layers', [])
        if layers:
            print(f\"{event['eventTime']} {event['userIdentity']['arn']}: layers={layers}\")
    except:
        pass
"
```

Policy control: use an AWS Config managed rule or SCP to enforce approved layer ARNs only.

```python
# AWS Config rule: flag functions using unapproved layers.
# Lambda-backed Config rule.
APPROVED_LAYER_PREFIXES = [
    "arn:aws:lambda:us-east-1:123456789012:layer:",          # Internal layers.
    "arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:38",  # Pinned AWS layer.
]

def evaluate_compliance(configuration_item):
    layers = configuration_item.get("configuration", {}).get("layers", [])
    for layer in layers:
        arn = layer["arn"]
        if not any(arn.startswith(prefix) for prefix in APPROVED_LAYER_PREFIXES):
            return "NON_COMPLIANT", f"Unapproved layer: {arn}"
    return "COMPLIANT", ""
```

### Step 7: Environment Variable Security — Moving Secrets to Parameter Store

```python
# BAD: secrets in environment variables.
# Visible to anyone with lambda:GetFunction; logged in CloudTrail on UpdateFunctionConfiguration.
import os
db_password = os.environ["DB_PASSWORD"]  # Plaintext in Lambda config.

# GOOD: retrieve secrets at runtime from SSM Parameter Store or Secrets Manager.
import boto3
from functools import lru_cache

ssm = boto3.client("ssm")
secrets = boto3.client("secretsmanager")

@lru_cache(maxsize=None)
def get_parameter(name: str) -> str:
    """Fetch and cache SSM parameter. Cache survives across warm invocations."""
    response = ssm.get_parameter(Name=name, WithDecryption=True)
    return response["Parameter"]["Value"]

@lru_cache(maxsize=None)
def get_secret(secret_id: str) -> dict:
    """Fetch and cache Secrets Manager secret."""
    response = secrets.get_secret_value(SecretId=secret_id)
    return json.loads(response["SecretString"])

def handler(event, context):
    # Retrieved once per warm execution environment, not per invocation.
    db_password = get_parameter("/prod/payment-processor/db-password")
    api_creds = get_secret("prod/payment-processor/api-credentials")
    # ...
```

```bash
# Audit: find Lambda functions with likely secrets in environment variables.
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | while read fn; do
    envvars=$(aws lambda get-function-configuration --function-name "$fn" \
      --query 'Environment.Variables' --output json 2>/dev/null)
    if echo "$envvars" | grep -iE '"(password|secret|key|token|credential|passwd)":' > /dev/null; then
      echo "POTENTIAL SECRET IN ENV VARS: $fn"
    fi
  done
```

### Step 8: VPC Lambda Security

Lambda functions outside a VPC have unrestricted internet egress — any outbound HTTP call succeeds without network-level logging. Placing Lambda in a VPC forces all traffic through VPC routing, enabling security group controls and VPC Flow Logs.

```bash
# Configure Lambda in VPC with restrictive security group.
aws lambda update-function-configuration \
  --function-name payment-processor \
  --vpc-config SubnetIds=subnet-abc123,subnet-def456,SecurityGroupIds=sg-lambda-payment

# Security group: allow only necessary outbound traffic.
# Inbound: no rules needed (Lambda initiates connections; it does not listen).
# Outbound: allow only HTTPS to specific CIDR or prefix list.
aws ec2 authorize-security-group-egress \
  --group-id sg-lambda-payment \
  --ip-permissions '[
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
     "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "Internal HTTPS only"}]}
  ]'

# Block all other egress — prevents direct exfiltration to internet.
aws ec2 revoke-security-group-egress \
  --group-id sg-lambda-payment \
  --ip-permissions '[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]'
```

Enable VPC Flow Logs to capture Lambda egress attempts:

```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-prod123 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flow-logs/prod \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/vpc-flow-logs-role
```

### Step 9: Detecting Exfiltration from Lambda

```bash
# VPC Flow Logs Insights query: Lambda subnet traffic to unexpected external destinations.
# Run against /vpc/flow-logs/prod log group.
fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter srcAddr like /10\.100\.1\./   # Lambda subnet CIDR.
| filter not (dstAddr like /10\./ or dstAddr like /172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\./ or dstAddr like /192\.168\./)
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes by dstAddr, dstPort
| sort total_bytes desc
| limit 20
```

```sql
-- CloudWatch Logs Insights: find outbound HTTP calls logged by the function itself.
-- Requires the function to log outbound requests (e.g., via requests library logging).
fields @timestamp, @requestId, message
| filter message like /requests\.packages\.urllib3|urllib\.request|http\.client|outbound_request/
| filter message like /https?:\/\/(?!internal\.|10\.|172\.|192\.168\.)/
| sort @timestamp desc
```

DNS-based exfiltration detection via Route 53 Resolver query logs:

```bash
# Enable Route 53 Resolver query logging for VPC.
aws route53resolver create-resolver-query-log-config \
  --name prod-vpc-dns-logs \
  --destination-arn arn:aws:logs:us-east-1:123456789012:log-group:/route53/resolver-query-logs

aws route53resolver associate-resolver-query-log-config \
  --resolver-query-log-config-id rqlc-abc123 \
  --resource-id vpc-prod123
```

```sql
-- Route 53 Resolver query logs: detect DNS queries to unusual domains from Lambda.
-- High-entropy subdomain queries may indicate DNS tunnelling exfiltration.
fields @timestamp, srcAddr, query_name, query_type
| filter srcAddr like /10\.100\.1\./   # Lambda subnet.
| filter query_name not like /amazonaws\.com|internal\.example\.com/
| stats count() as query_count by query_name
| sort query_count desc
```

### Step 10: GCP Cloud Functions Audit Logging

On GCP, Cloud Audit Logs capture control-plane operations on Cloud Functions. Data access logs must be explicitly enabled.

```bash
# Enable Cloud Audit Logs for Cloud Functions (data access).
gcloud projects get-iam-policy my-project --format=json > policy.json
# Add to policy.json under auditConfigs:
# {
#   "service": "cloudfunctions.googleapis.com",
#   "auditLogConfigs": [
#     {"logType": "ADMIN_READ"},
#     {"logType": "DATA_READ"},
#     {"logType": "DATA_WRITE"}
#   ]
# }
gcloud projects set-iam-policy my-project policy.json

# Query Cloud Audit Logs for unexpected function invocations.
gcloud logging read \
  'resource.type="cloud_function"
   protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CallFunction"
   NOT protoPayload.authenticationInfo.principalEmail=~"@my-project.iam.gserviceaccount.com"' \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, resource.labels.function_name)" \
  --limit=50
```

GCP Cloud Functions security events to monitor via Log-based metrics:

| Log Filter | Security Signal |
|------------|----------------|
| `methodName="UpdateFunction"` | Function code or config changed |
| `methodName="CallFunction" AND NOT principalEmail like service-account` | Direct invocation from user identity |
| `severity=ERROR AND resource.type=cloud_function` | Runtime errors (may indicate injection attempts) |
| `httpRequest.status=403 AND resource.type=cloud_function` | Access denied — possible probing |

## Telemetry

Key metrics and log signals to emit and alert on:

```
lambda_near_timeout_invocations_total{function, region}         counter
lambda_authorisation_failures_total{function, caller}           counter
lambda_cross_account_invocations_total{function, caller_account} counter
lambda_external_layer_count{function, layer_arn}                gauge   # Should match approved list.
lambda_plaintext_secret_env_vars{function}                      gauge   # Should be 0.
lambda_vpc_attached{function}                                   gauge   # Should be 1 for sensitive functions.
vpc_flow_unexpected_egress_bytes{src_subnet, dst_addr}          counter
```

Alert on:

- `lambda_near_timeout_invocations_total` sustained above baseline — potential crypto mining; escalate to incident response.
- `lambda_cross_account_invocations_total` non-zero — unexpected external invocation; review CloudTrail for the source ARN.
- `lambda_external_layer_count` includes non-approved ARN — quarantine function and review layer code.
- `lambda_plaintext_secret_env_vars` non-zero — secret rotation and migration to Parameter Store required.
- Route 53 Resolver queries with high-entropy subdomain labels from Lambda subnets — potential DNS tunnelling.

## Expected Behaviour

| Control | Without It | With It |
|---------|-----------|---------|
| CloudTrail data events enabled | `InvokeFunction` calls not logged; no audit trail | Every invocation logged with caller identity and timestamp |
| Secrets in Parameter Store | DB passwords visible via `lambda:GetFunction` | Secrets require `ssm:GetParameter` with separate IAM policy; not in function config |
| Layer version pinning | New layer version auto-picked up; supply-chain update can inject code | Layer ARN is immutable; update requires explicit code change |
| Lambda in VPC with restrictive SG | Compromised function has unrestricted internet egress | Egress blocked to internet; exfiltration requires VPC-resident infrastructure |
| Structured security logging | Security events are print statements; no queryable context | CloudWatch Logs Insights can query by event type, caller, request ID |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Lambda in VPC | Network-level egress control; VPC Flow Logs | Cold start latency increase (100–500ms); requires NAT gateway for internet access | Use Provisioned Concurrency for latency-sensitive functions |
| SSM Parameter Store for secrets | Secrets not in function config or CloudTrail | Additional API call on cold start; adds ~20–50ms latency | Cache with `lru_cache`; use SSM advanced parameters with higher throughput |
| CloudTrail data events | Full invocation audit trail | Additional CloudTrail cost (~$0.10 per 100,000 events) | Scope data events to high-value functions only |
| Pinned layer ARNs | Supply-chain updates don't auto-apply | Security patches in layers require explicit deploy | Add layer version update check to CI/CD pipeline; automate with EventBridge |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CloudTrail data events not enabled | Invocation events missing from audit trail | Periodic CloudTrail configuration audit; AWS Config rule | Enable data events; accept gap in historical log coverage |
| Lambda Insights layer incompatible with runtime | Function fails to initialise; increased cold starts | CloudWatch Errors metric spike post-deploy | Pin Lambda Insights layer to compatible version; test in staging |
| SSM Parameter Store throttled | `ThrottlingException` on cold start; function fails | `SSM_GetParameter_Throttled` CloudWatch metric | Increase Parameter Store throughput limit; add exponential backoff with jitter |
| VPC NAT gateway misconfigured | Lambda cannot reach AWS service endpoints | `ETIMEDOUT` in function logs on SSM/Secrets Manager calls | Add VPC endpoints for SSM, Secrets Manager, CloudWatch to avoid NAT gateway |
| Log group retention not set | CloudWatch Logs accumulate indefinitely | Log group storage metric growing without bound | Set 30–90 day retention on all Lambda log groups; enforce via AWS Config |

## Related Articles

- [Cloud Provider Audit Logs](/articles/observability/cloud-provider-audit-logs/)
- [Data Exfiltration Detection](/articles/observability/data-exfiltration-detection/)
- [Application Security Logging](/articles/observability/application-security-logging/)
- [Distributed Tracing Security](/articles/observability/distributed-tracing-security/)
- [Detection as Code with Sigma](/articles/observability/detection-as-code-sigma/)
