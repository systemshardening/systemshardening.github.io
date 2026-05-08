---
title: "Cloud Network Security Hardening: AWS, GCP, and Azure"
description: "Cloud networks are not secure by default. Misconfigured security groups, open IMDS endpoints, and absent private service endpoints routinely lead to credential theft and data exfiltration. This guide covers the controls that matter: VPC design, IMDS v2 enforcement, private endpoints, flow log analysis, and cross-cloud parity across AWS, GCP, and Azure."
slug: cloud-network-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - cloud-security
  - aws-vpc
  - security-groups
  - private-endpoints
  - network-segmentation
personas:
  - security-engineer
  - platform-engineer
article_number: 498
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/cloud-network-security-hardening/
---

# Cloud Network Security Hardening: AWS, GCP, and Azure

## The Problem

Cloud networks ship with defaults that optimise for getting workloads running, not for limiting blast radius. A fresh AWS VPC has a default security group that allows all outbound traffic. EC2 instances launched into a public subnet receive public IPs and are reachable from the internet unless a security group blocks inbound traffic — and engineers routinely open `0.0.0.0/0` inbound on port 22 or 443 "just for testing" and forget to close it.

The exploitable consequence is not just open ports. Cloud-native attack chains compound the problem:

- **SSRF to IMDS credential theft.** A server-side request forgery flaw in a web application lets an attacker reach `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` — the EC2 Instance Metadata Service. Without IMDSv2 enforcement, any HTTP request to that IP from the instance returns live AWS credentials.
- **Lateral movement within a VPC.** Security groups that allow broad internal ranges (`10.0.0.0/8` on all ports) mean a compromised application tier can connect to the data tier, the management plane, and every other service in the VPC without encountering a control.
- **Data exfiltration via internet gateways.** S3 buckets are reachable over the public internet. An application running in a private subnet that routes to an internet gateway can exfiltrate data to any S3 bucket — including attacker-controlled ones — unless egress is constrained to private service endpoints.
- **Misconfigured security groups.** Automated scans consistently find production security groups with `0.0.0.0/0` inbound on administrative ports, often introduced by engineers who needed temporary access and never removed it.

The controls described here address all four of these patterns. The emphasis is on defaults that are secure rather than reactive patching after a misconfiguration is found.

---

## VPC Design: Three-Tier Subnet Segmentation

The foundational control is subnet structure. Do not put everything in one subnet and rely on security groups alone. Subnets enforce blast-radius boundaries at the network layer before security group rules are evaluated.

**Three-tier layout:**

```
Internet Gateway
       │
┌──────▼────────┐
│  Public Tier  │  Load balancers, NAT gateways, bastion hosts
│  10.0.0.0/24  │  (no application or data workloads here)
└──────┬────────┘
       │  (only through load balancer, no direct routing)
┌──────▼────────┐
│ Private Tier  │  Application servers, containers, compute
│  10.0.1.0/24  │  Outbound via NAT only, no public IPs
└──────┬────────┘
       │  (only through app tier, no direct routing)
┌──────▼────────┐
│  Data Tier    │  RDS, ElastiCache, OpenSearch
│  10.0.2.0/24  │  No internet route at all — not even NAT
└───────────────┘
```

The data tier has no route to an internet gateway and no NAT gateway. A compromised database cannot initiate outbound connections to the internet. The private tier reaches the internet only through a NAT gateway — it can pull software updates, but inbound connections from the internet require passing through the public tier load balancer.

Terraform module pattern for this layout:

```hcl
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = false   # never auto-assign public IPs
  tags = { Tier = "public" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
  tags = { Tier = "private" }
}

resource "aws_subnet" "data" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false
  tags = { Tier = "data" }
}

# Data tier route table: no default route — no internet, no NAT
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  # intentionally empty: no 0.0.0.0/0 route
}
```

---

## Security Groups vs NACLs: When to Use Each

AWS has two overlapping network controls: Security Groups (SGs) and Network Access Control Lists (NACLs). Engineers frequently misunderstand the relationship.

**Security Groups** are stateful and instance-level. A response to an allowed inbound connection is automatically permitted outbound, without an explicit outbound rule. SGs are the primary day-to-day control. Default them to deny; add only explicit permit rules.

**NACLs** are stateless and subnet-level. Inbound and outbound rules are evaluated independently. Responses require explicit outbound permit rules (or an ephemeral port range). NACLs operate before security groups in the evaluation order.

Use NACLs for:
- Hard blocking of known-bad IP ranges (blocklists) that should never reach the subnet regardless of SG rules
- Enforcing subnet-tier boundaries (prevent the data tier from ever receiving traffic from the internet, even if SG misconfiguration occurs)
- Response to active incidents: a NACL rule blocks traffic faster than modifying every SG attached to instances in the subnet

Use Security Groups for:
- Per-workload least-privilege rules (application servers may accept only port 8080 from the load balancer SG)
- Reference SG IDs instead of CIDR ranges wherever possible — tying permission to identity, not IP address

```hcl
# Correct: reference the ALB security group, not a CIDR
resource "aws_security_group_rule" "app_inbound_from_alb" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.alb.id
}

# Wrong: open to any IP in the VPC
# cidr_blocks = ["10.0.0.0/8"]  # never do this for application traffic
```

All security groups should have an explicit egress rule set rather than the default "all traffic allowed outbound". Restrict egress to what the application actually needs:

```hcl
resource "aws_security_group" "app" {
  name   = "app-servers"
  vpc_id = aws_vpc.main.id

  # Remove default allow-all egress
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # HTTPS to internet — constrain further with private endpoints
    description = "HTTPS outbound — replace with private endpoint after endpoints are deployed"
  }

  egress {
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.db.id
    description              = "PostgreSQL to data tier only"
  }
}
```

---

## IMDSv2 Enforcement: Blocking SSRF-Based Credential Theft

The Instance Metadata Service is the most common vector for cloud credential theft. IMDSv1 responds to any HTTP GET from the instance; a single SSRF vulnerability in a web application is sufficient for an attacker to retrieve IAM credentials by fetching `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

IMDSv2 requires a PUT request with a TTL header to obtain a session token, which is then used in subsequent GET requests. This breaks SSRF-based attacks because SSRF vulnerabilities typically follow redirects to a second GET, not a PUT-then-GET sequence.

Enforce IMDSv2 at launch configuration level so it cannot be bypassed:

```hcl
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # enforces IMDSv2
    http_put_response_hop_limit = 1            # prevents container-to-host escalation
  }
}
```

The `http_put_response_hop_limit = 1` setting is critical for containerised workloads. The default value of 2 allows a container to reach the host's IMDS endpoint; setting it to 1 ensures the TTL expires before a request from a container reaches the metadata service.

Enforce IMDSv2 account-wide using an SCP:

```json
{
  "Sid": "RequireIMDSv2",
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}
```

Audit existing instances that still have IMDSv1 active:

```bash
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[?MetadataOptions.HttpTokens!=`required`].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table
```

---

## Private Endpoints: Removing the Public Internet Route for AWS Services

S3, ECR, Secrets Manager, SSM, and most AWS managed services are reachable over the public internet by default. An application running in a private subnet resolves `s3.amazonaws.com` to a public IP, routes through the NAT gateway, exits the VPC, and reaches S3 over the internet. This means sensitive data in transit traverses the public internet and is visible to any routing hop between the NAT gateway and the S3 endpoint.

VPC Endpoints (Gateway and Interface types) keep this traffic inside the AWS network and allow attaching endpoint policies that restrict which S3 buckets or Secrets Manager secrets the endpoint can access — preventing an attacker who has compromised an instance from exfiltrating data to attacker-controlled buckets using the instance's IAM role.

```hcl
# Gateway endpoint for S3 (free, attaches to route table)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.data.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowOwnBucketsOnly"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource  = [
        "arn:aws:s3:::${var.app_bucket}",
        "arn:aws:s3:::${var.app_bucket}/*"
      ]
    }]
  })
}

# Interface endpoint for Secrets Manager (private DNS resolution)
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}
```

With `private_dns_enabled = true`, the application resolves `secretsmanager.us-east-1.amazonaws.com` to a private IP inside the VPC. No changes to application code are needed; DNS handles the routing transparently.

The endpoint policy on the S3 gateway endpoint restricts the endpoint to only allow operations on named buckets. Even if an attacker gains IAM credentials, they cannot use those credentials through this endpoint to access other S3 buckets.

---

## VPC Flow Logs: Enabling and Querying for Threats

Flow logs record connection metadata (source IP, destination IP, port, protocol, bytes, action) for all network interfaces in a VPC. They do not capture payload content, but metadata is sufficient for most threat-hunting and forensic workflows.

Enable at VPC level to capture all interfaces, including those attached after the flow log is created:

```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0abc123 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination "arn:aws:s3:::my-flowlogs-bucket/vpc-flowlogs/" \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
```

Query flow logs with Athena to find outbound connections from private subnets to unexpected destinations:

```sql
-- Find instances making outbound connections to IPs not in the VPC CIDR
SELECT srcaddr, dstaddr, dstport, SUM(bytes) AS total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND srcaddr LIKE '10.0.1.%'          -- private tier subnet
  AND dstaddr NOT LIKE '10.0.%'        -- destination outside VPC
  AND dstaddr NOT IN (
    SELECT ip FROM aws_managed_prefixes -- exclude known AWS service IPs
  )
  AND start > to_unixtime(current_timestamp - interval '24' hour)
GROUP BY srcaddr, dstaddr, dstport
ORDER BY total_bytes DESC
LIMIT 50;
```

```sql
-- Find rejected connections: probing or lateral movement attempts
SELECT dstaddr, dstport, COUNT(*) AS rejected_count
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND start > to_unixtime(current_timestamp - interval '1' hour)
GROUP BY dstaddr, dstport
HAVING COUNT(*) > 100
ORDER BY rejected_count DESC;
```

---

## GCP Equivalent Controls

GCP's network model differs from AWS but the security principles map directly.

**VPC Firewall Rules** are GCP's equivalent of security groups — they operate at the VPC level and apply to instances based on network tags or service accounts. Prefer service-account-based rules over tag-based rules; tags are mutable by anyone with instance-edit permissions, but service accounts are identity-bound.

```bash
# Allow only app-server service account to reach database on port 5432
gcloud compute firewall-rules create allow-app-to-db \
  --network=prod-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-service-accounts=app-server@project.iam.gserviceaccount.com \
  --target-service-accounts=database@project.iam.gserviceaccount.com \
  --priority=1000
```

**Private Google Access** allows instances without external IPs to reach Google APIs (Cloud Storage, Pub/Sub, BigQuery) without traversing the internet. Enable it on private subnets:

```bash
gcloud compute networks subnets update private-subnet \
  --region=us-central1 \
  --enable-private-ip-google-access
```

**VPC Service Controls** are GCP's most powerful exfiltration-prevention control. They create a security perimeter around GCP services; API calls crossing the perimeter (from outside, or to external projects) are denied. This prevents an attacker with a compromised service account from exfiltrating Cloud Storage data to an external GCP project.

```bash
gcloud access-context-manager perimeters create prod-perimeter \
  --title="Production Perimeter" \
  --resources=projects/123456789 \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com,secretmanager.googleapis.com \
  --policy=accessPolicies/POLICY_ID
```

**GCP VPC Flow Logs** are enabled per-subnet and written to Cloud Logging:

```bash
gcloud compute networks subnets update private-subnet \
  --region=us-central1 \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0 \
  --logging-metadata=include-all
```

---

## Azure Equivalent Controls

**Network Security Groups (NSGs)** are Azure's equivalent of AWS security groups — stateful, attached to subnets or individual NICs. Apply NSGs at both the subnet level and the NIC level for defence-in-depth. Subnet-level NSGs enforce zone-boundary rules; NIC-level NSGs enforce per-workload rules.

```hcl
resource "azurerm_network_security_rule" "allow_app_to_db" {
  name                        = "allow-app-to-db"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.data.name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = "10.0.1.0/24"   # app subnet CIDR
  destination_address_prefix  = "10.0.2.0/24"   # data subnet CIDR
}

# Explicit deny-all at lower priority
resource "azurerm_network_security_rule" "deny_all_inbound" {
  name                        = "deny-all-inbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  # ...
}
```

**Azure Private Endpoints** attach a private IP from the VNet to a managed service (Storage, Key Vault, SQL). The service's DNS resolves to a private IP within the VNet. Disable public network access on the service once private endpoints are in place:

```bash
# Disable public access to a storage account after private endpoint creation
az storage account update \
  --name mystorageaccount \
  --resource-group prod-rg \
  --default-action Deny \
  --public-network-access Disabled
```

**Azure Firewall** provides centralised egress control for a hub-and-spoke topology. Use application rules (FQDN-based) rather than network rules (IP-based) for outbound HTTPS — this allows control by destination domain rather than trying to maintain IP blocklists:

```
Application Rule: Allow app VNet to reach *.blob.core.windows.net on HTTPS
Network Rule:    Deny all other outbound from app VNet on 443
```

**Network Watcher Flow Logs** are enabled per-NSG:

```bash
az network watcher flow-log create \
  --location eastus \
  --name prod-flowlog \
  --nsg prod-nsg \
  --storage-account flowlogs-storage \
  --enabled true \
  --format JSON \
  --log-version 2 \
  --retention 90
```

---

## Inter-VPC Connectivity: Least Privilege Cross-VPC Access

As infrastructure scales, workloads span multiple VPCs. Three mechanisms exist for cross-VPC connectivity; they have very different security properties.

**VPC Peering** creates a direct network route between two VPCs. Any instance in VPC-A that has a security group allowing traffic to VPC-B's CIDR can reach any instance in VPC-B that accepts it. Peering is bidirectional and does not support transitive routing, but within a peered pair the blast radius is large — a compromise in VPC-A with an overly permissive security group reaches the entire peered VPC-B CIDR.

**Transit Gateway** is a hub for connecting many VPCs. It introduces central routing control but without route table segmentation it creates a full mesh at the network layer. Configure separate Transit Gateway route tables for each security domain and limit which VPCs can see each other's routes.

**PrivateLink** (AWS) / Private Service Connect (GCP) exposes a single service endpoint from the producer VPC to the consumer VPC. The consumer sees only the endpoint, not any other resources in the producer VPC. This is the most secure option for cross-VPC service access: it provides exactly the connectivity needed with no additional network-layer access.

Decision tree:
- Internal service accessed by multiple consumers → PrivateLink/Private Service Connect
- Data pipeline requiring broad access between tightly controlled VPCs → Transit Gateway with per-domain route tables
- Simple two-VPC connectivity where both VPCs are in the same trust domain → peering with strict SG rules

---

## Infrastructure as Code: Static Analysis for Network Misconfiguration

Misconfigured security groups and missing private endpoints are reliably caught by static analysis before they reach production. Run these tools as part of the CI pipeline on every Terraform plan.

**tfsec** detects common patterns:

```bash
tfsec . --format json --out tfsec-results.json

# Key rules to watch for in results:
# aws-ec2-no-public-ip-subnet          - subnets with map_public_ip_on_launch = true
# aws-ec2-no-public-ingress-sgr        - security group rules with 0.0.0.0/0 inbound
# aws-ec2-require-vpc-flow-logs-for-all-vpcs
# aws-ec2-enforce-http-token-imds      - IMDSv2 not required
```

**Checkov** provides broader coverage including Azure and GCP resources:

```bash
checkov -d . --framework terraform --check \
  CKV_AWS_8,CKV_AWS_24,CKV_AWS_25,CKV_AWS_79,CKV_AWS_130 \
  --output json > checkov-results.json

# CKV_AWS_8:   IMDSv2 required on EC2 instances
# CKV_AWS_24:  No unrestricted SSH (0.0.0.0/0 on port 22)
# CKV_AWS_25:  No unrestricted RDP (0.0.0.0/0 on port 3389)
# CKV_AWS_79:  IMDSv2 enforced
# CKV_AWS_130: VPC endpoint for S3 exists
```

Custom Checkov policy for detecting data-tier subnets with internet routes:

```python
# checkov/custom_checks/data_tier_no_internet_route.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DataTierNoInternetRoute(BaseResourceCheck):
    def __init__(self):
        name = "Ensure data tier route tables have no default route"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_route"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        dest = conf.get("destination_cidr_block", [""])[0]
        gateway = conf.get("gateway_id", [""])[0]
        # Flag any default route pointing to an internet gateway
        if dest == "0.0.0.0/0" and "igw-" in str(gateway):
            return CheckResult.FAILED
        return CheckResult.PASSED
```

---

## Hardening Checklist

Work through these controls in order — earlier items reduce the most common attack vectors; later items harden the residual risk.

**VPC Architecture**
- Three-tier subnet design with public/private/data layers
- Data tier route tables have no default route (no internet, no NAT)
- `map_public_ip_on_launch = false` on all non-public subnets
- NAT gateway in each AZ for private tier outbound (no direct internet route)

**Security Groups and NACLs**
- Default SGs deny all inbound and all outbound
- No rules with `0.0.0.0/0` inbound on administrative ports (22, 3389, 5432, etc.)
- Egress rules explicitly enumerate permitted destinations; no catch-all allow-all egress
- Reference SG IDs rather than CIDR ranges for intra-VPC application traffic
- NACLs on data tier subnets explicitly block inbound from the internet CIDR

**IMDSv2**
- `http_tokens = required` on all EC2 instance configurations
- `http_put_response_hop_limit = 1` for instances running containers
- SCP enforcing IMDSv2 at the account/OU level
- Regular audit of instances with IMDSv1 still accessible

**Private Endpoints**
- Gateway endpoints for S3 and DynamoDB on all VPCs with application workloads
- Interface endpoints for Secrets Manager, SSM, ECR, and KMS
- Endpoint policies restricting access to named resources (not wildcard `*`)
- Public network access disabled on S3 buckets and other managed services that have private endpoints

**Flow Logs**
- VPC flow logs enabled on all VPCs, all traffic types
- Logs retained for at least 90 days
- Athena/BigQuery/Log Analytics queries scheduled for high-volume outbound to unexpected destinations
- Alerts on rejected connections above threshold (potential scanning or lateral movement)

**Static Analysis**
- tfsec and Checkov integrated in CI pipeline on all Terraform changes
- Security group and NACL changes require security team review
- Suppression list for accepted findings is reviewed quarterly

---

## Conclusion

Cloud network security failures are almost always configuration failures, not zero-days. Security groups with `0.0.0.0/0` inbound, IMDSv1 endpoints still responding to unauthenticated GET requests, and S3 traffic routed through the public internet are all detectable with static analysis and periodic audits.

The controls described here — subnet segmentation, least-privilege SG rules, IMDSv2 enforcement, private service endpoints, and flow log monitoring — form a complete defence against the most common cloud network attack patterns. None requires novel tooling; all can be expressed in Terraform, enforced in CI, and audited with built-in cloud provider tooling.

The discipline required is not technical; it is organisational. Make insecure defaults impossible to deploy by encoding these patterns in reusable modules, running Checkov on every plan, and using SCPs to prevent account-level bypasses. The security boundary then holds regardless of which engineer writes the next resource block.
