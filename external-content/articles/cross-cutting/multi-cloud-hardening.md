---
title: "Multi-Cloud Hardening: Consistent Security Posture Across Providers"
description: "Running infrastructure across multiple cloud providers means maintaining consistent security controls across fundamentally different systems."
slug: "multi-cloud-hardening"
date: 2026-02-04
lastmod: 2026-02-04
category: "cross-cutting"
tags: ["multi-cloud", "terraform", "iam", "observability", "aws", "gcp", "security-posture"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 95
difficulty: "advanced"
estimated_reading_time: 15
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "Vultr"
    id: 12
    category: "cloud-provider"
premium_pack: "multi-cloud-terraform-module-pack"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/multi-cloud-hardening/index.html"
---

# Multi-Cloud Hardening: Consistent Security Posture Across Providers

## Problem

Running infrastructure across multiple cloud providers means maintaining consistent security controls across fundamentally different systems. AWS security groups, GCP firewall rules, and smaller provider firewalls all accomplish the same goal with different syntax, different defaults, and different failure modes. IAM models diverge significantly: AWS IAM policies, GCP IAM bindings, and provider-specific RBAC systems all express access control differently.

Most multi-cloud deployments end up with inconsistent security postures. The AWS account has fine-grained IAM policies because that is where the team started. The GCP project has overly permissive roles because it was set up quickly for a specific workload. The smaller provider has whatever defaults it shipped with. Nobody has a unified view of security posture across all providers.

The result: your security is only as strong as your weakest provider configuration. An attacker does not need to breach your hardened AWS account when your GCP project has a public storage bucket.

**Target systems:** Infrastructure spanning AWS, GCP, and/or smaller providers (Civo, Vultr, DigitalOcean). [Terraform](https://www.terraform.io) for infrastructure as code. Centralised observability across providers.

## Threat Model

- **Adversary:** Attacker targeting the least-hardened provider in a multi-cloud deployment. Also: automated scanners that discover misconfigured resources across any cloud provider.
- **Objective:** Exploit inconsistent security controls. Find the public bucket, the overly permissive IAM role, or the unpatched VM on the provider that received less attention.
- **Blast radius:** A breach on one provider may provide credentials or network access to resources on other providers (cross-cloud VPN, shared secrets, federated identity). Multi-cloud does not inherently limit blast radius unless provider boundaries are enforced as trust boundaries.

## Configuration

### Unified Firewall Module

Abstract provider-specific firewall syntax behind a common Terraform interface.

```hcl
# modules/firewall/main.tf
# Unified firewall module that works across providers

variable "provider_type" {
  type        = string
  description = "Cloud provider: aws, gcp, civo"
}

variable "rules" {
  type = list(object({
    name      = string
    direction = string  # "ingress" or "egress"
    protocol  = string
    port      = number
    source    = string  # CIDR block
    action    = string  # "allow" or "deny"
  }))
}

# AWS Security Group
resource "aws_security_group" "this" {
  count = var.provider_type == "aws" ? 1 : 0
  name  = "hardened-sg"

  dynamic "ingress" {
    for_each = [for r in var.rules : r if r.direction == "ingress" && r.action == "allow"]
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = [ingress.value.source]
      description = ingress.value.name
    }
  }

  dynamic "egress" {
    for_each = [for r in var.rules : r if r.direction == "egress" && r.action == "allow"]
    content {
      from_port   = egress.value.port
      to_port     = egress.value.port
      protocol    = egress.value.protocol
      cidr_blocks = [egress.value.source]
      description = egress.value.name
    }
  }

  tags = {
    managed-by = "terraform"
    security   = "hardened"
  }
}

# GCP Firewall Rule
resource "google_compute_firewall" "this" {
  for_each = var.provider_type == "gcp" ? {
    for r in var.rules : r.name => r
  } : {}

  name      = each.value.name
  network   = var.network_name
  direction = upper(each.value.direction)

  dynamic "allow" {
    for_each = each.value.action == "allow" ? [1] : []
    content {
      protocol = each.value.protocol
      ports    = [each.value.port]
    }
  }

  dynamic "deny" {
    for_each = each.value.action == "deny" ? [1] : []
    content {
      protocol = each.value.protocol
      ports    = [each.value.port]
    }
  }

  source_ranges = each.value.direction == "ingress" ? [each.value.source] : null
}

# Civo Firewall
resource "civo_firewall" "this" {
  count = var.provider_type == "civo" ? 1 : 0
  name  = "hardened-fw"

  dynamic "ingress_rule" {
    for_each = [for r in var.rules : r if r.direction == "ingress"]
    content {
      label      = ingress_rule.value.name
      protocol   = ingress_rule.value.protocol
      port_range = tostring(ingress_rule.value.port)
      cidr       = [ingress_rule.value.source]
      action     = ingress_rule.value.action
    }
  }
}
```

```hcl
# Usage: consistent rules across all providers
module "firewall_aws" {
  source        = "./modules/firewall"
  provider_type = "aws"
  rules         = local.standard_firewall_rules
}

module "firewall_gcp" {
  source        = "./modules/firewall"
  provider_type = "gcp"
  network_name  = google_compute_network.main.name
  rules         = local.standard_firewall_rules
}

module "firewall_civo" {
  source        = "./modules/firewall"
  provider_type = "civo"
  rules         = local.standard_firewall_rules
}

locals {
  standard_firewall_rules = [
    {
      name      = "allow-https"
      direction = "ingress"
      protocol  = "tcp"
      port      = 443
      source    = "0.0.0.0/0"
      action    = "allow"
    },
    {
      name      = "allow-ssh-vpn-only"
      direction = "ingress"
      protocol  = "tcp"
      port      = 22
      source    = "10.0.0.0/8"  # VPN CIDR only
      action    = "allow"
    },
  ]
}
```

### Unified IAM Role Definitions

Map common role definitions to provider-specific IAM constructs.

```hcl
# modules/iam-role/main.tf
variable "role_name" {
  type = string
}

variable "role_type" {
  type        = string
  description = "Standard role: readonly, deployer, admin"
  validation {
    condition     = contains(["readonly", "deployer", "admin"], var.role_type)
    error_message = "role_type must be: readonly, deployer, or admin"
  }
}

variable "provider_type" {
  type = string
}

# AWS IAM Role
resource "aws_iam_role" "this" {
  count = var.provider_type == "aws" ? 1 : 0
  name  = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Federated = var.oidc_provider_arn
      }
      Condition = {
        StringEquals = {
          "${var.oidc_provider}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account}"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "this" {
  count = var.provider_type == "aws" ? 1 : 0
  name  = "${var.role_name}-policy"
  role  = aws_iam_role.this[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = var.role_type == "readonly" ? [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = var.resource_arns
      }
    ] : var.role_type == "deployer" ? [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = var.resource_arns
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:PutImage"]
        Resource = "*"
      }
    ] : []  # admin handled separately with explicit review
  })
}

# GCP IAM Binding
resource "google_project_iam_member" "this" {
  for_each = var.provider_type == "gcp" ? toset(
    var.role_type == "readonly" ? ["roles/storage.objectViewer"] :
    var.role_type == "deployer" ? ["roles/storage.objectAdmin", "roles/container.developer"] :
    []
  ) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${var.service_account_email}"
}
```

### Cross-Cloud Network Security

```hcl
# cross-cloud-vpn.tf
# Encrypted site-to-site VPN between providers

# AWS side
resource "aws_vpn_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "cross-cloud-vpn" }
}

resource "aws_customer_gateway" "gcp" {
  bgp_asn    = 65000
  ip_address = google_compute_address.vpn_ip.address
  type       = "ipsec.1"
  tags       = { Name = "gcp-gateway" }
}

resource "aws_vpn_connection" "to_gcp" {
  vpn_gateway_id      = aws_vpn_gateway.main.id
  customer_gateway_id = aws_customer_gateway.gcp.id
  type                = "ipsec.1"
  static_routes_only  = true

  tags = { Name = "aws-to-gcp" }
}

# Route only specific CIDRs through the VPN
# Do NOT route all traffic cross-cloud
resource "aws_vpn_connection_route" "gcp_services" {
  vpn_connection_id      = aws_vpn_connection.to_gcp.id
  destination_cidr_block = "10.100.0.0/16"  # GCP service subnet only
}
```

### Centralised Observability

```yaml
# otel-collector-multicloud.yaml
# Single OTel collector config that normalises metrics from all providers
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317

      # AWS CloudWatch metrics
      awscloudwatch:
        region: us-east-1
        metrics:
          named:
            - namespace: AWS/EC2
              metric_name: CPUUtilization
              period: 300
            - namespace: AWS/RDS
              metric_name: DatabaseConnections
              period: 300

      # GCP Monitoring metrics
      googlecloudmonitoring:
        project: my-project
        metrics_list:
          - metric_type: "compute.googleapis.com/instance/cpu/utilization"

    processors:
      # Normalise provider-specific labels to common schema
      attributes:
        actions:
          - key: cloud.provider
            action: upsert
          - key: cloud.region
            action: upsert
          - key: cloud.account_id
            action: upsert

    exporters:
      prometheusremotewrite:
        endpoint: "https://prometheus.grafana.net/api/prom/push"
        headers:
          Authorization: "Bearer ${GRAFANA_CLOUD_TOKEN}"

    service:
      pipelines:
        metrics:
          receivers: [otlp, awscloudwatch, googlecloudmonitoring]
          processors: [attributes]
          exporters: [prometheusremotewrite]
```

### Provider-Specific Security Features

Some provider-specific security features should not be abstracted away. Use them directly.

```hcl
# Use AWS GuardDuty - do not abstract this
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection { scan_ec2_instance_with_findings { ebs_volumes { enable = true } } }
  }
}

# Use GCP Security Command Center - do not abstract this
resource "google_project_service" "scc" {
  service = "securitycenter.googleapis.com"
}

# Forward findings from both to a central alert pipeline
# GuardDuty -> EventBridge -> SNS -> PagerDuty
# SCC -> Pub/Sub -> Cloud Function -> PagerDuty
```

## Expected Behaviour

- Firewall rules are defined once and applied consistently across all providers via Terraform
- IAM roles follow the same permission model (readonly, deployer, admin) regardless of provider
- Cross-cloud VPN traffic is encrypted and routed only to specific service CIDRs
- All metrics and logs from all providers flow to a single observability backend
- Provider-specific security features (GuardDuty, SCC) are enabled and alert to a central pipeline
- A security posture change on one provider triggers the same Terraform module update for all providers

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Unified Terraform modules | Consistent security across providers | Modules must handle provider-specific edge cases; adds abstraction complexity | Keep modules focused on common patterns. Provider-specific features stay outside the abstraction. |
| Single observability backend | Unified security view across all infrastructure | Vendor dependency on observability provider | OTel collector makes the exporter swappable. Switch backends without changing instrumentation. |
| Cross-cloud VPN | Encrypted inter-provider communication | VPN becomes a single point of failure for cross-cloud services | Run redundant VPN tunnels. Design services to degrade gracefully if cross-cloud connectivity fails. |
| Provider-specific features not abstracted | Best-in-class detection per provider (GuardDuty, SCC) | Different alert formats, different severity scales, different response procedures per provider | Normalise alert severity in the central pipeline. Map provider-specific findings to common categories. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Terraform module drift between providers | Security groups on one provider do not match intent | `terraform plan` shows unexpected diff; compliance scan detects inconsistency | Run `terraform apply` to reconcile. Add CI check that runs `terraform plan` on every PR. |
| Cross-cloud VPN tunnel down | Services cannot reach cross-cloud dependencies | VPN health check fails; application timeout errors | Redundant tunnels. If both fail, services should return degraded responses (not crash). |
| Provider IAM mapping incorrect | Role on one provider has more permissions than intended | Periodic IAM audit script compares effective permissions across providers | Fix the Terraform module mapping. Add integration tests that verify IAM role capabilities per provider. |
| Observability backend unreachable | No metrics or logs from any provider | OTel collector health check; no data in dashboards | OTel collector buffers locally. Switch to secondary backend or self-hosted [Prometheus](https://prometheus.io) as fallback. |

## When to Consider a Managed Alternative

[Grafana Cloud](https://grafana.com/cloud) for cloud-agnostic observability that ingests metrics, logs, and traces from any provider through OTel. [Civo](https://www.civo.com) and [Vultr](https://www.vultr.com) as managed [Kubernetes](https://kubernetes.io) alternatives to hyperscalers, offering simpler security models with fewer provider-specific quirks. For teams that find multi-cloud Terraform abstraction too complex, standardising on a single Kubernetes distribution across providers reduces the abstraction surface.

**Premium content pack:** Multi-cloud Terraform module pack. Unified firewall, IAM, and VPN modules for AWS, GCP, and Civo. OTel collector configurations for cross-cloud metric normalisation. Compliance check scripts that compare security posture across providers.


## Related Articles

- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Migrating from Self-Hosted Prometheus to Grafana Cloud: Preserving Dashboards, Alerts, and History](/articles/cross-cutting/migrate-prometheus-grafana-cloud/)
- [Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover](/articles/cross-cutting/security-infra-disaster-recovery/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
- [Migrating from Self-Managed Kubernetes to a Managed Provider Without Losing Your Security Posture](/articles/cross-cutting/migrate-to-managed-k8s/)
