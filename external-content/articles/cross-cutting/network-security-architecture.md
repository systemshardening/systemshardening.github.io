---
title: "Network Security Architecture: Zones, Segmentation, and Defence-in-Depth Design"
description: "A flat network where every host can reach every other host is a lateral movement enabler. Defence-in-depth network design uses zones, segmentation, inspection, and access controls to contain breaches and limit their blast radius. This guide covers zone-based architecture, modern cloud network design, east-west traffic inspection, and mapping controls to threat scenarios."
slug: network-security-architecture
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - network-architecture
  - network-segmentation
  - zero-trust
  - defence-in-depth
  - firewall-design
personas:
  - security-engineer
  - network-engineer
article_number: 618
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/network-security-architecture/
---

# Network Security Architecture: Zones, Segmentation, and Defence-in-Depth Design

## Problem

A flat network where every host can reach every other host is not a network topology — it is a lateral movement runway. An attacker who compromises any single workload on a flat network has implicit access to every database, every management interface, and every internal API. No additional credentials required. The network itself provides the access.

Flat networks are the norm, not the exception. Default VPC configurations route all subnets to each other. Default Kubernetes installations allow every pod to reach every other pod. Default VLAN configurations in many on-premise environments do the same. Security teams layer firewalls at the perimeter and call it done, then discover during incident response that the attacker had moved from a compromised web server to an internal database in under four minutes — because nothing stood in the way.

Defence-in-depth network design rejects this model. It organises systems into security zones with different trust levels, enforces that traffic crossing zone boundaries is inspected and authorised, and applies additional controls within zones for sensitive workloads. When a breach occurs — and it will — the architecture limits what the attacker can reach and buys time to detect and respond.

**Target systems:** Any environment with multiple services, trust levels, or sensitivity classifications. On-premise data centres, cloud VPCs, Kubernetes clusters, hybrid architectures. The controls differ by platform; the design principles do not.

## Threat Model

- **Adversary:** Attacker with a foothold in one zone — most commonly via a compromised internet-facing service, a phishing attack on a workstation, or a supply-chain compromise. Their immediate objective is lateral movement to higher-value targets (databases, credential stores, management interfaces).
- **Technique:** Network scanning to discover adjacent hosts, exploitation of trust relationships between services, abuse of overly permissive security group or firewall rules, credential theft from services running in the same network segment.
- **Blast radius without segmentation:** Unlimited. A compromised web server reaches the database. A compromised database server reaches the management network. A compromised developer workstation reaches everything the developer has ever connected to. One breach becomes a full network compromise.
- **Blast radius with segmentation:** Contained to the zone the attacker entered. East-west movement blocked by firewall rules, network policies, or security groups. Management plane unreachable from the application zone. Database zone unreachable from the DMZ. The attacker must compromise additional controls — and generate additional detectable signals — to move.

## Zone-Based Architecture

A zone-based architecture organises the network into layers with explicit, enforced boundaries between them. Traffic is permitted to cross boundaries only through defined choke points where it can be inspected. Traffic within a zone is not automatically trusted — lateral movement within a zone is still possible — but zone boundaries are where the strongest controls are applied.

### The Five-Zone Model

A practical baseline for most organisations uses five zones:

**Internet zone.** Untrusted. Everything outside your control. No system in any internal zone should initiate outbound connections to the internet directly, and the internet should not have direct access to anything internal. All traffic flows through defined inspection points.

**DMZ (Demilitarised Zone).** Semi-trusted. Internet-facing services that must be reachable by external clients: web application firewalls, load balancers, reverse proxies, API gateways. These systems accept inbound traffic from the internet but are explicitly prohibited from initiating connections to the internal zone. If an attacker compromises a system in the DMZ, they hit a firewall boundary when attempting to reach internal services.

**Internal zone.** Application workloads, business logic services, internal APIs. Reachable from the DMZ for legitimate application traffic (proxied via the DMZ tier), but not directly reachable from the internet. Systems here can call databases in the data zone but cannot initiate connections to the internet directly.

**Data zone.** Databases, object stores, secret management systems, backup infrastructure. The most sensitive zone. Accepts connections only from the internal application zone on specific ports for specific services. No inbound access from the DMZ. No inbound access from the internet. No outbound internet access. If a system in this zone has an internet route, something is wrong.

**Management zone (out-of-band).** Jump hosts, privileged access workstations (PAWs), monitoring infrastructure, configuration management. Used exclusively for administrative access to systems in all other zones. Critically: management traffic and application traffic must never share the same network path. An attacker in the application zone must not be able to reach the management plane.

### Traffic Flow Rules

The key principle: traffic crosses zone boundaries only in one direction (inbound toward sensitive zones), only through inspection points, and only for explicitly permitted flows. Anything not explicitly permitted is denied.

Permitted flows:
- Internet → DMZ: allowed on ports 80/443 only, through WAF/CDN
- DMZ → Internal: allowed on specific application ports, through load balancer or reverse proxy
- Internal → Data: allowed on specific database or secret manager ports, to specific service endpoints only
- Management → All zones: allowed on management ports (SSH, RDP, API management endpoints) only from PAW/bastion hosts

Blocked flows:
- Internet → Internal: blocked at perimeter firewall
- Internet → Data: blocked at perimeter firewall
- DMZ → Data: blocked at firewall between DMZ and data zone
- Internal → Internet: blocked by default; outbound proxy required for approved destinations
- Data → Internal: blocked (data zone systems do not initiate connections outbound)
- Application traffic → Management: blocked (management zone isolated from application zones)

## Why DMZ-Only Design Is Insufficient

The classic DMZ addresses the perimeter problem. It does not address the east-west problem.

When every service inside the DMZ can freely reach every other service in the same DMZ, a compromised web server can attack the CDN origin, the API gateway, the authentication proxy, and any other DMZ resident. Internal zones with no further segmentation exhibit the same problem: a compromised application server can attempt connections to every other application server, every database, and every internal API.

Attackers know this. Post-compromise toolkits immediately scan adjacent subnets. Common targets include:
- Other application servers (for credential theft, configuration files, session data)
- Database ports (3306, 5432, 1433, 27017) on any reachable host
- Internal APIs and microservices that trust network location
- Management interfaces (SSH port 22, RDP port 3389, Kubernetes API port 6443)
- Secret stores and vault instances
- Backup systems (often low-security, high-value)

Segmentation within zones addresses east-west movement. The mechanism differs by platform, but the requirement is the same: workloads in the same zone that do not need to communicate with each other must not be able to.

## Modern Cloud Network Architecture

Cloud providers use different terminology but the same underlying model. In AWS, GCP, or Azure, implement zone-based design as follows.

### VPC and Subnet Layout

Use a VPC per environment (production, staging, development) rather than a single VPC with everything in it. Environment separation at the VPC level means a breach in the development environment cannot laterally move to production — there is no route between them.

Within the production VPC, implement separate subnets per zone:

```
Production VPC (10.0.0.0/16)
├── Public subnets (10.0.0.0/20)     — Load balancers, NAT gateways only
├── Application subnets (10.0.16.0/20) — Application servers, container nodes
├── Data subnets (10.0.32.0/20)      — RDS, ElastiCache, OpenSearch
└── Management subnets (10.0.48.0/20) — Bastion hosts, monitoring
```

The public subnet contains only the load balancer tier. Application servers run in private subnets with no internet-facing IP addresses. Databases run in data subnets that have no route to the internet — not even an outbound route through a NAT gateway.

### Security Group Design (AWS Example)

Security groups enforce east-west controls within and between subnets. The principle is default-deny with specific allows.

```hcl
# Public-facing load balancer: accepts HTTPS from internet only
resource "aws_security_group" "alb" {
  name   = "alb-public"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

# Application tier: accepts traffic only from the load balancer
resource "aws_security_group" "app" {
  name   = "app-internal"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.data.id]
  }
}

# Data tier: accepts traffic only from the application tier
resource "aws_security_group" "data" {
  name   = "data-isolated"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # No egress rules: data tier makes no outbound connections
}
```

Note that security groups reference other security group IDs rather than CIDR blocks. This is critical: CIDR-based rules permit any host in the subnet range, including an attacker who has pivoted to a host in that range. Security group references permit only traffic originating from a network interface that belongs to the referenced group — a meaningful constraint.

### Removing Internet Routes from Sensitive Tiers

Data tier subnets must have no route to the internet. Verify this in your route table configuration. A data subnet with a NAT gateway route can exfiltrate data outbound. It can also download attacker tooling. Remove the route entirely.

```hcl
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id

  # Local VPC traffic only — no internet gateway, no NAT gateway
  tags = { Name = "data-no-internet" }
}

resource "aws_route_table_association" "data" {
  subnet_id      = aws_subnet.data.id
  route_table_id = aws_route_table.data.id
}
```

Use VPC endpoints for AWS service access (S3, Secrets Manager, KMS) from the data tier. VPC endpoints route traffic through the AWS private network without touching the internet, and you can attach endpoint policies to restrict which specific resources each subnet can access.

## East-West Traffic Inspection

Zone boundaries address inter-zone traffic. East-west controls address intra-zone traffic — preventing lateral movement between workloads in the same zone.

### Kubernetes NetworkPolicy

By default, every pod in a Kubernetes cluster can reach every other pod on every port. NetworkPolicy resources restrict this. Default-deny policies must be applied explicitly — they are not the Kubernetes default.

```yaml
# Default deny all ingress and egress in the production namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# Allow the payment service to receive traffic only from the API gateway
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-service-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8080
---
# Allow the payment service to reach only the database, on the database port
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-service-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: data
          podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    # Allow DNS resolution
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
```

NetworkPolicy requires a CNI plugin that supports it. [Calico](https://projectcalico.docs.tigera.io/), [Cilium](https://cilium.io), and [Weave Net](https://github.com/weaveworks/weave) all implement NetworkPolicy. The default `kubenet` plugin does not. Verify your CNI before relying on NetworkPolicy for enforcement.

### Service Mesh mTLS

NetworkPolicy controls which pods can talk to which other pods. It does not authenticate the traffic or prevent a compromised pod from impersonating a legitimate service. Mutual TLS (mTLS) via a service mesh addresses this: every service presents a cryptographic identity, and connections are established only after both sides verify each other's certificates.

[Istio](https://istio.io) in `STRICT` mode rejects any connection without a valid client certificate. An attacker who compromises a pod and attempts to call another service must present a valid SPIFFE identity — which they cannot obtain without compromising the identity issuance system.

```yaml
# Enforce mTLS across the entire mesh
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

NetworkPolicy and mTLS are complementary, not alternatives. NetworkPolicy enforces at the kernel/network layer; mTLS enforces at the application/TLS layer. Both together mean an attacker must break two independent controls to impersonate a service.

### On-Premise Microsegmentation

In on-premise environments without a service mesh, microsegmentation is implemented at the hypervisor or switch level using tools like [VMware NSX](https://www.vmware.com/products/nsx.html), [Illumio](https://www.illumio.com), or host-based firewall policies enforced centrally. The principle is identical: create per-workload or per-application firewall rules rather than per-VLAN rules. Segment at the workload level, not just the network level.

## Internet-Facing Layer Design

The internet-facing layer is where the attack surface is largest and where defence-in-depth is most critical. Layer the controls from the outside in.

**CDN and WAF at the edge.** A Content Delivery Network (CDN) like [Cloudflare](https://www.cloudflare.com) or [AWS CloudFront](https://aws.amazon.com/cloudfront/) sits between the internet and your origin. It absorbs DDoS volumetric attacks before they reach your infrastructure. Attach a Web Application Firewall (WAF) at this layer to inspect HTTP traffic for OWASP Top 10 patterns (SQLi, XSS, path traversal, RCE payloads) before requests reach your application. The WAF is not the only control — it has false negative rates — but it blocks automated scanning and common exploitation patterns.

**Load balancer in the public subnet.** The load balancer terminates TLS and forwards decrypted traffic to application instances in the private subnet. It has a public IP address; the application servers behind it do not. Compromise the load balancer configuration and you gain the ability to redirect traffic — serious, but not an immediate database breach because the load balancer cannot reach the database directly.

**Application servers in the private subnet.** No public IP addresses. No internet routes. Outbound internet access (for package updates, external APIs) goes through an egress proxy or NAT gateway with outbound allow-lists. Inbound application traffic comes only from the load balancer security group.

**Databases in the data subnet with no internet route.** As described above. No public endpoint. No internet route. Only the application tier can connect, on the database port, with credentials retrieved at runtime from a secrets manager.

The data flow diagram for this architecture:

```
Internet → [CDN/WAF] → [ALB: public subnet] → [App: private subnet] → [DB: data subnet]
                                                       ↑
                                            [Secrets Manager via VPC endpoint]
```

Every arrow is an explicit security group rule or VPC endpoint policy. Nothing in this diagram can be reversed by an attacker without compromising additional controls at each boundary.

## Management Plane Isolation

The management plane is how administrators access systems to configure, patch, and debug them. If the management plane shares a network path with application traffic, an attacker in the application zone can attempt to reach management interfaces directly.

### Dedicated Management Network

Management traffic — SSH, RDP, API server access, monitoring, configuration management — must traverse a separate network segment that is unreachable from the application and DMZ zones. In cloud environments, this is a dedicated management VPC or subnet with no route from the application VPC. In on-premise environments, this is a dedicated management VLAN with ACLs preventing application VLANs from routing to it.

### Bastion Hosts and Privileged Access Workstations

No one connects directly from their workstation to production systems. All administrative access flows through a bastion host (jump server) in the management subnet. The bastion host is the only point where external administrative access is permitted.

```
Analyst workstation → [VPN/Identity-Aware Proxy] → [Bastion: management subnet] → [Production systems]
```

The bastion host should:
- Run no application workloads (single purpose only)
- Enforce multi-factor authentication
- Log all sessions (SSH audit logs, session recording)
- Have no persistent credentials — administrators authenticate with short-lived certificates from an SSH Certificate Authority or a PAM system
- Be patched aggressively (it is a high-value target)

For cloud environments, consider [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or [GCP Identity-Aware Proxy](https://cloud.google.com/iap) as alternatives to a traditional bastion host. These route administrative sessions over the cloud provider's control plane, with IAM-based access control, without requiring inbound SSH port 22 to be open anywhere.

### Out-of-Band Access for Infrastructure

When the production network is down — the scenario where you most need management access — in-band management fails. Out-of-band (OOB) access via IPMI/BMC for physical servers, or via cloud provider serial console for virtual machines, allows access to infrastructure regardless of operating system or network state. OOB interfaces must be on the management network and never exposed to the internet or application networks.

## Detecting and Blocking Lateral Movement

Architecture limits blast radius. Detection identifies when an attacker is testing those limits.

### Network-Level Indicators

At the network level, lateral movement generates:
- Port scan traffic: sequential connection attempts across a subnet range
- Unusual protocol usage: SMB, NetBIOS, WMI, LDAP queries from systems that should not be making them
- Connection attempts to blocked ports (firewall deny logs)
- Outbound connections from the data zone (it should have none)

Configure your firewall and security group logs to capture denied connection attempts. A single denied connection from a database server to an external IP is anomalous and warrants investigation. A sweep of denied connection attempts from one host to many others is almost certainly reconnaissance or lateral movement tooling.

### Kubernetes-Level Indicators

In Kubernetes environments, NetworkPolicy violations are dropped silently by default. To detect them, use [Cilium](https://cilium.io) with Hubble observability, which provides a flow log of allowed and dropped connections:

```bash
# View dropped flows in the production namespace
hubble observe --namespace production --verdict DROPPED

# Alert on unexpected cross-namespace flows
hubble observe --from-namespace production --to-namespace data --verdict DROPPED
```

Alternatively, instrument your CNI with [Falco](https://falco.org) rules that fire on unexpected outbound connections from application pods.

### Cloud-Level Indicators

In cloud environments, VPC Flow Logs (AWS), VPC Flow Logs (GCP), or NSG Flow Logs (Azure) record every accepted and rejected connection. Ship these to your SIEM and alert on:
- Rejected connections from the data subnet to any destination (data zone should make no outbound connections)
- Connections from the application subnet to management subnet (application should not reach management)
- Port scans: one source IP making connections to many destination ports on many destination IPs

```
# Example AWS CloudWatch Logs Insights query for lateral movement indicators
fields @timestamp, srcAddr, dstAddr, dstPort, action
| filter action = "REJECT"
| filter srcAddr like /10\.0\.32\./ # Data subnet
| stats count(*) as rejected_connections by srcAddr, dstAddr
| sort rejected_connections desc
```

## Zero Trust as Network Architecture Evolution

Zone-based architecture organises the network into trust levels and uses boundaries to enforce them. Zero trust extends this to remove implicit trust from the network location entirely — even within a zone.

The architectural shift is from perimeter-based to identity-based trust:

| Perimeter model | Zero trust model |
|----------------|------------------|
| Inside the zone = trusted | Identity + attestation required on every request |
| IP address as identity | Cryptographic certificate (SPIFFE/X.509) as identity |
| Zone firewall rules | Per-service authorisation policies |
| East-west uninspected | mTLS + authorisation policy on all service-to-service traffic |
| VPN for admin access | Identity-aware proxy + short-lived credentials |

Zero trust does not replace zone-based architecture. It builds on it. Zones still organise the network and provide an outer containment layer. Zero trust adds per-request identity verification within and across those zones. The combination is more robust than either alone: an attacker who compromises a pod in the application zone still cannot reach the database because (a) the security group blocks the connection and (b) even if they somehow reach the database subnet, the database proxy requires a valid mTLS certificate with the correct SPIFFE identity.

## Architecture Documentation as a Security Artefact

A network architecture diagram is not a decoration. It is a security artefact that should be maintained, versioned, and used for threat modelling.

### What to Document

A complete network diagram should show:
- All zones and their trust levels
- All inter-zone boundaries and the controls enforced at each boundary (firewall, WAF, load balancer)
- All permitted traffic flows with source, destination, port, and protocol
- All management access paths
- All external dependencies and the network path to reach them

### Data Flow Diagrams for Threat Modelling

A data flow diagram (DFD) shows where data originates, where it flows, where it is stored, and what trust boundaries it crosses. Trust boundaries in a DFD correspond directly to zone boundaries in the network architecture.

For each trust boundary a data flow crosses, ask:
- Is this traffic authenticated?
- Is this traffic encrypted?
- Is there a firewall or inspection point at this boundary?
- What happens if the system on the other side of this boundary is compromised?
- Can an attacker manipulate what crosses this boundary (injection, replay, MITM)?

Answering these questions systematically for every boundary in your DFD produces a prioritised list of controls to verify or implement. It also makes it immediately clear when a proposed architectural change introduces a new boundary crossing that lacks controls.

Maintain your network diagrams and DFDs in version control alongside your infrastructure-as-code. When the architecture changes — a new service is added, a subnet is reorganised, a new external API is integrated — update the diagram in the same pull request. The diagram should be a trusted record of the current state, not an aspirational document of what the network used to look like.

## Common Architectural Mistakes

**Shared management and application networks.** Often done to "save complexity." Results in an attacker in the application zone having a network path to SSH and management APIs.

**Security group rules using CIDR blocks instead of security group references.** Permits any host in the subnet, not just hosts running the intended service. When a subnet is compromised, CIDR-based rules permit the attacker to make the same connections the legitimate service does.

**Internet routes on data subnets.** Sometimes added to enable automated backups or software updates without thinking through the implications. Auditable via AWS Config rule `no-unrestricted-route-to-igw` or equivalent.

**No default-deny NetworkPolicy in Kubernetes.** Default Kubernetes networking is open. NetworkPolicy resources must be applied explicitly. A namespace with no NetworkPolicy has no east-west controls at all.

**Monolithic VPCs with no subnet-level controls.** A single VPC with all instances in one or two subnets, relying entirely on instance-level security groups. Works until someone misconfigures a security group or an attacker exploits a host-based vulnerability and can reach the unprotected internal network.

**Management access over the application network.** Administrators SSHing directly to production instances over the same network that carries application traffic. The management path should never share infrastructure with the application path.

## Related Articles

- [Zero Trust Networking: Identity-Based Access Beyond Perimeter Security](/articles/cross-cutting/zero-trust-networking/)
- [Network Segmentation Patterns: Zones, VLANs, and Microsegmentation](/articles/network/network-segmentation-patterns/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [mTLS for Service-to-Service Communication: Istio, Linkerd, and DIY with cert-manager](/articles/network/mtls-service-mesh/)
- [Threat Modelling at Scale: Automating Data Flow Diagrams and Control Mapping](/articles/cross-cutting/threat-modeling-at-scale/)
- [Production Access Management: Privileged Access, Just-in-Time, and Session Recording](/articles/cross-cutting/production-access-management/)
