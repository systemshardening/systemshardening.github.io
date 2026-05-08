---
title: "Production Access Management with Teleport and Boundary: Brokered, Recorded, Auditable Access"
description: "Static SSH keys + bastion hosts is the 1990s model. Teleport / Boundary broker access dynamically, record sessions, and integrate with identity. The 2026 default."
slug: "production-access-management"
date: 2026-04-29
lastmod: 2026-04-29
category: "cross-cutting"
tags: ["teleport", "boundary", "production-access", "session-recording", "zero-trust"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 219
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cross-cutting/production-access-management/index.html"
---

# Production Access Management with Teleport and Boundary: Brokered, Recorded, Auditable Access

## Problem

Operator access to production hosts has long been a structural weakness:

- **Static SSH keys** distributed by config management; key rotation rarely happens; departed engineers' keys often persist.
- **Bastion hosts** with shared accounts; "who logged in" requires correlating multiple logs.
- **VPN + direct SSH** model gives broad network access on top of host access.
- **Database access** via shared passwords in 1Password / Vault that everyone copies into their `.psqlrc`.
- **Kubernetes access** via long-lived kubeconfigs distributed manually.

The pattern: operators need access; access becomes static; access drifts; access leaks. Each compromise of an operator's laptop / credentials grants the attacker the same broad, persistent reach.

By 2026, brokered access management is the default. Teleport (gravitational) and HashiCorp Boundary are the two leading open-source options; commercial offerings like StrongDM, Tailscale SSH, and Cloudflare Access provide similar capabilities.

The architecture: a centralized broker sits between operators and production. Operators authenticate to the broker via SSO (OIDC); the broker issues a short-lived certificate or session; the operator uses it to access production. The broker records the session, enforces RBAC, and revokes access at the end of the certificate's lifetime.

The properties that matter:

- **Just-in-time access** with short TTLs (default 1-8 hours).
- **Session recording** for SSH, kubectl exec, database queries.
- **Identity-bound** to the SSO user, not a shared account.
- **RBAC** at the broker, not per-host.
- **Audit** centralized and structured.
- **No-VPN** model — broker handles network access.

The specific gaps in pre-broker setups:

- Operator SSH keys persist after employees leave.
- Database access uses shared credentials; no per-user audit.
- Kubernetes context switching is manual; everyone has every cluster's kubeconfig.
- "Quick fix" production access becomes permanent.
- Compliance audits manually correlate "who did what" across many sources.

This article covers Teleport's architecture, RBAC and approval workflow, session recording for SSH / k8s / databases, the migration from static SSH, and the operational integration with on-call / break-glass scenarios.

**Target systems:** Teleport 16+, HashiCorp Boundary 0.18+, StrongDM (commercial), Cloudflare Access; integrates with Okta, Azure AD, Google Workspace, GitHub for SSO.

## Threat Model

- **Adversary 1 — Stolen operator credential:** an attacker has the operator's laptop, SSH keys, or VPN cert. Wants to reach production.
- **Adversary 2 — Departed employee:** still has access via legacy SSH keys not yet rotated.
- **Adversary 3 — Insider abuse:** legitimate operator using their access for unauthorized actions, expecting no accountability.
- **Adversary 4 — Lateral movement:** attacker with one host's access tries to reach others on the production network.
- **Adversary 5 — Credential exfil from operator endpoint:** malware on operator laptop reads SSH keys, browser cookies, Vault tokens.
- **Access level:** Adversary 1 has operator endpoint compromise. Adversary 2 has historical credentials. Adversary 3 has legitimate access. Adversary 4 has one host. Adversary 5 has malware on endpoint.
- **Objective:** Read or modify production data; pivot through production; act without leaving traceable footprint.
- **Blast radius:** With static SSH: a stolen key reaches every host the user had access to, indefinitely. With brokered access: stolen credentials grant only what's currently active (often nothing — sessions are short-lived); the broker enforces fresh authentication for each access.

## Configuration

### Step 1: Teleport Architecture

Teleport has three roles:

- **Auth Service:** issues certificates; manages roles and users; integrates with SSO.
- **Proxy Service:** the public-facing entry point; handles user-facing connections.
- **Agents:** installed on each managed resource (server, k8s cluster, database). Connect outbound to the Proxy.

Operators connect to the Proxy via `tsh` (CLI) or a web UI; the Proxy routes to the Agent on the requested resource.

```bash
# Install Teleport on the auth + proxy server.
curl -fsSL https://get.gravitational.com/teleport.repo | sudo bash
sudo apt install teleport
```

```yaml
# /etc/teleport.yaml on the central server.
version: v3
teleport:
  nodename: teleport-prod
  data_dir: /var/lib/teleport
  log:
    output: stdout
auth_service:
  enabled: yes
  cluster_name: prod.internal.example.com
  authentication:
    type: oidc
    oidc:
      issuer_url: https://login.example.com/
      client_id: teleport-prod
      client_secret_file: /etc/teleport/oidc-client-secret
      redirect_url: https://teleport.example.com/v1/webapi/oidc/callback
      claims_to_roles:
        - claim: groups
          value: sre-team
          roles: [sre]
        - claim: groups
          value: payments-team
          roles: [payments-developer]
proxy_service:
  enabled: yes
  public_addr: teleport.example.com:443
  https_keypairs:
    - cert_file: /etc/teleport/tls.crt
      key_file: /etc/teleport/tls.key
```

Connect to SSO; user authenticates via existing identity provider; Teleport issues a certificate scoped to the user's roles.

### Step 2: Role Definitions

```yaml
# roles/sre.yaml
kind: role
version: v7
metadata:
  name: sre
spec:
  options:
    max_session_ttl: 8h
    forward_agent: false
    require_session_mfa: true   # MFA on every session; replays don't help
  allow:
    logins: [ec2-user, ubuntu]
    node_labels:
      'env': ['production', 'staging']
    kubernetes_labels:
      'cluster': ['*']
    db_labels:
      'env': ['production']
    db_users: ['readonly', 'breakglass']
    db_names: ['*']
    rules:
      - resources: [session]
        verbs: [list, read]
  deny:
    logins: [root]
    node_labels:
      'tag': ['hardened-prod']   # certain tagged hosts are off-limits even to SRE
```

The role is a least-privilege shape: SREs can SSH as `ec2-user` to production hosts, exec into any K8s namespace, query databases as `readonly` or `breakglass` user. They cannot become `root` directly; cannot reach hardened-prod-tagged hosts.

### Step 3: Session Recording

Every session is recorded by default. SSH sessions to disk as keystroke replay; kubectl exec sessions as command + output; database queries as audit log.

```yaml
auth_service:
  session_recording: node-sync     # record at the node
  proxy_listener_mode: multiplex
```

Recording modes:

- `node-sync` — recording to the node's local disk, synced to S3 / GCS in real time. Tamper-resistant: the operator on the node can't easily delete the recording.
- `proxy` — recording at the Proxy. Less reliable if the connection terminates abnormally.
- `off` — explicitly disabled; not recommended for production.

Replays:

```bash
tsh ssh sessions ls
# 2026-04-29 10:00  alice@teleport-prod  node prod-web-01  duration 12m
# 2026-04-29 11:30  bob@teleport-prod    node prod-db-01   duration 5m

tsh play <session-id>
# Replays the session at original speed in the terminal.
```

For database access, queries are logged in structured JSON:

```bash
tsh db logs query <session-id>
# {"timestamp": "2026-04-29T10:01:23Z", "user": "alice", "query": "SELECT * FROM orders WHERE customer_id = 5"}
```

### Step 4: Access Requests / JIT

For elevated permissions beyond a user's standing role, use access requests:

```yaml
# roles/sre.yaml — extends the role.
spec:
  allow:
    request:
      roles: [prod-write, prod-admin]
      thresholds:
        - approve: 1
          deny: 1
      annotations:
        purpose: ['*']
```

```bash
# Operator requests elevated access.
tsh request create --roles=prod-write --reason="Investigating SEV2 incident #1234, fixing payment-api memory leak"

# Approver receives notification (Slack, email).
tsh request review --approve <request-id> --reason="Approved per incident-1234"

# Operator now has prod-write role for the request's TTL.
tsh login --request-id=<id>
```

Standing access stays minimal; elevation is recorded with explicit business reason.

### Step 5: Database Access

Database connections route through Teleport, with per-query logging.

```yaml
db_service:
  enabled: yes
  resources:
    - labels:
        env: production
  databases:
    - name: payments-db
      protocol: postgres
      uri: payments-db.internal:5432
      ad: {}
```

Operator connects via `tsh`:

```bash
tsh db login payments-db --db-user=readonly --db-name=payments
tsh db connect payments-db
# psql session opens; queries logged via Teleport's audit pipeline.
```

The actual database password isn't shared; Teleport authenticates to the database on the operator's behalf using a service account (or a Vault-issued dynamic credential, depending on configuration).

### Step 6: Kubernetes Access

Teleport can serve as the Kubernetes API entrypoint:

```yaml
kubernetes_service:
  enabled: yes
  kube_cluster_name: prod-east
  resources:
    - labels:
        env: production
```

Operators get a kubeconfig automatically:

```bash
tsh kube login prod-east
kubectl get pods   # routed through Teleport
```

The kubeconfig is short-lived; refreshes via `tsh login`. Compromised laptop = access expires within the session TTL.

Kubernetes RBAC is layered with Teleport's role:

```yaml
kind: role
version: v7
metadata:
  name: payments-developer
spec:
  allow:
    kubernetes_labels:
      env: ['production']
    kubernetes_groups: ['payments-developer']
    kubernetes_users: ['payments-developer']
    kubernetes_resources:
      - kind: pod
        namespace: payments
        verbs: ['get', 'list', 'exec']
      - kind: deployment
        namespace: payments
        verbs: ['get', 'list', 'patch']
```

Per-resource access at the K8s layer; Teleport issues a kubeconfig with the appropriate restrictions.

### Step 7: Boundary as an Alternative

Boundary's model is similar but with a different decomposition:

```hcl
# Boundary controller config.
controller {
  name = "controller-prod"
  description = "Production controller"

  database {
    url = "postgresql://boundary@db.internal:5432/boundary"
  }
}

listener "tcp" {
  address = "0.0.0.0:9200"
  purpose = "api"
  tls_disable = false
  tls_cert_file = "/etc/boundary/tls.crt"
  tls_key_file = "/etc/boundary/tls.key"
}
```

```bash
# Define a target.
boundary targets create tcp -name "payments-db" \
  -default-port 5432 \
  -session-connection-limit 10 \
  -session-max-seconds 14400 \
  -host-source ${HOST_SET_ID}

# Operator connects.
boundary connect postgres -target-id <target-id>
# Boundary establishes a tunnel to payments-db; operator's psql connects to localhost.
```

Boundary is lighter on session recording but excellent on TCP-level brokering. Often paired with Vault for dynamic database credentials.

### Step 8: Integration With On-Call

For emergency access during incidents:

```yaml
# roles/oncall-emergency.yaml
kind: role
metadata:
  name: oncall-emergency
spec:
  options:
    max_session_ttl: 4h
    require_session_mfa: true
  allow:
    request:
      roles: [prod-admin]
      thresholds:
        - approve: 1                     # only need 1 approver for emergencies
          deny: 1
      annotations:
        incident: ['SEV1', 'SEV2']       # require an incident reason
        pagerduty_active_incident: ['true']
```

A custom plugin verifies the user is currently on-call (PagerDuty integration); approves automatically if so. Audit log captures every emergency elevation with the linked incident.

### Step 9: Telemetry

```
teleport_sessions_started_total{cluster, type}
teleport_sessions_recorded_total{cluster}
teleport_access_requests_total{role, result}
teleport_session_duration_seconds
teleport_failed_auth_total{user, reason}
teleport_audit_events_total{type}
```

Alert on:
- `failed_auth_total` rising for a specific user — possible compromised credential or stale config.
- `access_requests_total{result="denied"}` rising — possible attempted privilege escalation.
- Sessions exceeding expected duration — possible long-running unauthorized activity.

## Expected Behaviour

| Signal | Static SSH + bastions | Teleport / Boundary |
|--------|------------------------|----------------------|
| Departed employee SSH access | Until rotation | Expires at TTL (8h) automatically |
| Per-user audit | Manual log correlation | Centralized; structured by user/session |
| Session replay | Manual / impossible | Built-in; standard kubectl/SSH/DB |
| Per-resource access control | Per-host config | Centralized RBAC |
| Database query audit | Database-side audit (often disabled) | Per-query log with user attribution |
| Kubernetes access | Kubeconfig per cluster, distributed manually | Routed through broker; identity-bound |
| Compromise of one machine | Broad reach | Bounded to that one TTL window |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Centralized broker | Single audit pane | Single point of failure | Run in HA; for short outages, break-glass procedure documented. |
| Session recording | Forensic clarity | Storage cost; privacy implications | Encrypted at rest; short retention for routine sessions, longer for elevated. |
| Identity-bound certificates | No shared credentials | SSO outage = no access | Plan break-glass for SSO unavailability. |
| Just-in-time elevation | Minimal standing access | Friction during incidents | Auto-approve for on-call during active SEV1; manual approval otherwise. |
| Database brokerage | Per-query audit | Latency overhead | Negligible for interactive queries; matters less for query-heavy applications. |
| Migration from static | Long-term security improvement | Engineering effort | Phased rollout; per-team migration; coexist briefly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Teleport / Boundary controller down | All operator access blocked | Service health check fails | HA deploy; for outage longer than break-glass window, use the documented emergency procedure. |
| SSO outage | All authentication blocked | Auth provider error | Local fallback users with high audit; avoid using unless emergency. |
| Stale role assignments | Departed user retains access | Periodic SSO sync drift | Continuous sync with SSO; alert on stale role assignments. |
| Session recording storage full | Sessions stop recording | `teleport_sessions_recorded_total` rate stalls | Alert on storage utilization; migrate to S3 / GCS at >70% local capacity. |
| Approval flow misuse | Auto-approval for non-emergency | Audit shows elevations without active incidents | Tighten auto-approval criteria; require manual approval for non-incident elevations. |
| Privilege drift | Role accumulates over time | Periodic role audit | Review roles quarterly; remove unused permissions. |
| Latency-sensitive workload broken | DB queries slow due to broker | App-level latency monitors | Some workloads (high-throughput batch) bypass broker; document the exemption with compensating controls. |

## When to Consider a Managed Alternative

Self-hosted Teleport / Boundary requires HA infrastructure, session-recording storage, integration with SSO, and ongoing operational care (8-15 hours/month for a multi-environment fleet).

- **Teleport Cloud:** managed Teleport; SSO integration; session storage included.
- **StrongDM:** commercial broker; multi-protocol, audit pipeline integrated.
- **Cloudflare Access:** identity-bound zero-trust gateway; integrates with existing IdP.

For organizations with strict regulatory constraints prohibiting third-party brokers, self-hosted Teleport with on-prem session recording is the right choice.

## Related Articles

- [SPIFFE / SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [Zero-Trust Networking for Production](/articles/cross-cutting/zero-trust-networking/)
- [WireGuard Mesh for Internal Zero-Trust Networking](/articles/network/wireguard-mesh/)
- [Just-in-Time CI Access](/articles/cicd/jit-ci-access/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
