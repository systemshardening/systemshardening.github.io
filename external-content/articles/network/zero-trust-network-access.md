---
title: "Zero Trust Network Access: Replacing VPN with Identity-Aware Proxies"
description: "VPNs grant network-level trust the moment a credential is accepted. ZTNA grants per-application access based on verified identity, device posture, and context — then terminates the session. Here is how to build it."
slug: zero-trust-network-access
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - zero-trust
  - ztna
  - identity-aware-proxy
  - beyondcorp
  - network-access-control
personas:
  - security-engineer
  - platform-engineer
article_number: 491
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/zero-trust-network-access/
---

# Zero Trust Network Access: Replacing VPN with Identity-Aware Proxies

## The Problem

A VPN concentrator, once connected, makes the client a member of an internal IP subnet. The access decision is binary and happens exactly once: a user proves their credentials at tunnel establishment, and the tunnel remains trusted for hours or days. From that point forward, the user can reach anything the subnet routing policy allows — usually far more than they need.

This is the implicit-trust problem. The network perimeter model assumes that everything inside the network is safe and everything outside is hostile. In practice:

- **Lateral movement is trivially easy after VPN compromise.** A phished VPN credential or a malware-infected device connected to VPN now has direct Layer-3 access to every internal service, database, and admin interface that isn't separately firewalled. The 2020 SolarWinds intrusion spread precisely because internal network access, once obtained, was treated as implicitly trusted.
- **VPN credentials are high-value targets.** Unlike web-application credentials, a stolen VPN username/password (or certificate) hands the adversary a route into the network. Pulse Secure, Fortinet, Citrix, and GlobalProtect have each had critical pre-auth or post-auth RCEs in the last four years. These aren't implementation bugs — they are the consequence of a single gateway that, if compromised, voids the perimeter entirely.
- **No per-application access control.** VPNs operate at Layer 3. They have no visibility into which application a user is accessing, what device they are using, whether that device is compliant, or what time of day it is. A contractor with VPN access is functionally equivalent to a senior engineer with the same VPN profile.
- **Split-tunnel and full-tunnel both have problems.** Full tunnel routes all traffic through the corporate network (expensive, high-latency, breaks consumer cloud services). Split tunnel exposes internal resources to whatever else is running on the remote device.
- **Remote workers are the majority.** The assumption that employees are in an office and the VPN is an exception has inverted. Designing around a model where 80 percent of your workforce is "untrusted" is not sustainable.

The specific gaps in a VPN-centric network:

- One set of credentials grants access to hundreds of internal services with no individual authorization check.
- Device posture (patch level, EDR status, disk encryption) is unknown at access time and never re-evaluated mid-session.
- North-south access is controlled at the perimeter; east-west access between internal services is uncontrolled.
- Audit logs record "user connected VPN" not "user accessed payroll database at 2:47 AM."
- Legacy on-prem applications cannot be individually exposed to an identity-aware model without a proxy layer.

**Target systems:** Any organization moving from VPN-only remote access to application-level access control. Reference implementations covered: Pomerium 0.28+ (open source identity-aware proxy), Tailscale 1.78+ with ACLs as a ZTNA control plane, Cloudflare Access (managed), Google BeyondCorp Enterprise (managed), along with standard OIDC/SAML identity providers (Okta, Entra ID, Google Workspace).

## Threat Model

- **Adversary 1 — Stolen VPN credential:** an attacker has obtained valid VPN credentials via phishing, credential stuffing, or an infostealerlog. Wants unrestricted internal network access.
- **Adversary 2 — Compromised internal device:** an attacker controls a machine already inside the network (via malware, rogue insider, supply-chain compromise). Wants to reach services outside their intended scope.
- **Adversary 3 — Compromised identity provider session:** an attacker has a valid IdP session token (cookie theft, session hijacking). Wants to access specific high-value applications.
- **Adversary 4 — Unmanaged / bring-your-own device access:** a contractor or third party accesses internal applications from a device with no EDR, no MDM enrollment, outdated OS. The device is a foothold for further compromise.
- **Access level:** Adversaries 1 and 2 have network-layer access. Adversary 3 has application-layer identity. Adversary 4 has legitimate but uncontrolled access.
- **Objective:** Reach internal applications (source code, internal APIs, databases, admin panels, developer tooling) and exfiltrate data or pivot to higher-value targets.
- **Blast radius:** In a VPN-only model, a single compromised credential can reach the entire internal RFC-1918 space. In a ZTNA model, a compromised session token grants access only to applications the policy explicitly permits, only from devices that pass posture checks, and only during the session lifetime — not a persistent tunnel.

## The BeyondCorp Model

Google published the BeyondCorp architecture in a series of research papers starting in 2014. The core insight: move access control from the network perimeter to the application layer, and base decisions on verified device identity plus user identity rather than network location.

The four components of the original BeyondCorp design:

1. **Device inventory service** — a continuously synchronized database of every device that is allowed to access corporate applications, each with a certificate issued by a corporate CA. Devices not in inventory cannot authenticate.
2. **Access proxy** — all application traffic is routed through a proxy that terminates the connection, evaluates the request against policy, and forwards only if the policy is satisfied. The application never receives a request that hasn't passed the proxy.
3. **Single sign-on** — user identity is established via a centralized IdP (originally Google internal SSO, now OIDC/SAML in commercial implementations). The proxy validates the SSO token on every request.
4. **Per-application access policies** — rather than "employee can reach the internal network," policies are "user in group `eng-backend`, on a managed device, from a low-risk country, can reach `api-internal.corp:8443`."

The critical property: the internal network itself is treated as untrusted. BeyondCorp engineers operate from the same coffee shop they used to need a VPN for — the proxy, not the network location, is the enforcement point.

## Identity-Aware Proxy Pattern

An identity-aware proxy (IAP) sits in front of an application and handles authentication and authorization before proxying the request upstream. The application sees only requests that have already been validated.

```
User → [IAP: verify OIDC token + device cert + policy] → Internal App
```

The IAP typically:
1. Redirects unauthenticated requests to the IdP login flow (OIDC authorization code flow).
2. Validates the returned token (signature, expiry, claims).
3. Evaluates the device certificate (is this device in inventory? is the cert valid and not revoked?).
4. Checks contextual signals: IP risk score, time of day, MFA recency.
5. Forwards the request with identity headers (`X-Forwarded-User`, `X-Forwarded-Groups`) if all checks pass, or returns 403 if any fail.

Commercial implementations:
- **Cloudflare Access** — managed IAP in Cloudflare's global network. Zero-config tunnel (cloudflared) from your origin to Cloudflare; all access policies defined in the dashboard or via Terraform. OIDC, SAML, device posture via WARP client.
- **Google BeyondCorp Enterprise** — Google's commercial product; IAP for GCP-hosted applications plus on-prem via BeyondCorp connectors. Deep integration with Workspace identity and Chrome device management.
- **Pomerium** — open source, self-hosted. OIDC/SAML support, per-route policy as YAML/Rego, device identity via mTLS client certificates, no SaaS dependency.

## Self-Hosted ZTNA with Pomerium

Pomerium is the open-source option for organizations that cannot route traffic through a third-party managed service. It runs as a single binary or as a set of Kubernetes deployments.

### Install and Bootstrap

```bash
# Install on Debian/Ubuntu
curl -fsSL https://pkg.pomerium.com/apt/gpg.key | sudo apt-key add -
echo "deb https://pkg.pomerium.com/apt/stable focal main" | \
  sudo tee /etc/apt/sources.list.d/pomerium.list
sudo apt-get update && sudo apt-get install -y pomerium

# Generate a shared secret (used between Pomerium services)
openssl rand -hex 32
```

### Policy Configuration

Pomerium's core is its `policy.yaml`. Each route defines the upstream service, the authentication provider, and the authorization rule.

```yaml
# /etc/pomerium/config.yaml
authenticate_service_url: https://auth.corp.example.com

# OIDC provider — Okta example
idp_provider: oidc
idp_provider_url: https://corp.okta.com/oauth2/default
idp_client_id: "0oa1b2c3d4e5f6g7h8i9"
idp_client_secret: "env:IDP_CLIENT_SECRET"

# Cookie settings
cookie_secret: "env:COOKIE_SECRET"
cookie_domain: .corp.example.com
cookie_secure: true
cookie_http_only: true

# Device identity: require a client certificate signed by the internal CA
downstream_mtls:
  ca: /etc/pomerium/internal-ca.crt
  enforcement: policy  # policy can require cert; not all routes need it

routes:
  # Internal Grafana — requires engineering group membership
  - from: https://grafana.corp.example.com
    to: http://grafana.monitoring.svc.cluster.local:3000
    policy:
      - allow:
          and:
            - claim/groups: "engineering"
            - device:
                is_managed: true

  # Kubernetes dashboard — requires sre group + MFA within 15 minutes
  - from: https://k8s-dashboard.corp.example.com
    to: http://kubernetes-dashboard.kube-system.svc.cluster.local:443
    tls_skip_verify: false
    policy:
      - allow:
          and:
            - claim/groups: "sre"
            - claim/acr: "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
            - device:
                is_managed: true

  # Internal API — service account bypass with specific client cert CN
  - from: https://internal-api.corp.example.com
    to: http://api-service.backend.svc.cluster.local:8080
    policy:
      - allow:
          or:
            - claim/groups: "backend-engineers"
            - client_certificate:
                spki_hash: "sha256/AAAAAA..."  # pinned service account cert

  # Legacy app — no OIDC, use HTTP basic + Pomerium as auth layer
  - from: https://legacy.corp.example.com
    to: http://legacy-app.internal:8080
    allow_public_unauthenticated_access: false
    policy:
      - allow:
          and:
            - claim/email: { ends_with: "@corp.example.com" }
    # Inject identity headers so the app can log the user
    set_request_headers:
      X-Pomerium-Claim-Email: "{user_email}"
      X-Pomerium-Claim-Groups: "{user_groups}"
```

The `device.is_managed: true` check requires either an MDM-enrolled device certificate or a WARP-equivalent device posture attestation. This is what closes the "valid IdP session, unmanaged device" gap.

### Kubernetes Deployment

```yaml
# pomerium-config secret
apiVersion: v1
kind: Secret
metadata:
  name: pomerium-config
  namespace: pomerium
type: Opaque
stringData:
  IDP_CLIENT_SECRET: "..."
  COOKIE_SECRET: "..."
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pomerium-proxy
  namespace: pomerium
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pomerium-proxy
  template:
    metadata:
      labels:
        app: pomerium-proxy
    spec:
      containers:
        - name: pomerium
          image: pomerium/pomerium:v0.28.0
          args: ["--config=/etc/pomerium/config.yaml"]
          ports:
            - containerPort: 443
              name: https
            - containerPort: 9090
              name: metrics
          volumeMounts:
            - name: config
              mountPath: /etc/pomerium
          envFrom:
            - secretRef:
                name: pomerium-config
          readinessProbe:
            httpGet:
              path: /ping
              port: 443
              scheme: HTTPS
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: config
          configMap:
            name: pomerium-config
```

## Tailscale ACL Policies as a ZTNA Alternative

Tailscale offers a different ZTNA shape: instead of a reverse proxy in front of applications, each node in the Tailscale mesh has identity, and ACLs control which identities can reach which nodes and ports. This is appropriate for infrastructure-level access (SSH to servers, internal APIs, database ports) rather than browser-based application access.

```json
// tailscale ACL policy (HuJSON format, submitted via `tailscale up` or the admin API)
{
  "tagOwners": {
    "tag:production": ["autogroup:admin"],
    "tag:staging":    ["autogroup:admin"],
    "tag:developer":  ["autogroup:member"]
  },

  "acls": [
    // Engineers can SSH to staging; no access to production SSH
    {
      "action": "accept",
      "src":    ["group:engineering"],
      "dst":    ["tag:staging:22"]
    },
    // SRE can SSH to production
    {
      "action": "accept",
      "src":    ["group:sre"],
      "dst":    ["tag:production:22"]
    },
    // Backend services reach each other on 8080-8090
    {
      "action": "accept",
      "src":    ["tag:production"],
      "dst":    ["tag:production:8080-8090"]
    },
    // Default deny — implicit in Tailscale, explicit here for documentation
    {
      "action": "accept",
      "src":    ["autogroup:admin"],
      "dst":    ["*:*"]
    }
  ],

  // Require re-authentication every 12 hours; no persistent sessions
  "autoApprovers": {},
  "ssh": [
    {
      "action": "accept",
      "src":    ["group:sre"],
      "dst":    ["tag:production"],
      "users":  ["autogroup:nonroot"]
    }
  ]
}
```

For self-hosted control plane, Headscale 0.24+ implements the Tailscale coordination protocol and can serve ACL policies from a local file or via API — no dependency on Tailscale's managed infrastructure.

```bash
# headscale config — /etc/headscale/config.yaml (excerpt)
server_url: https://headscale.corp.example.com:443
listen_addr: 0.0.0.0:443
metrics_listen_addr: 0.0.0.0:9090

# OIDC integration
oidc:
  issuer: https://corp.okta.com/oauth2/default
  client_id: "headscale-client"
  client_secret_path: /run/secrets/headscale-oidc-secret
  # Map OIDC groups to Tailscale tags
  extra_claims:
    - groups

# ACL policy file
acls_path: /etc/headscale/acls.hujson
```

## Device Posture Checks

Identity alone is insufficient. A valid IdP session on an unpatched, malware-infected device is not a trustworthy access event. Device posture checks add a second signal:

**Certificate-based posture (recommended baseline):** Issue a short-lived device certificate (ACME or internal CA, 24-hour lifetime) only to MDM-enrolled devices that pass a compliance check. The IAP requires a valid client certificate in addition to the OIDC token.

```bash
# Example: issue device cert via CFSSL on enrollment
cfssl gencert \
  -ca /etc/pki/device-ca.pem \
  -ca-key /etc/pki/device-ca-key.pem \
  -config /etc/cfssl/config.json \
  -profile device \
  device-csr.json | cfssljson -bare device
```

The certificate's CN encodes the device ID from MDM. The IAP validates the cert and looks up the device ID in the inventory API to confirm current compliance status.

**EDR integration:** Crowdstrike Falcon Zero Trust Assessment (ZTA), SentinelOne Ranger, and Microsoft Defender for Endpoint all expose a device health score via API or agent-reported header. Pomerium's `device` policy block and Cloudflare Access posture rules can consume these scores.

**OS version checks via MDM:** Intune, Jamf Pro, and Kandji all expose compliance APIs. A posture service (or the IAP directly) queries whether the device has the required OS patch level before issuing the device certificate or granting access.

**Practical tiering:**

| Risk level | Access allowed | Device requirements |
|---|---|---|
| High (production, PII data) | SRE, backend-eng groups | MDM enrolled + EDR active + OS current + device cert |
| Medium (staging, internal tools) | All engineering | MDM enrolled + device cert |
| Low (intranet, wikis) | All corp users | Valid OIDC session |

## Eliminating VPN: Handling Legacy Applications

Modern applications that support OIDC can be placed behind Pomerium or Cloudflare Access with zero code changes — the proxy handles auth entirely. Legacy applications that expect Basic Auth or Windows Integrated Auth require a different approach.

**Option 1 — Header injection:** Pomerium can inject `X-Forwarded-User` and `X-Forwarded-Groups` headers after authenticating the user. Some legacy apps can be configured to trust these headers for authentication.

**Option 2 — TCP tunneling:** Pomerium's TCP tunneling mode creates an authenticated, encrypted tunnel to non-HTTP services (PostgreSQL, Redis, internal SMTP). The pomerium-cli client handles the OIDC flow locally:

```bash
# Developer connects to a production Postgres via Pomerium TCP proxy
pomerium-cli tcp postgres-prod.corp.example.com:5432 \
  --listen localhost:15432

# Then use normal pg client against localhost:15432
psql -h localhost -p 15432 -U appuser mydb
```

**Option 3 — Service account bypass with pinned certificates:** Internal automation that cannot perform interactive OIDC flows uses a pinned client certificate. The Pomerium policy allows the specific certificate SPKI hash without requiring the interactive auth flow.

## mTLS as ZTNA Complement for Service-to-Service Traffic

ZTNA addresses user-to-application access. Service-to-service traffic inside the cluster requires a parallel mechanism: mutual TLS (mTLS) with SPIFFE workload identity.

SPIRE (SPIFFE Runtime Environment) issues short-lived X.509 SVIDs (SPIFFE Verifiable Identity Documents) to each workload. Envoy or Linkerd consumes these SVIDs to enforce mTLS between every pair of services, with policy at the service-identity level rather than the IP level.

```yaml
# Linkerd authorization policy — only the payment-service can reach the billing-service
apiVersion: policy.linkerd.io/v1beta3
kind: AuthorizationPolicy
metadata:
  name: billing-to-payment-only
  namespace: finance
spec:
  targetRef:
    group: core
    kind: Service
    name: billing-service
  requiredAuthenticationRefs:
    - name: payment-service-identity
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
---
apiVersion: policy.linkerd.io/v1beta3
kind: MeshTLSAuthentication
metadata:
  name: payment-service-identity
  namespace: finance
spec:
  identities:
    - "payment-service.finance.serviceaccount.identity.linkerd.cluster.local"
```

This closes the east-west access gap that ZTNA alone does not address: a compromised pod cannot reach the billing service even if it has a valid OIDC session, because its SPIFFE identity does not match the authorization policy.

## Migration Path: Running ZTNA Alongside Existing VPN

Migrating from VPN to ZTNA is a months-long process. Running both in parallel is standard practice:

**Phase 1 — Inventory (weeks 1-4):** List every internal application and which groups need access. This is often the first time the organization has a complete access map. Identify device management gaps (which endpoints are MDM-enrolled?).

**Phase 2 — Deploy IAP for low-risk applications (weeks 5-8):** Move internal wikis, developer portals, monitoring dashboards behind Pomerium or Cloudflare Access. VPN remains active. Validate that authentication flows work, device cert issuance is operational, and user experience is acceptable.

**Phase 3 — Migrate high-traffic developer applications (weeks 9-16):** Source code repositories, CI/CD consoles, internal APIs. Users access these via IAP; VPN is no longer required for them. Keep VPN available for edge cases.

**Phase 4 — Legacy and TCP applications (weeks 17-24):** Migrate database access and legacy apps via TCP tunneling or header-injection wrappers.

**Phase 5 — VPN retirement for covered applications:** Once all applications are behind IAP, communicate a VPN deprecation timeline. Retain VPN only for specific use cases (emergency access, raw network debugging by network team) with heavily audited access.

```bash
# Smoke test IAP deployment before VPN cutover
# Verify policy denies unauthenticated requests
curl -I https://grafana.corp.example.com
# Expected: 302 redirect to IdP

# Verify policy denies wrong group
# (from a test user not in the engineering group)
curl -H "Cookie: _pomerium=<test-user-session>" \
     https://grafana.corp.example.com
# Expected: 403 Forbidden

# Verify policy allows correct group + managed device
# (from a test user in engineering with valid device cert)
curl --cert /etc/pki/device.pem \
     --key /etc/pki/device.key \
     -H "Cookie: _pomerium=<eng-user-session>" \
     https://grafana.corp.example.com
# Expected: 200 OK
```

## CISA Zero Trust Maturity Model and NIST SP 800-207

The CISA Zero Trust Maturity Model (updated 2023, v2.0) defines five pillars — Identity, Devices, Networks, Applications, and Data — each with three maturity levels: Traditional, Advanced, and Optimal.

For a ZTNA implementation, the relevant mappings:

**Identity pillar — Advanced level:** MFA enforced enterprise-wide, risk-based authentication for high-value applications, identity integrated with device compliance status. The Pomerium policy configuration above, combined with an MDM-backed device cert, satisfies Advanced. Optimal requires continuous session risk evaluation and integration with a UEBA (user and entity behavior analytics) platform.

**Devices pillar — Advanced level:** All devices in a managed inventory with compliance policies enforced; device health signals integrated into access decisions. The MDM + device certificate pattern above satisfies this.

**Networks pillar — Advanced level:** Micro-segmentation deployed for most workloads; traffic between workloads encrypted and authenticated; network access granted per-request based on identity. The combination of Pomerium for user access and mTLS via Linkerd or Envoy for service-to-service access satisfies Advanced. Optimal adds automated anomaly detection and dynamic policy updates.

**NIST SP 800-207** (Zero Trust Architecture, 2020) defines three ZTA deployment models:

1. **Identity-governed** — the IAP pattern described here. An enhanced identity governance infrastructure with per-request access decisions.
2. **Micro-segmented** — network segmentation with software-defined perimeters; each segment has its own gateway.
3. **Software-defined perimeter** — dynamic policy controller issues per-session network credentials; no standing access.

The Pomerium + mTLS stack satisfies NIST's identity-governed model for application access and the micro-segmented model for service-to-service. For FISMA compliance or FedRAMP boundaries, NIST 800-207 alignment is increasingly expected in 2025-2026 procurement.

## Hardening Checklist

- [ ] All internal applications proxied behind IAP; no direct internal IP access from VPN for covered apps
- [ ] Device certificate issuance tied to MDM enrollment and compliance status; certs expire in ≤24 hours
- [ ] OIDC token lifetime set to 1 hour; refresh tokens bound to device certificate
- [ ] Per-route policies reviewed and documented; no wildcard group grants to high-risk applications
- [ ] MFA required (and enforced in policy via `acr` claim) for applications with access to production data
- [ ] IAP access logs forwarded to SIEM; alert on repeated 403s (policy evaluation failures) and off-hours access to sensitive routes
- [ ] Pomerium metrics (`:9090/metrics`) scraped; alert on `pomerium_policy_evaluation_duration_seconds` spikes indicating policy engine overload
- [ ] mTLS deployed for all service-to-service communication within cluster; SPIFFE SVIDs rotate every 1 hour
- [ ] Legacy applications behind TCP tunnel or header-injection wrapper; not directly exposed to VPN subnet
- [ ] VPN access audited quarterly; groups and IP assignments reviewed against IAP coverage
- [ ] CISA ZT Maturity self-assessment completed; gaps documented and tracked against roadmap
