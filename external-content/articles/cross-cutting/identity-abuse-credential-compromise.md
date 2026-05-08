---
title: "Identity Abuse and Credential Compromise: Defending Against Attackers Who Log In Instead of Break In"
description: "Nearly 80% of intrusion detections in 2026 are malware-free. Attackers steal valid credentials, hijack session tokens, exploit federated access, and bypass weak MFA to move laterally without triggering traditional malware detection. This article covers the defensive controls for identity-based attacks."
slug: "identity-abuse-credential-compromise"
date: 2026-04-23
lastmod: 2026-04-23
category: "cross-cutting"
tags: ["identity", "credentials", "session-tokens", "mfa-bypass", "zero-trust", "lateral-movement", "authentication", "sso"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 159
difficulty: "advanced"
estimated_reading_time: 24
provider_bridges:
  - name: "Teleport"
    id: 41
    category: "identity"
  - name: "CrowdStrike"
    id: 158
    category: "endpoint-security"
  - name: "Tailscale"
    id: 40
    category: "identity"
premium_pack: "identity-defence-pack"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/identity-abuse-credential-compromise/index.html"
---

# Identity Abuse and Credential Compromise: Defending Against Attackers Who Log In Instead of Break In

## Problem

The primary intrusion method has shifted. By 2026, nearly 80% of detected intrusions are malware-free. Attackers do not need to exploit vulnerabilities or deploy malware when they can simply log in with stolen credentials.

The attack chain:

1. **Credential theft** via phishing (AI-generated, see [Defending Against AI-Amplified Social Engineering](/articles/ai-landscape/ai-social-engineering-defence/)), credential stuffing from breached databases, or infostealer malware that harvests browser-stored passwords and session cookies.
2. **Session token hijack** instead of stealing passwords, attackers steal active session tokens (cookies, JWTs, OAuth tokens) that bypass MFA entirely. The token is already authenticated; no MFA challenge is triggered.
3. **MFA bypass** via MFA fatigue (bombing the user with push notifications until they approve), SIM swapping (redirecting SMS codes), or real-time phishing proxies (tools like evilginx2 that relay the MFA challenge and capture the authenticated session).
4. **Federated access abuse** by compromising a single identity provider (IdP) account that grants access to dozens of downstream applications via SSO. One compromised Google Workspace or Microsoft Entra ID account can access Slack, AWS, GitHub, Jira, and every other SSO-integrated service.
5. **Lateral movement without malware** by using the compromised credentials to access internal services, download source code, read secrets, and pivot to higher-privilege accounts, all through legitimate authenticated sessions.

Traditional security monitoring focuses on malware indicators: file hashes, process anomalies, network signatures. Identity-based attacks generate none of these signals. The attacker looks exactly like a legitimate user because they are using a legitimate user's credentials.

## Threat Model

- **Adversary:** Attacker in possession of valid credentials (username + password, session token, or OAuth token). May have obtained credentials through phishing, credential stuffing, infostealer malware, or dark web purchase.
- **Access level:** Authenticated user. The attacker has the same access as the compromised account. If the account has admin privileges, the attacker has admin privileges.
- **Objective:** Data exfiltration (source code, customer data, secrets). Privilege escalation (access higher-privilege accounts). Persistence (add attacker-controlled credentials or API keys). Financial gain (access billing, modify payment details). Supply chain compromise (access CI/CD pipelines to inject backdoors).
- **Blast radius:** Depends on the compromised account's access level. A developer account gives access to source code and CI/CD. An admin account gives access to everything. An IdP admin account gives access to every SSO-integrated application.

**The key shift:** The distinction between "authorised user" and "attacker" is no longer binary. The attacker IS an authorised user, using valid credentials. Detection must focus on behaviour anomalies, not credential validity.

## Configuration

### 1. Eliminate Password-Based Authentication

Passwords are the root cause of credential compromise. Remove them entirely.

```bash
# Enforce FIDO2/WebAuthn for all admin accounts
# SSH: require security keys
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "admin@company.com"

# Remove password authentication entirely from SSH
# /etc/ssh/sshd_config.d/no-passwords.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
```

**For web applications, enforce phishing-resistant MFA:**

```yaml
# identity-provider-policy.yaml
# Organisational authentication policy
authentication:
  # Require FIDO2 for all privileged accounts
  admin_accounts:
    mfa_method: "fido2_webauthn"
    session_lifetime: "4h"
    re_auth_for_sensitive_actions: true

  # Require FIDO2 or TOTP for standard accounts
  standard_accounts:
    mfa_method: "fido2_webauthn,totp"
    session_lifetime: "8h"

  # Block SMS and push-notification MFA (vulnerable to SIM swap and fatigue)
  blocked_methods:
    - "sms"
    - "push_notification_without_number_matching"
```

### 2. Harden Session Tokens Against Hijacking

Session token theft bypasses MFA because the token represents an already-authenticated session.

**Reduce session token lifetime:**

```yaml
# oauth2-proxy-config.yaml
# Short-lived sessions force re-authentication frequently,
# limiting the window for stolen token use.
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-proxy-config
  namespace: auth
data:
  oauth2-proxy.cfg: |
    cookie_expire = "4h"
    cookie_refresh = "1h"
    cookie_secure = true
    cookie_httponly = true
    cookie_samesite = "strict"
    cookie_domains = [".example.com"]

    # Bind session to client IP (breaks on IP change but prevents token replay)
    session_cookie_minimal = false

    # Force re-authentication for sensitive paths
    skip_auth_routes = []
```

**Bind tokens to device fingerprint:**

```nginx
# nginx-token-binding.conf
# Add client fingerprint headers that the application can use
# to detect token replay from a different device.

map $http_user_agent $device_fingerprint {
    default "$remote_addr-$http_user_agent";
}

server {
    location / {
        proxy_set_header X-Device-Fingerprint $device_fingerprint;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://backend;
    }
}
```

**Monitor for token reuse from multiple IPs:**

```yaml
# prometheus-token-anomaly.yaml
groups:
  - name: session-anomaly
    interval: 1m
    rules:
      # Alert when the same session token is used from multiple IPs
      - alert: SessionTokenMultipleIPs
        expr: >
          count by (session_id) (
            count by (session_id, client_ip) (
              rate(http_requests_total[5m])
            )
          ) > 1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Session {{ $labels.session_id }} used from multiple IPs"
          description: >
            Same session token seen from different client IPs.
            This is a strong indicator of session token theft.
            Investigate immediately and invalidate the session.

      # Alert on authentication from impossible travel
      - alert: ImpossibleTravel
        expr: >
          authentication_success_total
          and on (user)
          (
            count by (user) (
              count_values("country", authentication_geo_country) > 1
            )
          )
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.user }} authenticated from multiple countries in short window"
```

### 3. Limit Blast Radius of Compromised Credentials

Assume credentials will be compromised. Limit what a compromised account can reach.

**Implement just-in-time (JIT) access:**

```bash
#!/bin/bash
# jit-access.sh
# Grant temporary elevated access that expires automatically.

USER="${1}"
ROLE="${2}"
DURATION="${3:-4h}"

echo "=== JIT Access Grant ==="
echo "User: ${USER}"
echo "Role: ${ROLE}"
echo "Duration: ${DURATION}"
echo "Expires: $(date -d "+${DURATION}" -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Approved by: $(whoami)"
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Create temporary Kubernetes RBAC binding
kubectl create rolebinding "jit-${USER}-${ROLE}" \
  --clusterrole="${ROLE}" \
  --user="${USER}" \
  --namespace=production

# Schedule automatic revocation
echo "kubectl delete rolebinding jit-${USER}-${ROLE} -n production" | \
  at "now + ${DURATION}"

echo "=== Access granted. Will be automatically revoked in ${DURATION}. ==="
```

**Segment access by environment:**

```yaml
# rbac-segmented.yaml
# Separate credentials for each environment.
# Compromising dev credentials does not grant staging or production access.

# Development access
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-dev
  namespace: development
subjects:
  - kind: Group
    name: "developers"
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
---
# Staging access (read-only for developers)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-staging-readonly
  namespace: staging
subjects:
  - kind: Group
    name: "developers"
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
---
# Production access (admin only, via JIT)
# No standing access for developers.
# Access must be requested via JIT process.
```

### 4. Detect Identity-Based Lateral Movement

Identity-based attacks generate no malware signals. Detect them through authentication and access pattern anomalies.

```yaml
# identity-detection-rules.yaml
groups:
  - name: identity-anomaly
    interval: 1m
    rules:
      # User accessing a service they have never accessed before
      - alert: FirstTimeServiceAccess
        expr: >
          authentication_success_total
          unless on (user, service)
          authentication_success_total offset 30d
        for: 1m
        labels:
          severity: info
        annotations:
          summary: "{{ $labels.user }} accessed {{ $labels.service }} for the first time"

      # Spike in resources accessed by a single user
      - alert: UserAccessSpike
        expr: >
          count by (user) (
            rate(api_requests_total[1h])
          ) > 3 * avg_over_time(
            count by (user) (rate(api_requests_total[1h]))[7d:1h]
          )
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.user }} accessing 3x more resources than baseline"
          description: >
            User is accessing significantly more resources than their
            7-day average. May indicate credential compromise and
            data exfiltration.

      # Service account used from unexpected source
      - alert: ServiceAccountFromUnexpectedSource
        expr: >
          kubernetes_api_audit_total{user_type="serviceaccount"}
          unless on (user, source_ip)
          kubernetes_api_audit_total{user_type="serviceaccount"} offset 7d
        labels:
          severity: warning
        annotations:
          summary: "Service account {{ $labels.user }} used from new source IP"

      # After-hours access to sensitive resources
      - alert: AfterHoursAccess
        expr: >
          authentication_success_total{service=~"production-.*|admin-.*"}
          and on() (hour() < 6 or hour() > 22)
        labels:
          severity: info
        annotations:
          summary: "{{ $labels.user }} accessed {{ $labels.service }} outside business hours"
```

### 5. Federated Access Hardening

A compromised IdP account grants access to every SSO-integrated application. Harden the federation layer.

```yaml
# federation-hardening-checklist.yaml
# Applied at the identity provider level (Google Workspace, Microsoft Entra ID, Okta)

sso_hardening:
  # Require step-up authentication for sensitive applications
  conditional_access:
    - application: "AWS Console"
      require: "fido2 + device_compliance"
    - application: "GitHub"
      require: "fido2"
    - application: "Production Kubernetes"
      require: "fido2 + jit_approval"

  # Limit session propagation
  session_controls:
    - max_session_lifetime: "8h"
    - require_reauth_for_admin_actions: true
    - block_concurrent_sessions_per_user: true

  # Monitor for suspicious SSO patterns
  monitoring:
    - alert_on_new_application_consent: true
    - alert_on_admin_role_assignment: true
    - alert_on_mfa_method_change: true
    - alert_on_recovery_email_change: true
```

## Expected Behaviour

- **No passwords:** All authentication uses FIDO2/WebAuthn or short-lived SSH certificates. Password-based attacks have zero attack surface.
- **Short-lived sessions:** Session tokens expire in 4 hours. Stolen tokens have a limited exploitation window.
- **Token binding:** Sessions are bound to device fingerprint. Token replay from a different device triggers an alert.
- **JIT access:** No standing privileged access. Elevated permissions expire automatically after the approved duration.
- **Behavioural detection:** First-time service access, access volume spikes, impossible travel, and after-hours access generate alerts within 5 minutes.
- **Federated hardening:** Step-up authentication required for sensitive SSO applications. MFA method changes and admin role assignments generate immediate alerts.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| No passwords | Users must carry hardware security keys | Key loss = account lockout | Two keys per user (primary + backup). Emergency recovery via in-person verification. |
| 4-hour session lifetime | Users re-authenticate multiple times per day | Productivity impact from frequent re-auth | Use session refresh (re-auth every 4h, not every request). Extend to 8h for low-risk applications. |
| JIT access | Engineers must request and wait for elevated access | Slows incident response when immediate access is needed | Break-glass procedure with post-hoc review. Pre-approved JIT for on-call engineers. |
| Behavioural alerting | First-time access alerts fire for legitimate new access | Alert fatigue from normal access pattern changes | Suppress alerts during onboarding periods. Correlate multiple signals before escalating. |
| Block concurrent sessions | User on two devices simultaneously is blocked | Breaks legitimate multi-device workflows | Allow 2 concurrent sessions maximum. Alert on 3+. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Compromised IdP admin account | Attacker accesses all SSO applications | Unusual admin actions in IdP audit log; alert on admin role assignment | Revoke all sessions for the compromised account. Rotate IdP admin credentials. Review all recent admin actions. |
| Session token stolen via XSS | Attacker accesses application with stolen session cookie | Token used from unexpected IP/device (detected by binding check) | Invalidate all sessions for the affected user. Fix the XSS vulnerability. Rotate all session signing keys. |
| MFA fatigue attack succeeds | User approves a push notification from the attacker | Successful MFA approval followed by login from unexpected location | Replace push MFA with FIDO2 (no approve button to fatigue). Investigate the account immediately. |
| JIT access not revoked | Temporary elevated access persists beyond the approved window | `at` job fails; RBAC binding still exists after expiration | Implement a reconciliation cron job that removes all JIT bindings older than their duration. Monitor for orphaned bindings. |
| Impossible travel alert false positive | User using VPN exits in a different country | Alert fires for legitimate VPN use | Correlate with VPN connection logs. Suppress impossible travel alerts when VPN connection is active from a known endpoint. |

## When to Consider a Managed Alternative

**Transition point:** Managing JIT access, session binding, behavioural detection, and IdP hardening for 50+ users across 20+ SSO applications requires dedicated identity security expertise.

- **[Teleport](https://goteleport.com):** Unified access platform with short-lived certificates, session recording, JIT access requests, and device trust. Replaces SSH keys, VPN, and Kubernetes kubeconfig with identity-aware access that expires automatically.
- **[CrowdStrike Falcon Identity Protection](https://www.crowdstrike.com):** Detects identity-based attacks (lateral movement, privilege escalation, credential theft) across Active Directory, Azure AD, and cloud services. ML-based detection of anomalous authentication patterns that traditional SIEM misses.
- **[Tailscale](https://tailscale.com):** Zero-trust network access that replaces VPN. Every connection is authenticated per-user with SSO integration. Access control lists define which users can reach which services. No standing network access.

**Premium content pack:** Identity defence templates. JIT access scripts for Kubernetes and AWS. Session token binding configurations. Behavioural detection alerting rules. Federated access hardening checklists for Google Workspace, Microsoft Entra ID, and Okta.

## Related Articles

- [Defending Against AI-Amplified Social Engineering: Phishing, Voice Cloning, and Deepfake Impersonation](/articles/ai-landscape/ai-social-engineering-defence/)
- [PAM Configuration Hardening: Password Policies, Login Controls, and MFA Integration](/articles/linux/pam-hardening/)
- [SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging](/articles/linux/ssh-hardening/)
- [Secure Cloud VM Access: SSH Key Authentication, Two-Factor Login, VPN, and Audit Logging](/articles/linux/secure-cloud-vm-access/)
- [Kubernetes Service Account Token Security: Bound Tokens, Projected Volumes, and OIDC](/articles/kubernetes/service-account-tokens/)
