---
title: "Identity Federation Security: Trust, Attribute Mapping, and Cross-Domain Access"
description: "Federating identity across organisational boundaries introduces trust chains, attribute mapping risks, and cross-domain privilege escalation paths. This guide covers SAML and OIDC federation security, IdP trust hierarchy design, attribute mapping hardening, preventing privilege escalation via federation, and monitoring federated access."
slug: identity-federation-security
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - identity-federation
  - saml
  - oidc
  - sso
  - trust-hierarchy
personas:
  - security-engineer
  - platform-engineer
article_number: 605
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/identity-federation-security/
---

# Identity Federation Security: Trust, Attribute Mapping, and Cross-Domain Access

## Problem

Identity federation is the practice of allowing one organisation's identity provider to vouch for users in another organisation's systems. When Company A's IdP asserts "this is alice@company-a.com and she is in the engineering group", Company B's service provider (SP) accepts that assertion and grants access accordingly — without Company B managing Alice's credentials. The appeal is clear: single sign-on across organisational boundaries, no shared password databases, and centralised lifecycle management.

The security problem is structural. Federation transfers trust across a boundary. Every hop in a federation chain — from the user's home IdP, through intermediate IdPs, through cloud provider identity brokers, to the final SP — expands the attack surface. A compromise at any upstream point compromises everything downstream. Unlike a single-organisation IdP compromise (which affects that organisation's services), a compromised federated IdP affects every SP that trusts it — potentially dozens of organisations.

The specific failure modes that recur in production environments:

- **Compromised IdP as universal impersonator.** Any system that trusts an IdP's assertions accepts whatever that IdP says about users. A compromised IdP can assert that the attacker is any user — including administrators — in any connected SP.
- **Attribute injection for privilege escalation.** Federation assertions carry attributes (group memberships, roles, entitlements). If an attacker can manipulate an IdP's attribute store, add themselves to a privileged group, or exploit flawed attribute mapping logic at the SP, they gain elevated access without compromising any individual account.
- **XML Signature Wrapping (XSW) in SAML.** SAML assertions are XML documents with digital signatures. XSW attacks exploit the gap between which XML element the IdP signs and which element the SP validates — an attacker can wrap a legitimate signed element inside a malicious assertion, causing the SP to accept an unsigned forged assertion as if it were signed.
- **Trust hierarchy sprawl.** Each new federation relationship added for convenience extends the trust graph. A SaaS application trusted by a cloud IdP trusted by the enterprise IdP means the SaaS app's security posture is now relevant to the enterprise's identity perimeter.
- **Orphaned federation trusts.** After a merger, acquisition, contract end, or service decommission, IdP trusts are frequently not removed. Old federation relationships represent standing access from an organisation that may no longer have the same security posture.

**Target systems:** Any SAML 2.0 identity provider or service provider (Okta, Microsoft Entra ID, Google Workspace, Keycloak, ADFS, Shibboleth); OIDC federation implementations including AWS IAM Identity Center, GCP Workload Identity Federation, Azure AD B2B; SPIFFE/SPIRE trust domain federation; enterprise SSO infrastructure (ADFS, PingFederate).

## Threat Model

**1. Compromised IdP → full SP access**

An attacker who gains administrative access to a trusted IdP does not need to attack each SP individually. They can issue assertions (SAML) or tokens (OIDC) for any user — including super-admins — in every connected SP. If the enterprise IdP federates to 40 SaaS applications, a single IdP compromise grants access to all 40. The attacker's entry point may be the IdP admin console, the IdP's credential store, or the IdP's signing key material.

**2. XML Signature Wrapping (XSW) at SAML SPs**

An attacker obtains a valid SAML assertion for a low-privilege account (by legitimately authenticating as that user). They craft a malicious assertion with elevated attributes but reference the legitimate assertion's signature in a way that causes the SP's XML parser to validate the signature against the legitimate element while consuming the forged element's attributes. SPs that use naive "find the Signature element and verify it" without anchoring verification to the specific element being consumed are vulnerable. Dozens of SP libraries have had XSW CVEs over the past decade; the attack is known but recurs because XML signature handling is genuinely complex.

**3. Attribute manipulation → role escalation**

An IdP stores group membership in LDAP or a database. The federation assertion maps `memberOf: cn=devops-team,ou=groups,dc=company,dc=com` to the SP's `devops` role. An attacker with write access to LDAP (a misconfigured service account, an over-permissioned developer account, an LDAP injection) adds themselves to `cn=platform-admins`. On next login, their SAML assertion includes the platform-admins group, and the SP grants admin access. The SP never saw a credential compromise; the attack happened entirely in the attribute store.

**4. Nonce and state omission in OIDC federation → CSRF**

OIDC federation flows that omit the `nonce` parameter (for ID token replay prevention) or the `state` parameter (for CSRF protection on the authorization endpoint) allow an attacker to construct malicious authorization flows. Without `state`, an attacker can initiate an authorization flow on behalf of a victim and capture the resulting code. Without `nonce`, an intercepted ID token can be replayed in a different session.

**5. Trust chain amplification via hub IdPs**

An organisation operates a hub IdP that accepts assertions from partner organisations (the "inbound" federation) and re-issues its own assertions to downstream SPs (the "outbound" federation). A compromise in any partner IdP that the hub trusts can flow through the hub to all downstream SPs — including internal systems that have no direct relationship with the partner. This is not a misconfiguration; it is the intended design. The risk is that the downstream SPs accept the hub's assertions at face value without knowing that those assertions were derived from a partner's compromised assertion.

**Blast radius:** An IdP that 50 SaaS applications trust, and that is itself trusted by a cloud provider IAM system, represents a single point of failure for access to every one of those systems for every user in the organisation.

## Configuration / Implementation

### SAML Federation Hardening

SAML assertion security depends on three independently necessary controls: signature validation, audience restriction, and replay prevention. Failing any one of them is independently exploitable.

**Signature verification — validate the right element**

The most common XSW mitigation is ensuring the SP validates the signature on the specific `Assertion` element it will consume, not any `Signature` element it finds in the document:

```python
# python3-saml / onelogin style — enforce strict mode
from onelogin.saml2.auth import OneLogin_Saml2_Auth

settings = {
    "strict": True,               # Enables all security checks
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "rejectDeprecatedAlgorithm": True,   # Block SHA-1 assertions
        "wantXMLValidation": True,
    }
}
```

Never accept `RSA-SHA1` or `DSA-SHA1` signed assertions. These are deprecated and SHA-1 collision attacks make them unsafe for assertion integrity. Explicitly configure `rejectDeprecatedAlgorithm: true` in your SP library.

**Audience restriction — assertions must be addressed to your SP**

A SAML assertion contains an `<AudienceRestriction>` element naming the intended SP. Validate it:

```xml
<!-- IdP must include this in every assertion -->
<saml:Conditions NotBefore="2026-05-07T10:00:00Z" NotOnOrAfter="2026-05-07T10:05:00Z">
  <saml:AudienceRestriction>
    <saml:Audience>https://sp.company-b.com/saml/metadata</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>
```

Your SP must reject any assertion whose `<Audience>` does not exactly match your registered entity ID. An assertion signed for a different SP is valid XML with a valid signature — it is not valid for your system.

**Replay prevention — track assertion IDs**

SAML assertions include an `ID` attribute on the `<Assertion>` element, a `NotOnOrAfter` timestamp, and optionally a `<SubjectConfirmationData>` element with its own timestamp. Implement assertion ID tracking:

```python
import redis
import hashlib

def validate_and_consume_assertion_id(assertion_id: str, not_on_or_after: datetime) -> bool:
    """
    Returns True if assertion_id has not been seen before.
    Stores the ID until its NotOnOrAfter time to prevent replay.
    """
    r = redis.Redis()
    key = f"saml:used_assertion:{hashlib.sha256(assertion_id.encode()).hexdigest()}"
    ttl_seconds = int((not_on_or_after - datetime.utcnow()).total_seconds()) + 60

    # SET NX — only set if key does not exist
    was_new = r.set(key, "1", ex=ttl_seconds, nx=True)
    return was_new is not None   # None means key already existed — replay attempt
```

Store the assertion ID in a distributed cache (Redis, Memcached, or a database) until the assertion's `NotOnOrAfter` time. A replayed assertion with the same ID is rejected. Note: this must be shared state across all SP instances in a cluster.

**Clock skew tolerance**

SAML timestamps are UTC. Allow a small clock skew tolerance (no more than 120 seconds) in both directions when validating `NotBefore` and `NotOnOrAfter`. Never allow tolerance greater than the assertion's validity window — if your SP accepts assertions valid for 5 minutes with a 10-minute skew tolerance, replay prevention becomes meaningless.

### OIDC Federation Hardening

OIDC federation differs from SAML structurally but shares the core challenge: validating that a token came from the trusted issuer and was intended for your system.

**Issuer validation**

Always validate the `iss` claim in the ID token against your pre-configured trusted issuer list. Never derive the issuer URL from the token itself:

```go
// Go — validating OIDC ID tokens with go-oidc
package main

import (
    "context"
    oidc "github.com/coreos/go-oidc/v3/oidc"
)

func validateIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
    // Issuer URL is configured at startup — never taken from the token
    provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
    if err != nil {
        return nil, err
    }

    verifier := provider.Verifier(&oidc.Config{
        ClientID: "your-client-id",   // Validates the `aud` claim
    })

    return verifier.Verify(ctx, rawIDToken)
}
```

The `oidc.NewProvider` call fetches the provider's discovery document and public keys. The verifier then validates `iss`, `aud`, `exp`, and the token signature against those keys. Never call `jwt.Parse` with only signature verification — it will not validate issuer or audience.

**Nonce and state for CSRF and replay prevention**

```python
import secrets
import hashlib

def start_oidc_flow(session):
    # state — CSRF protection for the authorization endpoint callback
    state = secrets.token_urlsafe(32)
    session['oidc_state'] = state

    # nonce — prevents ID token replay across sessions
    nonce = secrets.token_urlsafe(32)
    # Store the hash, not the nonce itself, to prevent timing attacks
    session['oidc_nonce_hash'] = hashlib.sha256(nonce.encode()).hexdigest()

    return state, nonce  # Both are sent in the authorization request

def complete_oidc_flow(session, returned_state, id_token_nonce_claim):
    if returned_state != session.get('oidc_state'):
        raise ValueError("State mismatch — CSRF or session confusion")

    expected_nonce_hash = session.get('oidc_nonce_hash')
    actual_nonce_hash = hashlib.sha256(id_token_nonce_claim.encode()).hexdigest()
    if not secrets.compare_digest(expected_nonce_hash, actual_nonce_hash):
        raise ValueError("Nonce mismatch — potential token replay")
```

**PKCE for all public clients**

For any OIDC federation flow involving a browser-based or native application, always require PKCE (RFC 7636). This prevents authorization code interception even if the redirect URI is compromised.

### IdP Trust Hierarchy Design

Every federation trust relationship represents a potential amplification path. Design the hierarchy deliberately.

**Model the trust graph before adding relationships**

A typical enterprise trust chain: Active Directory → Entra ID (SAML/OIDC federation) → AWS IAM Identity Center → AWS account role. A compromise at the AD level flows to every AWS account. A compromise at Entra ID flows to every SP that Entra ID federates to, including AWS.

```
Enterprise AD (authoritative)
    └── Entra ID (enterprise IdP)
            ├── AWS IAM Identity Center → {prod,staging,dev} AWS accounts
            ├── Google Workspace (SAML SP)
            ├── Salesforce (SAML SP)
            └── GitHub Enterprise (OIDC SP)
                    └── third-party GitHub Apps (OAuth federation)
```

Before adding a new SP to the enterprise IdP, document:
- What attributes does the SP consume?
- What access does each attribute value grant?
- What is the SP's own security posture?
- Does the SP re-federate to other systems?

**Limit claim pass-through at hub IdPs**

If your organisation operates a hub IdP that accepts assertions from partner organisations and re-issues assertions to internal SPs, never pass partner-sourced attributes through unchanged. Explicitly map and filter:

```yaml
# Keycloak identity provider mapper — restrict which attributes pass through
# from a partner IdP to internal SPs
identityProviderMapper:
  name: partner-group-to-internal-role
  identityProviderAlias: partner-company-saml
  identityProviderMapper: hardcoded-role-idp-mapper
  config:
    role: "internal-reader"           # Only ever grant reader — not admin
    # Never use 'oidc-user-attribute-idp-mapper' to pass groups through
    # without explicit allow-listing
```

Any attribute sourced from a partner IdP should be treated as untrusted input and mapped through an explicit allow-list, never passed through as-is.

### Attribute Mapping Hardening

Attribute mapping is the translation layer between what the IdP asserts and what the SP grants. It is frequently the weakest link.

**Principle of least privilege in attribute mapping**

Map the minimum necessary. An IdP group should map to the minimum SP role needed for the members' work:

```xml
<!-- Shibboleth SP attribute mapping — attribute-map.xml -->
<Attributes xmlns="urn:mace:shibboleth:2.0:attribute-map">

  <!-- Accept email — safe, non-privileged -->
  <Attribute name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
             id="eduPersonEntitlement"/>

  <!-- Accept group membership but ONLY from expected IdP -->
  <Attribute name="urn:oid:1.3.6.1.4.1.5923.1.5.1.1"
             id="isMemberOf"
             permitAny="false">
    <!-- Only accept this attribute from the configured trusted IdP -->
  </Attribute>

  <!-- DO NOT accept arbitrary attributes from partner IdPs -->
  <!-- Explicitly list accepted attributes; reject everything else -->

</Attributes>
```

At the SP application layer, map IdP groups to application roles through a configuration-file-controlled allow-list:

```python
# group_role_mapping.py — reviewed and version-controlled
SAML_GROUP_TO_APP_ROLE = {
    "cn=platform-readers,ou=groups,dc=company,dc=com": "reader",
    "cn=platform-operators,ou=groups,dc=company,dc=com": "operator",
    # Note: 'admin' role is NOT mapped from any federated group
    # Admins are provisioned directly in the application
}

def map_groups_to_role(saml_groups: list[str]) -> str:
    """Returns the highest role granted by any group membership."""
    role = "no-access"
    role_order = ["no-access", "reader", "operator"]
    for group in saml_groups:
        mapped = SAML_GROUP_TO_APP_ROLE.get(group)
        if mapped and role_order.index(mapped) > role_order.index(role):
            role = mapped
    return role
```

Store this mapping in version control. Changes to attribute mapping should go through code review, not direct configuration edits.

**Protect privileged roles from federation**

Some roles should never be grantable via federation assertions. Define them explicitly in the application:

- Application super-admin: provisioned directly, never via SAML/OIDC group
- Break-glass accounts: local credentials only, no federation path
- Service accounts: SPIFFE workload identity or API keys, never federated user identity

### Just-In-Time Provisioning Security

JIT provisioning creates user accounts in the SP on first successful federated authentication. It removes the need to pre-provision accounts but introduces a risk: the provisioning logic determines what access the newly-created account receives, and that logic derives access from the IdP's assertion attributes.

**Harden JIT provisioning logic**

```python
def provision_or_update_user_from_saml(saml_attributes: dict) -> User:
    """
    Called on every successful SAML authentication.
    Creates the user if they don't exist; updates attributes on subsequent logins.
    """
    email = saml_attributes.get('email')
    if not email:
        raise ProvisioningError("SAML assertion missing required email attribute")

    # Validate email domain against allowed IdP domains
    allowed_domains = config.ALLOWED_FEDERATION_DOMAINS  # e.g. ["company-a.com", "partner-b.com"]
    domain = email.split('@')[1]
    if domain not in allowed_domains:
        raise ProvisioningError(f"Email domain {domain} not in allowed federation domains")

    # Map groups — using the restricted mapping, not raw group values
    groups = saml_attributes.get('groups', [])
    role = map_groups_to_role(groups)

    # Never automatically grant admin on first provision
    # Admin access requires a separate out-of-band request
    if role == "admin":
        log.warning(f"JIT provisioning attempted admin grant for {email} — downgraded to operator")
        role = "operator"

    user, created = User.objects.update_or_create(
        email=email,
        defaults={'role': role, 'last_federated_login': datetime.utcnow()}
    )

    if created:
        audit_log.info(f"JIT provisioned new user {email} with role {role} from federation")
        alert_security_team(f"New federated user provisioned: {email}")

    return user
```

Alert on every JIT provisioning event. New accounts appearing in your system without a corresponding access request ticket are an early indicator of either a misconfigured IdP or an attacker using a compromised IdP account.

### SPIFFE Federation Across Trust Domains

For machine-to-machine identity across organisational or cluster boundaries, SPIFFE/SPIRE provides federation between trust domains. A workload in trust domain `spiffe://prod.company-a.com` can authenticate to services in `spiffe://services.company-b.com` without sharing a root CA.

**Configure SPIRE bundle federation**

```bash
# On SPIRE server in company-a's trust domain:
# Export the trust bundle (public keys only) to share with company-b
spire-server bundle show -format spiffe > company-a-bundle.jwks

# On SPIRE server in company-b's trust domain:
# Import company-a's bundle — establishes directional federation
spire-server bundle set \
  -format spiffe \
  -id "spiffe://prod.company-a.com" \
  < company-a-bundle.jwks

# Verify the federation is established
spire-server bundle list
# Should show: spiffe://prod.company-a.com with key rotation timestamp
```

**Apply SPIRE authorization policies to federated identities**

Federation establishes that company-b can verify company-a's SVID signatures — it does not automatically grant access. Apply explicit authorization policies at the workload level:

```yaml
# Envoy RBAC policy — only allow specific federated SPIFFE IDs
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-partner-workload
  namespace: payments
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
          # Only these specific workloads from company-a's trust domain
          - "spiffe://prod.company-a.com/ns/billing/sa/invoice-service"
          # Not: "spiffe://prod.company-a.com/*" — wildcard grants too much
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/v1/payments/reconcile"]
```

Never use wildcard SPIFFE ID matching in federation authorization policies. A wildcard `spiffe://partner.com/*` means any workload in the partner's trust domain can access your service — including workloads the partner added after you established the relationship.

### Monitoring Federated Authentication

Federated authentication events require their own monitoring strategy. Standard authentication alerts ("failed password attempt") don't apply — federation failures look different.

**Events to alert on**

```yaml
# Example alert rules — translate to your SIEM query language

# 1. New federation trust relationship created in IdP
# Keycloak: admin events with operationType=CREATE, resourceType=IDENTITY_PROVIDER
# Entra ID: AuditLogs | where OperationName == "Add federated identity credential"
- alert: NewFederationTrustCreated
  description: A new IdP trust or federated identity credential was added
  severity: high
  action: Require change ticket reference; review new trust scope

# 2. Authentication from a new federated IdP (unexpected issuer)
- alert: UnexpectedFederationIssuer
  description: Login accepted from an issuer not in the approved IdP list
  severity: critical
  action: Immediate investigation; check for IdP misconfiguration or rogue trust

# 3. Attribute values outside expected range
# e.g., group claim contains a value not in the known group list
- alert: UnknownGroupInFederationAssertion
  description: SAML assertion contains a group value not in the known group mapping
  severity: medium
  action: Investigate whether IdP group was added without change control

# 4. JIT provisioning rate spike
- alert: JITProvisioningSpike
  description: More than N new users provisioned from federation in 1 hour
  severity: high
  action: May indicate compromised IdP issuing assertions for non-existent users

# 5. Assertion replay attempt
- alert: SAMLAssertionReplayAttempted
  description: SAML assertion ID was submitted more than once
  severity: high
  action: Investigate the source IP; check for assertion theft
```

**Log what matters**

Every federated authentication event should log: the IdP entity ID or issuer URL, the authenticated user's identifier, the complete set of attributes received (group memberships, roles), the SP that processed the assertion, the assertion ID, and the result. This creates a complete audit trail for "what access did this federation trust grant, to whom, and when".

### Decommissioning Federation Safely

Removing a trusted IdP from your system requires a migration plan. An abrupt removal locks out every user who authenticated only through that IdP.

**Pre-removal checklist**

1. **Identify all users sourced from this IdP.** Query your user store for accounts whose `identity_provider` field matches the IdP being decommissioned. In most systems, JIT-provisioned accounts carry the IdP as metadata.

2. **Assess their current access.** What roles do these users hold? Are any of them application admins or owners?

3. **Plan migration.** Options: migrate users to a new IdP (new federation trust), convert to local credentials, or disable accounts if the relationship is genuinely ending.

4. **Set a cutover date and notify users** at least 30 days in advance for non-emergency decommissions.

5. **Disable the IdP trust before removing it.** Disabling (not deleting) allows you to re-enable quickly if the migration fails. Verify no users are logging in via the disabled IdP before deleting the trust.

```bash
# Keycloak — disable an identity provider (does not delete it)
kcadm.sh update identity-provider/instances/partner-company-saml \
  -r your-realm \
  -s enabled=false

# Verify no active sessions from this IdP (check realm sessions)
kcadm.sh get sessions/realm -r your-realm \
  | jq '.[] | select(.identityProvider == "partner-company-saml")'

# After confirmed migration — delete the trust
# Note: this is irreversible in most IdPs
kcadm.sh delete identity-provider/instances/partner-company-saml -r your-realm
```

6. **Remove the SP metadata from the partner IdP.** Federation is bidirectional. Removing the trust from your side prevents new logins; removing your SP's metadata from the partner IdP prevents the partner from issuing assertions addressed to your SP entity ID in future (assertions that would be rejected by your SP but could indicate continued attempts).

7. **Audit residual access.** After decommission, run an access review of all accounts that were sourced from the removed IdP. Accounts that were converted to local credentials now have no IdP-driven attribute updates — their role assignments are now static and should be reviewed periodically.

## Verification

**Test SAML signature enforcement**

```python
# Use the python-saml test utilities to verify your SP rejects:
# 1. Assertions with no signature
# 2. Assertions with SHA-1 signatures
# 3. Assertions with mismatched audience
# 4. Replayed assertion IDs

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# Test: verify assertion with wrong audience is rejected
malformed_assertion = build_test_assertion(
    audience="https://wrong-sp.example.com/saml/metadata",
    valid_signature=True
)
# Your SP should raise an exception, not grant access
```

**Test attribute mapping boundaries**

Before deploying attribute mapping changes to production, test with crafted assertions that include:
- Groups that should map to admin roles (to verify admin is not grantable via federation if you've excluded it)
- Unknown group values (to verify they default to no-access, not to some default role)
- Missing required attributes (to verify the SP rejects incomplete assertions rather than failing open)

**Audit active federation trusts quarterly**

```bash
# Entra ID — list all configured identity providers
az ad app list --query "[?contains(web.redirectUriSettings[].uri, 'saml')]" --output table

# Keycloak — list all identity providers across all realms
for realm in $(kcadm.sh get realms --fields realm | jq -r '.[].realm'); do
  echo "=== $realm ==="
  kcadm.sh get identity-provider/instances -r "$realm" \
    --fields alias,providerId,enabled,config.singleSignOnServiceUrl
done
```

Compare the output against your documented federation trust register. Any IdP trust not in the register is an uncontrolled trust relationship and should be investigated immediately.

## References

- [SAML Security Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [NIST SP 800-63C — Federation and Assertions](https://pages.nist.gov/800-63-4/sp800-63c.html)
- [SPIFFE Federation Documentation](https://spiffe.io/docs/latest/architecture/federation/)
- [XML Signature Wrapping Attacks — Felix Günther et al.](https://doi.org/10.1145/2382196.2382204)
- [SAML 2.0 Security Considerations — OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- [Entra ID Federation Security — Microsoft](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp)
