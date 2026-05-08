---
title: "Financial-Grade API (FAPI 2.0) Security: Open Banking, PSD2, and DPoP-Bound Tokens"
description: "FAPI 2.0 is the OpenID Foundation's security profile for high-value financial APIs — used by Open Banking UK, PSD2 in Europe, and CDR in Australia. It mandates mTLS sender-binding, DPoP proof-of-possession, PAR, and pushed authorization. This guide implements FAPI 2.0 requirements and shows how each control addresses specific financial API attack vectors."
slug: financial-grade-api-fapi-security
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - fapi
  - open-banking
  - psd2
  - oauth2
  - dpop
personas:
  - security-engineer
  - platform-engineer
article_number: 627
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/network/financial-grade-api-fapi-security/
---

# Financial-Grade API (FAPI 2.0) Security: Open Banking, PSD2, and DPoP-Bound Tokens

## Problem

Standard OAuth 2.0 and OpenID Connect were designed for general-purpose delegation scenarios — a user granting a third-party app access to their Google Drive or GitHub repositories. Financial APIs face a categorically different threat model. The consequences of a compromised access token in a payment initiation flow are immediate and irreversible: funds move, account data is exfiltrated, and regulatory penalties follow.

Standard OAuth 2.0 bearer tokens have three fundamental weaknesses in financial contexts:

**Token replay.** A bearer token is a secret string. Whoever presents it is authenticated. If an attacker intercepts the token — from a TLS interception point, a misconfigured logging pipeline that captures Authorization headers, or a compromised proxy — they can replay it from any device, any IP, any location, until it expires. The resource server has no mechanism to verify that the entity presenting the token is the same entity that obtained it.

**Authorization request tampering.** In the standard OAuth authorization code flow, the client constructs an authorization URL and redirects the user's browser. Those query parameters travel through the browser, through redirect chains, and potentially through analytics and logging systems. An attacker positioned anywhere in that chain can modify `scope`, `redirect_uri`, or `state` parameters before they reach the authorization server. Mix-up attacks — where the client is tricked into sending credentials to the wrong authorization server — are a documented attack class against multi-AS deployments.

**No proof of intended recipient.** A standard access token carries no binding to the client that requested it. If a token is issued to TPP-A and somehow obtained by TPP-B, TPP-B can use it freely. There is no cryptographic link between the token and the key material of the legitimate client.

### Regulatory Context

Three major regulatory frameworks mandate FAPI-compliant implementations:

- **Open Banking UK (FCA):** The Open Banking Implementation Entity (OBIE) mandates FAPI 1.0 Advanced for all CMA9 banks, with FAPI 2.0 baseline under active migration. Third-party providers must be registered with the FCA and present valid eIDAS or OBIE certificates.
- **PSD2 RTS (EBA):** The European Banking Authority's Regulatory Technical Standards on Strong Customer Authentication require TPPs to authenticate to ASPSPs (banks) using qualified electronic seals (QESeal certificates). The Berlin Group's NextGenPSD2 framework maps directly to FAPI security requirements.
- **Australian CDR:** The Consumer Data Right framework mandates FAPI 1.0 Advanced and is transitioning to FAPI 2.0. The ACCC registers data holders and accredited data recipients, and mutual TLS with sector-specific certificates is required for all API calls.

FAPI 2.0 — published by the OpenID Foundation — is the current-generation profile. It replaces FAPI 1.0 Advanced, removes the implicit flow entirely, mandates DPoP or mTLS for sender-constraining tokens, and requires Pushed Authorization Requests as the baseline authorization initiation mechanism.

## Threat Model

**Stolen TPP credentials replayed from a different device.** A third-party provider's OAuth client secret or private key is extracted from a compromised server. The attacker uses these credentials to obtain access tokens from the authorization server. With standard OAuth, those tokens work from any IP or device. With mTLS sender-constraining (RFC 8705), the token is cryptographically bound to the client certificate that was presented during token issuance — an attacker without that certificate cannot use the token.

**Authorization request injection.** During the OAuth authorization code flow, an attacker injects a crafted authorization request — modifying the `scope` to include account data the user never consented to, or swapping the `redirect_uri` to an attacker-controlled endpoint. PAR (RFC 9126) eliminates this by having the client submit the full authorization request directly to the authorization server's PAR endpoint before any redirect occurs. The AS returns a `request_uri` reference. Nothing sensitive travels through the browser.

**Man-in-the-middle on the API gateway stripping or replacing TLS client certificates.** An attacker or misconfigured proxy between the TPP and the bank's API gateway terminates TLS and re-establishes a new TLS connection upstream without the client certificate. If the backend API server trusts the gateway's forwarded certificate header without validating that it came from a legitimate mTLS termination point, the MTLS binding is bypassed. Correct deployments validate the `cnf.x5t#S256` claim in the access token against a certificate fingerprint that was verified at the TLS layer before token issuance — not from a header that downstream components could forge.

## Configuration

### mTLS Sender-Constrained Tokens (RFC 8705)

Mutual TLS token binding works as follows: when the TPP client authenticates to the authorization server to obtain a token, it presents its TLS client certificate. The authorization server computes the SHA-256 thumbprint of that certificate and embeds it in the access token as the `cnf.x5t#S256` claim. At the resource server, every API request must be made over mTLS with the same client certificate. The resource server extracts the certificate thumbprint from the TLS session and compares it against the `cnf.x5t#S256` claim in the token. If they do not match, the request is rejected.

**Nginx mTLS configuration for an Open Banking API gateway:**

```nginx
# /etc/nginx/conf.d/openbanking-api.conf

server {
    listen 443 ssl;
    server_name api.bank.example.com;

    # Server certificate
    ssl_certificate     /etc/ssl/certs/bank-api-server.pem;
    ssl_certificate_key /etc/ssl/private/bank-api-server.key;

    # Require client certificate from a trusted CA
    # Open Banking UK: OBIE root CA or FCA-approved eIDAS CA
    ssl_client_certificate /etc/ssl/certs/obie-root-ca-bundle.pem;
    ssl_verify_client      on;
    ssl_verify_depth       3;

    # Minimum TLS version — FAPI 2.0 requires TLS 1.2 minimum, 1.3 preferred
    ssl_protocols TLSv1.2 TLSv1.3;

    # Restricted cipher suites — no RC4, no 3DES, no export ciphers
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;

    # OCSP stapling for certificate status
    ssl_stapling        on;
    ssl_stapling_verify on;

    location /open-banking/v3.1/ {
        # Forward client certificate fingerprint (SHA-256) to upstream
        # The upstream token introspection service uses this to verify cnf binding
        proxy_set_header X-Client-Cert-Thumbprint $ssl_client_fingerprint;

        # Forward the full client certificate for introspection (PEM-encoded, URL-encoded)
        proxy_set_header X-Client-Cert            $ssl_client_escaped_cert;

        # Do NOT trust these headers from downstream — only set them here at TLS termination
        proxy_pass http://openbanking-backend;

        # Security headers required by Open Banking UK
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
    }
}
```

**Token introspection response with certificate binding:**

```json
{
  "active": true,
  "sub": "user-12345",
  "scope": "accounts payments",
  "client_id": "tpp-client-abc",
  "exp": 1715097600,
  "iat": 1715094000,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

The backend API validates `cnf.x5t#S256` against `X-Client-Cert-Thumbprint`. If they do not match, return `401 Unauthorized`. The critical implementation point: the `X-Client-Cert-Thumbprint` header must only be trusted when it arrives from the Nginx mTLS termination point — never from an arbitrary caller who could forge the header value.

**Envoy mTLS with certificate forwarding:**

```yaml
# envoy-openbanking-listener.yaml
static_resources:
  listeners:
  - name: openbanking_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: 8443 }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain: { filename: /etc/ssl/certs/bank-api-server.pem }
              private_key: { filename: /etc/ssl/private/bank-api-server.key }
            validation_context:
              trusted_ca: { filename: /etc/ssl/certs/obie-root-ca-bundle.pem }
              verify_certificate_spki:
              - "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2="
            tls_params:
              tls_minimum_protocol_version: TLSv1_2
              cipher_suites:
              - ECDHE-ECDSA-AES256-GCM-SHA384
              - ECDHE-RSA-AES256-GCM-SHA384
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          forward_client_cert_details: SANITIZE_SET
          set_current_client_cert_details:
            subject: true
            cert: true
            chain: true
            dns: true
            uri: true
```

### DPoP — Demonstrating Proof of Possession (RFC 9449)

DPoP is an alternative (or complement) to mTLS for sender-constraining tokens. Instead of binding a token to a client certificate, DPoP binds it to an ephemeral asymmetric key pair that the client generates. For every HTTP request to a protected resource, the client signs a DPoP proof JWT with the private key. The resource server validates the proof.

**DPoP proof structure.** The proof is a JWT with a JOSE header containing `typ: dpop+jwt` and the public key in JWK format. The payload contains:

- `jti`: a unique identifier (prevents proof replay)
- `htm`: the HTTP method of the request (`GET`, `POST`, etc.)
- `htu`: the HTTP URI of the request (without query string or fragment)
- `iat`: issued-at timestamp (proofs are only valid within a tight window — typically ±60 seconds)
- `nonce`: a server-provided nonce (prevents offline replay; the resource server rotates nonces)
- `ath`: when using DPoP with an access token, the SHA-256 hash of the token (base64url-encoded)

**Python DPoP proof generation:**

```python
import base64
import hashlib
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import jwt  # PyJWT >= 2.8.0

def generate_dpop_key_pair():
    """Generate an ephemeral EC P-256 key pair for DPoP."""
    private_key = generate_private_key(SECP256R1())
    return private_key

def private_key_to_jwk(private_key):
    """Convert EC private key to JWK format (public portion only)."""
    public_key = private_key.public_key()
    public_numbers = public_key.public_key().public_numbers()  # type: ignore
    x = base64.urlsafe_b64encode(
        public_numbers.x.to_bytes(32, "big")
    ).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(
        public_numbers.y.to_bytes(32, "big")
    ).rstrip(b"=").decode()
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y}

def create_dpop_proof(
    private_key,
    http_method: str,
    http_uri: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """
    Create a DPoP proof JWT for an HTTP request.

    Args:
        private_key: The EC private key to sign with.
        http_method: The HTTP method in uppercase (e.g. "GET", "POST").
        http_uri: The full request URI without query string or fragment.
        access_token: If present, include the ath claim (token hash).
        nonce: If present, include the server-provided nonce.

    Returns:
        A signed DPoP proof JWT string.
    """
    jwk_public = private_key_to_jwk(private_key)

    headers = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk_public,
    }

    payload: dict = {
        "jti": str(uuid.uuid4()),
        "htm": http_method.upper(),
        "htu": http_uri,
        "iat": int(time.time()),
    }

    if access_token is not None:
        # ath: base64url(SHA-256(access_token_ascii_bytes))
        token_hash = hashlib.sha256(access_token.encode("ascii")).digest()
        payload["ath"] = base64.urlsafe_b64encode(token_hash).rstrip(b"=").decode()

    if nonce is not None:
        payload["nonce"] = nonce

    proof = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
    return proof
```

**Go DPoP proof validation at the resource server:**

```go
package dpop

import (
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

const (
    maxProofAge    = 60 * time.Second
    dpopHeaderName = "DPoP"
)

type DPoPClaims struct {
    JTI   string `json:"jti"`
    HTM   string `json:"htm"`
    HTU   string `json:"htu"`
    ATH   string `json:"ath,omitempty"`
    Nonce string `json:"nonce,omitempty"`
    jwt.RegisteredClaims
}

// ValidateDPoPProof validates a DPoP proof header against the incoming request.
// It checks:
//   - proof signature against the public key embedded in the JWT header
//   - htm matches the request method
//   - htu matches the request URI (scheme + host + path, no query)
//   - iat is within the acceptable skew window
//   - ath matches the SHA-256 of the bearer access token (if provided)
//   - nonce matches the expected server nonce (if nonce enforcement is enabled)
func ValidateDPoPProof(
    r *http.Request,
    accessToken string,
    expectedNonce string,
    usedJTIs JTIStore,
) error {
    proofHeader := r.Header.Get(dpopHeaderName)
    if proofHeader == "" {
        return errors.New("missing DPoP proof header")
    }

    // Parse without verification first to extract the embedded JWK
    unverified, _, err := new(jwt.Parser).ParseUnverified(proofHeader, &DPoPClaims{})
    if err != nil {
        return fmt.Errorf("unparseable DPoP proof: %w", err)
    }

    // Extract jwk from header
    jwkRaw, ok := unverified.Header["jwk"]
    if !ok {
        return errors.New("DPoP proof missing jwk header")
    }

    pubKey, err := extractPublicKeyFromJWK(jwkRaw)
    if err != nil {
        return fmt.Errorf("invalid jwk in DPoP proof: %w", err)
    }

    // Now verify signature with the extracted public key
    token, err := jwt.ParseWithClaims(
        proofHeader,
        &DPoPClaims{},
        func(t *jwt.Token) (interface{}, error) {
            if t.Header["typ"] != "dpop+jwt" {
                return nil, errors.New("DPoP proof must have typ=dpop+jwt")
            }
            return pubKey, nil
        },
    )
    if err != nil || !token.Valid {
        return fmt.Errorf("DPoP proof signature invalid: %w", err)
    }

    claims, ok := token.Claims.(*DPoPClaims)
    if !ok {
        return errors.New("failed to extract DPoP claims")
    }

    // Validate htm
    if !strings.EqualFold(claims.HTM, r.Method) {
        return fmt.Errorf("DPoP htm mismatch: got %q, want %q", claims.HTM, r.Method)
    }

    // Validate htu (scheme + host + path, no query/fragment)
    expectedHTU := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
    if claims.HTU != expectedHTU {
        return fmt.Errorf("DPoP htu mismatch: got %q, want %q", claims.HTU, expectedHTU)
    }

    // Validate iat (freshness)
    iat := claims.IssuedAt.Time
    if time.Since(iat) > maxProofAge || time.Until(iat) > maxProofAge {
        return fmt.Errorf("DPoP proof iat out of acceptable window: %v", iat)
    }

    // Validate jti uniqueness (replay prevention)
    if usedJTIs.Contains(claims.JTI) {
        return fmt.Errorf("DPoP proof jti already used: %s", claims.JTI)
    }
    usedJTIs.Add(claims.JTI, iat.Add(maxProofAge*2))

    // Validate ath if access token is present
    if accessToken != "" {
        hash := sha256.Sum256([]byte(accessToken))
        expectedATH := base64.RawURLEncoding.EncodeToString(hash[:])
        if claims.ATH != expectedATH {
            return errors.New("DPoP ath does not match access token hash")
        }
    }

    // Validate nonce if enforcement is active
    if expectedNonce != "" && claims.Nonce != expectedNonce {
        return errors.New("DPoP nonce mismatch")
    }

    return nil
}
```

### Pushed Authorization Requests (PAR, RFC 9126)

In a standard authorization code flow, the client constructs an authorization URL and redirects the user's browser to it. The full set of authorization parameters — `scope`, `redirect_uri`, `state`, `code_challenge` — travels through the browser and is visible in server logs, referrer headers, and browser history.

PAR inverts this. Before redirecting the user, the client POSTs the authorization request directly to the authorization server's PAR endpoint using its client credentials. The AS validates the request immediately and returns a `request_uri` — an opaque reference that expires in 60–90 seconds. The client then redirects the user using only that reference. Nothing sensitive travels through the browser.

```
POST /as/par HTTP/1.1
Host: auth.bank.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <client_assertion_jwt>

response_type=code
&client_id=tpp-client-abc
&redirect_uri=https%3A%2F%2Ftpp.example.com%2Fcallback
&scope=openid+accounts+payments
&state=abc123
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
```

The AS responds:

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY",
  "expires_in": 60
}
```

The client then redirects to:

```
https://auth.bank.example.com/authorize
  ?client_id=tpp-client-abc
  &request_uri=urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY
```

FAPI 2.0 mandates PAR. Authorization servers that accept authorization requests directly via redirect (without PAR) are non-compliant.

**Keycloak PAR configuration:**

```properties
# keycloak/conf/keycloak.conf
features=par
par-request-uri-lifespan=60
```

### JWT Authorization Requests (JAR, RFC 9101)

JAR adds a second layer of protection: the entire authorization request is signed as a JWT using the client's private key. Even if request parameters are somehow visible in transit, they cannot be modified without invalidating the signature. Combined with PAR, JAR provides both confidentiality (nothing in the browser) and integrity (signed by the client).

With JAR, the PAR request body becomes:

```
POST /as/par HTTP/1.1
Host: auth.bank.example.com
Content-Type: application/x-www-form-urlencoded

client_id=tpp-client-abc
&request=eyJhbGciOiJQUzI1NiIsImtpZCI6InRwcC1zaWduaW5nLWtleSJ9...
```

The `request` parameter is a signed JWT (using PS256 or ES256) containing all authorization parameters.

### JARM — JWT Secured Authorization Response Mode (FAPI 2.0)

FAPI 2.0 mandates that authorization responses are also signed. Instead of the AS returning `code=abc&state=xyz` in the redirect, it returns a signed JWT: `response=eyJ...`. The client verifies the JWT signature against the AS's published JWKS before using the authorization code.

This prevents:
- Code injection: an attacker inserting a valid-looking authorization code they control
- Response tampering: modification of `state` or other parameters

### FAPI 2.0 Compliance Checklist

| Requirement | Standard | Status Check |
|---|---|---|
| PKCE with S256 required | RFC 7636 | Reject `code_challenge_method=plain` |
| No implicit flow | FAPI 2.0 §4.3 | Reject `response_type=token` or `response_type=id_token` |
| No `response_type=token` | FAPI 2.0 §4.3 | Authorization server rejects |
| PAR required | RFC 9126 | Reject authorization requests not via PAR |
| JAR for request signing | RFC 9101 | Require signed `request` parameter |
| mTLS or DPoP sender-constraining | RFC 8705 / RFC 9449 | Token introspection validates `cnf` |
| TLS 1.2 minimum | FAPI 2.0 §6 | Nginx/Envoy: `ssl_protocols TLSv1.2 TLSv1.3` |
| No weak cipher suites | FAPI 2.0 §6 | No RC4, 3DES, NULL, EXPORT ciphers |
| Authorization code ≤ 10 minutes | FAPI 2.0 §4.3.1 | AS configuration |
| Access token ≤ 5 minutes | FAPI 2.0 §4.3.1 | AS configuration |
| Refresh token rotation | FAPI 2.0 | Issue new RT on each refresh |
| JARM signed authorization response | OIDF JARM | `response_mode=jwt` |
| Nonce binding in ID token | OIDC §3.1.2 | ID token `nonce` must match request |
| PKJWT client authentication | RFC 7523 | `private_key_jwt` client auth method |

## Expected Behaviour

| Attack Vector | FAPI Control | Verification |
|---|---|---|
| Bearer token replayed from stolen credential | mTLS sender-constraining (RFC 8705) | Resource server compares `cnf.x5t#S256` against TLS session certificate fingerprint |
| Bearer token replayed with DPoP key compromise | DPoP nonce binding (RFC 9449) | Nonce rotated by server; old proofs rejected; jti uniqueness enforced |
| Authorization request injection via browser | PAR (RFC 9126) | AS validates request before redirect; browser only carries opaque `request_uri` |
| Parameter tampering in authorization redirect | JAR (RFC 9101) | Authorization request signed by client; AS rejects unsigned or tampered requests |
| Authorization response code injection | JARM | AS signs authorization response; client verifies signature before exchanging code |
| Mix-up attack (wrong AS receives code) | `iss` parameter (RFC 9207) | Client validates `iss` in authorization response matches expected AS |
| CSRF on redirect | PKCE + state | `code_verifier` / `state` bound to session; cannot be replayed cross-site |
| MitM stripping client certificate header | mTLS at TLS layer | `X-Client-Cert-Thumbprint` only set at mTLS termination point; downstream can't forge |
| Token replay after TLS interception | DPoP `htm`/`htu`/`iat` claims | Proof binds token to exact HTTP method, URI, and timestamp |
| Expired or reused DPoP proof | jti + iat validation | JTI stored in short-lived cache; iat outside ±60s window rejected |

## Trade-offs

**Implementation complexity.** A standard OAuth 2.0 integration requires configuring an authorization server, validating JWTs, and managing client secrets. A FAPI 2.0 compliant implementation adds: mTLS certificate management across all TPPs, DPoP key generation and proof creation on every request, PAR endpoint integration, JAR signing, JARM validation, and PKJWT client authentication. The attack surface is meaningfully reduced, but the integration surface is substantially larger.

**Latency.** DPoP proof generation is asymmetric cryptographic work. For EC P-256, proof signing takes approximately 0.1–0.3 ms on modern hardware — negligible per-request overhead. But DPoP validation at the resource server includes a JTI uniqueness check against a distributed cache (Redis, Memcached). Under high throughput, that cache lookup adds 1–5 ms of latency. mTLS adds TLS handshake overhead, particularly for short-lived connections. Connection pooling and session resumption mitigate this, but connection resumption must be configured carefully — TLS session tickets can bypass client certificate re-validation if the session ticket key is long-lived.

**Certificate management overhead.** Open Banking UK requires TPPs to use OBIE-issued certificates or FCA-approved eIDAS certificates. These have 1–2 year validity periods and must be revoked via OCSP when a TPP's registration is cancelled. The bank's API gateway must validate OCSP responses on every mTLS handshake — or use OCSP stapling with a short staple refresh interval (≤1 hour for regulatory contexts). CRL distribution is an alternative but produces larger payloads and is slower to reflect revocations. A TPP whose FCA registration is cancelled should lose API access within hours, not days.

**Key rotation for DPoP.** DPoP keys are ephemeral by design — clients can generate a new key pair for each session or even each token request. But if the client generates a key pair per token, the authorization server must bind the token to that specific key and the resource server must validate against it. Long-lived DPoP key pairs are simpler operationally but widen the window of exposure if the private key is compromised. FAPI 2.0 implementations should generate DPoP key pairs per authorization session and discard them after the session ends.

## Failure Modes

Common FAPI implementation mistakes observed in Open Banking assessments:

**Trusting the certificate header without verifying source.** The most prevalent finding: the API gateway correctly terminates mTLS, extracts the client certificate, and forwards it as an HTTP header (`X-Client-Cert` or `X-SSL-Client-Cert`). But the upstream application also accepts this header from unauthenticated callers. Any client can forge the header and present any certificate thumbprint, bypassing mTLS binding entirely. The fix: strip certificate headers at the edge proxy and only re-add them after mTLS termination. Add network policy or IP allowlisting to ensure the upstream only accepts requests from the mTLS termination point.

**DPoP proof not bound to access token.** RFC 9449 requires the `ath` claim (SHA-256 of the access token) in DPoP proofs used at resource servers. Implementations that validate the DPoP proof structure but skip `ath` verification allow an attacker who obtains a valid DPoP-protected access token to use it with any DPoP key pair — defeating the purpose of DPoP. The resource server must always validate `ath` when an access token is present.

**PAR implemented but not enforced.** The authorization server exposes a PAR endpoint, and compliant TPPs use it. But the server also continues to accept direct authorization requests without PAR. Non-compliant integrations proceed undetected. FAPI 2.0 requires the AS to reject authorization requests that do not reference a valid `request_uri`. This must be enforced at the AS level, not left to TPP compliance.

**Weak client authentication alongside PKJWT.** FAPI 2.0 requires `private_key_jwt` for client authentication. Some authorization servers are configured to accept `client_secret_basic` as a fallback. A TPP that fails to configure private key authentication falls back to the weaker method without error. The AS must explicitly disable all client authentication methods except `private_key_jwt` and `tls_client_auth` (for mTLS client authentication).

**Authorization code lifetime not enforced.** FAPI 2.0 requires authorization codes to be valid for at most 10 minutes. Authorization servers with default configuration often issue codes valid for 30 minutes to 1 hour. An authorization code intercepted from a log or a browser's history has a much larger replay window than intended.

**DPoP nonce not rotated.** Nonce binding is a FAPI 2.0 requirement for DPoP. Resource servers that implement DPoP but never rotate nonces — or use static nonces — defeat the replay-prevention purpose of nonces. Nonces should be rotated at a cadence shorter than the access token lifetime (e.g., every 30–60 seconds for 5-minute tokens).

**JARM not validated before code exchange.** The client receives a signed authorization response JWT, extracts the code, and exchanges it immediately — without verifying the JARM signature. An attacker who can inject a crafted authorization response (code injection) bypasses JARM protection entirely. JARM validation must happen before the code is used.

**TLS version misconfiguration.** FAPI 2.0 requires TLS 1.2 minimum and prohibits weak cipher suites. Nginx configurations that include `TLSv1` or `TLSv1.1` in `ssl_protocols`, or that include `ssl_ciphers ALL` or `ssl_ciphers HIGH:MEDIUM`, will pass basic connectivity testing but fail FAPI security assessments. Use explicit cipher suite allowlists and verify with `openssl s_client -tls1` that TLS 1.0 connections are rejected.
