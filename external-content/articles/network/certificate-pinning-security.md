---
title: "Certificate Pinning Security: Modern Approaches After HPKP Deprecation"
description: "HTTP Public Key Pinning was deprecated in 2018 after bricking sites and creating unrecoverable outages. This article covers what replaces it: static pinning in mobile apps via Android NSC and iOS NSPinnedDomains, SPKI hash pinning in Go service clients, DANE/TLSA, CAA records, mTLS for service-to-service auth, and CT log monitoring — plus when pinning causes more harm than it prevents."
slug: certificate-pinning-security
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - certificate-pinning
  - tls
  - hpkp
  - mobile-security
  - zero-trust
personas:
  - security-engineer
  - platform-engineer
article_number: 503
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/certificate-pinning-security/
---

# Certificate Pinning Security: Modern Approaches After HPKP Deprecation

## The Problem

The TLS certificate authority system has a structural flaw that pinning was designed to correct: any of the roughly 150 publicly trusted CAs can issue a valid, browser-trusted certificate for any domain, at any time, without the domain owner's knowledge or consent.

This is not a theoretical concern. In 2011, DigiNotar — a Dutch CA — was compromised. The attacker issued wildcard certificates for `*.google.com`, `*.yahoo.com`, and dozens of other high-value domains. These certificates were used by Iranian intelligence to intercept HTTPS traffic for hundreds of thousands of Iranian citizens via a government-operated man-in-the-middle proxy. DigiNotar was bankrupt within weeks, but the damage was done and the attack had been active for months before discovery.

In 2016, WoSign — a Chinese CA — was caught backdating certificates and issuing SHA-1 certificates after the industry deadline. The CA also issued certificates for domains its customers did not control. Mozilla and Apple removed WoSign from their trust stores.

Corporate environments introduce a different class of threat: enterprise TLS inspection. Security appliances from products like Palo Alto, Zscaler, and Cisco Umbrella perform legitimate MitM decryption by installing a corporate root CA in all managed endpoints. From a security monitoring perspective, this is intentional. From the perspective of a mobile application connecting to its backend API, it is indistinguishable from an attack.

Certificate pinning was the response to all of these scenarios: instead of trusting the global CA store, a client hard-codes exactly which certificates or public keys it will accept for a given server. Anything else — even a valid, properly signed certificate — is rejected.

The approach works. The problem is that it also fails catastrophically when it goes wrong.

## Why HPKP Failed

HTTP Public Key Pinning (HPKP, RFC 7469) was standardised in 2015. The mechanism was elegant: a web server sent a `Public-Key-Pins` HTTP response header listing the SHA-256 hashes of acceptable SPKI values for its certificate chain. Browsers cached these pins for the duration of the `max-age` directive — up to months — and refused future connections that presented a non-pinned certificate.

The failure modes were not subtle.

**Bricking via header injection.** Any server-side vulnerability that allowed an attacker to inject arbitrary HTTP response headers — reflected XSS writing to a `Set-Cookie` analog, a misconfigured reverse proxy prepending headers, even a buggy CDN — could be used to serve a `Public-Key-Pins` header pointing to a key the attacker controlled. Browsers would cache the pin. When the legitimate certificate rotated, browsers would reject it. The site would be unreachable for the entire `max-age` period for every user who received the injected header. There was no recovery mechanism.

**Misconfiguration with no safety net.** Unlike most security headers, a wrong HPKP configuration is not merely ineffective — it is actively destructive. Setting a pin for the current certificate without including a backup pin for the next key meant that any certificate renewal created a browser lockout. Operators who set `max-age=5184000` (60 days) and then lost access to their private key had no recourse. The website was gone for 60 days from the perspective of any browser that had cached the pin.

**No enterprise proxy compatibility.** Every enterprise that deployed TLS inspection was incompatible with HPKP. The corporate MitM certificate would not match the pin, so HPKP-enabled sites became unreachable for corporate users — a significant real-world support and compatibility problem.

Chrome removed HPKP support in Chrome 67 (May 2018). Firefox followed. The RFC remains as historical reference. HPKP is dead.

## What Replaced It

The HPKP post-mortem produced a set of layered alternatives that together achieve most of what HPKP intended, without the single-point-of-failure failure mode.

### Certificate Transparency

Certificate Transparency (RFC 9162) requires every publicly trusted certificate to be logged in a public, append-only, cryptographically auditable log before browsers will trust it. This does not prevent a rogue CA from issuing a certificate for your domain — it makes such issuance publicly visible within minutes.

CT monitoring, combined with alerting on unexpected issuances, provides detection rather than prevention. For most public-facing services this is the right trade-off: you learn about a rogue certificate immediately and can respond (revoke, notify, investigate) rather than blocking the connection in a way that might also break legitimate users.

The `Expect-CT` header has been deprecated as CT is now mandatory. The practical tooling is covered in detail in [TLS Certificate Transparency Monitoring](/articles/network/tls-certificate-transparency/).

### CAA DNS Records

Certification Authority Authorization (CAA, RFC 8659) is a DNS record that specifies which CAs are permitted to issue certificates for a domain. A compliant CA must check CAA records before issuance and refuse if not listed.

```bash
# Query CAA records for a domain
dig CAA example.com

# Example CAA record set — only Let's Encrypt and DigiCert permitted
example.com. 300 IN CAA 0 issue "letsencrypt.org"
example.com. 300 IN CAA 0 issue "digicert.com"
example.com. 300 IN CAA 0 issuewild "digicert.com"
example.com. 300 IN CAA 0 iodef "mailto:security@example.com"
```

CAA records reduce the attack surface — a rogue CA that honours CAA records cannot issue for your domain. The limits: CAA is advisory for CAs (though it is a baseline requirement in the CA/Browser Forum), and a fully compromised CA can ignore it. CAA is a useful preventive control, not a guarantee.

### DANE/TLSA

DNS-Based Authentication of Named Entities (DANE, RFC 6698) uses DNSSEC-secured DNS records to specify exactly which TLS certificate or public key a service should present. A `TLSA` record in DNS acts like HPKP but is managed in DNS rather than via HTTP headers, and requires DNSSEC to prevent DNS spoofing.

```bash
# TLSA record for SMTP on port 25 with DNSSEC
# Format: usage selector matching-type cert-data
# Usage 3 (DANE-EE) = exact certificate match
# Selector 1 = SPKI hash
# Matching type 1 = SHA-256

_25._tcp.mail.example.com. 300 IN TLSA 3 1 1 (
  abc123def456...  # SHA-256 of the SPKI
)

# Generate the SPKI hash for a certificate
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | base64
```

DANE is widely used for SMTP (email delivery) where DNSSEC adoption is higher. For HTTPS it sees limited deployment because most clients do not perform DNSSEC validation. DANE solves the rogue CA problem elegantly where it is deployable, but the DNSSEC dependency limits its reach.

## Static Certificate Pinning in Mobile Applications

Mobile applications — iOS and Android — are the primary use case where static certificate pinning remains the right answer. The client is controlled software distributed by the developer. The server endpoints are known at build time. The risk of a corporate proxy intercepting your banking app's API traffic is a real threat model, not a paranoid edge case.

The key decision is what to pin:

- **Leaf certificate**: strongest binding, breaks on every certificate renewal. Acceptable only if you ship updates frequently and control the renewal cadence precisely.
- **Intermediate CA certificate**: rotates less often (typically 1-5 years), provides a buffer for leaf rotation without breaking the pin. Recommended for most cases.
- **Public key hash (SPKI)**: pin the public key rather than the certificate. You can renew the certificate (new expiry, new issuer, new SAN) without changing the pin, as long as you keep the same key pair. This is the preferred approach when you want pinning without operational brittleness.

### Android: Network Security Config

Android 7.0+ supports declarative certificate pinning via a `network_security_config.xml` file. No code changes required; the OS enforces the policy.

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>

        <pin-set expiration="2027-01-01">
            <!-- Primary pin: SHA-256 of the SPKI, base64-encoded -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- Backup pin: next key pair, generated and stored offline -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>

        <!-- Trust system CAs only within the pinned domain -->
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml: reference the config -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

```bash
# Generate the SPKI hash from an existing certificate
openssl x509 -in api-cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64

# Or directly from a live server
openssl s_client -connect api.example.com:443 -servername api.example.com 2>/dev/null \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

The `expiration` attribute on `<pin-set>` is intentional: when the pin set expires, Android falls back to normal CA validation rather than blocking all connections. This is a hard lesson from HPKP — a built-in expiry prevents permanent lockout if something goes wrong.

### iOS: NSPinnedDomains in Info.plist

Apple introduced `NSPinnedDomains` in iOS 14 / macOS 11 as part of App Transport Security. Like Android NSC, it is declarative and enforced by the OS for `URLSession` traffic.

```xml
<!-- Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <!-- Pin the SPKI of the leaf certificate -->
            <key>NSPinnedLeafIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</string>
                </dict>
                <!-- Backup pin -->
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</string>
                </dict>
            </array>
            <!-- Or pin the CA / intermediate instead -->
            <key>NSPinnedCAIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

For third-party HTTP clients (AFNetworking, Alamofire, custom `NSURLSession` subclasses) that do not use the system stack, you must implement pinning explicitly in the `URLSessionDelegate`. The OS-level `NSPinnedDomains` only enforces for `URLSession` using the default session configuration.

## Service-to-Service TLS Pinning in Go

For internal microservices that call known, controlled endpoints, embedding the expected SPKI hash in the client provides defence-in-depth against a compromised CA or a misconfigured service mesh.

```go
package main

import (
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "errors"
    "fmt"
    "net/http"
)

// expectedSPKI is the base64-encoded SHA-256 hash of the server's SPKI.
// Pin the intermediate CA key if you want rotation flexibility without
// changing client code on every leaf renewal.
const expectedSPKI = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// backupSPKI is the backup pin — the next key pair, generated in advance.
const backupSPKI = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

func spkiHash(cert *x509.Certificate) string {
    spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
    if err != nil {
        return ""
    }
    hash := sha256.Sum256(spkiDER)
    return base64.StdEncoding.EncodeToString(hash[:])
}

func pinnedTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        // VerifyPeerCertificate is called after standard chain validation.
        // Setting InsecureSkipVerify = false (the default) means the standard
        // validation still runs — pinning is additive, not a replacement.
        VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            for _, chain := range verifiedChains {
                for _, cert := range chain {
                    h := spkiHash(cert)
                    if h == expectedSPKI || h == backupSPKI {
                        return nil // at least one cert in the chain matches
                    }
                }
            }
            return errors.New("certificate pinning: no cert in chain matched pinned SPKI")
        },
    }
}

func main() {
    transport := &http.Transport{
        TLSClientConfig: pinnedTLSConfig(),
    }
    client := &http.Client{Transport: transport}

    resp, err := client.Get("https://internal-api.example.com/health")
    if err != nil {
        fmt.Printf("request failed: %v\n", err)
        return
    }
    defer resp.Body.Close()
    fmt.Printf("status: %s\n", resp.Status)
}
```

A few implementation notes:

- Check the entire verified chain, not just the leaf. Pinning an intermediate CA key here means the leaf can rotate freely.
- Keep the standard validation path intact (`InsecureSkipVerify` remains `false`). Pinning does not replace hostname verification or expiry checking — it adds an additional constraint.
- Store the pin constants in configuration, not compiled into the binary, so you can rotate them without a full rebuild.

## mTLS as a Pinning Alternative for Service-to-Service

For service-to-service authentication inside a controlled environment, mutual TLS (mTLS) is often a cleaner solution than one-sided certificate pinning.

With mTLS both endpoints present certificates. The server verifies the client's certificate against a trusted CA, and the client verifies the server's certificate against a trusted CA. If your internal CA (cert-manager backed by Vault, for example) is the only CA either side trusts, then the effective guarantee is: only services that obtained a certificate from your internal CA can establish connections. A rogue external CA certificate is simply not in the trust store.

This achieves the core goal of pinning — rejecting certificates from unexpected issuers — without hard-coding specific key material that must be updated on every renewal. The mTLS trust anchor is the internal CA, not a specific certificate or key.

The trade-off: mTLS requires infrastructure (a CA, certificate issuance, rotation), and adds latency (client certificate exchange). For Kubernetes service meshes (Istio, Linkerd, Cilium), mTLS is typically automatic and the infrastructure cost is already paid. See [mTLS for Service-to-Service Communication](/articles/network/mtls-service-mesh/) for implementation detail.

When to use pinning over mTLS: when you are calling an external service you do not control (a third-party payment API, a government endpoint) and you want assurance that you are talking to the specific expected server rather than any server with a valid public CA certificate.

## Backup Pins Are Not Optional

Every pinning deployment — mobile app, service client, DANE record — must include at least one backup pin before going live.

The backup pin is the SPKI hash of the next key pair you will use. Generate the key pair, compute its SPKI hash, include it as a backup pin, then store the private key securely offline. When it is time to rotate:

1. Issue a new certificate using the backup key pair.
2. Deploy the new certificate to the server.
3. Update the pin set to promote the backup to primary and generate a new backup.
4. Ship the updated app / config.

If you skip the backup pin and lose access to your private key — hardware failure, HSM incident, vendor bankruptcy — your pinned clients are permanently locked out with no recovery path.

```bash
# Generate a backup key pair and compute its SPKI hash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out backup-key.pem
openssl pkey -in backup-key.pem -pubout -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
# Store backup-key.pem in your key management system, offline HSM, or secret manager
# The hash output goes into your pin configuration immediately
```

## Pinning in Kubernetes with cert-manager and OPA

In Kubernetes, cert-manager can issue certificates from a specific internal ClusterIssuer or CA. OPA Gatekeeper or Kyverno can enforce that workloads only trust expected certificate issuers.

```yaml
# cert-manager: ClusterIssuer backed by an internal CA
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: internal-ca-issuer
spec:
  ca:
    secretName: internal-ca-key-pair  # secret containing the CA cert and key
---
# Certificate for a service — issued by the internal CA only
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payment-service-tls
  namespace: payments
spec:
  secretName: payment-service-tls
  issuerRef:
    name: internal-ca-issuer
    kind: ClusterIssuer
  dnsNames:
    - payment-service.payments.svc.cluster.local
```

```yaml
# OPA Gatekeeper ConstraintTemplate: enforce expected certificate issuer
# for Ingress resources (simplified example)
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: ingresscertissuer
spec:
  crd:
    spec:
      names:
        kind: IngressCertIssuer
      validation:
        openAPIV3Schema:
          properties:
            allowedIssuers:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package ingresscertissuer

        violation[{"msg": msg}] {
          input.review.kind.kind == "Certificate"
          issuer := input.review.object.spec.issuerRef.name
          allowed := {i | i := input.parameters.allowedIssuers[_]}
          not issuer in allowed
          msg := sprintf("certificate issuer %q is not in the allowed list", [issuer])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: IngressCertIssuer
metadata:
  name: require-internal-ca
spec:
  match:
    kinds:
      - apiGroups: ["cert-manager.io"]
        kinds: ["Certificate"]
    namespaces: ["payments", "auth", "api"]
  parameters:
    allowedIssuers:
      - internal-ca-issuer
```

## Detecting Pinning Bypass Attacks

When an attacker or enterprise proxy intercepts TLS, the substituted certificate leaves observable traces.

**CT log monitoring for unexpected issuances.** If your domain has a CAA record restricting issuance to specific CAs, and you monitor CT logs for any certificate issued for your domains, an unexpected issuance from a different CA (or even an unexpected certificate from your CA) is an indicator of either CA misissuance or infrastructure compromise. Tools like [certspotter](https://github.com/SSLMate/certspotter), [crt.sh](https://crt.sh), and Cloudflare's CT log API provide monitoring interfaces.

**JA3/JA4 fingerprinting for proxy detection.** TLS interception proxies present a different TLS ClientHello fingerprint than the original client. When your server observes connections that claim to originate from your mobile app (by User-Agent or client certificate) but present a JA3 fingerprint that does not match known mobile OS TLS stacks, this is a signal that the connection is being intercepted. JA3 fingerprinting is covered in depth in [Passive TLS Fingerprinting with JA3 and JA4](/articles/network/tls-fingerprinting-ja3-ja4/).

```bash
# Extract JA3 fingerprints from a pcap to baseline expected client behaviour
# Requires zeek or the ja3 tool
zeek -r traffic.pcap /opt/zeek/share/zeek/site/ja3/ja3.zeek
grep "JA3" conn.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# Known JA3 hashes for common mobile TLS stacks (examples)
# iOS 17 URLSession:  ecc748e4a98f85d5ebb...
# Android 14 OkHttp:  b32309a26951912be7...
# Compare observed hashes against these baselines in your SIEM
```

**Certificate issuer anomaly detection.** In service meshes where all internal certificates should be issued by your internal CA, alert on any observed certificate in mTLS handshakes that chains to a public CA. This is straightforward to implement in Envoy via access log fields (`%DOWNSTREAM_PEER_ISSUER%`, `%UPSTREAM_PEER_ISSUER%`) fed into your SIEM.

## When NOT to Pin

Certificate pinning creates operational risk proportional to how hard it is to push updates to the pinning clients. Before implementing pinning, ask whether the threat model justifies the maintenance overhead.

**Consumer-facing public services.** If you operate a public website or API consumed by third-party developers and web browsers, certificate pinning is the wrong tool. You cannot ship your pins to all client implementations. Certificate rotation, CA migration, and CDN changes become coordination problems involving parties you do not control. Use CT monitoring and CAA records instead.

**Services behind enterprise proxies.** Many of your users may be on corporate networks where TLS inspection is mandatory and controlled by their employer. Pinning will break these users. Intentionally breaking enterprise TLS inspection creates support burden and, in regulated industries, compliance problems for your customers.

**Short-lived services and rapid iteration.** If your certificate or key rotates more frequently than your client release cycle, pins will expire before users update. SPKI pinning (key-level, not cert-level) partially mitigates this, but only if you maintain key continuity.

**Where to use CT monitoring instead.** For any public-facing service where pinning is impractical, the right control set is: CAA records to restrict which CAs can issue, CT monitoring to detect if those records are violated, alerting with a response playbook, and HSTS with a long `max-age` to prevent protocol downgrade. This is lower operational risk than pinning and still provides meaningful protection against rogue certificate issuance.

## Summary

The CA trust model has structural weaknesses that certificate pinning was designed to address. HPKP — the original HTTP-based pinning mechanism — failed because it provided no recovery path from misconfiguration and could be weaponised to permanently brick sites via header injection.

Modern certificate pinning is applied selectively:

- **Mobile apps** use OS-level declarative pinning (Android NSC, iOS NSPinnedDomains) with SPKI hashes, expiration dates, and mandatory backup pins.
- **Service clients in controlled environments** use `VerifyPeerCertificate` callbacks pinned to the internal CA's SPKI hash, or delegate to mTLS for mutual authentication.
- **Infrastructure** uses CAA records to restrict issuance and DANE/TLSA where DNSSEC is available.
- **Public-facing services** rely on CT log monitoring and alerting rather than client-side pinning.

The universal rule from the HPKP disaster: never deploy a primary pin without a tested backup pin, a rotation procedure documented before you need it, and a maximum pin lifetime that limits the blast radius if something goes wrong.
