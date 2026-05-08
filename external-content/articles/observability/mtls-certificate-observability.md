---
title: "mTLS Observability: Monitoring Certificate Health, Detecting Misconfigurations, and Alerting on TLS Failures"
description: "When mTLS is misconfigured, traffic silently falls back to plaintext or fails — with no visible error unless you have the right metrics. This guide covers the key signals to track: handshake failure rates, certificate expiry, plaintext traffic detection, Istio and Linkerd mTLS coverage metrics, and SPIFFE SVID rotation health."
slug: mtls-certificate-observability
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - mtls
  - certificate-monitoring
  - service-mesh
  - tls-observability
  - spiffe
personas:
  - security-engineer
  - platform-engineer
article_number: 565
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/mtls-certificate-observability/
---

# mTLS Observability: Monitoring Certificate Health, Detecting Misconfigurations, and Alerting on TLS Failures

## The Observability Gap in mTLS Deployments

Mutual TLS provides strong service-to-service authentication: both parties present X.509 certificates, the TLS handshake validates both, and traffic is encrypted in transit. The security model is sound. The operational problem is that when mTLS breaks, it often breaks silently.

A misconfigured `PeerAuthentication` policy in Istio that was meant to enforce STRICT mode may instead default to PERMISSIVE, allowing plaintext alongside authenticated traffic. A cert-manager `Certificate` resource that fails to renew will cause a handshake failure at expiry — at 3am, 14 months after the initial deployment, when everyone has forgotten the certificate exists. A Linkerd proxy that fails to mount its injected identity certificate will silently communicate without mTLS rather than refuse to start.

These failures share a common property: they are invisible unless you are measuring the right things. HTTP status codes continue returning 200. Health checks pass. The service mesh control plane shows no obvious error. But traffic is either unencrypted or failing at the TLS layer before application-level metrics even see it.

The three failure modes to instrument against:

- **Silent plaintext fallback.** mTLS is optional rather than enforced. Some requests flow encrypted, some do not. Average encryption coverage drops below 100% with no alert firing.
- **Certificate expiry.** A workload certificate — whether managed by cert-manager, SPIRE, or manual provisioning — expires. All TLS handshakes with that workload fail simultaneously.
- **Handshake misconfiguration.** A cipher suite restriction, a certificate chain validation failure, or a hostname mismatch causes handshakes to fail for a specific workload pair. Traffic for that route drops to zero with TLS errors in the proxy access log.

Addressing all three requires metrics, recording rules, and alerts tuned to the mTLS layer rather than the application layer.

**Target systems:** Istio 1.20+, Linkerd 2.14+, cert-manager 1.13+, SPIRE 1.9+, Prometheus 2.50+, Envoy 1.29+.

## Key mTLS Metrics to Track

Before writing alerts, establish which metrics exist in your environment and what they represent.

**TLS handshake failure rate** is the most direct signal of mTLS breakdown. In Envoy-based meshes (Istio), this is exposed as `envoy_cluster_ssl_handshake_errors_total` and `envoy_listener_ssl_handshake_errors_total`. An increase in this counter on a workload means that service's downstream or upstream TLS connections are failing at the handshake phase — before any application traffic is exchanged.

**Certificate expiry countdown** is the most actionable leading indicator. The time remaining before a certificate expires is known days or weeks in advance. Alerting at 14 days and 7 days gives ample time to trigger rotation before an outage.

**mTLS coverage percentage** — the fraction of inbound requests that arrived over a mutually authenticated TLS connection versus plaintext — tells you whether your enforcement policy is working. A namespace that should be 100% STRICT showing 97% mTLS coverage means three percent of requests are bypassing authentication.

**Cipher suite distribution** matters for compliance. If your policy requires TLS 1.3 or restricts cipher suites to FIPS-approved algorithms, the actual negotiated cipher suites should be tracked and compared against the allowed set. Envoy exposes negotiated cipher suite counters on the cluster and listener stats.

## Istio mTLS Metrics

Istio's metrics are emitted by Envoy sidecars and reported through the telemetry pipeline to Prometheus. The key metrics:

`istio_requests_total` is the primary request counter. It carries a `connection_security_policy` label whose value is either `mutual_tls` or `none`. The ratio of `mutual_tls` to total requests for a given source and destination is your mTLS coverage for that service pair.

```promql
# mTLS coverage for all workloads in the production namespace
sum(rate(istio_requests_total{
  destination_service_namespace="production",
  connection_security_policy="mutual_tls"
}[5m]))
/
sum(rate(istio_requests_total{
  destination_service_namespace="production"
}[5m]))
```

`envoy_cluster_ssl_handshake` counts successful TLS handshakes per upstream cluster. Pairing it against `envoy_cluster_ssl_handshake_errors_total` gives a handshake success ratio per cluster.

`pilot_xds_pushes` and `pilot_xds_push_errors` reflect control plane health. When Istiod fails to push xDS configuration updates (including certificate distributions), proxies continue using stale configuration. A spike in `pilot_xds_push_errors` upstream of a certificate rotation event indicates that new certificates are not reaching proxies.

`envoy_cluster_ssl_session_reuse` tracks TLS session resumption. Unusually low session reuse rates can indicate that certificates are rotating more frequently than expected, which may itself indicate a rotation loop or cert-manager misconfiguration.

For connection-level (non-HTTP) traffic, `istio_tcp_connections_opened_total` also carries the `connection_security_policy` label and provides the equivalent mTLS coverage signal for TCP workloads.

## Linkerd mTLS Metrics

Linkerd's proxy emits mTLS status through response classification labels rather than a separate TLS metric. The key metric is `response_total` with the `tls` label:

```promql
# Linkerd: fraction of responses that were TLS-authenticated
sum(rate(response_total{tls="true"}[5m]))
/
sum(rate(response_total[5m]))
```

The `tls` label takes the value `"true"` for requests that were mutually authenticated, `"false"` for plaintext, and `"no_tls_info"` for requests where TLS status was unavailable. A nonzero rate for `tls="false"` in a namespace where mTLS should be enforced is an immediate investigation trigger.

Linkerd's identity controller exposes certificate issuance and rotation events through its own metrics:

```promql
# Certificate issuance failures in the Linkerd identity controller
rate(identity_cert_issuance_failures_total[5m])
```

A sustained nonzero rate here means that workloads are failing to obtain SPIFFE-style identity certificates from the Linkerd identity controller, and will eventually fall back to unauthenticated communication when their current certificates expire.

## Prometheus Recording Rules for mTLS Coverage

Recording rules pre-compute expensive aggregations and make alert evaluation faster. Define a recording rule that captures per-namespace mTLS coverage:

```yaml
groups:
  - name: mtls_coverage
    interval: 60s
    rules:
      - record: namespace:istio_mtls_coverage:ratio
        expr: |
          sum by (destination_service_namespace) (
            rate(istio_requests_total{
              connection_security_policy="mutual_tls"
            }[5m])
          )
          /
          sum by (destination_service_namespace) (
            rate(istio_requests_total[5m])
          )

      - alert: NamespaceMTLSCoverageBelowThreshold
        expr: namespace:istio_mtls_coverage:ratio < 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Namespace {{ $labels.destination_service_namespace }} mTLS coverage below 100%"
          description: |
            mTLS coverage in namespace {{ $labels.destination_service_namespace }}
            is {{ $value | humanizePercentage }}. Expected 100% for STRICT mode.
            Investigate PeerAuthentication policies and proxy injection status.

      - alert: TLSHandshakeErrorRateHigh
        expr: |
          sum by (pod, namespace) (
            rate(envoy_cluster_ssl_handshake_errors_total[5m])
          ) > 0.01
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: "TLS handshake errors on {{ $labels.pod }}"
          description: |
            Pod {{ $labels.pod }} in {{ $labels.namespace }} is experiencing
            {{ $value | humanize }} TLS handshake errors per second.
            Check certificate validity, chain trust, and cipher suite policy.
```

The `NamespaceMTLSCoverageBelowThreshold` alert is intentionally strict: any drop below 100% in a STRICT-mode namespace is worth investigating. If you have legitimately mixed namespaces, add a label exclusion or raise the threshold to match your policy.

## Certificate Expiry Monitoring with cert-manager

cert-manager manages X.509 certificates as `Certificate` Kubernetes resources and exposes Prometheus metrics through its controller. The core metric for expiry monitoring is `certmanager_certificate_expiration_timestamp_seconds`, which is a gauge reporting the Unix timestamp of each certificate's `notAfter` field.

The time-to-expiry in seconds is:

```promql
certmanager_certificate_expiration_timestamp_seconds
- time()
```

Alerting rules for two warning thresholds:

```yaml
groups:
  - name: cert_manager_expiry
    rules:
      - alert: CertificateExpiryWarning
        expr: |
          (certmanager_certificate_expiration_timestamp_seconds - time()) < (14 * 24 * 3600)
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.name }} in {{ $labels.namespace }} expires in < 14 days"
          description: |
            Certificate {{ $labels.name }} (namespace: {{ $labels.namespace }})
            expires in {{ $value | humanizeDuration }}.
            cert-manager should be renewing at 2/3 of the certificate lifetime.
            Check cert-manager controller logs for renewal errors.

      - alert: CertificateExpiryCritical
        expr: |
          (certmanager_certificate_expiration_timestamp_seconds - time()) < (3 * 24 * 3600)
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Certificate {{ $labels.name }} in {{ $labels.namespace }} expires in < 3 days"

      - alert: CertificateRenewalFailed
        expr: certmanager_certificate_ready_status{condition="False"} == 1
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.name }} in {{ $labels.namespace }} is not ready"
          description: |
            cert-manager reports certificate {{ $labels.name }} as not ready.
            This may indicate a renewal failure. Check the Certificate resource
            status conditions and cert-manager controller logs.
```

The `certmanager_certificate_ready_status` metric exposes the cert-manager `Certificate` resource's `Ready` condition as a gauge. A value of 1 with `condition="False"` means the certificate is in a failed state — either the initial issuance failed or a renewal attempt is failing.

cert-manager also exposes `certmanager_http_acme_client_request_errors_total` for ACME challenges and `certmanager_controller_sync_error_count` for synchronization failures. If your mTLS certificates use an internal CA via cert-manager's `ClusterIssuer`, watch the issuer readiness metric:

```promql
certmanager_clusterissuer_ready_status{condition="True"} == 0
```

A ClusterIssuer going unready means all new certificate requests will fail, even though existing certificates remain valid until their individual expiry.

## SPIFFE Workload Identity Certificate Monitoring

SPIRE (the SPIFFE Runtime Environment) manages short-lived SVIDs (SPIFFE Verifiable Identity Documents) that are automatically rotated before expiry. Because SVID lifetimes are typically measured in hours rather than months, the rotation machinery itself must be monitored — not just the expiry timestamp.

SPIRE Server exposes Prometheus metrics at its health endpoint. Key metrics:

`spire_server_agent_count` — the number of registered SPIRE agents. A drop in this count can indicate agents are losing their connection to the server, which would prevent workloads on those nodes from rotating their SVIDs.

`spire_server_entry_count` — total registered workload entries. An unexpected drop indicates that entries were deleted or the server state is inconsistent.

`spire_server_ca_jwt_signing_key_expire_in_seconds` and `spire_server_ca_x509_signing_key_expire_in_seconds` — time remaining before the CA signing key expires. SPIRE rotates these automatically, but if rotation fails the entire SVID issuance pipeline breaks.

```yaml
groups:
  - name: spire_health
    rules:
      - alert: SPIREAgentDisconnected
        expr: |
          decrease(spire_server_agent_count[10m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SPIRE agent count decreased"
          description: |
            The number of connected SPIRE agents decreased by {{ $value }}
            in the last 10 minutes. Workloads on disconnected nodes will
            fail to rotate their SVIDs and may exhaust their certificate TTL.

      - alert: SPIRECASigningKeyExpiringSoon
        expr: |
          spire_server_ca_x509_signing_key_expire_in_seconds < 3600
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "SPIRE CA X.509 signing key expires in < 1 hour"
          description: |
            The SPIRE Server CA signing key expires in
            {{ $value | humanizeDuration }}. If key rotation fails,
            new SVID issuance will stop and workloads will be unable
            to establish mTLS connections after their current SVIDs expire.
```

On the workload side, the SPIFFE Workload API exposes SVID rotation events. The `spiffe_svid_rotation_total` counter (emitted by SPIRE Agent) should be incrementing at approximately the rate of `(workload count) / (SVID TTL / 2)`. A stalled rotation counter means workloads are not refreshing their identities.

## Detecting Plaintext Traffic in a Should-Be-mTLS Cluster

Metrics tell you that plaintext traffic exists. Network flow visibility tells you which workloads are sending it.

**Cilium Hubble** provides per-flow TLS metadata. Plaintext flows where mTLS is expected can be identified through the Hubble API:

```bash
# Query Hubble for non-TLS flows in the production namespace
hubble observe \
  --namespace production \
  --protocol tcp \
  --verdict FORWARDED \
  -o json \
  | jq 'select(.l4.TCP != null and .is_reply == false and (.l7 | not))'
```

Flows without an L7 (application-layer) record that are TCP and not TLS-terminated are candidates for plaintext detection. Hubble's flow records include `l7_proto` for HTTP/2 (used by gRPC) — if you see HTTP/2 flows without TLS, those are unencrypted gRPC connections that should be mTLS.

**Istio PeerAuthentication policy audit** is the control-plane complement. A namespace in PERMISSIVE mode will accept both mTLS and plaintext. Audit all PeerAuthentication policies for unintentional PERMISSIVE settings:

```bash
kubectl get peerauthentication \
  --all-namespaces \
  -o json \
  | jq '.items[] | select(.spec.mtls.mode == "PERMISSIVE" or .spec.mtls == null)
        | {namespace: .metadata.namespace, name: .metadata.name, mode: .spec.mtls.mode}'
```

A null `.spec.mtls` means the policy inherits from the mesh-level default. If the mesh default is PERMISSIVE (the Istio default during migration), workloads with no explicit STRICT policy will accept plaintext traffic silently.

The Istio AuthorizationPolicy can be used to explicitly deny plaintext:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-mtls
  namespace: production
spec:
  action: DENY
  rules:
    - from:
        - source:
            notPrincipals: ["*"]
```

This denies requests that do not carry an authenticated SPIFFE principal — which plaintext requests will never have. Unlike PeerAuthentication, this generates an explicit `403 RBAC: access denied` log entry in the Envoy access log, which is auditable.

## Debugging TLS Handshake Failures

When `envoy_cluster_ssl_handshake_errors_total` increments, the Envoy access log contains the detail needed to diagnose the cause.

Enable TLS error fields in the Envoy access log format for Istio proxies:

```yaml
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: access-log-tls-errors
  namespace: istio-system
spec:
  accessLogging:
    - providers:
        - name: envoy
      format:
        text: |
          [%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
          %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT%
          "%UPSTREAM_TRANSPORT_FAILURE_REASON%" "%TLS_VERSION%"
          "%TLS_CIPHER_SUITE%" "%PEER_CERTIFICATE_V_START%" "%PEER_CERTIFICATE_V_END%"
```

The `%UPSTREAM_TRANSPORT_FAILURE_REASON%` field contains the SSL error string when a TLS handshake fails. Common values:

- `TLS_error:|268435581:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED` — the upstream certificate could not be validated against the trusted CA bundle. Check whether the upstream's certificate was issued by the expected mesh CA.
- `TLS_error:|336151574:SSL routines:ssl3_read_bytes:sslv3 alert certificate expired` — the upstream certificate has expired. Cross-reference with `certmanager_certificate_expiration_timestamp_seconds` for that workload.
- `TLS_error:|268436502:SSL routines:OPENSSL_internal:NO_SHARED_CIPHER` — the configured cipher suite policies on the two proxies are incompatible. Check if a custom `EnvoyFilter` or `DestinationRule` is restricting cipher suites.

Aggregate TLS error reasons across the fleet using log query tooling:

```logql
# Loki: TLS handshake errors by reason in the last hour
{app="istio-proxy"} 
  |= "TLS_error" 
  | regexp `UPSTREAM_TRANSPORT_FAILURE_REASON: "(?P<tls_error>[^"]+)"`
  | line_format "{{.tls_error}}"
```

This surfaces the distribution of SSL error types across your mesh, which is essential for distinguishing a single misconfigured workload from a mesh-wide CA rotation problem.

## Putting It Together: mTLS Observability Dashboard

A production-ready mTLS observability setup requires signals at four layers:

1. **Coverage layer** — `istio_requests_total` with `connection_security_policy` label, or Linkerd's `response_total` with `tls` label. Alert when coverage drops below 100% in STRICT-mode namespaces.

2. **Certificate health layer** — cert-manager `certmanager_certificate_expiration_timestamp_seconds` and `certmanager_certificate_ready_status`. Alert at 14 days and 3 days before expiry, and immediately on not-ready state.

3. **Identity rotation layer** — SPIRE agent and server metrics covering agent connectivity, SVID rotation rates, and CA signing key expiry. Alert on agent disconnection and stalled rotation.

4. **Failure diagnosis layer** — Envoy access logs with `UPSTREAM_TRANSPORT_FAILURE_REASON` for handshake error classification. Aggregate by error type for fleet-wide SSL error analysis.

The coverage layer tells you mTLS is not 100%. The certificate health layer tells you a specific certificate is about to expire or has failed to renew. The identity rotation layer tells you the SPIFFE machinery is broken. The failure diagnosis layer tells you the exact SSL error when a handshake fails.

Without all four, you are likely to discover mTLS problems from user-reported errors rather than from your own monitoring.

## Summary

mTLS is not a set-and-forget control. Certificates expire, renewal pipelines fail, PeerAuthentication policies are misconfigured, and SPIRE agents lose connectivity to the server. The operational discipline that makes mTLS reliable is the same discipline that makes any security control reliable: instrument it, set thresholds, and alert before the failure becomes an outage.

The minimal viable mTLS observability stack is: a Prometheus scrape of cert-manager and SPIRE metrics, two Prometheus alerting rules (mTLS coverage below 100%, certificate expiry within 14 days), and Envoy access logging with `UPSTREAM_TRANSPORT_FAILURE_REASON` enabled. Everything beyond that improves mean time to diagnosis.
