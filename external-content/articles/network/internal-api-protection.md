---
title: "Protecting Internal APIs: Network Segmentation, Authentication, and Access Logging"
description: "\"It's internal\" is the most dangerous phrase in infrastructure security. Internal APIs sit behind the perimeter and receive minimal scrutiny."
slug: "internal-api-protection"
date: 2026-04-05
lastmod: 2026-04-05
category: "network"
tags: ["internal-api", "zero-trust", "network-policy", "mtls", "kubernetes", "service-mesh", "access-logging"]
personas: ["security-engineer", "platform-engineer"]
article_number: 46
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "monitoring"
  - name: "Grafana Cloud"
    id: 108
    category: "monitoring"
published: true
layout: article.njk
permalink: "/articles/network/internal-api-protection/index.html"
---

# Protecting Internal APIs: Network Segmentation, Authentication, and Access Logging

## Problem

"It's internal" is the most dangerous phrase in infrastructure security. Internal APIs sit behind the perimeter and receive minimal scrutiny:

- **Flat network topology.** In a default [Kubernetes](https://kubernetes.io) cluster, every pod can talk to every other pod on every port. A compromised pod in the frontend namespace can directly call the database admin API in the backend namespace.
- **No authentication on internal endpoints.** Teams skip authentication because "only our services call this." After a container escape or SSRF vulnerability, the attacker can call every internal API with no credentials required.
- **No access logging.** External-facing APIs log every request. Internal APIs often log nothing, or log only errors. When an attacker pivots through internal services, there is no audit trail to reconstruct the attack path.
- **Implicit trust based on network position.** If a request arrives on the internal network, it is trusted. This model collapses the moment any single service is compromised.
- **Overly broad service accounts.** A single service token grants access to every internal API. There is no principle of least privilege for service-to-service communication.

Zero-trust networking means authenticating and authorizing every request regardless of network position. For internal APIs, this requires network segmentation, per-service identity, and comprehensive access logging.

**Target systems:** Kubernetes clusters with internal microservices, VM-based deployments with internal REST or gRPC APIs, any environment where services communicate over a shared network.

## Threat Model

- **Adversary:** Attacker who has compromised a single service or pod through an application vulnerability (SSRF, RCE, dependency exploit). May also be a malicious insider with access to deploy workloads.
- **Access level:** Network access from within the cluster or internal network. May have compromised service credentials for one service.
- **Objective:** Lateral movement to access sensitive internal APIs (admin endpoints, data stores, secrets managers). Data exfiltration through internal APIs that return bulk data. Privilege escalation by calling administrative RPCs from a non-privileged context.
- **Blast radius:** Without segmentation, every internal service is reachable. With the controls in this article, the blast radius is limited to the compromised service's explicitly authorized API calls.

## Configuration

### Kubernetes Network Policies: Restricting Pod-to-Pod Communication

Network policies are the foundation of internal API protection. They define which pods can communicate with which other pods on which ports.

Default-deny policy for a namespace (every namespace should have this):

```yaml
# default-deny.yaml
# Apply to every namespace that contains services.
# After applying, only explicitly allowed traffic flows.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  # No ingress or egress rules = deny all traffic
```

Allow specific service-to-service communication:

```yaml
# allow-api-gateway-to-user-service.yaml
# Only the api-gateway pods can reach the user-service on port 8080.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-gateway-to-user-service
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: user-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: frontend
          podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8080
---
# allow-user-service-to-database.yaml
# Only user-service can reach the database on port 5432.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-user-service-to-database
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: user-service
      ports:
        - protocol: TCP
          port: 5432
```

Allow DNS resolution (required for service discovery after default-deny):

```yaml
# allow-dns.yaml
# All pods need DNS access. Apply in every namespace with default-deny.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Service Mesh Authorization: [Istio](https://istio.io) AuthorizationPolicy

Network policies control L3/L4 (IP and port). Service mesh authorization controls L7 (HTTP method, path, headers, service identity):

```yaml
# istio-authz-user-service.yaml
# Only api-gateway can call GET /users and POST /users.
# Only admin-service can call DELETE /users/*.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: user-service-authz
  namespace: backend
spec:
  selector:
    matchLabels:
      app: user-service
  action: ALLOW
  rules:
    # api-gateway can read and create users
    - from:
        - source:
            principals:
              - "cluster.local/ns/frontend/sa/api-gateway"
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/v1/users", "/api/v1/users/*"]
    # admin-service can do everything including delete
    - from:
        - source:
            principals:
              - "cluster.local/ns/backend/sa/admin-service"
      to:
        - operation:
            methods: ["GET", "POST", "PUT", "DELETE"]
            paths: ["/api/v1/users", "/api/v1/users/*"]
    # Health checks from any mesh service
    - from:
        - source:
            namespaces: ["istio-system"]
      to:
        - operation:
            methods: ["GET"]
            paths: ["/healthz", "/readyz"]
---
# Default deny for the namespace: reject anything not explicitly allowed
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: default-deny
  namespace: backend
spec:
  # Empty spec = deny all
  {}
```

### [Linkerd](https://linkerd.io) Server Authorization

For Linkerd-based meshes, use Server and ServerAuthorization resources:

```yaml
# linkerd-server.yaml
apiVersion: policy.linkerd.io/v1beta2
kind: Server
metadata:
  name: user-service-http
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: user-service
  port: 8080
  proxyProtocol: HTTP/2
---
apiVersion: policy.linkerd.io/v1alpha1
kind: ServerAuthorization
metadata:
  name: allow-api-gateway
  namespace: backend
spec:
  server:
    name: user-service-http
  client:
    meshTLS:
      serviceAccounts:
        - name: api-gateway
          namespace: frontend
```

### mTLS Without a Service Mesh

If you cannot deploy a service mesh, implement mTLS directly. Generate certificates with a shared CA and verify them at each service:

```bash
#!/bin/bash
# generate-service-certs.sh
# Generate a CA and per-service certificates for internal mTLS.

# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -sha256 -days 365 -key ca.key \
  -out ca.crt -subj "/CN=Internal Services CA"

# Generate certificate for user-service
openssl genrsa -out user-service.key 2048
openssl req -new -key user-service.key \
  -out user-service.csr \
  -subj "/CN=user-service" \
  -addext "subjectAltName=DNS:user-service.backend.svc.cluster.local,DNS:user-service"

openssl x509 -req -sha256 -days 90 \
  -in user-service.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out user-service.crt \
  -extfile <(printf "subjectAltName=DNS:user-service.backend.svc.cluster.local,DNS:user-service")

# Generate certificate for api-gateway
openssl genrsa -out api-gateway.key 2048
openssl req -new -key api-gateway.key \
  -out api-gateway.csr \
  -subj "/CN=api-gateway" \
  -addext "subjectAltName=DNS:api-gateway.frontend.svc.cluster.local,DNS:api-gateway"

openssl x509 -req -sha256 -days 90 \
  -in api-gateway.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out api-gateway.crt \
  -extfile <(printf "subjectAltName=DNS:api-gateway.frontend.svc.cluster.local,DNS:api-gateway")
```

[NGINX](https://nginx.org) configuration for internal API with mTLS:

```nginx
# /etc/nginx/conf.d/internal-api.conf
# Internal API endpoint requiring client certificate authentication.

server {
    listen 8443 ssl;
    server_name user-service.backend.svc.cluster.local;

    # Server certificate
    ssl_certificate /etc/certs/user-service.crt;
    ssl_certificate_key /etc/certs/user-service.key;

    # Require client certificate (mTLS)
    ssl_client_certificate /etc/certs/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # TLS hardening
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Log the client certificate CN for audit trail
    log_format internal_api escape=json
        '{'
            '"time": "$time_iso8601",'
            '"client_cn": "$ssl_client_s_dn_cn",'
            '"remote_addr": "$remote_addr",'
            '"request_method": "$request_method",'
            '"request_uri": "$request_uri",'
            '"status": "$status",'
            '"body_bytes_sent": "$body_bytes_sent",'
            '"request_time": "$request_time"'
        '}';

    access_log /var/log/nginx/internal-api.json internal_api;

    # Route-level authorization based on client certificate CN
    location /api/v1/users {
        # Only allow api-gateway and admin-service
        if ($ssl_client_s_dn_cn !~ "^(api-gateway|admin-service)$") {
            return 403;
        }
        proxy_pass http://127.0.0.1:8080;
    }

    location /api/v1/admin {
        # Only allow admin-service
        if ($ssl_client_s_dn_cn != "admin-service") {
            return 403;
        }
        proxy_pass http://127.0.0.1:8080;
    }

    # Health check endpoint (no client cert required for probes)
    location /healthz {
        # Kubernetes probes do not send client certs.
        # Serve health on a separate listener (see below)
        # or allow unauthenticated access to health only.
        return 200 "ok";
    }
}

# Separate listener for health checks (no mTLS)
server {
    listen 8080;
    server_name _;

    # Only allow connections from the pod's own network
    allow 10.0.0.0/8;
    deny all;

    location /healthz {
        return 200 "ok";
    }
}
```

### Comprehensive Access Logging for Internal APIs

Every internal API call must be logged with enough detail to reconstruct an attack path:

```python
# Python (Flask) middleware for internal API access logging
import json
import time
import logging
from functools import wraps
from flask import Flask, request, g

app = Flask(__name__)

# Structured logger for security events
security_logger = logging.getLogger('security.access')
handler = logging.FileHandler('/var/log/app/internal-api-access.json')
security_logger.addHandler(handler)
security_logger.setLevel(logging.INFO)

@app.before_request
def log_request_start():
    g.start_time = time.time()

@app.after_request
def log_request(response):
    duration = time.time() - g.start_time

    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "caller_identity": request.headers.get(
            "X-Service-Name",
            request.environ.get("SSL_CLIENT_S_DN_CN", "unknown")
        ),
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf-8"),
        "status_code": response.status_code,
        "response_size": response.content_length,
        "duration_ms": round(duration * 1000, 2),
        "user_agent": request.user_agent.string,
    }

    security_logger.info(json.dumps(log_entry))
    return response
```

### Detecting Unauthorized Internal API Access

Use log analysis to detect anomalous access patterns:

```bash
#!/bin/bash
# detect-anomalous-access.sh
# Run periodically (cron) to detect unexpected callers.

LOG_FILE="/var/log/nginx/internal-api.json"

# Find caller CNs that are not in the expected set
EXPECTED_CALLERS="api-gateway|admin-service|reporting-service"

jq -r '.client_cn' "$LOG_FILE" | \
  sort -u | \
  grep -vE "^($EXPECTED_CALLERS)$" | \
  while read -r unexpected_caller; do
    echo "ALERT: Unexpected caller detected: $unexpected_caller"
    # Count requests from this caller
    count=$(jq -r "select(.client_cn == \"$unexpected_caller\") | .request_uri" "$LOG_FILE" | wc -l)
    echo "  Request count: $count"
    # Show accessed endpoints
    jq -r "select(.client_cn == \"$unexpected_caller\") | .request_uri" "$LOG_FILE" | sort -u
  done
```

[Prometheus](https://prometheus.io) alerting rule for unauthorized access:

```yaml
# prometheus-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: internal-api-security
  namespace: monitoring
spec:
  groups:
    - name: internal-api-unauthorized
      rules:
        - alert: UnauthorizedInternalAPIAccess
          expr: |
            sum by (source_service, target_service, target_path) (
              rate(internal_api_requests_total{status_code="403"}[5m])
            ) > 0.1
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Unauthorized internal API access from {{ $labels.source_service }} to {{ $labels.target_service }}{{ $labels.target_path }}"
            description: "More than 0.1 req/s of 403 responses detected. Possible lateral movement attempt."

        - alert: NewInternalAPICaller
          expr: |
            count by (target_service) (
              count_over_time(
                internal_api_requests_total{source_service!~"api-gateway|admin-service|reporting-service"}[5m]
              )
            ) > 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Unknown service calling {{ $labels.target_service }}"
            description: "A service identity not in the expected caller list is making requests."
```

## Expected Behaviour

After applying the internal API protection configuration:

```bash
# Verify default-deny network policy is active
# From a pod in the frontend namespace, try to reach postgres
kubectl exec -n frontend deploy/test-pod -- \
  curl -s --max-time 3 postgres.backend:5432
# Expected: connection timeout (blocked by network policy)

# Verify allowed path works
# From api-gateway, call user-service
kubectl exec -n frontend deploy/api-gateway -- \
  curl -s --cacert /etc/certs/ca.crt \
  --cert /etc/certs/api-gateway.crt \
  --key /etc/certs/api-gateway.key \
  https://user-service.backend:8443/api/v1/users
# Expected: 200 with user list

# Verify unauthorized service is rejected
# From reporting-service, try to delete a user
kubectl exec -n backend deploy/reporting-service -- \
  curl -s -o /dev/null -w "%{http_code}" \
  --cacert /etc/certs/ca.crt \
  --cert /etc/certs/reporting-service.crt \
  --key /etc/certs/reporting-service.key \
  -X DELETE \
  https://user-service.backend:8443/api/v1/users/123
# Expected: 403

# Verify access log contains caller identity
kubectl exec -n backend deploy/user-service -- \
  tail -1 /var/log/nginx/internal-api.json | jq .
# Expected: {"time": "...", "client_cn": "api-gateway", "request_method": "GET", ...}
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny network policies | All pod communication must be explicitly allowed | New services cannot communicate until policies are created; debugging connectivity is harder | Maintain network policy templates per service type; use `kubectl describe networkpolicy` for troubleshooting |
| Istio AuthorizationPolicy | Requires running a service mesh with sidecar injection | Mesh adds latency (1-3ms per hop) and resource overhead (sidecar containers) | Profile the latency impact; use Linkerd for lower overhead if Istio is too heavy |
| mTLS for all internal APIs | Certificate management for every service | Certificate rotation failures cause complete service communication breakdown | Automate rotation with [cert-manager](https://cert-manager.io); use short-lived certificates (24-72h) so stale certs expire quickly |
| Comprehensive access logging | Log volume increases significantly for high-throughput internal APIs | Storage costs increase; log pipeline may become a bottleneck | Sample high-volume endpoints (log 10% of health checks, 100% of mutation operations); use structured logging for efficient querying |
| Per-service identity (CN-based) | Each service needs a unique certificate with a specific CN | Identity spoofing if CA key is compromised | Protect CA key with HSM or Vault PKI; use SPIFFE for standardized identity |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Default-deny blocks legitimate traffic | New service cannot reach its dependencies; health checks fail | Service does not become ready; pod logs show connection refused or timeout | Create the appropriate NetworkPolicy allowing the required traffic flow |
| Network policy CNI not installed | NetworkPolicy resources are accepted but have no effect | Test with a pod that should be blocked; if traffic flows, the CNI does not enforce policies | Install a CNI that supports NetworkPolicy ([Calico](https://www.tigera.io/project-calico/), [Cilium](https://cilium.io), Weave Net) |
| mTLS certificate expired | All authenticated API calls fail with TLS handshake error | Connection error rate spikes; services log TLS errors | Renew certificate immediately; implement monitoring for certificate expiry (alert at 7 days remaining) |
| Service mesh sidecar not injected | Service bypasses all mesh authorization policies | AuthorizationPolicy has no effect on the uninjected pod; traffic flows without mTLS | Verify namespace label for sidecar injection; use Istio PeerAuthentication STRICT mode to reject non-mTLS traffic |
| Access log pipeline failure | Logs stop flowing; no visibility into internal API access | Log volume drops to zero in monitoring dashboard | Fix log pipeline; internal APIs continue to function (logging failure should not block traffic) |
| Overly restrictive authorization policy | Legitimate service calls are blocked after policy update | 403 spike from affected service pair; application errors | Review the AuthorizationPolicy; add the missing source/operation rule |

## When to Consider a Managed Alternative

**Transition point:** When managing network policies, certificates, and access logging across 30+ microservices requires dedicated staffing, or when you need centralized visibility into all service-to-service communication patterns without instrumenting each service individually.

**What managed alternatives handle:**

- **[Sysdig](https://sysdig.com):** Runtime visibility into all network connections between services, including connections that bypass intended network policies. Detects unexpected communication patterns (a frontend pod connecting directly to a database) without requiring log instrumentation in each service.

- **[Grafana Cloud](https://grafana.com/cloud):** Centralized log aggregation and analysis for internal API access logs. Pre-built dashboards for service-to-service communication patterns. Alerting on anomalous access patterns without managing your own Prometheus/[Loki](https://grafana.com/oss/loki/) stack.

**What you still control:** Network policy definitions, service identity management, and authorization rules remain your responsibility. Monitoring tools provide visibility and alerting, but the actual access control decisions (which service can call which API) are always defined and enforced in your infrastructure.
