---
title: "Security Issues in Observability Tooling: Reporting Vulnerabilities in Prometheus, Grafana, and Elasticsearch"
description: "Observability tools store security-sensitive data — logs containing credentials, metrics revealing system behaviour, traces with PII. Vulnerabilities in Prometheus, Grafana, Elasticsearch, and Loki can expose this data or provide a pivot into the infrastructure they monitor. This guide covers the security disclosure processes for major observability projects, how to report vulnerabilities, and how to respond as a consumer."
slug: oss-observability-security-disclosure
date: 2026-05-08
lastmod: 2026-05-08
category: observability
tags:
  - open-source-security
  - prometheus
  - grafana
  - elasticsearch
  - responsible-disclosure
personas:
  - security-engineer
  - security-analyst
article_number: 685
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/oss-observability-security-disclosure/
---

# Security Issues in Observability Tooling: Reporting Vulnerabilities in Prometheus, Grafana, and Elasticsearch

Observability tools occupy a privileged position in your infrastructure. Prometheus scrapes metrics from every service. Grafana dashboards display your topology, capacity, and error rates. Elasticsearch indexes logs from every application, often including authentication events, API keys printed to debug output, and HTTP request bodies. Loki ingests structured logs that may contain PII. Tempo and Jaeger trace requests that cross trust boundaries.

When any of these tools has a vulnerability, the blast radius is unusually wide — not because the tool itself is critical infrastructure in the availability sense, but because it has read access to security-sensitive data from every system it monitors.

This article covers the vulnerability history of major observability tools, how each project handles security disclosures, how to respond as a consumer when a CVE is published, and what to do if you discover a vulnerability yourself.

## Why Observability Tool Vulnerabilities Are High-Impact

The standard argument for why a component is high-risk focuses on what it does: a payment service is high-risk because it handles money; an authentication service is high-risk because it controls access. Observability tools present a different kind of risk — they are high-impact because of what they *see*, not what they do.

Consider the data that flows through a typical observability stack:

- **Prometheus** collects metrics that include JVM heap sizes, database connection pool exhaustion, and queue depths. An attacker reading these metrics learns exactly where your bottlenecks are and when your systems are under stress.
- **Grafana** dashboards synthesise this into annotated infrastructure maps. A compromised Grafana instance reveals service topology, dependencies, and often includes links to runbooks and playbooks.
- **Elasticsearch** indexes application logs. Even well-behaved applications emit sensitive data in logs: database query strings, HTTP headers containing tokens, startup configuration echoed at INFO level.
- **Loki** stores log streams from Kubernetes pods, including logs from secrets-management sidecars and certificate renewal jobs.

### The Watching the Watchers Problem

There is a second-order risk that is less often discussed: if an attacker can manipulate or erase data in your observability stack, they can cover their tracks. A SIEM that indexes security events is only useful if the indexes are tamper-evident. Elasticsearch does not provide write-once storage by default — an attacker with index-level write access can delete or modify log entries after the fact.

This is sometimes called the "watching the watchers" problem. The tools you rely on to detect intrusions are themselves potential targets. If your incident response process depends on log completeness, a compromised Elasticsearch cluster makes forensic analysis unreliable.

### Recent Vulnerability History

Several high-profile CVEs illustrate the pattern:

**Grafana path traversal (CVE-2021-43798)** — Grafana's plugin system exposed a path traversal vulnerability that allowed unauthenticated attackers to read arbitrary files on the Grafana server. On a typical deployment, this meant reading `/etc/grafana/grafana.ini`, which contains database credentials for Grafana's internal SQLite or PostgreSQL instance, SMTP credentials, and secret key material.

**Grafana SQL injection via plugin datasources (2021)** — Several Grafana datasource plugins failed to sanitise query parameters, enabling SQL injection through crafted dashboard queries. Because Grafana datasources often connect to internal databases with broad read permissions, this could expose data that was never intended to flow through Grafana at all.

**Elasticsearch log4j (CVE-2021-44228, 2021)** — Elasticsearch 7.x shipped with log4j 2.x in the class path. The log4j JNDI injection vulnerability allowed attackers who could cause Elasticsearch to log a crafted string to achieve remote code execution. In practice, this meant that any application which could write to an Elasticsearch index could potentially trigger RCE on the Elasticsearch node.

**Prometheus remote_write SSRF** — Prometheus's `remote_write` configuration directs scrape data to external endpoints. If the Prometheus configuration can be modified — through a misconfigured Alertmanager, a compromised CI/CD pipeline, or a privileged Kubernetes service account — an attacker can redirect metrics to an internal URL, effectively using Prometheus as an SSRF proxy to reach services that are otherwise only accessible within the cluster network.

## Threat Model

Understanding the attack surface of each tool helps prioritise your response when a CVE is published.

**Unauthenticated access to Grafana dashboards** — Grafana has had multiple authentication bypass vulnerabilities. An unauthenticated attacker who reaches the Grafana HTTP interface can read dashboards that show service names, IP addresses, database identifiers, and error patterns. This is reconnaissance of high quality — the same information a security engineer would use to understand the system is also useful to an attacker.

**SSRF via Prometheus alerting** — Prometheus evaluates alerting rules and fires webhooks via Alertmanager. Anyone who can write an alerting rule — any engineer with access to the Prometheus configuration or the `PrometheusRule` CRD in Kubernetes — can cause Prometheus or Alertmanager to send an HTTP POST to an arbitrary URL. This includes internal metadata endpoints, cloud provider IMDS endpoints (169.254.169.254), and other internal services behind the cluster network boundary.

**Elasticsearch index injection** — If application code constructs Elasticsearch queries using unvalidated log data, a crafted log message can alter the query structure. This is analogous to SQL injection but in a JSON query DSL. The consequence is usually information disclosure — returning records the query was not intended to return — rather than write access, but in a logging context this can still expose sensitive data from unrelated indexes.

## The CNCF Security Disclosure Process

The Cloud Native Computing Foundation maintains a security process for its hosted projects. The primary contact for CNCF-wide security issues is **cncf-security@lists.cncf.io**. This address is monitored by members of the CNCF Technical Advisory Group for Security (TAG Security).

For most CNCF projects, the preferred reporting path is through **GitHub private security advisories**, which GitHub has supported natively since 2022. Navigating to a project's GitHub repository and selecting Security → Report a vulnerability creates a private draft advisory that only the project maintainers can see.

The CNCF security response SLA for graduated projects is:
- Acknowledgement of the report within **7 days**
- An initial assessment (confirming or denying the vulnerability) within **14 days**
- A fix or mitigation within **90 days** for standard severity issues
- Expedited timelines for critical vulnerabilities at the discretion of the project security team

Not all CNCF projects have dedicated security teams. Projects with their own security contacts include:

- **Prometheus** — `prometheus-security@googlegroups.com`
- **Jaeger** — GitHub private advisories, monitored by the Jaeger maintainer group
- **Fluentd** — `security@fluentd.org`, maintained by the Fluentd core team

Smaller projects may rely entirely on CNCF's central security team for triage and coordination.

## Prometheus Security Disclosure

Prometheus uses two reporting channels:

- **Email**: `prometheus-security@googlegroups.com`
- **GitHub private advisories**: `github.com/prometheus/prometheus/security/advisories`

The Prometheus security advisory history shows a consistent pattern around network exposure. The scraping model — where Prometheus initiates connections to monitored targets — is relatively well-bounded. The risk surfaces that have historically produced vulnerabilities are:

- **Alert webhook notifications**: Alertmanager sends HTTP requests to configured receivers. A misconfigured or attacker-controlled receiver URL can be used for SSRF.
- **Remote write endpoints**: Prometheus can be configured to forward time series to remote storage. An attacker who can modify this configuration can redirect metrics, exfiltrate data, or probe internal services.
- **Scrape target manipulation**: In dynamic environments using service discovery, an attacker who can inject scrape targets (e.g., via a Kubernetes annotation on a pod they control) can cause Prometheus to send authenticated HTTP requests to arbitrary endpoints.

The threat model specific to Prometheus is worth internalising: **anyone who can modify alerting rules or Prometheus configuration can exfiltrate data through webhook notifications**. This is not a vulnerability in the traditional sense — it is intended functionality. The control is access to the configuration, not the Prometheus binary itself.

**Responding to a Prometheus CVE:**

```bash
# Check current Prometheus version
promtool --version

# Or via the HTTP API
curl -s http://localhost:9090/api/v1/status/buildinfo | jq '.data.version'
```

Prometheus follows semantic versioning. Security fixes are backported to the most recent minor release. Check the [Prometheus releases page](https://github.com/prometheus/prometheus/releases) for the advisory announcement and the minimum safe version. On Kubernetes, update the image tag in your StatefulSet or Deployment and perform a rolling restart.

## Grafana Security Disclosure

Grafana Labs operates the most mature security programme of any observability vendor in this space:

- **Email**: `security@grafana.com`
- **Bug bounty**: HackerOne programme at `hackerone.com/grafana`
- **Security advisories**: GitHub security advisories at `github.com/grafana/grafana/security/advisories`
- **RSS feed**: `https://grafana.com/security/security-advisories/` publishes machine-readable advisories

Grafana has a paid bug bounty programme with defined severity tiers and rewards. This attracts external security researchers, which means Grafana's vulnerability disclosure rate is higher than tools that rely solely on community reports — but it also means the project finds and fixes vulnerabilities faster.

### Grafana Vulnerability Patterns

Grafana's vulnerability history clusters around several recurring patterns:

**Plugin datasource injection** — Grafana plugins receive user input (dashboard variable values, query parameters) and pass it to backend datasources. Plugins that construct queries by string concatenation rather than parameterised queries are susceptible to injection. This affects both SQL datasources (PostgreSQL, MySQL) and time-series datasources with query languages.

**Authentication bypass** — Grafana has had multiple CVEs where specific request paths bypassed authentication middleware. CVE-2021-43798 (path traversal) and CVE-2022-21673 (authentication bypass in certain middleware configurations) are examples. These vulnerabilities are typically in URL routing logic and affect all Grafana deployments regardless of datasource configuration.

**Image renderer RCE** — The Grafana image renderer is a separate Node.js service that uses Chromium to render dashboard panels to PNG for alerting notifications. Chromium sandboxing issues in the renderer have produced remote code execution vulnerabilities that affect installations using the rendering service.

### Grafana CVE Response Procedure

```bash
# Check installed Grafana version (package manager install)
grafana-cli --version

# Or via the HTTP API
curl -s http://localhost:3000/api/health | jq '.version'

# Docker image version
docker inspect grafana/grafana:latest | jq '.[0].Config.Labels'
```

For package manager installations, Grafana publishes to their own APT and YUM repositories. A standard `apt-get update && apt-get upgrade grafana` will pull the latest version. For Docker deployments, pull the updated image and restart the container.

Grafana plugins have a separate release cycle from the core product. When a CVE affects a plugin, updating the Grafana binary is not sufficient — you must also update the plugin:

```bash
# List installed plugins and versions
grafana-cli plugins ls

# Update a specific plugin
grafana-cli plugins update grafana-piechart-panel

# Update all plugins
grafana-cli plugins update-all
```

**Grafana Enterprise vs OSS security advisories** — Grafana Enterprise ships additional features (enhanced RBAC, reporting, data source permissions). Some CVEs affect only OSS, some only Enterprise, and some both. The Grafana security advisory page clearly identifies which editions are affected. If you run Grafana Enterprise, subscribe to advisories with the Enterprise filter applied.

## Elasticsearch and OpenSearch Security Disclosure

Elastic's security reporting contact is **security@elastic.co**. Published advisories appear on the [Elastic Security Advisory page](https://www.elastic.co/community/security). Elastic operates a bug bounty programme through HackerOne.

OpenSearch — the AWS-maintained fork of Elasticsearch — uses GitHub private advisories at `github.com/opensearch-project/OpenSearch/security/advisories`.

### The Log4j Incident as a Case Study

The log4j vulnerability in December 2021 affected Elasticsearch 7.x in a way that illustrates both the risk and the response pattern. Elasticsearch shipped with log4j 2.x as a logging dependency. The JNDI injection vulnerability (CVE-2021-44228) meant that any string processed by log4j that contained a `${jndi:...}` expression would cause log4j to make an outbound LDAP connection, which could be used to load and execute arbitrary Java classes.

In an Elasticsearch context, this was triggerable by indexing a document containing a crafted string — because Elasticsearch logs document content in various circumstances (debug logging, shard allocation logging). An application that writes user-controlled content to Elasticsearch could therefore trigger RCE on the Elasticsearch nodes.

The response from the consumer side looked like this:

1. **Identify exposure** — Is your Elasticsearch version in the affected range? (`curl -s http://localhost:9200 | jq '.version.number'`)
2. **Apply the immediate mitigation** — Elastic published JVM startup flag mitigations (`-Dlog4j2.formatMsgNoLookups=true`) within 24 hours of the CVE publication. These could be applied without a full upgrade.
3. **Plan the upgrade** — Elasticsearch rolling upgrades require careful sequencing: upgrade one node at a time, verify cluster health between each node, and avoid crossing major version boundaries in a single upgrade.
4. **Verify** — After upgrading, confirm the log4j version in use: `find /usr/share/elasticsearch -name 'log4j*.jar'`

This pattern — immediate mitigation followed by a planned upgrade — is the standard consumer response to critical CVEs in stateful components like Elasticsearch.

### Elasticsearch Vulnerability Patterns

Beyond log4j, Elasticsearch vulnerability history includes:

- **Kibana SSRF** — Kibana (the Elasticsearch UI) has had SSRF vulnerabilities in its proxy endpoints. An attacker with access to Kibana can cause it to make HTTP requests to internal services.
- **Index privilege escalation** — Elasticsearch's security model uses index-level privileges. Vulnerabilities in the privilege evaluation logic have occasionally allowed users to read or write indexes outside their granted scope.
- **Snapshot repository path traversal** — Elasticsearch snapshot and restore functionality has had path traversal issues that could expose files outside the intended snapshot directory.

## Loki, Tempo, and the Grafana Labs Security Umbrella

Grafana Labs now maintains Loki (log aggregation), Tempo (distributed tracing), and Mimir (long-term metrics storage) under a single security programme. Security issues in any of these tools should be reported to `security@grafana.com` or via the respective GitHub private advisory mechanism.

Loki-specific vulnerabilities of note:

**Log injection** — Loki indexes log streams by label set. If an attacker can influence the label values attached to log streams — for example, by controlling Kubernetes pod labels in a multi-tenant environment — they may be able to inject log data into another tenant's stream, polluting the audit trail.

**LogQL injection** — Loki's query language (LogQL) is used in Grafana dashboard queries. If a Grafana dashboard accepts user input and interpolates it directly into a LogQL query, an attacker can manipulate the query to return data from log streams outside the intended scope.

## Consumer Response Workflow

### Automated Vulnerability Tracking

Subscribe to security advisories from each tool using GitHub's native advisory subscription (Watch → Security alerts on each repository). For tools not on GitHub, use RSS where available (Grafana publishes an advisory RSS feed; Elastic's advisory page supports RSS).

Container image scanning integrates with this workflow. Configure Grype or Trivy to scan observability tool images in your container registry on a scheduled basis:

```bash
# Scan the Grafana image for known CVEs
grype grafana/grafana:10.4.0

# Scan Prometheus
grype prom/prometheus:v2.51.0

# Scan Elasticsearch
grype docker.elastic.co/elasticsearch/elasticsearch:8.13.0
```

In a CI/CD context, add image scanning to the pipeline that updates image tags. If a scan fails above your defined severity threshold, block the promotion and alert the team.

### Zero-Downtime Upgrade Procedures

**Prometheus rolling restart** — Prometheus is stateless across restarts (TSDB data persists on disk, but no in-flight connections are lost). A rolling restart is safe: update the image or binary, verify the new version starts successfully and scrapes targets, then confirm alerting rules are evaluated correctly.

```bash
# Kubernetes: update image and wait for rollout
kubectl set image deployment/prometheus prometheus=prom/prometheus:v2.52.0 -n monitoring
kubectl rollout status deployment/prometheus -n monitoring
```

**Grafana with persistent storage** — Grafana stores dashboard definitions and user data in a SQLite or external database. Update the image, ensure the persistent volume is mounted, and verify dashboards are intact post-restart. If using an external database (PostgreSQL, MySQL), the upgrade does not affect the database schema in most minor version bumps — check the release notes for schema migration requirements.

**Elasticsearch cluster rolling upgrade** — Elasticsearch rolling upgrades require:
1. Disable shard allocation before upgrading each node: `PUT _cluster/settings {"persistent": {"cluster.routing.allocation.enable": "primaries"}}`
2. Stop the node, upgrade the package, start the node
3. Wait for the node to rejoin and cluster health to return to green: `GET _cluster/health`
4. Re-enable shard allocation: `PUT _cluster/settings {"persistent": {"cluster.routing.allocation.enable": null}}`
5. Repeat for each node

Do not proceed to the next node until the cluster is healthy. Mixed-version clusters are only supported for the duration of a rolling upgrade — a cluster left in mixed-version state is unsupported and may exhibit unpredictable behaviour.

### Verifying the Upgrade

After upgrading any observability tool:

1. Confirm the new version is deployed (version endpoint or binary version flag)
2. Verify that existing dashboards and alerts still function
3. Monitor error rates in the upgraded tool's own logs for 15–30 minutes
4. Confirm that any custom plugins or integrations are compatible with the new version

## What to Do If You Find a Vulnerability

If you discover a vulnerability in an observability tool, responsible disclosure means reporting privately before publishing any technical details.

**Scope your proof of concept carefully.** Demonstrating that you can read Elasticsearch indexes without authorisation does not require reading real production data. Use a test index with synthetic data. Document what data would be accessible in a real deployment without accessing it.

**Use the correct reporting channel.** Each project has a preferred channel. Avoid opening public GitHub issues for security vulnerabilities — these are immediately visible to potential attackers. Use private advisories or the security email addresses listed above.

**Expect and respect embargo periods.** Projects coordinate patch releases across distributions, cloud providers, and downstream consumers before publishing CVE details. An embargo period of 30–90 days is normal for high-severity vulnerabilities. Publishing before the embargo lifts puts users at risk before they have a path to remediation.

Reporting vulnerabilities in widely-deployed tools like Prometheus and Grafana has outsized impact. These tools are deployed in hundreds of thousands of organisations. A single CVE can expose security-sensitive observability data across all of them.

## Reference: Reporting and Response by Tool

| Tool | Reporting Channel | Advisory Feed | Typical Patch Time | Emergency Upgrade |
|---|---|---|---|---|
| Prometheus | prometheus-security@googlegroups.com / GitHub private advisory | GitHub releases RSS | 30–90 days | `kubectl set image` + rollout |
| Grafana OSS | security@grafana.com / HackerOne | grafana.com/security/security-advisories/ (RSS) | 7–30 days (mature programme) | `apt upgrade grafana` or pull new Docker image |
| Grafana Enterprise | security@grafana.com | Same RSS feed, Enterprise filter | 7–30 days | Grafana Enterprise upgrade procedure |
| Elasticsearch | security@elastic.co / HackerOne | elastic.co/community/security | 14–60 days | Rolling cluster upgrade (node by node) |
| OpenSearch | GitHub private advisory | github.com/opensearch-project security | 30–90 days | Rolling cluster upgrade |
| Loki | security@grafana.com | grafana.com/security/security-advisories/ (RSS) | 7–30 days | `kubectl set image` + rollout |
| Tempo | security@grafana.com | grafana.com/security/security-advisories/ (RSS) | 7–30 days | `kubectl set image` + rollout |
| Alertmanager | prometheus-security@googlegroups.com | GitHub releases RSS | 30–90 days | Must upgrade alongside Prometheus |

## Trade-offs

**Upgrade frequency vs stability** — Frequent upgrades keep you current with security fixes but introduce regression risk. Observability tools are instrumentation, not critical path — but a broken Grafana or a misconfigured Prometheus after an upgrade can produce alert fatigue or silently miss real incidents. Balance upgrade frequency against the cost of testing.

**Centralised patch management vs team autonomy** — A platform team managing a shared Grafana instance can apply security patches quickly and uniformly. Teams managing their own Grafana deployments have faster feature iteration but slower security response. Centralised management wins for security; distributed management wins for developer velocity.

**Version pinning vs automatic security updates** — Pinning observability tool versions to a specific tag gives you reproducible deployments and controlled change. Enabling automatic patch-level updates (e.g., `grafana/grafana:10.4` rather than `grafana/grafana:10.4.0`) means security fixes are applied without manual intervention, but also means the running version may differ from what your runbooks document.

## Failure Modes

**Grafana plugin not updated when core Grafana is** — Plugins have a separate release cycle. If you update the Grafana binary but not the installed plugins, you may still be running a vulnerable version of a plugin. Always run `grafana-cli plugins update-all` as part of the Grafana upgrade procedure and verify plugin versions post-upgrade.

**Elasticsearch rolling upgrade leaving cluster in mixed-version state** — If a node upgrade fails partway through, the cluster may remain in a mixed-version state. Elasticsearch supports this only transiently during upgrades. A cluster left in mixed-version state for extended periods may experience split-brain scenarios or index corruption. Monitor cluster health throughout the upgrade and have a rollback plan if a node fails to rejoin.

**Prometheus Alertmanager not updated alongside Prometheus** — Prometheus and Alertmanager are separate binaries with separate release cycles and separate version numbers. A CVE in Alertmanager requires updating Alertmanager specifically — updating Prometheus does not fix Alertmanager vulnerabilities, and vice versa. Always check which component is affected by a CVE and update each component independently.

**Loki and Prometheus running incompatible scrape configurations after upgrade** — Loki exposes a Prometheus-compatible metrics endpoint. If a Prometheus upgrade changes scrape behaviour or metric format expectations, dashboards that query Loki metrics may break silently. Verify dashboard functionality after upgrading any component in the stack, not just the component with the CVE.

## Summary

Observability tools are high-value targets because of the security-sensitive data they collect, not because they are operationally critical. Prometheus, Grafana, and Elasticsearch have mature but distinct security disclosure programmes. Each has a documented reporting channel, a published advisory feed, and an established upgrade path.

As a consumer, the minimum effective posture is: subscribe to security advisories for each tool you run, scan container images for known CVEs on a scheduled basis, and have a documented upgrade procedure for each tool that accounts for its statefulness and any downstream dependencies. When a CVE is published, your response time is determined by how much of this work you have already done.

If you find a vulnerability, report it privately through the appropriate channel and give the project time to patch before publishing technical details. Observability tools are deployed at scale — responsible disclosure protects the organisations that depend on them.
