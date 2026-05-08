---
title: "Grafana Plugin Trust and RCE: The CVE-2026-27876 Attack Chain"
description: "CVE-2026-27876 chains a SQL expressions file-write with Grafana's enterprise plugin loader to achieve RCE from Viewer access. Understand the delayed-disclosure pattern and how to harden plugin trust, feature toggles, and filesystem permissions."
slug: grafana-plugin-trust-rce
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags:
  - grafana
  - plugin-security
  - rce
  - cve
  - enterprise
personas:
  - platform-engineer
  - security-engineer
article_number: 395
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/grafana-plugin-trust-rce/
---

## The Problem

CVE-2026-27876 is a CVSS 9.1 vulnerability in Grafana that chains two distinct weaknesses to produce remote code execution from a Viewer-level account. The first weakness lives in the SQL expressions evaluator: when the `sqlExpressions` feature toggle is enabled, Grafana allows users to run DuckDB queries against datasource results as a transformation layer. A path traversal in the expression evaluator's file-handling code lets a crafted query write arbitrary content to any path reachable by the Grafana process user — including the directory from which Grafana Enterprise loads plugin binaries. The second weakness is not a bug but a design assumption: Grafana Enterprise loads plugins from a configurable local filesystem path and executes them directly as the `grafana` OS user. An attacker who can write to that path can replace a plugin binary with arbitrary code. On the next plugin load — which may happen without a full Grafana restart — that code executes with the same privileges as the Grafana server process.

The two weaknesses together produce a kill chain that begins with authenticated Viewer access and ends with arbitrary command execution on the Grafana host. Each step in isolation is serious but limited. A file write that can only reach the Grafana config directory can overwrite datasource credentials or corrupt alerting rules — damaging, but constrained. Plugin binary execution without a write primitive requires a separate delivery mechanism. The combination removes both constraints simultaneously.

What makes this vulnerability operationally interesting beyond the technical chain is how Grafana Labs disclosed it. Grafana 12.4.2 shipped on a Tuesday with the release notes describing a "security fix" affecting the SQL expressions evaluator. No CVE ID appeared in those release notes. Seven days later, the CVE-2026-27876 advisory was published separately, referencing 12.4.2 as the fix and providing the full attack chain description. This sequence — patch first, assign CVE and publish advisory one week later — is a deliberate Grafana Labs policy for certain vulnerability classes. The rationale is that large operators running Grafana at scale need time to promote a patch through staging and into production before the precise attack surface is described in exploitable detail. A complete advisory published on patch day gives attackers and defenders the same information simultaneously; the week delay gives defenders a structural head start.

The tradeoff is real, and the costs fall on different parties depending on how they track security. Operators who watch the Grafana release notes and treat any "security fix" label as a reason to upgrade immediately are protected within the patch window. Operators who rely on CVE scanners — NIST NVD, their vulnerability management platform, or Dependabot security advisories — see nothing actionable until the CVE is assigned. There is a further gap for operators who watch GitHub: the commits that fixed the path traversal in `pkg/expr/sql.go` and added plugin path validation in `pkg/plugins/manager/loader/` were both visible in the public repository between the 12.4.2 tag and the advisory publication. A researcher correlating the changelog label "security fix" with the diff could reconstruct the injection point before the CVE ID existed. This means the week-long head start is real but not absolute, and it depends on attackers not actively monitoring the Grafana repository.

The `sqlExpressions` feature toggle was classified as `publicPreview` stability — technically available but not recommended for stable production deployments. In practice, operators enable `publicPreview` toggles during evaluation, find the SQL transformation capability genuinely useful, and leave the toggle enabled indefinitely. Grafana does not enforce toggle rollback. The attack surface that Grafana's own documentation considers preview-grade is frequently the attack surface that production deployments are actually exposing.

## Threat Model

The attack requires one condition that is off by default: the `sqlExpressions` feature toggle must be enabled. In Grafana OSS this toggle is disabled unless explicitly set. In some Grafana Cloud managed tenants and Grafana Enterprise deployments, it is enabled as part of an advanced data transformation package. Any deployment that enables it should treat it as a high-severity attack surface until patched.

A Viewer-level user — the lowest role in a Grafana organisation, typically granted broadly in multi-tenant or developer-facing deployments — can submit crafted SQL expression payloads through the Grafana expression API. No dashboard editor access is required. No admin token is needed. The path traversal in the evaluator does not require knowledge of the exact Grafana directory structure; a sequence of `../` components in the expression's file reference traverses to any path the process user can write to.

The file write primitive alone is sufficient for several damaging outcomes before the plugin chain is involved. Writing to `/etc/grafana/grafana.ini` or its equivalent can inject a new datasource configuration, replace an SMTP credential, or disable authentication requirements on next restart. Writing to `/var/lib/grafana/grafana.db` (where SQLite deployments store all Grafana state, including the encrypted secret store) can corrupt or replace the database. Writing to a mounted configuration volume in a Kubernetes deployment can propagate changes to other replicas that share the same ConfigMap mount point.

The plugin chain elevates the file write to code execution. Grafana Enterprise loads plugins from a directory configured in `grafana.ini` under `[plugins] plugins_path`. By default this is `/var/lib/grafana/plugins/`. Plugin binaries are executed directly by the Grafana server process when the plugin is first loaded or when Grafana restarts. Writing a malicious binary to replace an existing plugin binary — a plausible target is any Enterprise plugin already installed, because its binary name and path are predictable — converts the file write into a code execution primitive. The resulting execution context is the `grafana` OS user account with access to all environment variables the Grafana process holds, including datasource connection strings, API tokens, and encryption keys passed via environment variables in container deployments.

In a container or Kubernetes environment where Grafana runs as root (a common misconfiguration despite the official image defaulting to UID 472), code execution from the plugin binary yields root on the container, which may translate to a node escape depending on the pod's security context and host volume mounts.

The blast radius from code execution on the Grafana process is wide regardless of container or host deployment. Grafana's process has live connections to every configured datasource — Prometheus, Loki, Elasticsearch, and in enterprise deployments frequently RDS databases, cloud provider APIs, and internal secret managers. An attacker executing code in the Grafana process can read the decrypted form of every datasource credential from memory or from the environment, then pivot laterally to every system those credentials reach.

## Hardening Configuration

### 1. Upgrade

The definitive fix is upgrading to a patched release. The following versions contain the SQL expression path traversal fix and the plugin path validation:

- Grafana 11.6.14 and later 11.6.x releases
- Grafana 12.1.10 and later 12.1.x releases
- Grafana 12.2.8 and later 12.2.x releases
- Grafana 12.3.6 and later 12.3.x releases
- Grafana 12.4.2 and later 12.4.x releases

Verify the running version before and after upgrade:

```bash
grafana-server -v
```

In Kubernetes, verify the image tag on the running deployment:

```bash
kubectl get deployment grafana -n monitoring -o jsonpath='{.spec.template.spec.containers[0].image}'
```

### 2. Disable sqlExpressions

If upgrading is not immediately possible, disabling the `sqlExpressions` feature toggle is a complete compensating control for this specific CVE. The path traversal in the expression evaluator cannot be reached if the toggle is off, because the expression API rejects the request before it reaches the evaluator.

In `grafana.ini`:

```ini
[feature_toggles]
sqlExpressions = false
```

Via environment variable in a container deployment:

```bash
GF_FEATURE_TOGGLES_SQLEXPRESSIONS=false
```

Verify the toggle state after restarting Grafana by querying the runtime settings API:

```bash
curl -s -u admin:${GRAFANA_ADMIN_PASS} http://localhost:3000/api/frontend/settings \
  | jq '.featureToggles.sqlExpressions'
```

The expected output is `null` or `false`. Any truthy value indicates the toggle is still active and the API response should be treated as a continued exposure.

### 3. Plugin Directory Permissions

The plugin directory must not be writable by the `grafana` process user. If the process user can write to it, the file write primitive from the SQL expression evaluator can immediately escalate to code execution without any additional privilege step.

On a Linux host, set the plugin directory ownership to root and restrict write access:

```bash
chown -R root:root /var/lib/grafana/plugins
chmod -R 755 /var/lib/grafana/plugins
```

Verify that the `grafana` user cannot write to the directory:

```bash
sudo -u grafana touch /var/lib/grafana/plugins/.write-test 2>&1
```

The command should fail with `Permission denied`. If it succeeds, the directory permissions are insufficient.

For additional protection, use `chattr` to make the directory immutable at the filesystem level:

```bash
chattr +i /var/lib/grafana/plugins
```

Note that `chattr +i` prevents even root from writing to the directory without first removing the immutable flag. This is appropriate when plugin installation is handled exclusively through deployment pipelines rather than at runtime.

In Kubernetes, mount the plugin directory as a read-only volume:

```yaml
volumeMounts:
  - name: grafana-plugins
    mountPath: /var/lib/grafana/plugins
    readOnly: true
volumes:
  - name: grafana-plugins
    configMap:
      name: grafana-plugins
```

For deployments that install plugins at build time and bake them into the container image, no runtime plugin directory mount is needed at all — remove the plugin volume entirely and let the container filesystem serve the plugin binaries from the image layer, which the running process cannot modify.

### 4. Plugin Signature Enforcement

Grafana's plugin signing requirement provides a chain of trust between Grafana Labs and the plugin developer. It does not prevent execution of a plugin binary that an attacker has written to disk through a separate vulnerability — signature validation occurs at plugin load time, not as a continuous integrity check. However, enforcing the requirement prevents unsigned binaries from loading even if written to the plugin directory.

In `grafana.ini`:

```ini
[plugins]
allow_loading_unsigned_plugins =
```

Leaving `allow_loading_unsigned_plugins` empty means no unsigned plugins are permitted. Any value in this field is an explicit allowlist of plugin IDs that may load without a valid signature. Review this list: every entry is a plugin that bypasses Grafana's signing requirement and could be replaced with an arbitrary binary.

Verify signature enforcement is active by checking Grafana's startup log for any unsigned plugin that would have loaded under a permissive configuration:

```bash
journalctl -u grafana-server --since "1 hour ago" | grep -i "unsigned"
```

Under enforced signing, a line like `Plugin XYZ is unsigned` appears in the log and Grafana refuses to load that plugin. If you see this and the plugin is intentional, add it explicitly to `allow_loading_unsigned_plugins` with documented justification.

### 5. Run Grafana as Non-Root with no-new-privileges

The `grafana` OS user should be a system account with no login shell, no sudo access, and no supplementary groups that grant write access to sensitive directories. Verify the account configuration:

```bash
getent passwd grafana
```

The shell field should be `/sbin/nologin` or `/bin/false`.

In a systemd unit, enforce `NoNewPrivileges` and additional sandboxing:

```ini
[Service]
User=grafana
Group=grafana
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/grafana /var/log/grafana
PrivateTmp=true
```

In Kubernetes, enforce a restrictive security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 472
  runAsGroup: 472
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

`readOnlyRootFilesystem: true` is particularly effective here: it prevents any process inside the container from writing to paths that are not explicitly mounted as writable volumes, which eliminates the plugin binary overwrite path even if the file write primitive is somehow triggered.

### 6. RBAC Role Minimisation

Because CVE-2026-27876 is exploitable from Viewer access, reducing who holds even Viewer roles in Grafana orgs shrinks the attacker pool. In multi-tenant Grafana deployments, it is common to grant Viewer access to broad groups of developers or operations staff on the assumption that read access to dashboards is low-risk. This CVE demonstrates that read-access roles are not low-risk when combined with feature toggles that expose execution surfaces.

Audit Grafana organisation membership:

```bash
curl -s -u admin:${GRAFANA_ADMIN_PASS} http://localhost:3000/api/org/users \
  | jq '.[] | {login: .login, role: .role, lastSeenAt: .lastSeenAt}'
```

Remove users who have not accessed Grafana in the past 90 days. Restrict Viewer role grants to users who have a documented need to view specific dashboards rather than all dashboards in an org.

Use Grafana's data source query permissions feature (available in Grafana Enterprise and Grafana Cloud) to restrict which roles can submit queries to SQL-capable datasources — even before the SQL expression evaluator is reached, restricting datasource query access reduces the data surface available to a Viewer-level attacker.

## Expected Behaviour After Hardening

After disabling `sqlExpressions`, the SQL expressions option disappears from the panel editor's query transformation list. Existing dashboard panels that were using SQL expression transformations render an error indicating the feature is unavailable. The expression API at `/api/ds/query` rejects payloads containing SQL expression type with a 400 response and a message indicating the feature toggle is not enabled. The path traversal is unreachable.

After applying read-only permissions to the plugin directory, any process running as the `grafana` user that attempts to write to `/var/lib/grafana/plugins/` receives a `Permission denied` error. This applies to the Grafana server process itself, any plugin subprocess it spawns, and any code executing within a compromised expression evaluator. A test write from the grafana user account confirms the protection is active:

```bash
sudo -u grafana touch /var/lib/grafana/plugins/.write-test
```

After enabling unsigned plugin enforcement, Grafana startup logs contain explicit rejection messages for any plugin binary that lacks a valid Grafana Labs signature:

```
logger=plugin.loader level=warn msg="Plugin XYZ is unsigned"
```

Grafana continues starting but that plugin is not loaded. If this message appears for a plugin that was previously loading silently, it indicates the plugin was already unsigned and the enforcement is newly catching it — not that the plugin was recently modified.

## Trade-offs and Operational Considerations

Disabling `sqlExpressions` removes a legitimate data transformation capability. SQL expressions allow dashboard builders to perform joins and aggregations across datasource results without modifying the underlying datasource schema or writing separate ETL jobs. Teams that have built dashboards relying on this capability will see those dashboards break immediately after the toggle is disabled. Before disabling, audit which dashboards use SQL expression transforms:

```bash
curl -s -u admin:${GRAFANA_ADMIN_PASS} http://localhost:3000/api/search?type=dash-db \
  | jq -r '.[].uid' \
  | while read uid; do
      curl -s -u admin:${GRAFANA_ADMIN_PASS} "http://localhost:3000/api/dashboards/uid/${uid}" \
        | jq --arg uid "$uid" 'select(.dashboard.panels[]?.targets[]?.type == "math" or
            (.dashboard | tostring | test("sqlExpressions|sql_expression")))
            | {uid: $uid, title: .dashboard.title}'
    done
```

Grafana's native transformation pipeline (join by field, filter by value, organize fields, group by) covers many use cases that SQL expressions addressed. Migration effort varies from trivial to substantial depending on the complexity of the SQL expression logic.

Making the plugin directory read-only prevents runtime plugin installation through Grafana's plugin administration UI (`grafana-cli plugins install` and the Grafana UI plugin catalogue). Any plugin update requires rebuilding and redeploying the container image or rerunning the host-level provisioning that manages the plugin directory. This is a meaningful operational shift for teams accustomed to installing plugins interactively. It is, however, the right operational model for production Grafana: plugins should be versioned in configuration management, reviewed before installation, and deployed through the same pipeline that deploys other infrastructure changes.

Plugin signature enforcement blocks community plugins that have not completed Grafana Labs' signing programme. Some niche or recently published plugins may not be signed. If an unsigned plugin is genuinely required, add it to `allow_loading_unsigned_plugins` explicitly by plugin ID, document the security review outcome, and add a recurring review to re-evaluate whether a signed alternative exists.

## Failure Modes

Running multiple Grafana replicas behind a load balancer and disabling `sqlExpressions` in only one replica's configuration is a realistic operational error in deployments where Grafana configuration is managed per-instance rather than centrally. The replica with the toggle still enabled remains fully exploitable. Traffic from an attacker retrying requests will eventually hit the unpatched instance. Configuration management must propagate the toggle change to every Grafana instance that shares the same datasource database — they are all part of the same attack surface even if they are separate processes.

Protecting the plugin directory while leaving `/var/lib/grafana/` as a whole writable by the `grafana` user closes the code execution path but leaves the configuration overwrite path open. An attacker with the file write primitive can still overwrite `grafana.ini`, inject datasource credentials, or corrupt the SQLite database if those files are within the writable path. The hardening must cover both the plugin directory and the broader Grafana data directory. For the data directory, `ProtectSystem=strict` with explicit `ReadWritePaths` in the systemd unit, or a read-only root filesystem in Kubernetes with specific writable volume mounts for only the paths Grafana genuinely needs to write, provides the necessary restriction.

Failing to monitor Grafana startup logs for unsigned plugin warnings means that any plugin that is already installed without a valid signature — or one that an attacker has written to the plugin directory before the read-only mount was applied — can load silently. Startup log monitoring is not a compensating control for the directory permission hardening; it is a detection layer that confirms the enforcement is working as expected. Alert on any occurrence of `Plugin is unsigned` in Grafana startup logs so that the operations team investigates before the next Grafana restart silently loads an unexpected binary.

A subtler failure mode is relying on the CVE scanner to prompt patching action. As described, the CVE-2026-27876 advisory was published one week after the fix shipped in 12.4.2. A vulnerability management workflow that queries the NVD or a commercial feed for CVE IDs and generates tickets will generate no ticket during that week. Organisations whose patch cadence is driven by scanner output rather than by release monitoring will have no automated signal to patch. The correct posture is to subscribe to Grafana's security advisory feed at `https://grafana.com/security/security-advisories/` and treat any release note containing "security fix" as requiring the same response as a published CVE — even before the CVE ID exists.

## Related Articles
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
