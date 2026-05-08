---
title: "GitOps for OT Network Configuration: Preventing Conduit Drift"
description: "CISA identifies configuration drift as a key OT vulnerability. Manage firewall conduit rules and switch configs as Git-versioned code — with peer review, automated compliance checks, and drift detection that alerts when rules silently reopen IT-to-OT paths."
slug: ot-gitops-network-configuration
date: 2026-05-03
lastmod: 2026-05-03
category: cicd
tags:
  - ot-security
  - gitops
  - network-configuration
  - ics
  - drift-detection
personas:
  - platform-engineer
  - security-engineer
article_number: 410
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/cicd/ot-gitops-network-configuration/
---

# GitOps for OT Network Configuration: Preventing Conduit Drift

## The Problem

OT firewall and switch configurations degrade over time through accumulating exceptions. An engineer opens a temporary port for remote diagnostics; the change is never reverted. A vendor requests a permanent firewall rule "just for their equipment"; it is broader than necessary. After two years, the carefully designed ISA/IEC 62443 zone boundaries have been eroded by dozens of unreviewed changes.

CISA's April 2026 guidance, "Adapting Zero Trust Principles to Operational Technology," identifies this drift pattern explicitly: organisations that implement segmentation at deployment but do not have a process to detect and prevent drift are effectively unprotected within 12–18 months. The mechanism of degradation is mundane — a troubleshooting session, a vendor request, a missed cleanup task — but the cumulative effect is the same as having never segmented the network at all.

Git-backed infrastructure-as-code for OT network devices provides both detection and prevention. Every change is a commit. Every commit is reviewable. A CI pipeline can check that no proposed change violates conduit policy before it is applied. A scheduled drift-detection job can alert within 24 hours if a device's running configuration has diverged from what Git says it should be. This is not a theoretical improvement — it is a direct answer to the mechanism CISA describes: silent, unreviewed modification of rules that were carefully defined at deployment.

The scope here is OT network infrastructure configuration: firewall conduit rules, switch port-security settings, and VLAN assignments. This is distinct from OT patch management, which addresses software and firmware update pipelines. A correctly patched firewall running a drifted ruleset is still a security failure. Both dimensions require independent controls.

## Threat Model

- **Undocumented firewall exceptions that silently reopen IT→OT paths.** A segmentation project closes all IT-to-OT paths except approved conduits. Over 18 months, six "temporary" rules are added for troubleshooting and vendor access. None are removed. The network is effectively flat again, with no record of when each exception was created or why.

- **Rogue firewall rule added by a compromised admin account.** Without version control on device configurations, a rule inserted by an attacker is indistinguishable from one inserted by a legitimate engineer. There is no baseline to diff against, no alert when the configuration changes, and no audit trail showing when the change was made.

- **Vendor switch configuration change that disables port security.** A vendor engineer connects to a managed switch during a service call and disables 802.1X port authentication to simplify their access. The change is never reverted. Rogue device insertion is now possible on that switch segment.

- **Configuration restore after device failure that regresses security hardening.** A firewall fails and is replaced using a backup taken before the most recent security hardening pass. The restored device is running a version of the configuration that predates six months of improvements. Without Git as the authoritative source of the current desired configuration, this regression is invisible.

- **VLAN misconfiguration that places an OT device in the IT VLAN.** A switch port is misconfigured during cabling, placing a PLC on the IT VLAN rather than the OT VLAN. Without automated VLAN assignment tracking, this misconfiguration may persist indefinitely.

## Hardening Configuration

### 1. Repository Structure

The `ot-network-config` repository is the single source of truth for all OT network device configurations. Organise it by device type, with one configuration file per device and a separate conduit policy document that defines what is authoritative:

```text
ot-network-config/
├── conduit-policy.yaml
├── firewalls/
│   ├── fw-dmz-01.conf
│   ├── fw-ot-zone-a-01.conf
│   └── fw-ot-zone-b-01.conf
├── switches/
│   ├── sw-ot-floor-01.conf
│   ├── sw-ot-floor-02.conf
│   └── sw-dmz-01.conf
├── routers/
│   └── rtr-dmz-01.conf
├── scripts/
│   ├── check-conduit-compliance.py
│   ├── deploy-firewall.yml
│   └── detect-drift.sh
└── .github/
    └── workflows/
        ├── compliance-check.yml
        └── drift-detection.yml
```

The `conduit-policy.yaml` file is the authoritative definition of what network paths are permitted. All other files in the repository are validated against it. No configuration file may contain a rule that is not traceable to an entry in `conduit-policy.yaml`.

### 2. Conduit Policy as Code

`conduit-policy.yaml` defines the complete set of permitted communication paths between zones. Each entry specifies a source zone, destination zone, protocol, and port. Any firewall rule that cannot be traced to an entry here is a policy violation.

```yaml
schema_version: "1.0"
policy_owner: "ot-security@plant.example.com"
last_reviewed: "2026-05-01"
review_cycle_days: 90

zones:
  - id: corporate-it
    description: "Corporate IT network"
    cidr: "10.0.0.0/8"
  - id: dmz
    description: "OT DMZ — historian, jump server, data diode endpoints"
    cidr: "10.100.0.0/24"
  - id: ot-zone-a
    description: "Process control network — Zone A (reactors)"
    cidr: "192.168.10.0/24"
  - id: ot-zone-b
    description: "Process control network — Zone B (utilities)"
    cidr: "192.168.20.0/24"

conduits:
  - id: "C-001"
    description: "Historian read-only data pull from OT Zone A"
    source_zone: dmz
    destination_zone: ot-zone-a
    protocol: tcp
    destination_port: 102
    notes: "IEC 60870-5-104 from historian to SCADA server. Unidirectional read only."
    approved_by: "security-engineer@plant.example.com"
    approved_date: "2026-03-15"

  - id: "C-002"
    description: "Jump server SSH to OT engineering workstations"
    source_zone: dmz
    destination_zone: ot-zone-a
    protocol: tcp
    destination_port: 22
    notes: "Restricted to specific destination IPs defined in jump server ACL. Requires MFA."
    approved_by: "security-engineer@plant.example.com"
    approved_date: "2026-03-15"

  - id: "C-003"
    description: "OT Zone A NTP to internal NTP server in DMZ"
    source_zone: ot-zone-a
    destination_zone: dmz
    protocol: udp
    destination_port: 123
    notes: "Required for PLC time synchronisation."
    approved_by: "ot-operations@plant.example.com"
    approved_date: "2026-03-15"
```

This document is the starting point for firewall rule generation. The compliance checker (below) parses both this file and the device configuration files to verify alignment. When a new conduit is needed, an engineer opens a pull request that adds an entry to `conduit-policy.yaml` and adds the corresponding rule to the relevant `firewalls/*.conf` file. The PR must include the business justification and approval. The CI pipeline verifies that the rule matches a conduit entry and that no existing entries have been removed without a corresponding rule removal.

### 3. CI Pipeline: Compliance Check

A GitHub Actions workflow runs on every pull request that touches any file in the repository. It validates proposed firewall configurations against `conduit-policy.yaml` and rejects any rule that opens a path not covered by the policy.

```yaml
name: OT Network Compliance Check

on:
  pull_request:
    branches: [main]

jobs:
  compliance:
    runs-on: [self-hosted, dmz-runner]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install pyyaml

      - name: Run conduit compliance check
        run: python scripts/check-conduit-compliance.py
```

The compliance checker parses each firewall configuration file and verifies that every `accept` rule is matched by a conduit entry. The illustrative implementation below targets nftables format; adapt the rule parser for your deployed firewall vendor's configuration syntax:

```python
import sys
import re
import yaml
from pathlib import Path

def load_policy(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)

def parse_nftables_accept_rules(conf_path: str) -> list[dict]:
    rules = []
    with open(conf_path) as f:
        content = f.read()
    pattern = re.compile(
        r'ip\s+saddr\s+(\S+)\s+ip\s+daddr\s+(\S+)\s+'
        r'(\w+)\s+dport\s+(\d+)\s+accept'
    )
    for match in pattern.finditer(content):
        rules.append({
            "src": match.group(1),
            "dst": match.group(2),
            "proto": match.group(3),
            "port": int(match.group(4)),
            "raw": match.group(0).strip(),
        })
    return rules

def zone_for_cidr(cidr: str, zones: list[dict]) -> str | None:
    import ipaddress
    try:
        addr = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    for zone in zones:
        if addr.subnet_of(ipaddress.ip_network(zone["cidr"])):
            return zone["id"]
    return None

def rule_is_covered(rule: dict, conduits: list[dict], zones: list[dict]) -> bool:
    src_zone = zone_for_cidr(rule["src"], zones)
    dst_zone = zone_for_cidr(rule["dst"], zones)
    if src_zone is None or dst_zone is None:
        return False
    for conduit in conduits:
        if (
            conduit["source_zone"] == src_zone
            and conduit["destination_zone"] == dst_zone
            and conduit["protocol"] == rule["proto"]
            and conduit["destination_port"] == rule["port"]
        ):
            return True
    return False

def main():
    policy = load_policy("conduit-policy.yaml")
    zones = policy["zones"]
    conduits = policy["conduits"]

    violations = []
    for conf_file in Path("firewalls").glob("*.conf"):
        rules = parse_nftables_accept_rules(str(conf_file))
        for rule in rules:
            if not rule_is_covered(rule, conduits, zones):
                violations.append(f"{conf_file}: UNCOVERED RULE: {rule['raw']}")

    if violations:
        print("COMPLIANCE FAILURES:")
        for v in violations:
            print(f"  {v}")
        sys.exit(1)

    print("All firewall rules covered by conduit policy.")

if __name__ == "__main__":
    main()
```

A pull request that adds a rule permitting port 445 (SMB) from the corporate IT network to any OT zone will fail this check: there is no conduit entry covering that source zone, destination zone, and port combination. The PR cannot be merged until the CI check passes, which requires either removing the rule or adding a conduit entry — and adding a conduit entry requires its own peer review.

### 4. Automated Deployment to OT Devices

Approved configurations are deployed to OT firewalls from a CI runner that lives in the DMZ, not in the corporate IT network. The runner has SSH access to OT devices within its scope; it does not have unrestricted access to all OT devices. Credentials are short-lived SSH certificates issued by HashiCorp Vault, not long-lived private keys.

```yaml
name: Deploy OT Firewall Configuration

on:
  push:
    branches: [main]
    paths:
      - "firewalls/**"

jobs:
  deploy:
    runs-on: [self-hosted, dmz-runner]
    steps:
      - uses: actions/checkout@v4

      - name: Issue short-lived SSH certificate
        run: |
          vault write -field=signed_key \
            ssh/sign/ot-deploy \
            public_key=@/home/runner/.ssh/id_ed25519.pub \
            ttl=15m \
            > /home/runner/.ssh/id_ed25519-cert.pub

      - name: Deploy changed firewall configs
        run: ansible-playbook scripts/deploy-firewall.yml
```

The Ansible playbook copies the Git-tracked configuration to the target device and applies it atomically. A failed apply exits non-zero and halts the pipeline; the previous configuration remains active:

```yaml
- name: Deploy nftables configuration to OT firewalls
  hosts: ot_firewalls
  become: true
  serial: 1

  tasks:
    - name: Copy nftables configuration
      copy:
        src: "firewalls/{{ inventory_hostname }}.conf"
        dest: /etc/nftables.conf
        owner: root
        group: root
        mode: "0600"
        backup: true

    - name: Validate nftables configuration
      command: nft -c -f /etc/nftables.conf
      changed_when: false

    - name: Apply nftables configuration
      command: nft -f /etc/nftables.conf

    - name: Verify nftables is running
      command: nft list ruleset
      register: ruleset_output
      changed_when: false

    - name: Persist configuration across reboots
      service:
        name: nftables
        enabled: true
```

The `serial: 1` directive ensures firewalls are updated one at a time; a failure on the first device halts the play before touching subsequent devices. Every successful deployment is a Git commit with the SHA of the configuration that was applied, giving a complete deployment audit trail.

### 5. Drift Detection

A scheduled pipeline job runs daily and compares the running configuration of each OT network device against the Git-tracked version. Any divergence triggers an alert. This detects out-of-band changes — rules applied via direct SSH to the device, changes made through a vendor management interface, or configuration restores that loaded a stale backup.

```bash
#!/usr/bin/env bash

set -euo pipefail

REPO_DIR="/opt/ot-network-config"
ALERT_LOG="/var/log/ot-drift-alerts.jsonl"
DIFF_DIR="/tmp/ot-drift-diffs"
SSH_CERT="/home/runner/.ssh/id_ed25519-cert.pub"

mkdir -p "${DIFF_DIR}"

vault write -field=signed_key \
  ssh/sign/ot-drift-reader \
  public_key=@/home/runner/.ssh/id_ed25519.pub \
  ttl=10m \
  > "${SSH_CERT}"

FIREWALLS=$(awk '/\[ot_firewalls\]/{found=1; next} /\[/{found=0} found && /^[^;]/{print $1}' \
  "${REPO_DIR}/inventory.ini")

DRIFT_FOUND=0

for host in ${FIREWALLS}; do
  LIVE_CONFIG=$(ssh \
    -i /home/runner/.ssh/id_ed25519 \
    -o CertificateFile="${SSH_CERT}" \
    -o StrictHostKeyChecking=yes \
    "ot-deploy@${host}" \
    "nft list ruleset")

  GIT_CONFIG="${REPO_DIR}/firewalls/${host}.conf"

  if ! diff -u "${GIT_CONFIG}" <(echo "${LIVE_CONFIG}") \
       > "${DIFF_DIR}/${host}.diff" 2>&1; then

    DRIFT_FOUND=1
    jq -n \
      --arg host "${host}" \
      --arg diff "$(cat "${DIFF_DIR}/${host}.diff")" \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{event: "conduit_drift_detected", host: $host, diff: $diff, detected_at: $ts}' \
      >> "${ALERT_LOG}"

    echo "DRIFT DETECTED on ${host} — see ${DIFF_DIR}/${host}.diff"
  fi
done

if [ "${DRIFT_FOUND}" -eq 1 ]; then
  exit 1
fi

echo "No drift detected across all OT firewalls."
```

The drift detection job runs as a scheduled workflow. A non-zero exit code triggers an alert in the monitoring system. The diff output is written to the structured alert log, which is shipped to the SIEM. The detected drift should generate an incident ticket automatically — an email-only alert to an unmonitored mailbox is not sufficient.

### 6. Change Review Process

All OT network configuration changes are made exclusively through pull requests. No engineer — including OT security engineers and OT network engineers — has direct write access to `main`. Branch protection rules enforce this:

- Direct pushes to `main` are blocked for all users, including administrators.
- At least two approvals are required before merge: one from the OT security team and one from OT operations.
- The compliance check CI job must pass before merge is permitted.
- Commits must be signed.

A representative GitHub branch protection configuration:

```json
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "OT Network Compliance Check" }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  },
  "restrictions": {
    "users": [],
    "teams": []
  },
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_signatures": true
}
```

The `CODEOWNERS` file routes all reviews to the correct teams:

```text
firewalls/         @plant-org/ot-security @plant-org/ot-operations
switches/          @plant-org/ot-security @plant-org/ot-operations
routers/           @plant-org/ot-security @plant-org/ot-operations
conduit-policy.yaml  @plant-org/ot-security
```

Changes to `conduit-policy.yaml` require OT security team approval only; that team is responsible for policy decisions. Changes to device configuration files require both security and operations sign-off: operations confirms that the change does not disrupt process communication; security confirms that it does not open an unpolicied path.

## Expected Behaviour After Hardening

After drift detection: an OT network engineer connects directly to `fw-ot-zone-a-01` via SSH and adds an accept rule for port 3389 (RDP) from the DMZ to OT Zone A to facilitate a troubleshooting session. The change is applied to the running ruleset. The next morning, the drift detection job compares the live ruleset against `firewalls/fw-ot-zone-a-01.conf` in Git, finds the undeclared rule, writes a structured alert to the SIEM, and the pipeline exits non-zero. An incident ticket is opened automatically. The rule is identified, reviewed, and removed within hours — rather than persisting indefinitely as an undocumented exception.

After the compliance check: a PR is opened that adds an nftables accept rule for `ip saddr 10.0.0.0/8 ip daddr 192.168.10.0/24 tcp dport 445 accept` to `fw-dmz-01.conf`. The compliance checker finds no conduit entry covering the corporate IT network to OT Zone A on port 445. The CI job fails. The PR cannot be merged. The rule is blocked from ever reaching a device until a conduit entry is added and reviewed.

After the deployment pipeline: an approved change to `fw-ot-zone-a-01.conf` is merged. The deployment workflow triggers, issues a 15-minute SSH certificate from Vault, runs the Ansible playbook, validates the configuration before applying it, applies it atomically, and confirms the ruleset is live. The Git commit SHA, the identity that merged the PR, the approval timestamps, and the deployment timestamp form an unbroken audit trail.

## Trade-offs and Operational Considerations

OT firewall vendors produce configurations in vendor-specific formats. Fortinet FortiGate uses its own flat-file syntax; Palo Alto Networks firewalls use XML; Cisco ASA uses its own IOS-like format. The compliance checker and Ansible playbooks shown here target nftables on a Linux-based firewall. Adapting them to each vendor requires a parser for that vendor's configuration format. Budget engineering time for each vendor type deployed. A pragmatic sequencing: start with the device type that carries the most IT→OT traffic and expand from there.

SSH credential management for the CI runner requires care. The runner lives in the DMZ and has SSH access to OT devices. If the runner is compromised, an attacker has the same access. Mitigate this by scoping the deploy role in Vault to only the devices the runner manages, using short-lived certificates (15-minute TTL), and ensuring the runner has no write access to the Git repository itself — it can only read what has already been merged.

Emergency changes during a network outage may not permit the time for a pull request review cycle. Define a break-glass procedure: the engineer applying the emergency change records the exact commands run, opens a PR within two hours of the outage resolution that documents the change and brings the Git-tracked configuration into alignment with the live device, and triggers a post-incident review. The break-glass procedure must be tested at least annually so it is not invented under pressure during an actual outage.

OT engineers who are unfamiliar with Git workflows will find the pull-request model unfamiliar and potentially obstructive. Start with read-only access for OT operations staff — they can see the configuration and the audit trail without the risk of accidental commits. Introduce the PR workflow through a series of low-stakes changes (description fields, comments) before requiring it for all modifications. The investment in training pays back in the first incident where the audit trail identifies the source of a rogue rule.

## Failure Modes

**Compliance check implemented as advisory rather than blocking.** The CI pipeline runs and reports violations, but the branch protection configuration does not require the check to pass before merge. Engineers see the warning and merge anyway. The check produces output that no one acts on. Verify branch protection: the compliance check status context must appear in `required_status_checks` with `strict: true`. Test it by opening a PR with a known-bad rule and confirming the merge button is disabled.

**Drift detection alerts routed to an unmonitored inbox.** The daily drift job runs, detects divergence, and sends an email to an alias that was set up during the project but has never been monitored. Out-of-band changes accumulate undetected. Route drift alerts to the SIEM first, with the email as a secondary channel. Verify the SIEM alert by deliberately introducing a test divergence on a non-production device and confirming the alert fires and creates an incident ticket within the expected window.

**Deployment pipeline scoped to all OT devices rather than a subset.** The CI runner's Vault role grants SSH certificate issuance for every OT device in the environment. A compromised runner can now modify every firewall and switch simultaneously. Scope the Vault role to only the devices managed by that specific pipeline. Use separate runners with separate Vault roles for different OT zones.

**`conduit-policy.yaml` updated without meaningful peer review.** An engineer adds a broad conduit entry — `source_zone: corporate-it, destination_zone: ot-zone-a, protocol: tcp, destination_port: 0-65535` — and another engineer approves it without scrutiny. The policy file, which is the root of trust for the entire compliance checking system, drifts in the same way that individual device configurations drifted before Git was introduced. Require OT security team review for all changes to `conduit-policy.yaml` as a separate CODEOWNERS rule. Schedule a quarterly policy review that audits every conduit entry against current operational requirements and removes entries that are no longer needed.

## Related Articles

- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [Terraform Security](/articles/cicd/terraform-security/)
- [Pipeline Config Security](/articles/cicd/pipeline-config-security/)
- [OT Patch Management Pipeline](/articles/cicd/ot-patch-management-pipeline/)
