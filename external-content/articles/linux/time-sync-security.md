---
title: "Time Synchronization Security: Hardening NTP and Chrony Against Manipulation"
description: "Accurate time is a silent dependency of almost every security control on a Linux system."
slug: "time-sync-security"
date: 2026-02-15
lastmod: 2026-02-15
category: "linux"
tags: ["ntp", "chrony", "nts", "time-synchronization", "hardening", "linux"]
personas: ["systems-engineer", "sre"]
article_number: 17
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
published: true
layout: article.njk
permalink: "/articles/linux/time-sync-security/index.html"
---

# Time Synchronization Security: Hardening NTP and Chrony Against Manipulation

## Problem

Accurate time is a silent dependency of almost every security control on a Linux system. When an attacker can manipulate the system clock, the consequences extend far beyond incorrect timestamps:

- **TLS certificate validation breaks.** If the attacker sets the clock forward past a certificate's expiry, valid certificates are rejected. If they set the clock backward, revoked or expired certificates appear valid. An attacker who can manipulate time on a host can force it to accept a certificate that has been compromised and revoked.
- **TOTP two-factor authentication fails.** TOTP tokens are valid for a 30-second window. A clock skew of more than 30 seconds means legitimate users cannot authenticate, or tokens from the past/future are accepted.
- **Log correlation breaks.** Security incident investigation depends on correlating events across multiple hosts. A 5-second clock drift between your web server and your database server means you cannot determine which event happened first. A 60-second drift makes incident timelines meaningless.
- **Kerberos authentication fails.** Kerberos has a default maximum clock skew of 5 minutes. Beyond that, authentication tickets are rejected.
- **Distributed consensus breaks.** Raft (etcd, Consul) and Paxos-based systems use time for leader election timeouts. Sufficient clock skew can trigger split-brain or repeated leader elections.

Chrony is the default NTP implementation on Ubuntu 24.04, Debian 12, and RHEL 9. Its defaults trust upstream NTP servers without any authentication, meaning a man-in-the-middle attacker on the network path can send forged time responses.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9.

## Threat Model

- **Adversary:** Network-adjacent attacker who can intercept or forge NTP packets between the host and its time source (ARP spoofing, compromised router, rogue DHCP providing malicious NTP servers).
- **Access level:** Network access on the path between the host and its NTP server. NTP uses unauthenticated UDP by default, making forgery straightforward.
- **Objective:** Manipulate the system clock to bypass TLS certificate validation, accept expired/revoked certificates, break TOTP authentication, disrupt log correlation, or cause denial of service through Kerberos failures.
- **Blast radius:** Every time-dependent security control on the host. TLS, TOTP, Kerberos, log integrity, and distributed consensus are all affected simultaneously.

## Configuration

### Chrony Hardening

The default chrony configuration is functional but not hardened. It typically points at a pool of NTP servers without authentication and allows the clock to be stepped by large amounts.

Create a hardened chrony configuration:

```ini
# /etc/chrony/chrony.conf (Ubuntu/Debian)
# /etc/chrony.conf (RHEL/Rocky)

# --- Time Sources ---
# Use specific, trusted NTP servers instead of a generic pool.
# Multiple sources provide redundancy and allow chrony to detect outliers.
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
server nts.sth1.ntp.se iburst nts

# Minimum number of sources required to update the clock.
# With 4 sources, minsources=2 ensures a single rogue server cannot
# shift the clock on its own.
minsources 2

# --- Clock Discipline ---
# makestep: Allow stepping the clock by up to 0.1 seconds during the
# first 3 updates after start. After that, only slewing (gradual adjustment).
# A large step after initial sync means something is very wrong.
makestep 0.1 3

# Maximum allowed offset from the NTP source before chrony refuses
# to adjust. Prevents a compromised NTP server from making large changes.
maxchange 100 1 2

# Maximum clock drift rate (in ppm). If the measured drift exceeds this,
# chrony logs a warning. Useful for detecting hardware clock issues.
maxdrift 100

# --- Access Control ---
# Deny NTP client access from the network.
# This host is a client only, not a server.
deny all

# Restrict command access to localhost only.
# Prevents remote chronyc connections.
cmdallow 127.0.0.1
cmdallow ::1
cmddeny all

# Bind command socket to localhost only
bindcmdaddress 127.0.0.1
bindcmdaddress ::1

# --- Logging ---
# Log measurements, statistics, and tracking data
log measurements statistics tracking

# Log directory
logdir /var/log/chrony

# --- Security ---
# Drop root privileges after binding to NTP port
user _chrony

# NTS key storage (for NTS cookie caching)
ntsdumpdir /var/lib/chrony

# Store the drift rate between restarts
driftfile /var/lib/chrony/drift

# Use a hardware timestamp if available (improves accuracy)
hwtimestamp *
```

Apply and verify:

```bash
sudo systemctl restart chronyd

# Check chrony source status
chronyc sources -v
# Expected: 4 sources with "^*" marking the selected source
# NTS-authenticated sources show "N" in the mode column

# Check NTS status
chronyc -N authdata
# Expected: Shows NTS key establishment status for each server
# Mode should show "NTS" for all configured NTS servers

# Check tracking accuracy
chronyc tracking
# Key values:
#   System time: offset from NTP (should be sub-millisecond)
#   Last offset: last measured offset
#   RMS offset: average offset
```

### NTS (Network Time Security) Configuration

NTS is the successor to NTP symmetric key and autokey authentication. It uses TLS to authenticate the NTP server and establish session keys for authenticating subsequent NTP packets. Chrony has supported NTS since version 4.0.

NTS-enabled servers:

| Server | Provider | Location |
|--------|----------|----------|
| `time.cloudflare.com` | Cloudflare | Anycast (global) |
| `nts.netnod.se` | Netnod | Sweden |
| `ptbtime1.ptb.de` | PTB (German national metrology institute) | Germany |
| `nts.sth1.ntp.se` | Netnod | Stockholm |
| `nts.sth2.ntp.se` | Netnod | Stockholm |
| `virginia.time.system76.com` | System76 | Virginia, US |

Verify NTS is working:

```bash
# Check NTS key establishment
chronyc -N authdata
# Name/IP address   Mode KeyID Type KLen Last Atmp  NAK Cook CLen
# ================================================================
# time.cloudflare.com NTS     1  AEAD  256  33m    0    0    8  100
# nts.netnod.se      NTS     1  AEAD  256  33m    0    0    8  100

# "NAK" column should be 0 (no authentication failures)
# "Cook" column should show cached cookies (>0)
```

### Restricting NTP Sources with Firewall

Prevent the host from accepting time from unauthorized sources:

```bash
# nftables rules to restrict NTP traffic
table inet ntp_hardening {
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Allow NTP (port 123) and NTS-KE (port 4460) only to trusted servers
        # Replace these IPs with the resolved addresses of your NTP servers
        ip daddr { 162.159.200.1, 194.58.207.12 } udp dport 123 accept
        ip daddr { 162.159.200.1, 194.58.207.12 } tcp dport 4460 accept
        
        # Block all other outbound NTP
        udp dport 123 drop
        tcp dport 4460 drop
    }
    
    chain input {
        type filter hook input priority 0; policy accept;
        
        # Block inbound NTP requests (this host is not an NTP server)
        udp dport 123 drop
    }
}
```

### Monitoring Time Drift

Set up monitoring to detect when the clock drifts beyond acceptable thresholds:

```bash
# Prometheus node_exporter exposes time metrics by default:
# node_timex_offset_seconds - current clock offset
# node_timex_sync_status - 1 if synchronized, 0 if not

# Alert when drift exceeds 100ms (Prometheus alerting rule)
```

```yaml
# prometheus-alerts.yml
groups:
  - name: time_sync
    rules:
      - alert: ClockDriftHigh
        expr: abs(node_timex_offset_seconds) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Clock drift exceeds 100ms on {{ $labels.instance }}"
          
      - alert: ClockNotSynchronized
        expr: node_timex_sync_status != 1
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Clock not synchronized on {{ $labels.instance }}"
          
      - alert: NTPSourcesLow
        expr: chrony_sources_count < 2
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Fewer than 2 NTP sources on {{ $labels.instance }}"
```

For chrony-specific metrics, use the `chrony_exporter`:

```bash
# Install chrony_exporter for Prometheus
# Exposes: chrony_tracking_last_offset, chrony_tracking_rms_offset,
#          chrony_sources_count, chrony_source_last_sample_offset
```

### Manual Drift Check Script

```bash
#!/bin/bash
# check-time-sync.sh - verify time synchronization health

echo "=== Chrony Source Status ==="
chronyc sources

echo ""
echo "=== Tracking ==="
chronyc tracking

echo ""
echo "=== Time Offset ==="
OFFSET=$(chronyc tracking | grep "System time" | awk '{print $4}')
OFFSET_MS=$(echo "$OFFSET * 1000" | bc)
echo "Current offset: ${OFFSET_MS} ms"

if (( $(echo "$OFFSET_MS > 100 || $OFFSET_MS < -100" | bc -l) )); then
    echo "WARNING: Clock drift exceeds 100ms"
    exit 1
else
    echo "OK: Clock drift within acceptable range"
    exit 0
fi

echo ""
echo "=== NTS Authentication ==="
chronyc -N authdata
```

## Expected Behaviour

After applying chrony hardening:

- `chronyc sources` shows 4 NTS-authenticated sources with one selected (marked `^*`)
- `chronyc -N authdata` shows NTS mode for all sources with zero NAK (authentication failures)
- `chronyc tracking` shows sub-millisecond system time offset
- The clock does not step after initial synchronization (only slews gradually)
- `chronyc activity` shows the expected number of online sources
- Outbound NTP traffic goes only to the configured servers (verify with `tcpdump udp port 123`)
- No inbound NTP requests are accepted (the host is a client only)
- Prometheus metrics show `node_timex_sync_status = 1` and `node_timex_offset_seconds` near zero

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| NTS authentication | NTP responses are authenticated, preventing forgery | Slight latency on initial key establishment (one TLS handshake). Not all NTP servers support NTS yet. Fewer server options. | Use NTS where available. The initial handshake is a one-time cost per server; subsequent packets use cached session keys. |
| `minsources 2` | A single rogue NTP source cannot shift the clock | If 3 of 4 sources become unreachable, chrony stops updating the clock entirely | Configure at least 4 sources from different providers and networks. |
| `makestep 0.1 3` | Prevents large clock jumps after initial synchronization | If the clock drifts by more than 0.1 seconds, chrony logs a warning but does not correct it with a step. Correction must happen via slow slewing. | If a large correction is needed (after hardware failure or long downtime), manually run `chronyc makestep` or restart chrony to allow a new initial step. |
| Firewall NTP restriction | Prevents the host from receiving time from unauthorized sources (rogue DHCP, spoofed NTP) | NTP server IP changes require firewall updates | Use DNS names in chrony config. Update firewall rules when server IPs change. |
| `deny all` (NTP server access) | Host does not serve time to the network | Cannot use this host as a local NTP server for other hosts | If you need a local NTP stratum, configure a dedicated NTP server with appropriate access controls. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| All NTS sources unreachable | Chrony has no time source. Clock begins to drift based on the local oscillator quality (typically 10-100 ppm, or 0.9-8.6 seconds per day). | `chronyc sources` shows all sources as unreachable. `node_timex_sync_status = 0` in Prometheus. | Check network connectivity to NTS servers. Check if the firewall is blocking port 123 (UDP) or 4460 (TCP). Add backup NTS sources from different providers. |
| Clock drift causes TLS failures | Outbound HTTPS connections fail with "certificate not yet valid" or "certificate has expired". Internal services reject each other's certificates. | Application logs show TLS handshake errors related to certificate validity periods. `curl -v https://example.com` shows certificate time errors. | Run `chronyc makestep` to force an immediate clock correction. Investigate why NTP synchronization failed. |
| Clock drift breaks TOTP | Users cannot log in with TOTP. 2FA codes are consistently rejected. | Authentication logs show TOTP validation failures. Users report that codes from their authenticator apps are rejected. | Correct the clock with `chronyc makestep`. Most TOTP implementations accept codes within a 1-2 step window (30-60 seconds), so moderate drift may not be immediately visible. |
| NTS key establishment fails | Chrony falls back to unauthenticated NTP (if `nts` directive is set without requiring it) | `chronyc -N authdata` shows NAK count increasing or no NTS sessions established. Logs show TLS handshake failures. | Check that the system's CA certificates are current (`update-ca-certificates`). Verify DNS resolution is working (NTS-KE uses DNS). Check that port 4460 TCP is not blocked. |
| `makestep` limit prevents necessary correction | After long downtime, the clock is off by more than 0.1 seconds and chrony refuses to step it | `chronyc tracking` shows a large offset that is not decreasing. Slewing a 5-second offset at the maximum rate takes hours. | Restart chrony to get 3 new initial step opportunities. Or manually run `chronyc makestep` to force an immediate correction. |
| Rogue DHCP provides malicious NTP server | Host receives NTP from attacker-controlled server via DHCP option 42 | `chronyc sources` shows an unexpected NTP source. DHCP lease shows unknown NTP server. | Configure chrony with explicit servers (not DHCP-provided). Use the firewall rules from this article to block NTP to unauthorized destinations. Configure DHCP client to ignore NTP options. |

## When to Consider a Managed Alternative

**Transition point:** When you manage more than 10 hosts and need to monitor time synchronization health centrally, or when time drift exceeding 100ms has caused a production incident (TLS failures, TOTP failures, or broken log correlation).

**What managed providers handle:**

Cloud providers configure NTP on their instances automatically. AWS uses the Amazon Time Sync Service, GCP provides `metadata.google.internal` as an NTP source, and Azure uses `time.windows.com`. These are low-latency, authenticated (within the provider's network), and require no configuration.

Managed [Kubernetes](https://kubernetes.io) providers handle NTP on the underlying nodes. You do not configure chrony on managed node pools.

[Grafana Cloud](https://grafana.com/cloud) and [Axiom](https://axiom.co) can ingest time drift metrics from your fleet and provide dashboards and alerts when any host's clock drifts beyond your threshold. This centralised view is more effective than per-host monitoring scripts when managing a fleet.

**What you still control:** On self-managed infrastructure (bare metal, self-managed VMs), NTP configuration and monitoring are your responsibility. The chrony hardening in this article applies directly. Even on managed infrastructure, you should verify that time synchronization is healthy by monitoring the `node_timex_offset_seconds` metric and alerting when it exceeds your tolerance.

**Automation path:** For self-managed infrastructure, deploy the chrony configuration from this article through your configuration management tool. Use the Prometheus alerting rules to detect drift before it causes an outage. For fleet-wide time health visibility, the monitoring dashboard pack provides pre-built [Grafana](https://grafana.com) dashboards for time synchronization metrics across your entire infrastructure.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
- [Hardening /proc and /sys: Restricting Kernel Information Disclosure](/articles/linux/proc-sys-hardening/)
