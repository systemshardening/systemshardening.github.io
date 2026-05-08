---
title: "Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything"
description: "A team of 1-5 engineers cannot implement 100 hardening controls simultaneously. Most hardening guides present controls as equally important, leaving..."
slug: "hardening-small-teams"
date: 2026-01-12
lastmod: 2026-01-12
category: "cross-cutting"
tags: ["prioritisation", "small-teams", "hardening", "maturity-model", "roadmap"]
personas: ["devops-engineer", "systems-engineer"]
article_number: 92
difficulty: "beginner"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "small-team-hardening-kit"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/hardening-small-teams/index.html"
---

# Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything

## Problem

A team of 1-5 engineers cannot implement 100 hardening controls simultaneously. Most hardening guides present controls as equally important, leaving small teams paralysed by scope. The result: nothing gets done, or random controls are applied inconsistently.

Small teams face the same attackers as enterprises, automated scanners do not check your headcount before attacking. But the response must be different. A 100-person security team can implement everything in parallel. A 3-person DevOps team must choose: what do we do first, what do we skip, and when do we pay someone else to handle a layer?

This article provides a prioritised hardening roadmap with explicit "do this first" ordering, "skip this" guidance for controls that require dedicated staffing, and "pay for this" guidance for when managed services make more sense than DIY.

## Threat Model

- **Adversary:** Opportunistic attacker using automated scanning tools. Not a targeted nation-state attack; the most common threat to small organisations is automated exploitation of known vulnerabilities and default configurations.
- **Key insight:** Small teams face the same automated attacks as large enterprises, but with 1/100th the staffing. Prioritisation is not optional; it IS the strategy.

## Configuration

### The Hardening Maturity Model

Five stages, each building on the previous. Move through them in order. Do not skip ahead.

#### Stage 0: Defaults (Where Most Small Teams Start)

- Stock OS installation with default configurations
- SSH with password authentication
- No firewall rules (relying on cloud security groups only)
- No monitoring beyond uptime checks
- Secrets in environment variables or `.env` files
- No automated patching

**Time at Stage 0 should be zero.** If you are reading this article, move to Stage 1 today.

#### Stage 1: Essential Controls (Do This Today - 4 Hours)

These controls take under 4 hours total and block the most common automated attacks.

```bash
# 1. HTTPS everywhere (30 minutes)
# If you don't have TLS, set it up now.
# cert-manager + Let's Encrypt for Kubernetes.
# Certbot for standalone servers.
sudo apt install certbot
sudo certbot --nginx -d yourdomain.com

# 2. SSH key-only authentication (15 minutes)
# /etc/ssh/sshd_config:
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
MaxStartups 10:30:60
sudo systemctl restart sshd

# 3. Firewall default-deny (30 minutes)
# Cloud: configure security group to allow only 22, 80, 443
# Host: nftables or ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# 4. Automatic security updates (15 minutes)
# Ubuntu:
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
# This enables automatic security patches. Full package upgrades
# still require manual review.

# 5. MFA on all admin accounts (30 minutes)
# GitHub: enable 2FA for all org members (Settings → Authentication Security)
# Cloud provider: enable MFA on root/admin account
# SSH: add TOTP via pam_google_authenticator (optional - key-only auth is sufficient for Stage 1)
```

**Verification:** After Stage 1, your systems are protected against: password brute force (SSH keys + MFA), unencrypted traffic interception (HTTPS), known vulnerability exploitation (auto-updates), and network scanning (firewall default-deny).

#### Stage 2: Foundation (Do This Week - 1-2 Days)

```bash
# 6. sysctl hardening (1 hour)
# See Article #1 - apply the network, kernel, and filesystem sysctl settings.
# Download the config files and apply:
sudo cp 60-net-hardening.conf /etc/sysctl.d/
sudo cp 60-kernel-hardening.conf /etc/sysctl.d/
sudo cp 60-fs-hardening.conf /etc/sysctl.d/
sudo sysctl --system

# 7. NGINX hardening (1 hour)
# See Article #39 - apply the hardened nginx.conf template.
# Copy the complete hardened config and customise ReadWritePaths.

# 8. DNS security (1 hour)
# See Article #41 - set up CAA records and enable DNSSEC.
# At minimum: add CAA records to your DNS zone:
# example.com. IN CAA 0 issue "letsencrypt.org"
# example.com. IN CAA 0 issuewild "letsencrypt.org"

# 9. Backup encryption (2 hours)
# Encrypt all backups at rest.
# For PostgreSQL: pg_basebackup with encryption
# For general: use restic or borg with encryption keys
sudo apt install restic
restic init --repo s3:s3.amazonaws.com/your-backup-bucket
restic backup /var/lib/postgresql --exclude-caches

# 10. Secret management (2 hours)
# Move secrets out of .env files and into SOPS or Vault.
# For small teams: SOPS is simpler to start with.
# See Article #52 for full secret management guide.
```

#### Stage 3: Automated (Do This Month - 1-2 Weeks)

```bash
# 11. Ansible hardening playbooks (4-8 hours)
# See Article #15 - set up the Ansible playbook collection.
# This automates everything from Stages 1 and 2 across all hosts.
# Run on every new host. Schedule drift detection weekly.

# 12. CI/CD pipeline hardening (4 hours)
# See Article #55 - GitHub Actions permissions, SHA pinning, environment protection.
# Apply to all repositories.

# 13. Container image scanning (2 hours)
# Add Trivy to every CI pipeline:
# - uses: aquasecurity/trivy-action@v0.28.0
#   with:
#     severity: CRITICAL,HIGH
#     exit-code: 1

# 14. Kubernetes hardening (if applicable - 8-16 hours)
# See Article #91 - the complete K8s hardening guide.
# Apply: default-deny network policies, PSS restricted, RBAC least-privilege.

# 15. Scheduled compliance scans (2 hours)
# kube-bench for Kubernetes, InSpec for Linux.
# Schedule weekly via cron or CI pipeline.
```

#### Stage 4: Monitored (Ongoing)

```bash
# 16. Centralized logging (4-8 hours)
# See Article #62 - audit log pipeline.
# Ship audit logs from all hosts to a centralized backend.
# Start with Grafana Cloud (#108) free tier (50GB/month).

# 17. Security metrics and alerting (4 hours)
# See Article #64 - Prometheus security metrics.
# Deploy the PrometheusRule YAML with auth, RBAC, cert, and network alerts.

# 18. Runtime detection (4 hours)
# See Article #29 - Falco on Kubernetes.
# Deploy Falco, apply custom rules for your workload types.

# 19. Incident response runbooks (4 hours)
# Write runbooks for: credential compromise, service outage, data breach.
# Link runbooks to alert annotations.
```

#### Stage 5: Managed (Offload These - In This Order)

When your time is more valuable than the managed service cost, offload:

| Priority | What to offload | Why first | Provider | Cost |
|----------|----------------|-----------|----------|------|
| 1 | **DNS** | Easiest migration; eliminates DNSSEC management; immediate DDoS protection | [Cloudflare](https://www.cloudflare.com) free tier | Free |
| 2 | **Observability** | Eliminates Prometheus/[Loki](https://grafana.com/oss/loki/) cluster management; managed retention and alerting | [Grafana Cloud](https://grafana.com/cloud) | Free tier → $29/month |
| 3 | **K8s control plane** | Eliminates etcd, API server, and node management; saves 8-16 hours/month | [Civo](https://www.civo.com) or [DigitalOcean](https://www.digitalocean.com) | $20-60/month |
| 4 | **Runtime security** | Eliminates Falco rule maintenance; managed detection rules; compliance reporting | [Sysdig](https://sysdig.com) | Usage-based |
| 5 | **Edge security** | Eliminates WAF/DDoS management; managed bot detection | [Cloudflare](https://www.cloudflare.com) Pro | $20/month |

### What to Skip (and When to Revisit)

These controls require dedicated staffing that a 1-5 person team does not have. Skip them until your team grows past 5 engineers or compliance requirements demand them:

- **Custom [SELinux](https://github.com/SELinuxProject/selinux) policies:** Use [AppArmor](https://apparmor.net) defaults or container-level security instead. Revisit when you have a dedicated security engineer.
- **Full SIEM deployment:** Use Falco + Prometheus alerting instead. Revisit when you need cross-signal correlation.
- **Zero-trust networking:** Use network policies and mTLS (if on service mesh). Full zero-trust with SPIFFE/SPIRE is a 40+ hour investment.
- **Compliance automation (Vanta/Drata):** Use InSpec/kube-bench for technical compliance. Automation platforms are for when customers or investors require SOC 2 certification.
- **Custom seccomp profiles per workload:** Use RuntimeDefault for everything. Custom profiles take 2-4 hours per workload.

## Expected Behaviour

- Stage 1 complete within 1 day (4 hours of focused work)
- Stage 2 complete within 1 week
- Stage 3 complete within 1 month
- Each stage measurably improves security posture:
  - After Stage 1: SSL Labs A+, SSH brute force blocked, firewall active
  - After Stage 2: kube-bench score (if K8s), sysctl verification script passes
  - After Stage 3: Trivy scans in CI, Ansible playbooks enforce baseline
  - After Stage 4: Security alerts firing, audit logs centralized, runtime detection active

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Prioritised order (not everything at once) | Team ships improvements immediately | Lower-priority controls remain unaddressed | Accept the risk. Stage 1-3 cover 80% of automated attack surface. |
| Skip custom MAC policies | Reduced runtime confinement | Acceptable for most small teams; container isolation + seccomp RuntimeDefault provides basic confinement | Revisit when team size allows a security engineer. |
| Managed services early (Stage 5) | Monthly cost; vendor dependency | Service availability depends on provider | Choose providers with strong uptime track records. Use the free tier first. |
| Automated OS updates | Reduces patch window to hours | Risk of breaking change from unreviewed update | Unattended-upgrades applies security patches only (not full package upgrades). Breakage from security-only patches is extremely rare. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Skipped control gets exploited | Breach through an unhardened vector | Post-incident analysis identifies the gap | Promote the control to a higher priority. Implement immediately. |
| Automated update breaks service | Service outage after unattended-upgrades | Monitoring detects outage; automatic update logs in `/var/log/unattended-upgrades/` | Rollback the package. Add to exception list. Review before re-enabling. |
| Team tries to do everything at once | Nothing fully implemented; partial controls across all stages | Controls partially applied; compliance scans show inconsistent results | Reset. Complete the current stage fully before advancing. Partial implementation is worse than focused implementation. |
| Managed service outage | DNS, observability, or K8s control plane unavailable | Provider status page; synthetic monitoring | For DNS: pre-configure failover to a secondary provider. For observability: Prometheus local storage buffers during outages. For K8s: provider handles control plane HA. |

## When to Consider a Managed Alternative

**This article IS the managed adoption guide.** Stage 5 maps the exact order a small team should adopt paid services, with the first recommendation being [Cloudflare](https://www.cloudflare.com) free tier (zero cost, immediate value).

The complete adoption path:
1. [Cloudflare](https://www.cloudflare.com) free → DNS + basic DDoS ($0/month)
2. [Grafana Cloud](https://grafana.com/cloud) free → observability ($0/month → $29/month)
3. [Civo](https://www.civo.com) or [DigitalOcean](https://www.digitalocean.com) → managed K8s ($20-60/month)
4. [Sysdig](https://sysdig.com) → managed runtime security (usage-based)
5. [Cloudflare](https://www.cloudflare.com) Pro → managed WAF/edge ($20/month)

Total managed cost at full adoption: ~$100-200/month, less than a single day of engineering time per month.

**Premium content pack:** Small team hardening kit. Stage 1-3 implementation scripts, Ansible playbook starter, CI/CD templates, and a prioritisation checklist that maps each control to the specific articles on systemshardening.com.


## Related Articles

- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
- [Hardening Redis in Production: Authentication, TLS, ACLs, and Command Restriction](/articles/cross-cutting/redis-hardening/)
