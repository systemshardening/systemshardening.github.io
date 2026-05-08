---
title: "Linux Kernel Live Patching: kpatch and livepatch for Zero-Day Response"
description: "Kernel live patching applies security fixes to a running kernel without a reboot. kpatch on RHEL and livepatch on Ubuntu eliminate the window between CVE disclosure and the next maintenance window."
slug: "kernel-live-patching"
date: 2026-04-30
lastmod: 2026-04-30
category: "linux"
tags: ["kernel", "live-patching", "kpatch", "livepatch", "zero-day"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 263
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/linux/kernel-live-patching/index.html"
---

# Linux Kernel Live Patching: kpatch and livepatch for Zero-Day Response

## Problem

Critical kernel vulnerabilities — privilege escalation via `nf_tables`, use-after-free in `io_uring`, memory corruption in the network stack — require kernel updates to fix. The standard remediation path: package managers apply the patched kernel, systems reboot into it. For most production environments, that reboot doesn't happen for days or weeks, bounded by maintenance windows, change approval processes, and fear of disrupting running workloads.

The window between CVE disclosure and completed remediation across a fleet is typically 2–6 weeks. For actively exploited kernel CVEs (which appear in CISA's KEV catalogue within days of disclosure), that window is the exposure period.

Kernel live patching eliminates the reboot wait. A live patch modifies the running kernel in memory — replacing vulnerable function bodies with patched equivalents — without interrupting running processes, open connections, or mounted filesystems. After the live patch is applied, the vulnerability is mitigated even though the kernel version string hasn't changed.

Specific gaps in environments without live patching:

- Kernel CVEs sit unmitigated for weeks pending maintenance windows.
- Emergency reboots outside maintenance windows risk service disruption and require change approval under time pressure.
- Cloud auto-scaling groups may replace instances during rolling reboots, complicating patch verification.
- Containers running on unpatched kernels are vulnerable even if the container image is current.

**Target systems:** RHEL/CentOS 8+ with kpatch (kernel live patching daemon); Ubuntu 18.04+ with Canonical livepatch (cloud-based service) or klp (upstream kernel live patching framework); kernel 4.0+ with `CONFIG_LIVEPATCH=y`; systemd for patch application status.

## Threat Model

- **Adversary 1 — Exploit during the patch window:** A kernel privilege escalation CVE is published with a proof-of-concept exploit. An attacker targets unpatched hosts during the 2–6 week window before scheduled maintenance. A compromised container or web service calls the vulnerable syscall and escalates to root.
- **Adversary 2 — Exploitation via network stack vulnerability:** A remotely triggerable kernel CVE (TCP, netfilter, TLS) is exploited before a reboot is scheduled. Live patching mitigates the vulnerability immediately without requiring a reboot.
- **Adversary 3 — Live patch tampering:** An attacker with root access on the host modifies a live patch module before it's applied, or replaces a legitimately applied module with a malicious one. Live patch modules loaded via `insmod` don't have kernel module signing enforced by default.
- **Adversary 4 — Patch bypass via function not covered:** A live patch covers the known vulnerable function, but the attacker uses a different call path to the same vulnerable code that the patch doesn't intercept.
- **Access level:** Adversaries 1 and 2 have process-level execution (in a container or as a web service). Adversary 3 has root access. Adversary 4 has the ability to call kernel functions.
- **Objective:** Escalate privileges to root, escape a container, gain persistent kernel access.
- **Blast radius:** Without live patching: every kernel CVE requires either immediate disruptive reboots or weeks of exposure. With live patching: critical CVEs can be mitigated within hours of patch availability, while reboots into the updated kernel happen during the next scheduled maintenance window.

## Configuration

### Step 1: Verify Kernel Support

```bash
# Check if live patching is compiled in.
grep CONFIG_LIVEPATCH /boot/config-$(uname -r)
# Expected: CONFIG_LIVEPATCH=y

# Check if the live patch infrastructure is loaded.
ls /sys/kernel/livepatch/
# Empty if no patches applied; shows patch directories when active.

# On RHEL/CentOS: check kpatch.
rpm -q kpatch kpatch-patch
systemctl status kpatch

# On Ubuntu: check livepatch.
canonical-livepatch status --verbose
```

### Step 2: kpatch on RHEL/CentOS/AlmaLinux

kpatch is Red Hat's implementation, distributed as kpatch-patch RPM packages matching specific kernel versions.

```bash
# Install kpatch daemon.
dnf install kpatch kpatch-patch

# Enable and start the kpatch service.
systemctl enable --now kpatch

# Check available patches for the running kernel.
dnf list kpatch-patch-$(uname -r | tr - _ | sed 's/\.x86_64//')

# Install all available live patches for the running kernel.
dnf install "kpatch-patch-$(uname -r | tr - _ | sed 's/\.x86_64//')"

# Verify the patch was applied.
kpatch list
# Output: Loaded patch modules:
#   kpatch_patch_5_14_0_427_22_1_0_2_0 [enabled]
```

kpatch integration with systemd ensures patches are reapplied automatically if they are available when the system starts (for the same kernel version):

```bash
# The kpatch service checks /var/lib/kpatch/ for loaded modules on start.
systemctl cat kpatch | grep ExecStart
# ExecStart=/usr/sbin/kpatch load /var/lib/kpatch/$(uname -r)/*.ko

# Check which kernel functions are patched.
kpatch list -v
# Shows: patch module -> patched function names
```

### Step 3: Canonical Livepatch on Ubuntu

Ubuntu's livepatch service is cloud-based: Canonical builds patches for supported Ubuntu LTS kernels and delivers them automatically.

```bash
# Enable Ubuntu Pro (required for livepatch; free for personal use up to 5 machines).
sudo pro attach <token>

# Enable livepatch.
sudo pro enable livepatch

# Check status.
canonical-livepatch status
# Output:
# kernel: 5.15.0-100-generic
# server check-in: succeeded
# patch state: applied
# patches:
#   - version: 99.1 -- CVE-2024-XXXX: fixes nf_tables UAF

# Force a check-in and apply available patches.
canonical-livepatch refresh

# Verify specific CVEs are mitigated.
canonical-livepatch status --verbose | grep CVE
```

For fleet management, canonical-livepatch integrates with Landscape (Ubuntu's fleet management tool) to show patch status across all machines.

### Step 4: Upstream klp Framework (Kernel Modules)

For distributions not supported by kpatch or livepatch, or for custom patches, use the upstream `klp` framework directly:

```bash
# A live patch is a kernel module that uses klp_patch structures.
# Building a live patch requires the kernel source and specific headers.

# Install build dependencies.
dnf install kernel-devel elfutils-libelf-devel

# A minimal live patch module structure (C):
cat > my-livepatch.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

/* Replacement for the vulnerable function. */
static int patched_vulnerable_function(int arg)
{
    /* Patched implementation. */
    return 0;
}

static struct klp_func funcs[] = {
    {
        .old_name = "vulnerable_function",
        .new_func = patched_vulnerable_function,
    }, {}
};

static struct klp_object objs[] = {
    { .funcs = funcs }, {}
};

static struct klp_patch patch = {
    .mod = THIS_MODULE,
    .objs = objs,
};

static int __init livepatch_init(void)
{
    return klp_enable_patch(&patch);
}

MODULE_LICENSE("GPL");
module_init(livepatch_init);
EOF

# Build and sign the module.
make -C /lib/modules/$(uname -r)/build M=$PWD modules
# Sign with the kernel module signing key.
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
  /usr/src/linux-headers-$(uname -r)/certs/signing_key.pem \
  /usr/src/linux-headers-$(uname -r)/certs/signing_key.x509 \
  my-livepatch.ko

# Apply the live patch.
insmod my-livepatch.ko

# Check it's active.
cat /sys/kernel/livepatch/my_livepatch/enabled
# Output: 1
```

### Step 5: Verify Patch Application and Coverage

```bash
# List all applied live patches and their status.
ls /sys/kernel/livepatch/
# Each subdirectory is an applied patch.

for patch in /sys/kernel/livepatch/*/; do
  name=$(basename $patch)
  enabled=$(cat $patch/enabled)
  transition=$(cat $patch/transition)
  echo "Patch: $name | Enabled: $enabled | Transition: $transition"
done

# "transition: 1" means the patch is being applied (not yet complete).
# "transition: 0" means the patch is fully applied.
# The transition involves waiting for all tasks to leave the old function.

# Check which functions are patched.
for patch in /sys/kernel/livepatch/*/; do
  echo "=== $(basename $patch) ==="
  find $patch -name "patched" -exec cat {} \;
done

# Monitor transition completion (live patches complete when all tasks
# scheduled through the old function have returned).
watch -n 1 'cat /sys/kernel/livepatch/*/transition'
```

### Step 6: Module Signing for Live Patches

By default, `insmod` doesn't require live patch modules to be signed. Enable kernel module signing enforcement:

```bash
# Check if module signing is required.
cat /proc/sys/kernel/modules_disabled   # 0 = load allowed; 1 = no new modules
grep CONFIG_MODULE_SIG_FORCE /boot/config-$(uname -r)
# CONFIG_MODULE_SIG_FORCE=y means only signed modules load.

# If secure boot is enabled, modules must be signed with a trusted key.
# kpatch and livepatch packages are already signed by the vendor.

# For custom patches: sign with the kernel's enrolled key.
openssl req -new -nodes -utf8 -sha256 -days 36500 -batch \
  -x509 -config x509.genkey \
  -outform PEM -out kernel_key.pem \
  -keyout kernel_key.pem

# Enroll the key in the MOK (Machine Owner Key) database.
mokutil --import kernel_key.pem
# Requires a reboot to enroll via the MOK manager in UEFI.
```

### Step 7: Monitoring Across the Fleet

```bash
# Script: check live patch status across all hosts.
#!/bin/bash
for host in $(cat /etc/fleet-hosts.txt); do
  status=$(ssh $host "kpatch list 2>/dev/null | grep -c enabled || echo 0")
  kernel=$(ssh $host "uname -r")
  echo "$host: kernel=$kernel patches_active=$status"
done

# Prometheus exporter for kpatch status (custom).
# Export: livepatch_patch_enabled{patch_name, kernel_version} gauge
```

Prometheus metrics via node_exporter textfile collector:

```bash
# /etc/cron.d/livepatch-metrics
* * * * * root /usr/local/bin/collect-livepatch-metrics.sh > /var/lib/node_exporter/textfile_collector/livepatch.prom

# collect-livepatch-metrics.sh
#!/bin/bash
echo "# HELP livepatch_patches_active Number of active live patches"
echo "# TYPE livepatch_patches_active gauge"
count=$(ls /sys/kernel/livepatch/ 2>/dev/null | wc -l)
echo "livepatch_patches_active $count"

echo "# HELP livepatch_transition_pending Live patch transition not yet complete"
echo "# TYPE livepatch_transition_pending gauge"
pending=$(grep -l "^1$" /sys/kernel/livepatch/*/transition 2>/dev/null | wc -l)
echo "livepatch_transition_pending $pending"
```

### Step 8: Telemetry

```
livepatch_patches_active{host, kernel_version}          gauge
livepatch_transition_pending{host, patch_name}          gauge
livepatch_apply_success_total{host}                     counter
livepatch_apply_failure_total{host, reason}             counter
livepatch_cve_coverage{cve_id, host}                    gauge (1 = mitigated)
kernel_reboot_age_days{host}                            gauge
```

Alert on:

- `livepatch_apply_failure_total` non-zero — a patch failed to apply; the vulnerability is not mitigated on that host.
- `livepatch_transition_pending` > 0 for > 60 minutes — a patch is stuck in transition (a task is looping in the old function path); investigate.
- `kernel_reboot_age_days` > 90 — even with live patching, periodic reboots into the updated kernel baseline are necessary.
- A known-exploited CVE (from CISA KEV) without a corresponding `livepatch_cve_coverage` entry — the live patch doesn't exist yet; escalate the reboot priority.

## Expected Behaviour

| Signal | No live patching | With live patching |
|--------|-----------------|-------------------|
| Critical kernel CVE disclosed | Exposure until next reboot (days–weeks) | Patch applied within hours of release, no reboot |
| Maintenance window pressure | Emergency reboots required for critical CVEs | Reboot during normal window; no emergency |
| `uname -r` after patch | Shows new kernel version | Shows old kernel version; patch active in memory |
| Running processes during patch | N/A | Uninterrupted; patch applies transparently |
| Reboot still required? | For every kernel update | Yes, eventually — live patch is a temporary mitigation |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| No reboot required | Maintains service continuity; eliminates emergency reboots | Live patches accumulate; periodic reboots still needed to consolidate | Schedule reboots into updated kernels during normal maintenance windows monthly. |
| Vendor-provided patches | No custom build required; signed by vendor | Only supported kernel versions get patches | Subscribe to Ubuntu Pro or RHEL for guaranteed coverage; track kernel lifecycle. |
| Transition period | Safe to apply while tasks run | A long-running task in the old function delays full application | Most transitions complete in seconds; alert on >60 minute pending transitions. |
| Module signing enforcement | Prevents tampered patch modules | Custom patches require own signing key enrolled in UEFI | Use vendor patches for CVEs; reserve custom patches for exceptional cases. |
| Live patch limitations | Covers most function-level patches | Cannot patch data structure changes, init code, or certain interrupt handlers | These require reboots; live patching covers ~80% of kernel CVEs. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Patch stuck in transition | `/sys/kernel/livepatch/*/transition` = 1 indefinitely | `livepatch_transition_pending` alert > 60 min | Find the task holding the old function: `cat /sys/kernel/livepatch/*/transition` shows task info. Restart the task if possible; or reboot. |
| Patch application fails | `kpatch: failed to apply patch module` | `livepatch_apply_failure_total` alert | Check `dmesg` for the error; common causes: symbol not found (kernel version mismatch), module not signed. |
| No patch available for this CVE | Vulnerability not covered by live patching | CVE without `livepatch_cve_coverage` entry | Expedite the kernel reboot; apply other mitigations (seccomp, capability drops) to reduce exploitability. |
| Canonical livepatch service unreachable | `canonical-livepatch status` shows connection error | livepatch check-in failure metric | Check network connectivity; Canonical livepatch has an SLA for enterprise customers. |
| Live patch conflicts with loaded module | Kernel oops or warning after patch application | Kernel log; unexpected system behaviour | Remove the conflicting module; contact vendor; reboot into the patched kernel as a safe fallback. |

## Related Articles

- [Linux Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
- [Linux Kernel Lockdown](/articles/linux/kernel-lockdown/)
- [Linux IMA/EVM: Kernel-Level File Integrity Measurement](/articles/linux/linux-ima-evm/)
- [Secure Cloud VM Access](/articles/linux/secure-cloud-vm-access/)
- [Ansible OS Hardening Automation](/articles/linux/ansible-os-hardening/)
