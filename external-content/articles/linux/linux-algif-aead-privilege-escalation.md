---
title: "Linux algif_aead Privilege Escalation: Hardening Against CVE-2026-31431"
description: "CVE-2026-31431 Copy Fail lets an unprivileged user gain root via AEAD page-cache corruption. Understand the silent-patch pattern and how to close the gap with kernel settings, LSM policy, and live patching."
slug: linux-algif-aead-privilege-escalation
date: 2026-05-03
lastmod: 2026-05-03
category: linux
tags:
  - kernel
  - privilege-escalation
  - algif
  - cve
  - live-patching
personas:
  - platform-engineer
  - security-engineer
article_number: 391
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-algif-aead-privilege-escalation/
---

# Linux algif_aead Privilege Escalation: Hardening Against CVE-2026-31431

## The Problem

CVE-2026-31431, designated "Copy Fail" by its reporters, is a local privilege escalation in the Linux kernel's `algif_aead` socket interface, the kernel-side implementation of AEAD (Authenticated Encryption with Associated Data) operations exposed through `AF_ALG` sockets. It was publicly disclosed on April 29 2026 with a CVSS base score of 7.8 and, critically, with 91 proof-of-concept exploits already indexed in the wild as of April 30.

The vulnerability originates in a performance optimisation introduced to reduce memory copies during in-place AEAD operations. When a caller passes the same buffer as both input and output — a legitimate pattern for stream encryption — the `algif_aead` layer skips copying the input pages into kernel-owned memory and instead operates directly on the user-mapped pages. The optimisation is sound in isolation, but the implementation incorrectly marks those user pages writable in the page cache without first removing them from the read-only mapping used for file-backed pages. The result is that a page backing a read-only file — a setuid binary, a shared library, an `ld.so` segment — can be made writable from userspace by any process that can open an `AF_ALG` socket.

An unprivileged attacker follows a straightforward chain: open `AF_ALG`/`algif_aead`, set up an AEAD operation with a file-backed page as both the input and output buffer, trigger the optimised in-place path, and write arbitrary bytes into what the kernel believes is read-only page-cache memory. Targeting `sudo` or any setuid binary, the attacker replaces executable code with shellcode or a return-address trampoline. On a system with no live patch applied, the full escalation from unprivileged shell to root takes under ten seconds.

The patch-gap window for this CVE illustrates a pattern that recurs with kernel local privilege escalations. The fix — a one-line change restoring a `copy_user_highpage` call on the in-place path — was submitted to the `linux-stable-rc` tree and was visible in the public cgit mirror at `git.kernel.org` two days before any distribution or NVD advisory appeared. This is not an accident. The kernel security team (`security@kernel.org`) operates an embargo process that sends fixes to stable maintainers while forbidding public discussion, but cgit is not access-controlled. Anyone monitoring `linux-stable-rc` commits saw "algif_aead: restore copy on in-place aead op" on April 27 and could derive the vulnerability before disclosure. Security teams that watch stable-rc diffs have a reliable two-to-three-day early-warning signal for kernel LPEs. Teams that do not watch it are blind until distro advisories appear, which for enterprise distributions often lags the stable tag by two to six weeks.

Fixed versions: kernel 6.14.4 (mainline), 6.6.91 (LTS), 6.1.138 (LTS), 5.15.181 (LTS), and 5.10.238 (LTS). Kernels from 4.14 to 6.14.3 are affected for any configuration that builds `algif_aead` — which is the default for virtually all general-purpose distribution kernels.

## Threat Model

The exploit requires a local shell on the target system. There is no network attack vector. An attacker who can execute arbitrary code as any unprivileged user — including `www-data`, `nobody`, or an application-specific service account — can exploit this vulnerability if the kernel is unpatched and `AF_ALG` sockets are accessible.

The populations most directly exposed are:

- **Multi-tenant compute** — shared hosting environments, VPS providers, HPC clusters with multiple user accounts. Any tenant can escalate to root and access other tenants' data or pivot to the host.
- **Container hosts without user namespace isolation** — container runtimes configured with `--privileged` or without a seccomp/AppArmor profile, where container processes share the host kernel's `AF_ALG` implementation. A container escape followed by this LPE yields host root.
- **CI/CD runners** — self-hosted GitHub Actions runners, GitLab runners, and Jenkins agents often run untrusted pipeline code under a restricted user. An attacker who controls a pipeline definition gains LPE to the runner host.
- **Jump hosts and bastion servers** — these are not typically considered multi-tenant but frequently have multiple SSH sessions from different administrators simultaneously. A compromised session can exploit this to persist at the root level.

The "no untrusted users" assumption collapses rapidly when a prior vulnerability — a web application RCE, a container escape, a misconfigured service — drops an attacker to an unprivileged shell. The threat model should not treat LPE as irrelevant simply because direct multi-user access is absent.

The 91 publicly available proof-of-concept exploits raise the operational urgency significantly. The bar for exploitation is low: no kernel address leak is required beyond what `dmesg` exposes to unprivileged users on systems where `kernel.dmesg_restrict=0` (the default on many distributions), and the technique is not sensitive to ASLR because the attack targets the page cache rather than kernel data structures.

The affected kernel version range — 4.14 to 6.14.3 — covers every major enterprise Linux distribution still in mainstream support: RHEL 8 and 9, Ubuntu 20.04 and 22.04 LTS, Debian 11 and 12, and SUSE Linux Enterprise 15. All of them ship `algif_aead` enabled by default. None of them had applied vendor-side patches as of April 30 2026.

## Hardening Configuration

Mitigations divide into three layers: patching the kernel, disabling the vulnerable interface, and reducing the exploitability of an unpatched kernel through sysctl and LSM controls.

### Step 1: Verify Kernel Version

```bash
uname -r

# Compare against fixed versions.
# 6.14.4+  mainline
# 6.6.91+  LTS
# 6.1.138+ LTS
# 5.15.181+ LTS
# 5.10.238+ LTS

# Check if algif_aead is compiled in or as a module.
grep -E 'CONFIG_CRYPTO_USER_API_AEAD|CONFIG_CRYPTO_AUTHENC' /boot/config-$(uname -r)
# CONFIG_CRYPTO_USER_API_AEAD=m means loaded as a module — can be blocked.
# CONFIG_CRYPTO_USER_API_AEAD=y means built in — module unloading will not help.
```

If the running kernel is below the fixed version for its series, apply the update immediately. If the update is not yet available from the distribution, proceed with the mitigations below while the package lands.

### Step 2: Disable AF_ALG Socket Access

The `algif_aead` interface is part of the `AF_ALG` socket family. If no workload on the host uses kernel-offloaded cryptography through the `AF_ALG` interface — the common case for most general-purpose servers — the family can be restricted entirely.

Some distributions expose `kernel.unprivileged_af_alg`. Check first:

```bash
sysctl kernel.unprivileged_af_alg 2>/dev/null || echo "knob not available"
```

If the knob is present, set it persistently:

```bash
echo "kernel.unprivileged_af_alg = 0" | tee /etc/sysctl.d/99-algif-lockdown.conf
sysctl -p /etc/sysctl.d/99-algif-lockdown.conf
```

If the knob is not present (it was added only to some distribution kernels), block `AF_ALG` socket creation with a systemd-wide seccomp filter or via an LSM rule. The seccomp approach applies to any process without a specific exemption.

### Step 3: Seccomp Profile Blocking AF_ALG

For workloads running under systemd service units, add a `SystemCallFilter` that blocks `socket` calls with the `AF_ALG` family. The filter uses `~socket` to deny the syscall, combined with an argument filter.

The more targeted approach is a seccomp profile in JSON format suitable for container runtimes or `seccomp-bpf` application:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-af-alg.json
  containers:
    - name: app
      image: myapp:latest
```

The referenced profile at `/var/lib/kubelet/seccomp/profiles/block-af-alg.json`:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

The value `38` is `AF_ALG` on x86-64 and arm64. This filter allows all other socket families while denying `socket(AF_ALG, ...)` with `EPERM`.

For systemd service units that should not use `AF_ALG`:

```bash
# /etc/systemd/system/myservice.service.d/override.conf
[Service]
SystemCallFilter=~socket
SystemCallFilter=socket
```

The cleaner approach for a service that needs sockets but not `AF_ALG` is to use `RestrictAddressFamilies`:

```bash
# /etc/systemd/system/myservice.service.d/override.conf
[Service]
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

This directive drops `AF_ALG` from the allowed set without touching other socket families the service legitimately uses.

### Step 4: AppArmor and SELinux Containment

AppArmor profiles can restrict `AF_ALG` socket creation with the `network` rule:

```
profile myapp /usr/bin/myapp {
  network inet stream,
  network inet6 stream,
  network unix stream,
  # AF_ALG is omitted — creation is denied by default.
}
```

On SELinux systems, the `socket_class` type enforcement controls access. Processes confined to a non-privileged domain cannot create `AF_ALG` sockets unless the policy explicitly grants `alg_socket { create }`. The default targeted policy on RHEL does not grant this to confined user processes, so SELinux-enforcing systems with confined users have partial protection already.

However, LSM confinement only helps for processes running under an enforcing profile. Unconfined processes — which includes many services on default Debian and Ubuntu configurations — are not protected by AppArmor unless a profile is explicitly loaded and set to enforce.

### Step 5: Live Kernel Patching

The zero-downtime remediation path is a live kernel patch. kpatch (RHEL) and livepatch (Ubuntu/Canonical) both had modules for CVE-2026-31431 available within 48 hours of the public advisory.

For RHEL/CentOS systems:

```bash
kpatch install kpatch-patch-$(uname -r | tr - _)
kpatch list
# Expected output includes: CVE-2026-31431 (algif_aead) [enabled]
```

For Ubuntu with Canonical livepatch:

```bash
canonical-livepatch status --verbose | grep -i algif
# Expected: cve-2026-31431: applied
```

For upstream `klp`-based patching, verify the module is loaded:

```bash
cat /sys/kernel/livepatch/*/enabled
# 1 indicates active patch.
```

A live patch does not change the running kernel version string reported by `uname -r`. After the patch is confirmed active, the next scheduled maintenance window is the appropriate time to reboot into the fully updated kernel package.

### Step 6: Restrict Kernel Information Leaks

CVE-2026-31431 is exploitable without a kernel address leak, but ASLR-defeating techniques that layer on top of it become easier when `dmesg` and `/proc/kallsyms` are readable by unprivileged users. Apply these settings regardless of this specific CVE:

```bash
cat > /etc/sysctl.d/99-kernel-hardening.conf << 'EOF'
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
EOF

sysctl -p /etc/sysctl.d/99-kernel-hardening.conf
```

`kernel.dmesg_restrict=1` blocks unprivileged reads of `dmesg`. `kernel.kptr_restrict=2` suppresses all kernel pointer values in `/proc` and `sysfs` output, even for root. `kernel.perf_event_paranoid=3` blocks unprivileged `perf_event_open` calls, which are a separate avenue for kernel address enumeration.

## Expected Behaviour After Hardening

After applying the `RestrictAddressFamilies` or seccomp approach and confirming the live patch is active, verification should confirm both layers.

Confirm `AF_ALG` is blocked for a test process:

```bash
python3 -c "import socket; socket.socket(38, 1)"
# Expected: PermissionError: [Errno 1] Operation not permitted
```

In the audit log, a blocked attempt looks like:

```
type=SECCOMP msg=audit(1746316800.123:4501): auid=1001 uid=1001 gid=1001 ses=12 \
  subj=unconfined pid=38210 comm="python3" exe="/usr/bin/python3.11" \
  sig=0 arch=c000003e syscall=41 compat=0 ip=0x7f3b1c84e3d7 code=0x50000
```

Syscall 41 is `socket` on x86-64. `code=0x50000` is `SECCOMP_RET_ERRNO`.

An AppArmor denial produces a line in `/var/log/audit/audit.log` or `kern.log`:

```
audit: type=1400 audit(1746316802.441:4502): apparmor="DENIED" operation="create" \
  profile="/usr/bin/myapp" name="socket" pid=38215 comm="myapp" \
  family="alg" sock_type="seqpacket" protocol=0
```

Confirm live patch status:

```bash
kpatch list | grep -i "algif\|31431"
# [enabled] kpatch-5.15.180-0-200.el8.x86_64: CVE-2026-31431

# Or for Ubuntu:
canonical-livepatch status | grep cve-2026-31431
# cve-2026-31431: applied (reboot to complete)
```

Confirm sysctl values are persistent across a reload:

```bash
sysctl kernel.dmesg_restrict kernel.kptr_restrict kernel.perf_event_paranoid
# kernel.dmesg_restrict = 1
# kernel.kptr_restrict = 2
# kernel.perf_event_paranoid = 3
```

## Trade-offs and Operational Considerations

Disabling `AF_ALG` has consequences for subsystems that use kernel-offloaded cryptography. Before applying restrictions, check what is registered in `/proc/crypto`:

```bash
cat /proc/crypto | grep -E '^name|^module' | paste - -
```

The workloads affected by blocking `AF_ALG` socket creation:

- **`dm-crypt` on older kernels** — kernels before 5.9 used `AF_ALG` internally for dm-crypt AES offload. Kernels 5.9 and later use the generic crypto API directly. If `dm-crypt` volumes exist, test LUKS unlock after applying the restriction before deploying to production.
- **OpenSSL AF_ALG engine** — OpenSSL's `af_alg` engine (`openssl engine af_alg`) routes symmetric operations through the kernel. This engine is disabled by default on modern distributions and is rarely used in practice; `openssl speed -engine af_alg aes-256-gcm` will fail with `EPERM` after blocking, but the default software engine is unaffected.
- **LUKS unlock via kernel offload** — `cryptsetup` with `--perf-submit_from_crypt_cpus` on some configurations routes through `AF_ALG`. Test with `cryptsetup benchmark` if LUKS is in use.

The live patch timing gap is a real operational constraint. Canonical and Red Hat typically publish live patches five to ten days after the upstream stable kernel tag. For CVE-2026-31431, the upstream fix landed in stable-rc on April 27; a live patch may not be available until May 2–7. During that window, the seccomp and sysctl controls are the primary mitigations.

Enterprise distribution lag compounds this. RHEL 8 and 9 typically ship kernel updates two to six weeks after the upstream LTS tag. A system running RHEL 9 with no live patch applied and no `AF_ALG` restriction may remain fully vulnerable until late May or early June 2026 if no other action is taken.

## Failure Modes

**Forgetting non-obvious node types.** Fleet hardening tends to focus on application servers. Jump hosts, CI runners, monitoring agents, and developer workstations run the same vulnerable kernel and are equally exposed. Inventory systems should query kernel versions across all node categories, not just the primary compute tier.

**Container runtime not enforcing seccomp.** The Kubernetes default seccomp profile (`RuntimeDefault`) does not block `AF_ALG` socket creation. A pod without an explicit seccomp profile or with `securityContext.seccompProfile.type: Unconfined` inherits full syscall access. The seccomp profile described in Step 3 must be explicitly referenced in the pod spec — it is not applied automatically.

**AppArmor-confined containers with `af_alg` capability.** Container AppArmor profiles generated by tools like `bane` or `docker-default` sometimes include `network alg` to support broad compatibility. If the generated profile includes this permission, the `AF_ALG` restriction is not effective. Audit profiles with:

```bash
grep -r "network alg\|af_alg" /etc/apparmor.d/
```

Remove any `network alg` grant from profiles on hosts where `AF_ALG` should be blocked.

**Sysctl not persisting across reboots.** Settings applied with `sysctl -w` at runtime do not survive a reboot. The mitigation must be written to a file under `/etc/sysctl.d/` with the correct permissions and loaded via the init system. Verify persistence by checking the sysctl value after a reboot during the next scheduled maintenance window.

**Live patch not applied to all kernel versions in the fleet.** A fleet running multiple kernel versions — common when rolling updates are in progress — may have patches available for some kernel versions but not others. The kpatch or livepatch client will silently skip hosts where no compatible patch module exists. Audit patch status per kernel version, not just per host count.

## Related Articles

- [Linux Kernel Hardening](/articles/linux/kernel-module-hardening/)
- [Landlock LSM](/articles/linux/landlock-lsm/)
- [Seccomp BPF Without Containers](/articles/linux/seccomp-bpf-non-container/)
- [Linux Memory Protections](/articles/linux/linux-memory-protections/)
- [Linux Kernel Live Patching](/articles/linux/kernel-live-patching/)
