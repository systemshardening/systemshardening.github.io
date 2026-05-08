---
title: "Linux LPE Defence in Depth: Raising the Bar Against Kernel Privilege Escalation"
description: "2026's wave of kernel LPEs shows patches alone aren't enough. Build layered mitigations — seccomp-BPF blocking dangerous socket families, user namespace restrictions, kernel pointer hardening, and Landlock — that raise the exploitation bar regardless of which bug comes next."
slug: linux-lpe-defence-in-depth
date: 2026-05-04
lastmod: 2026-05-04
category: linux
tags:
  - kernel
  - privilege-escalation
  - seccomp
  - landlock
  - defence-in-depth
personas:
  - platform-engineer
  - security-engineer
article_number: 431
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-lpe-defence-in-depth/
---

# Linux LPE Defence in Depth: Raising the Bar Against Kernel Privilege Escalation

## The Problem

CVE-2026-31431 (Copy Fail) was the highest-profile kernel local privilege escalation of 2026, but it was not the first and will not be the last. The Linux kernel's attack surface — `AF_ALG` crypto sockets, `io_uring`, eBPF, netfilter, user namespaces, FUSE, `n_gsm` — presents dozens of subsystems that unprivileged users can reach, and each is a potential LPE path. The typical enterprise response is to wait for a kernel patch, apply it during the next maintenance window, and move on.

The problem is the timing gap. The average time from CVE disclosure to patch deployment across enterprise Linux fleets is 15–30 days. The average time from a patch commit landing in `linux-stable-rc` to a working public proof-of-concept is 2–7 days. That gap — days of active exploitation with no vendor patch applied — is the window defence-in-depth mitigations are designed to close.

The structure of a kernel LPE exploit is not arbitrary. It follows a predictable chain: an unprivileged user gains access to a subsystem with a vulnerability, turns that access into a memory-corruption primitive, escalates the primitive to an arbitrary kernel read or write, and then overwrites credentials or calls `commit_creds()` to gain root. Each link in that chain is a surface for a distinct mitigation layer. Blocking `AF_ALG` socket creation cuts the chain at the first link for Copy Fail. Suppressing kernel pointer values from unprivileged processes prevents the KASLR-bypass step common to many other LPEs. Restricting user namespaces eliminates the `CAP_SYS_ADMIN`-inside-namespace prerequisite that a third category of exploits depends on entirely.

None of these controls patches the underlying bug. What they do is increase the number of steps an attacker must successfully chain, raise the probability of generating audit-detectable noise at each step, and narrow the population of vulnerable processes even before the kernel package lands. The right framing is not "mitigation instead of patching" — it is "mitigation while waiting for the patch, and permanently after, because the next bug will arrive before the next maintenance window."

## Threat Model

The targeted adversary is a local unprivileged process. This covers more ground than it sounds:

- An SSH session under a limited account — a CI runner user, a deploy service account, an analyst with a shell but not sudo.
- A container workload that has achieved a container escape and now executes as a non-root UID against the host kernel.
- A compromised application process — a web server, a queue worker, a cron job — running as `www-data` or another application-specific account.
- An attacker who chained a prior vulnerability (a web application RCE, a deserialization flaw, an SSRF that led to metadata credential theft) to reach an unprivileged shell.

The specific kernel subsystems these adversaries can reach without elevated privilege include:

- `AF_ALG` — the kernel crypto socket family that was the entry point for Copy Fail. Available by default to all processes that can open a socket.
- `io_uring` — the asynchronous I/O interface that has been the source of multiple LPEs since 2022. Unprivileged access is the default on most distributions.
- `bpf()` syscall — the BPF subsystem with its verifier, which has been exploited via verifier logic bugs. `kernel.unprivileged_bpf_disabled=0` is common.
- User namespaces — the mechanism that grants `CAP_SYS_ADMIN` inside a namespace, unlocking further attack surface in netfilter, Keyring, and other subsystems. A precondition for entire classes of LPE.
- `FUSE` — filesystem-in-userspace can be used to race kernel operations that assume filesystem access is reliable.
- `n_gsm` — the GSM 07.10 tty discipline, an obscure interface that has produced kernel vulnerabilities despite having virtually no legitimate use on modern servers.

The attacker goal in every case is the same: transition from the current UID to `uid=0`, whether by overwriting `cred` structures directly, abusing a setuid binary that can be modified via the page cache, or exploiting a kernel code-execution primitive to call `commit_creds()`.

PoC exploits for high-severity kernel LPEs have consistently appeared within 2–7 days of public disclosure in 2025 and 2026. The threat model cannot assume that no working exploit exists for any given CVE simply because the CVE is new.

## Hardening Configuration

### 1. Block Dangerous Socket Families with seccomp-BPF

The `AF_ALG` socket family (socket domain value `38`) was the entry point for Copy Fail. A process that cannot open an `AF_ALG` socket cannot run the exploit, regardless of kernel patch status. The same logic applies to `AF_PACKET` (raw sockets, value `17`) and unfiltered `AF_NETLINK` access — both provide subsystem access that unprivileged processes have no legitimate need for in most server environments.

For systemd service units, `RestrictAddressFamilies` is the cleanest approach. It removes the listed socket families from the process's reachable set at the kernel level, with no seccomp profile to maintain:

```ini
[Service]
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

This allows only TCP/IP, IPv6, and Unix sockets. `AF_ALG`, `AF_PACKET`, `AF_NETLINK`, and every other family are implicitly denied. For services that need `AF_NETLINK` (for example, services that reconfigure routing), add `AF_NETLINK` explicitly rather than removing the restriction.

For container workloads in Kubernetes, a seccomp profile with argument-level filtering on the `socket` syscall blocks `AF_ALG` while permitting all other socket families:

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
    },
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        {
          "index": 0,
          "value": 17,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

Save this file on each node at `/var/lib/kubelet/seccomp/profiles/block-dangerous-sockets.json` and reference it in pod specs:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-dangerous-sockets.json
  containers:
    - name: app
      image: myapp:latest
```

The value `38` is `AF_ALG` and `17` is `AF_PACKET` on both x86-64 and arm64. The `errnoRet: 1` returns `EPERM` to the calling process.

For processes not managed by systemd or a container runtime — standalone daemons, cron jobs, scripts — use the `systemd-run` wrapper at launch or apply a system-wide restriction for the user namespace via PAM:

```bash
systemd-run --uid=appuser --property=RestrictAddressFamilies="AF_INET AF_INET6 AF_UNIX" /usr/local/bin/myapp
```

### 2. Restrict User Namespaces

User namespaces are a precondition for a distinct category of kernel LPEs. When an unprivileged process creates a user namespace, the kernel grants it `CAP_SYS_ADMIN` within that namespace. Several LPE exploit chains use user namespace creation as step one because the namespace grants access to interfaces — particularly Keyring and netfilter table operations — that are otherwise restricted to privileged processes.

Disabling unprivileged user namespace creation eliminates this entire category. The sysctl knob differs by distribution:

```bash
# Debian and Ubuntu
sysctl -w kernel.unprivileged_userns_clone=0

# RHEL, Rocky, AlmaLinux, Fedora
sysctl -w user.max_user_namespaces=0
```

Persist these settings:

```conf
# /etc/sysctl.d/99-lpe-hardening.conf

# Debian/Ubuntu: disable unprivileged user namespace creation
kernel.unprivileged_userns_clone = 0

# RHEL/Fedora: set maximum user namespaces to zero for unprivileged users
# (set to 0 to disable; adjust to a positive integer to re-enable)
user.max_user_namespaces = 0
```

Apply without rebooting:

```bash
sysctl -p /etc/sysctl.d/99-lpe-hardening.conf
```

The operational trade-off is significant: rootless containers (Docker without a daemon, Podman, Buildah), some Flatpak applications, and browser renderer sandboxes rely on user namespace creation. On servers running only purpose-built containerised workloads managed by a privileged daemon, this trade-off is acceptable — the daemon creates namespaces with its own privileges. On developer workstations or servers running rootless container workflows, disabling user namespaces breaks those workflows.

For environments where the restriction cannot be applied globally, Debian and Ubuntu (kernel 6.1+) support restricting user namespace creation to a specific set of binaries via AppArmor, leaving the global sysctl enabled:

```bash
# Allow only specific executables to create user namespaces.
echo '1' | tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns

# Then create an AppArmor rule permitting a specific binary.
# /etc/apparmor.d/local/allow-podman-userns:
# /usr/bin/newuidmap flags=(allow_incomplete) {
#   capability sys_admin,
# }
```

This per-binary approach lets operations teams maintain a named list of processes with legitimate user namespace access rather than an all-or-nothing toggle.

### 3. Kernel Pointer and Address Exposure Hardening

KASLR (Kernel Address Space Layout Randomisation) prevents exploits that require knowing the kernel's load address. Many exploit primitives combine an information-leak step — reading a kernel pointer from `/proc/kallsyms`, `dmesg`, or a `perf` event — with the actual corruption step. Suppressing those leaks forces an attacker to acquire address information through a separate, more difficult oracle, which adds steps and generates noise.

Three sysctl settings close the primary information-leak paths for unprivileged processes:

```conf
# /etc/sysctl.d/99-lpe-hardening.conf (continued)

# Suppress all kernel pointer values in /proc and sysfs output.
# At =2, even root sees zeroes unless CAP_SYSLOG is held.
# At =1, only unprivileged users see zeroes; root sees real addresses.
kernel.kptr_restrict = 2

# Block unprivileged access to dmesg. Kernel ring buffer frequently
# contains addresses from module loading, oops output, and subsystem init.
kernel.dmesg_restrict = 1

# Disable perf_event_open for unprivileged users entirely. Perf events
# can sample instruction pointers and are a KASLR-bypass oracle.
# =3 is stricter than the =2 default (which permits sampling with limitations).
kernel.perf_event_paranoid = 3
```

The combined `/etc/sysctl.d/99-lpe-hardening.conf` for all settings in this article:

```conf
kernel.unprivileged_userns_clone = 0
user.max_user_namespaces = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
```

The `kernel.kptr_restrict=2` setting affects root as well. Operations that require reading kernel symbols as root — `crash` analysis, certain bpftrace scripts — will need to lower this temporarily on debug nodes. On production, the trade-off favours suppression.

### 4. Kernel Lockdown Mode

Lockdown mode (the `lockdown` LSM, mainline since kernel 5.4) limits what the root user can do to the running kernel. In the context of LPE defence-in-depth, its primary value is limiting post-exploitation impact: even if an attacker achieves root through an LPE, lockdown prevents them from loading unsigned kernel modules, replacing the kernel via `kexec`, or reading kernel memory through `/dev/mem` and `/proc/kcore`.

Enable at boot by appending to the kernel command line in `/etc/default/grub`:

```conf
GRUB_CMDLINE_LINUX="... lockdown=confidentiality"
```

Rebuild the GRUB configuration and reboot:

```bash
sudo update-grub                                        # Debian / Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg            # RHEL / Rocky
```

Verify after reboot:

```bash
cat /sys/kernel/security/lockdown
```

The active mode appears in brackets. Target output: `none integrity [confidentiality]`.

For environments that cannot reboot immediately, lockdown can be raised at runtime (though it cannot be lowered without a reboot):

```bash
echo confidentiality | tee /sys/kernel/security/lockdown
```

`lockdown=integrity` blocks kernel modification operations (module loading, `kexec`, writes to `/dev/mem`). `lockdown=confidentiality` adds blocking of kernel memory reads (`/proc/kcore`, `/dev/kmem`, kernel pointer exposure even to root). For LPE post-exploitation containment, `confidentiality` provides substantially more coverage.

Lockdown breaks specific legitimate admin workflows that must be planned for:

- `kdump` crash capture via `kexec` — blocked under either mode. Use `pstore` for crash logging on production, or accept that post-mortem kernel core dumps require a reboot to a debug-configuration kernel.
- Out-of-tree kernel modules without signatures — `insmod` returns `EPERM`. Sign in-house modules with a key enrolled in the kernel's MOK keyring.
- Hibernation — writing the kernel image to disk is treated as a confidentiality violation. Disable the hibernate target on servers: `systemctl mask hibernate.target`.

### 5. Landlock LSM for Process Confinement

Landlock (mainline since kernel 5.13) allows a process to restrict its own access to filesystem paths and TCP ports at the kernel level, without root. In the LPE defence context, Landlock adds a post-exploitation layer: even if an attacker achieves root through an LPE, a process confined with Landlock cannot read or write outside its declared policy.

Landlock is applied programmatically. The following C fragment applies a minimal policy suitable for a web application process — read-only access to `/usr` and `/etc/ssl/certs`, read-write access to its data directory, TCP connections only to the database port:

```c
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr,
    size_t size, __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_add_rule(int ruleset_fd,
    enum landlock_rule_type type,
    const void *attr, __u32 flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, __u32 flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

#define FS_READ_ONLY (LANDLOCK_ACCESS_FS_READ_FILE | \
                      LANDLOCK_ACCESS_FS_READ_DIR  | \
                      LANDLOCK_ACCESS_FS_EXECUTE)

#define FS_READ_WRITE (FS_READ_ONLY | \
                       LANDLOCK_ACCESS_FS_WRITE_FILE | \
                       LANDLOCK_ACCESS_FS_MAKE_REG   | \
                       LANDLOCK_ACCESS_FS_MAKE_DIR   | \
                       LANDLOCK_ACCESS_FS_REMOVE_FILE | \
                       LANDLOCK_ACCESS_FS_TRUNCATE)

#define ALL_FS_ACCESS (FS_READ_WRITE | \
                       LANDLOCK_ACCESS_FS_REMOVE_DIR  | \
                       LANDLOCK_ACCESS_FS_MAKE_CHAR   | \
                       LANDLOCK_ACCESS_FS_MAKE_BLOCK  | \
                       LANDLOCK_ACCESS_FS_MAKE_SOCK   | \
                       LANDLOCK_ACCESS_FS_MAKE_FIFO   | \
                       LANDLOCK_ACCESS_FS_MAKE_SYM    | \
                       LANDLOCK_ACCESS_FS_REFER       | \
                       LANDLOCK_ACCESS_FS_IOCTL_DEV)

static int allow_path(int rs, const char *path, __u64 access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr pb = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(fd);
    return rc;
}

static int allow_tcp_connect(int rs, __u16 port) {
    struct landlock_net_port_attr np = {
        .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .port = port,
    };
    return landlock_add_rule(rs, LANDLOCK_RULE_NET_PORT, &np, 0);
}

int apply_webapp_sandbox(void) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = ALL_FS_ACCESS,
        .handled_access_net =
            LANDLOCK_ACCESS_NET_CONNECT_TCP |
            LANDLOCK_ACCESS_NET_BIND_TCP,
    };

    int rs = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (rs < 0) return -1;

    if (allow_path(rs, "/usr", FS_READ_ONLY) < 0) goto fail;
    if (allow_path(rs, "/etc/ssl/certs", FS_READ_ONLY) < 0) goto fail;
    if (allow_path(rs, "/var/lib/myapp", FS_READ_WRITE) < 0) goto fail;
    if (allow_path(rs, "/var/log/myapp", FS_READ_WRITE) < 0) goto fail;
    if (allow_tcp_connect(rs, 5432) < 0) goto fail;
    if (allow_tcp_connect(rs, 53) < 0) goto fail;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) goto fail;
    if (landlock_restrict_self(rs, 0) < 0) goto fail;

    close(rs);
    return 0;
fail:
    close(rs);
    return -1;
}
```

`PR_SET_NO_NEW_PRIVS` must be called before `landlock_restrict_self`. Without it, a setuid binary launched by the confined process could acquire additional privileges across exec and escape the Landlock policy.

For processes without source access, the `landlock-cli` wrapper from the `rust-landlock` project applies a policy before execing the target binary:

```bash
landlock-runner \
  --ro /usr \
  --ro /etc/ssl/certs \
  --rw /var/lib/myapp \
  --rw /var/log/myapp \
  --connect-tcp 5432 \
  --connect-tcp 53 \
  -- /usr/local/bin/myapp
```

systemd v254+ translates `ProtectSystem=strict` and `ReadWritePaths=` into Landlock rules on kernels that support it, providing Landlock confinement from a service unit without code changes:

```ini
[Service]
ExecStart=/usr/local/bin/myapp
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/myapp /var/log/myapp
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

Landlock complements seccomp, not replaces it. seccomp operates at the syscall layer and cannot distinguish access by path; Landlock operates at the VFS layer and cannot filter arbitrary syscalls. A process confined by both a seccomp profile that blocks `AF_ALG` and a Landlock policy that restricts filesystem access requires an attacker to defeat both mechanisms independently.

## Expected Behaviour After Hardening

After the seccomp `AF_ALG` block is applied, attempting to run the Copy Fail PoC returns `EPERM` at the `socket(AF_ALG, ...)` call. The exploit cannot advance past its first system call:

```bash
python3 -c "import socket; socket.socket(38, 1)"
```

Expected output: `PermissionError: [Errno 1] Operation not permitted`.

The audit log records the blocked attempt:

```text
type=SECCOMP msg=audit(1746403200.001:5120): auid=1002 uid=1002 gid=1002 \
  ses=14 subj=unconfined pid=41033 comm="python3" \
  exe="/usr/bin/python3.12" sig=0 arch=c000003e syscall=41 \
  compat=0 ip=0x7f2a3c14e3d7 code=0x50000
```

Syscall 41 is `socket` on x86-64. `code=0x50000` is `SECCOMP_RET_ERRNO`.

After `kernel.kptr_restrict=2` is applied, `/proc/kallsyms` shows only zeros for all kernel symbols to unprivileged users — KASLR bypass via address leaks from this interface is blocked:

```bash
grep 'T sys_write' /proc/kallsyms
```

Expected output: `0000000000000000 T __x64_sys_write`.

After user namespace restriction is applied, `unshare -U` from an unprivileged shell returns immediately with a permission error:

```bash
unshare -U /bin/bash
```

Expected output: `unshare: unshare failed: Operation not permitted`.

Verify Landlock is active on a running process:

```bash
grep -E "^(NoNewPrivs|Landlock)" /proc/$(pgrep -n myapp)/status
```

Expected output:

```text
NoNewPrivs:     1
Landlock_Restrict_Self: 1
```

## Trade-offs and Operational Considerations

User namespace restriction is the mitigation with the broadest operational impact. Rootless Docker, rootless Podman, Buildah, some Flatpak applications, and the Chromium and Firefox renderer sandboxes all depend on unprivileged user namespace creation. Before enabling `kernel.unprivileged_userns_clone=0` on any system, audit running processes for user namespace use:

```bash
find /proc -maxdepth 3 -name 'status' -exec grep -l "^Groups:" {} \; 2>/dev/null | \
  xargs -I{} sh -c 'dirname {} | xargs -I%% cat %%/status | grep -E "^(Name|NSpid)"'
```

A safer rollout: enable the restriction on servers first, where rootless container workflows are rare. Defer developer workstations and CI build hosts until a per-binary AppArmor allowlist is in place.

`lockdown=confidentiality` is incompatible with out-of-tree kernel modules that are not signed. Inventory active modules before enabling:

```bash
lsmod | awk 'NR>1 {print $1}' | while read m; do
  modinfo "$m" | grep -E '^(filename|sig_id|signer):'
done
```

Any module without a `signer:` line will fail to load under lockdown. Sign in-house modules using the kernel's `scripts/sign-file` tool and enroll the certificate via `mokutil` before switching lockdown on.

Seccomp profiles blocking `AF_ALG` must be applied consistently across all execution environments. A production Kubernetes pod with the profile and a CI build container without it leaves a gap — attackers who compromise the CI pipeline reach the same kernel. The profile should be part of the organisation's baseline pod security standard, not opt-in per workload.

Landlock requires kernel 5.13+ for filesystem restrictions and 6.7+ for TCP network restrictions. Most distributions in 2026 meet the filesystem threshold. Before deploying Landlock-based confinement, query the kernel's supported ABI:

```bash
python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
ret = libc.syscall(444, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
print(f'Landlock ABI version: {ret}')
"
```

ABI version 1 supports filesystem rules; version 4 adds TCP port rules. A return value of `-1` means Landlock is not supported on the current kernel.

## Failure Modes

`sysctl` settings applied with `sysctl -w` at runtime do not survive a reboot. The settings must be written to a file under `/etc/sysctl.d/` and loaded by the init system. Verify persistence explicitly after the next scheduled reboot:

```bash
sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.perf_event_paranoid
```

If any value differs from the expected setting, the file was not placed correctly or a conflicting file loaded later is overriding it. Check for conflicts:

```bash
sysctl --all --system 2>/dev/null | grep -E "kptr_restrict|dmesg_restrict|perf_event"
```

A seccomp profile that blocks `AF_ALG` in the production container but not in the CI build environment creates an asymmetric coverage gap. The CI environment runs against the same host kernel. The profile must be applied at both stages.

User namespace restrictions disabled for one service via an AppArmor exception or a per-namespace sysctl override must be tracked as a named exception with an owner and a review date. Exceptions that are not tracked become permanent. A recommended pattern is a comment in the AppArmor profile or sysctl drop-in that includes the JIRA/GitHub issue reference that approved the exception.

Landlock rulesets that grant access to `/` or to an ancestor directory containing sensitive paths provide no practical confinement. A policy that allows `FS_READ_FILE` on `/` is equivalent to no policy. Verify that allowlisted paths are the narrowest practical directories, not broad ancestors.

A `lockdown=confidentiality` setting applied via the GRUB command line can be silently removed when a distribution kernel package upgrade regenerates the GRUB configuration. Add a systemd unit as a fallback check that runs early in boot:

```ini
[Unit]
Description=Verify kernel lockdown is active
DefaultDependencies=no
After=local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'cat /sys/kernel/security/lockdown | grep -q confidentiality || \
  { echo "ALERT: kernel lockdown not active"; logger -p security.crit "lockdown not active"; }'
RemainAfterExit=yes

[Install]
WantedBy=basic.target
```

This does not re-enable lockdown — the unit cannot lower and re-raise it — but it generates an auditable alert when lockdown is missing, triggering operator investigation before the host processes production traffic.

## Related Articles

- [Linux algif_aead Privilege Escalation](/articles/linux/linux-algif-aead-privilege-escalation/)
- [Seccomp BPF Without Containers](/articles/linux/seccomp-bpf-non-container/)
- [Landlock LSM](/articles/linux/landlock-lsm/)
- [Kernel Lockdown](/articles/linux/kernel-lockdown/)
- [Linux Memory Protections](/articles/linux/linux-memory-protections/)
