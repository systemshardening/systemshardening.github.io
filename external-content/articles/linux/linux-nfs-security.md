---
title: "Linux NFS Security Hardening: Kerberos, Exports, and Protecting Network Filesystems"
description: "NFSv3 has no authentication model — any host that can reach port 2049 can mount your exports and spoof UIDs. This guide covers NFSv4 with Kerberos, export hardening, ID mapping, firewall rules, kernel TLS, and NFS in Kubernetes."
slug: linux-nfs-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - nfs
  - kerberos
  - network-filesystem
  - access-control
  - encryption
personas:
  - security-engineer
  - platform-engineer
article_number: 470
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-nfs-security/
---

# Linux NFS Security Hardening: Kerberos, Exports, and Protecting Network Filesystems

## The Problem

NFS was designed for trusted LAN environments in the 1980s. NFSv3, still widely deployed, has no concept of client authentication — any host that can reach TCP/UDP port 2049 can present a UID of 0 and gain root-equivalent access to every exported path. UID spoofing is not a theoretical attack; it requires a single `mount` command from an attacker who already has LAN access or who has compromised any machine with export permissions.

The attack surface:

- **No client authentication (NFSv3):** The server trusts the client's reported UID/GID. A client can `useradd -u 1001 victim` and read files owned by uid 1001 on any NFS server that exports to that subnet.
- **Cleartext data in transit (NFSv3/NFSv4 without `sec=krb5p`):** File content, metadata, and credentials traverse the wire unencrypted. Passive interception on a switched network is feasible via ARP spoofing.
- **`no_root_squash` misconfiguration:** A single export line with `no_root_squash` on a subnet grants any compromised host root access to the exported tree.
- **Wildcard exports:** `/data *(rw)` exports to every host on the internet if the firewall has any gap.
- **rpcbind (port 111) exposure:** rpcbind maps RPC programs to ports. Exposed externally, it provides a service enumeration target and has a history of vulnerabilities.

NFSv4 with Kerberos (GSSAPI) addresses authentication and optionally integrity/confidentiality, but the configuration involves multiple moving parts — KDC, keytabs, idmapd, and firewall rules — that are easy to misconfigure silently.

**Target systems:** RHEL 9 / Rocky Linux 9, Ubuntu 22.04+, Debian 12. Commands use `nfs-utils` and MIT Kerberos (`krb5-user`).

## NFSv4 and Kerberos: The Security Hierarchy

NFSv4 supports three Kerberos security flavors. They are not interchangeable — each adds a layer, and each has a performance cost:

| `sec=` option | Authentication | Integrity (HMAC) | Encryption |
|---|---|---|---|
| `krb5` | Yes (GSSAPI) | No | No |
| `krb5i` | Yes | Yes (SHA-1 HMAC) | No |
| `krb5p` | Yes | Yes | Yes (AES-128/256) |

**`sec=krb5`** proves that the client is who it claims to be (principal verified against KDC), but packet contents can be read and tampered with in transit. Use this only on isolated management networks where you need accountability without overhead.

**`sec=krb5i`** adds a per-packet HMAC. Prevents silent tampering but data is still readable. Appropriate for internal networks where confidentiality is covered at the network layer (IPsec, private VLAN) but you want tamper detection.

**`sec=krb5p`** encrypts every NFS RPC. Use this on any path that traverses shared infrastructure, multi-tenant environments, or when compliance requires encryption of data in transit. The CPU overhead on modern hardware with AES-NI is measurable but not prohibitive — expect 10–20% throughput reduction vs. `sec=none` for large sequential reads.

For a mixed environment, export the same path with multiple security flavors, ordered most-secure first:

```bash
# /etc/exports
/data/sensitive  *(sec=krb5p:krb5i,rw,sync,root_squash,no_subtree_check)
/data/shared     *(sec=krb5i:krb5,ro,sync,root_squash,no_subtree_check)
```

The server tries flavors left-to-right; the client negotiates the highest it supports. This allows a migration path without a hard cutover.

## Setting Up Kerberos-Authenticated NFS

### Prerequisites

A working MIT Kerberos KDC with principals for each NFS server and client. For production, use a redundant KDC. The NFS server needs a `nfs/<fqdn>@REALM` principal; clients need `host/<fqdn>@REALM`.

```bash
# On the KDC — create server principal and export keytab
kadmin.local -q "addprinc -randkey nfs/nfs01.example.com@EXAMPLE.COM"
kadmin.local -q "ktadd -k /tmp/nfs01.keytab nfs/nfs01.example.com@EXAMPLE.COM"

# Securely transfer to NFS server, then:
cp /tmp/nfs01.keytab /etc/krb5.keytab
chmod 600 /etc/krb5.keytab
chown root:root /etc/krb5.keytab
```

### `/etc/krb5.conf` on server and clients

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    # Disable weak enctypes
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    EXAMPLE.COM = {
        kdc = kdc01.example.com
        kdc = kdc02.example.com
        admin_server = kdc01.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com  = EXAMPLE.COM
```

Disabling `dns_lookup_kdc` prevents DNS spoofing from redirecting authentication to a rogue KDC. Restricting enctypes drops RC4/DES, which are trivially crackable.

### nfs-utils and rpc-gssd

```bash
# Server
apt install nfs-kernel-server krb5-user   # Debian/Ubuntu
dnf install nfs-utils krb5-workstation    # RHEL/Rocky

systemctl enable --now nfs-server rpc-gssd

# Client
apt install nfs-common krb5-user
systemctl enable --now rpc-gssd
```

`rpc-gssd` handles the GSSAPI token exchange on both client and server. If it is not running, Kerberos mounts fall back to `AUTH_SYS` (plain UID) or fail, depending on export configuration. Verify:

```bash
rpcinfo -p localhost | grep -E 'nfs|mountd'
systemctl status rpc-gssd
```

### Mounting on the client

```bash
# Permanent entry in /etc/fstab
nfs01.example.com:/data/sensitive  /mnt/sensitive  nfs4  sec=krb5p,rw,hard,intr,timeo=90,retrans=3,_netdev  0 0

# One-off mount for testing
mount -t nfs4 -o sec=krb5p nfs01.example.com:/data/sensitive /mnt/sensitive
```

The `_netdev` option ensures the mount is attempted only after the network is up. `hard,intr` with a reasonable `timeo` prevents silent data loss on server unavailability while still allowing process interruption.

## `/etc/exports` Hardening

Every option in an exports line has a security implication. The defaults are not safe defaults.

```bash
# /etc/exports — annotated hardened example

# BAD — do not use:
# /data *(rw,no_root_squash)

# GOOD — restrictive, Kerberos-authenticated export:
/data/app   10.10.5.0/24(sec=krb5p,rw,sync,root_squash,no_subtree_check)

# Read-only export to a specific host:
/data/reports  10.10.5.42(sec=krb5i,ro,sync,root_squash,no_subtree_check)
```

**Key options explained:**

`root_squash` (default, always keep): Maps uid 0 from the client to the anonymous uid (typically 65534 / `nfsnobody`). Without this, a client root can read or write any file on the export regardless of permissions. **Never use `no_root_squash` except in tightly controlled HPC environments where you explicitly need it.**

`all_squash`: Maps *all* client UIDs to the anonymous UID. Use this for public or untrusted read-only exports where you do not want any client UID to map to a real server user.

`sync` vs `async`: `async` allows the server to acknowledge writes before they hit stable storage — this improves throughput but risks data corruption on server crash. For security-sensitive data, use `sync`. The NFS client treats `async` exports as unreliable, and a server crash can silently lose acknowledged writes.

`no_subtree_check` (recommended): When exporting a subdirectory rather than a whole filesystem, the server performs subtree checking by default — it verifies each file access is within the exported subtree by traversing inodes. This has a race condition (see CVE-2006-3318 and related) and reduces performance. Unless you have a compelling reason to use subtree checking, disable it with `no_subtree_check`.

**Host patterns:** Never use `*` unless you understand that it matches every resolvable hostname, including hosts outside your organization if your DNS is misconfigured. Use explicit CIDR notation (`10.10.5.0/24`) or individual hostnames. Verify exports after changes:

```bash
exportfs -v
showmount -e localhost
```

After editing `/etc/exports`, reload without restarting the server:

```bash
exportfs -ra
```

## NFSv4 ID Mapping: idmapd.conf

NFSv4 uses string-form user identities (`user@domain`) rather than raw UIDs. The `nfsidmap` daemon (configured in `/etc/idmapd.conf`) translates between these and local UIDs. A domain mismatch between server and client causes every user to map to `nobody:nobody` — a silent failure mode that is easy to miss.

```ini
# /etc/idmapd.conf — must be IDENTICAL on server and all clients
[General]
Verbosity = 0
Pipefs-Directory = /run/rpc_pipefs
Domain = example.com          # Must match Kerberos realm (lowercased)

[Mapping]
Nobody-User = nobody
Nobody-Group = nogroup
```

The `Domain` field must match across every machine that shares NFS mounts. After changing `idmapd.conf`:

```bash
systemctl restart nfs-idmapd
nfsidmap -c    # flush the mapping cache
```

**The nobody:nobody danger:** If idmapd cannot resolve a principal to a local user, it falls back to the nobody uid. On a server with `root_squash` active, this means the mapped user has the permissions of `nobody` — usually harmless for reads but completely blocks writes. More dangerous: if `nobody` has been granted permissions to a path (e.g., via `chmod o+w`), unmapped clients get unexpected write access. Audit periodically:

```bash
find /exported -user nobody -o -group nogroup 2>/dev/null
```

## Firewall Rules: Locking Down NFS Ports

NFS requires several ports. In NFSv4, only port 2049 is strictly necessary (rpcbind/portmapper is not required for pure NFSv4 clients), but many deployments still use NFSv3 alongside it.

```bash
# nftables — server ruleset fragment
# Allow NFS only from trusted subnets, block everything else

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # NFS (NFSv4 TCP only — drop NFSv3 UDP)
        ip saddr 10.10.5.0/24 tcp dport 2049 accept
        ip6 saddr fd00::/8     tcp dport 2049 accept

        # rpcbind — only if NFSv3 required; otherwise block
        # ip saddr 10.10.5.0/24 tcp dport 111 accept

        # Drop rpcbind from all untrusted sources
        tcp dport 111 drop
        udp dport 111 drop

        # mountd, statd, lockd — pin to fixed ports and allow only from trusted
        # Add to /etc/nfs.conf:
        #   [mountd]
        #   port=20048
        #   [statd]
        #   port=20049
        #   [lockd]
        #   port=20050
        ip saddr 10.10.5.0/24 tcp dport { 20048, 20049, 20050 } accept
    }
}
```

Pin auxiliary NFS service ports in `/etc/nfs.conf` to make firewall rules stable:

```ini
# /etc/nfs.conf
[mountd]
port=20048

[statd]
port=20049

[lockd]
port=20050
```

For pure NFSv4-only environments, you can disable rpcbind entirely:

```bash
systemctl disable --now rpcbind rpcbind.socket
```

Verify that port 111 is no longer listening before proceeding.

## Kernel TLS for NFS (NFSv4.1+ with `nfs-tls`)

Kerberos `sec=krb5p` provides per-RPC encryption but at the cost of Kerberos infrastructure. Kernel TLS (kTLS) for NFS, introduced upstream in Linux 5.15 and stabilized in 6.x, provides TLS 1.3 transport-layer encryption for NFSv4.1+ without requiring a KDC. It is complementary to Kerberos — you can run both.

```bash
# Verify kernel module support
modinfo tls
grep CONFIG_TLS /boot/config-$(uname -r)   # should be =y or =m

# Load if module:
modprobe tls

# Server: generate or deploy certificates (standard X.509/TLS certs)
# Using a private CA or cert-manager for internal PKI

# /etc/nfs.conf — server
[nfsd]
tls=yes

# Mount with TLS on client
mount -t nfs4 -o tls nfs01.example.com:/data/secure /mnt/secure
```

Performance note: kTLS offloads AES-GCM to the kernel's crypto layer, benefiting from AES-NI. For large-file workloads the overhead is lower than userspace TLS, typically under 5% on modern CPUs. For latency-sensitive small-file workloads (e.g., `/home` directories), benchmark before deploying.

`nfs-tls` does not yet have wide distro packaging as of early 2026; RHEL 9.4+ and Ubuntu 24.04 ship kernel support but tooling varies. Check `tlshd` (the TLS handshake daemon from the `ktls-utils` package) for your distribution.

## Monitoring: Detecting Unauthorized Mounts and Auditing Access

### Detecting unauthorized NFS mounts

On the server, watch for mounts from unexpected clients:

```bash
# Current active mounts:
showmount --no-headers -a nfs01.example.com

# Parse /proc/net/rpc/nfsd for per-client stats:
cat /proc/net/rpc/nfsd

# Persistent monitoring — log new mounts via systemd journal:
journalctl -u nfs-server -f | grep -E 'mount|MOUNT'
```

For automated detection, configure an alert on unexpected source IPs in NFS server logs:

```bash
# /etc/rsyslog.d/nfs-alerts.conf
if $programname == 'rpc.mountd' and $msg contains 'authenticated mount' then {
    action(type="omfile" file="/var/log/nfs-mounts.log")
    stop
}
```

### auditd rules for NFS server file access

Place the exported tree under auditd monitoring for sensitive paths:

```bash
# /etc/audit/rules.d/nfs.rules

# Monitor writes to exported sensitive paths
-w /data/sensitive -p wa -k nfs_sensitive_write

# Monitor execution attempts (should be rare/never on NFS exports)
-w /data/app -p x -k nfs_exec_attempt

# Watch for changes to NFS configuration
-w /etc/exports -p wa -k nfs_exports_change
-w /etc/nfs.conf -p wa -k nfs_config_change
-w /etc/idmapd.conf -p wa -k nfs_idmap_change
-w /etc/krb5.keytab -p rwa -k nfs_keytab_access
```

Reload rules:

```bash
augenrules --load
auditctl -l | grep nfs
```

Query access events:

```bash
# All writes to the sensitive export in the last hour
ausearch -k nfs_sensitive_write --start recent -i

# Any execution attempts on NFS mounts
ausearch -k nfs_exec_attempt -i
```

### Detecting UID/GID mismatches (idmapd failures)

Log idmapd warnings to catch mapping failures early:

```bash
# Increase verbosity temporarily for debugging:
# /etc/idmapd.conf
[General]
Verbosity = 7

journalctl -u nfs-idmapd | grep -i 'nobody\|failed\|error'
```

## NFS in Containers and Kubernetes

### ReadWriteMany PVs: the shared access risk

NFS is one of the few volume types that supports `ReadWriteMany` in Kubernetes. This makes it appealing for shared workloads but concentrates risk: a compromised pod with a `RWX` PV mount can overwrite shared data that other pods depend on.

Key risks:

- **Privileged pods:** A pod running as uid 0 with `root_squash` disabled on the NFS server gets root access to the export. Always configure `root_squash` on exports used by Kubernetes.
- **UID collision:** Containers often run as uid 1000 or uid 0. If a container's uid matches a real uid on the NFS server, it gains that user's file permissions without any Kerberos authentication (when using `sec=sys`).
- **`hostNetwork: true` pods:** A pod with host networking can reach the NFS server directly from the node's IP, bypassing network policies.

### Kubernetes-specific hardening

```yaml
# SecurityContext — force non-root and a specific fsGroup
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001        # Dedicate a UID for this workload; map it on the NFS server
    runAsGroup: 10001
    fsGroup: 10001
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

On the NFS server side, create a matching uid/gid:

```bash
groupadd -g 10001 k8s-app
useradd -u 10001 -g k8s-app -s /sbin/nologin -M k8s-app
chown -R k8s-app:k8s-app /data/k8s-app
chmod 750 /data/k8s-app
```

Then export with `all_squash` and explicit anon uid/gid mapping to eliminate UID collision risk:

```bash
# /etc/exports
/data/k8s-app  10.20.0.0/16(sec=krb5p,rw,sync,all_squash,anonuid=10001,anongid=10001,no_subtree_check)
```

`all_squash` with explicit `anonuid`/`anongid` means every pod accessing this export is mapped to exactly `k8s-app` on the server, regardless of what UID the container reports. Combined with Kerberos, this gives you a clean principal-to-server-uid binding.

### Network policies for NFS access

Restrict which pods can reach the NFS server:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nfs-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      needs-nfs: "true"
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 2049
      protocol: TCP
    to:
    - ipBlock:
        cidr: 10.10.5.10/32   # NFS server IP
```

A default-deny egress policy in the namespace ensures that only pods explicitly labeled `needs-nfs: "true"` can reach port 2049.

## Operational Checklist

Before declaring an NFS deployment production-ready:

```bash
# 1. Verify no wildcard exports
exportfs -v | grep '\*'   # should return nothing

# 2. Confirm root_squash is active on all exports
exportfs -v | grep no_root_squash   # should return nothing

# 3. Verify Kerberos security flavor is negotiated
nfsstat -m   # check 'sec=' on mounted client

# 4. Confirm rpcbind is not exposed externally
ss -tlnp | grep :111
nmap -sU -p 111 <server-ip>   # from an external segment

# 5. Check idmapd domain consistency
grep Domain /etc/idmapd.conf   # compare on server and all clients

# 6. Audit files owned by nobody
find /exported -user nobody 2>/dev/null

# 7. Verify keytab permissions
ls -l /etc/krb5.keytab   # must be 600, owner root
klist -k /etc/krb5.keytab   # list principals in keytab
```

## Summary

NFSv3 with `sec=sys` is operationally convenient and a security liability. The migration path to secure NFS is incremental: start by restricting exports to explicit CIDR ranges and enabling `root_squash`, then move to NFSv4 with at minimum `sec=krb5i`, and finally `sec=krb5p` or kernel TLS for any path carrying sensitive data. ID mapping failures are silent by default — monitor `nfs-idmapd` logs and audit for `nobody`-owned files. In Kubernetes, `all_squash` with dedicated `anonuid`/`anongid` combined with strict `SecurityContext` is the most reliable way to eliminate UID-spoofing risk without deploying full Kerberos infrastructure into the cluster.
