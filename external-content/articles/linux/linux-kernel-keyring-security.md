---
title: "Linux Kernel Keyring Security and TPM2-Backed Keyrings"
description: "Harden the Linux kernel keyring subsystem with TPM2-backed key storage, IMA appraisal keyrings, keyctl ACL hardening, and monitoring for open source keyring CVE patch gaps."
slug: linux-kernel-keyring-security
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["keyring", "tpm2", "ima", "keyctl", "kernel", "credentials", "pkcs11"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 335
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/linux/linux-kernel-keyring-security/index.html"
---

# Linux Kernel Keyring Security and TPM2-Backed Keyrings

## Problem

The Linux kernel keyring is a kernel-managed credential store that holds cryptographic keys, authentication tokens, and sensitive secrets inside kernel memory. Unlike a file or environment variable, keyring data lives in kernel space and is never swapped to disk under normal operation. Processes interact with it through the `keyctl(2)` syscall or the userspace `keyctl` utility. The kernel organizes keyrings hierarchically: a thread keyring exists for the lifetime of a thread, a process keyring is shared by all threads of a process, a session keyring persists for the duration of a login session, and a user keyring is tied to a UID and shared across all sessions for that user. NFS credentials, Kerberos tickets, TLS private keys, and LUKS volume keys all legitimately land in one of these keyrings.

The security gap is subtle but consequential. Key permissions in the keyring subsystem are encoded as a 32-bit bitmask that independently controls possessor, user, group, and other access. The `possessor` category covers any process that has a reference to the keyring containing the key — a broader definition than most administrators expect. When a key is created with overly generous permissions (for example `0x3f3f3f3f`, which grants full access to all four categories), any process running as the same UID, or any process that has joined the session keyring, can call `keyctl read <key-id>` and retrieve the raw key material. This is not a kernel bug; it is the intended ACL behavior, and it catches operators off guard precisely because keyring permissions are rarely audited the way file permissions are.

IMA, the Integrity Measurement Architecture, depends on the kernel keyring subsystem for its own security guarantees. The `.ima` keyring holds the trusted CA certificates used to verify IMA file signatures, and the `.evm` keyring holds the keys used to protect security extended attributes. If the `.ima` keyring is world-writable, or if it allows unprivileged users to add keys, an attacker can install a self-signed certificate, sign a malicious binary with the corresponding private key, and pass IMA appraisal entirely. The IMA documentation assumes the keyring is locked at boot, but systems that do not explicitly call `keyctl restrict_keyring` leave the door open for post-boot key injection.

The open source nature of the Linux kernel creates a class of risk that deserves explicit attention: the patch-gap adversary. When a security-relevant fix lands in Linus Torvalds's mainline tree, it immediately becomes visible at https://git.kernel.org. Fixes are then backported to stable trees maintained by Greg Kroah-Hartman and Sasha Levin, and the stable-queue — the pending backport queue before a point release — is public at https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git. An attacker who monitors `git log --oneline --grep="keyring"` or `git log --oneline --grep="key_"` on the stable-rc tree can identify exploitable fixes days or weeks before a distribution ships the patch.

This patch-gap is not hypothetical. Historical keyring CVEs such as CVE-2016-0728 (a reference count leak allowing local privilege escalation) and CVE-2023-3161 (a use-after-free in the key garbage collector) followed the pattern: mainline fix committed, stable backport queued, CVE assigned, distribution advisory issued — with the window between mainline commit and distribution package update often stretching two to four weeks for RHEL and Ubuntu LTS users. Many keyring-related fixes never receive a CVE at all because maintainers classify them as "not a security issue" even when they affect key confidentiality or integrity. Operators must actively monitor upstream rather than relying solely on distribution security advisories.

The correct monitoring approach is to watch three sources simultaneously: the linux-kernel mailing list via lore.kernel.org for patch series tagged `[PATCH stable]` affecting `security/keys/`; the stable-queue git tree for queued patches; and the NVD at https://nvd.nist.gov/ for CVEs referencing `kernel/security/keys`. Cross-referencing these three surfaces fixes that have no CVE, fixes that have a CVE but no advisory yet from the distribution, and fixes that are in the stable queue but not yet in a released point kernel.

Target systems: Linux kernel >= 5.15, systemd >= 252, TPM2 chip required for hardware-backed keyrings.

## Threat Model

1. **Local attacker exploiting permissive possessor bits.** A process running as the same UID as a web application calls `keyctl list @s` to enumerate the session keyring, identifies a key holding a database connection string or TLS private key, and calls `keyctl read <key-id>` to extract it. The application developer added the key with default permissions without understanding that other processes in the session could read it.

2. **Container escape via shared session keyring.** A process inside a container that was started without proper user namespace isolation inherits the host's session keyring. The container runtime did not call `unshare(CLONE_NEWUSER)` or the orchestrator did not configure the container's UID mapping correctly. From inside the container, the attacker enumerates `@s` and reads keys that the host's init scripts loaded at boot — including LUKS unlock keys, service account tokens, or Kerberos credentials.

3. **Patch-gap adversary.** A threat actor runs a cron job against the stable-rc git tree, filtering commits that touch `security/keys/` or mention "use-after-free", "refcount", or "leak" in the context of keyrings. When such a commit appears, they analyze the diff to determine exploitability, build a proof-of-concept against the unpatched kernel version still shipping in production LTS distributions, and have a working exploit ready before the distribution's security team issues an advisory. RHEL 9 and Ubuntu 22.04 LTS users running the shipping 5.15 or 5.14 kernel are particularly exposed during this window.

4. **IMA bypass via unsigned key injection.** An attacker with local write access (through another vulnerability) adds a self-signed certificate to the `.ima` keyring before it has been locked. They then replace a system binary with a version signed by that certificate. All subsequent IMA appraisal checks for that binary pass. The system's integrity enforcement appears intact from the outside while running attacker-controlled code.

The blast radius across all four scenarios is bounded by how tightly keyring permissions are scoped, whether TPM2 binding prevents key material from being read outside the TPM's authorization protocol, whether the `.ima` keyring is locked at boot, and how quickly operators can detect and patch kernel versions when fixes appear upstream.

## Configuration / Implementation

### Auditing Keyring Permissions

Begin by examining what is currently in the session and user keyrings:

```bash
# Show session keyring with permission bitmasks
keyctl show @s

# Show user keyring
keyctl show @u

# Show process keyring
keyctl show @p
```

The permission bitmask printed by `keyctl show` takes the form `--alswrv------rwrv` where positions correspond to possessor, user, group, and other — each having view (v), read (r), write (w), search (s), link (l), and set-attribute (a) bits. A key showing `rwrv` in the "other" column is readable by any process, regardless of UID.

To enumerate all key IDs in the session keyring and inspect each:

```bash
# List key IDs in session keyring
keyctl list @s

# For each key ID returned, print its description and permissions
for keyid in $(keyctl list @s | awk -F: '{print $1}' | tr -d ' '); do
  echo "=== Key $keyid ==="
  keyctl rdescribe "$keyid" 2>/dev/null || true
done

# Print raw key material for a specific key (only works if you have read permission)
keyctl print <key-id>

# Show full permission bitmask numerically
keyctl stat <key-id>
```

Look specifically for keys with type `user`, `logon`, or `asymmetric` that have non-zero "other" read permission. Any key with permission bits where the fourth octet (other) includes `r` (read) or `v` (view) is accessible to all processes.

### Restricting Keyring Operations with Keyring ACLs

Remove read access from the "other" and "group" categories for keys that only the possessing process needs:

```bash
# Remove all non-possessor permissions from a specific key
# Permission format: 0x<possessor><user><group><other>
# Each nibble: view=0x01, read=0x02, write=0x04, search=0x08, link=0x10, setattr=0x20
# Possessor-only read+view+write+search: 0x3f000000
keyctl setperm <key-id> 0x3f000000

# For a key the owning user (not just possessor) also needs to read:
keyctl setperm <key-id> 0x3f3f0000

# Restrict the session keyring itself so only the possessor can link to it
keyctl setperm @s 0x3f000000
```

When creating new keys, pass explicit permissions at creation time rather than relying on defaults:

```bash
# Add a key to the session keyring with possessor-only permissions
keyid=$(keyctl add user myapp:dbpassword "$(cat /run/secrets/dbpass)" @s)
keyctl setperm "$keyid" 0x3f000000
```

The kernel configuration option `CONFIG_KEYS_REQUEST_CACHE` enables a per-task cache for `request_key()` lookups. While this improves performance, it means a process's effective keyring view is cached and may not immediately reflect permission changes. On systems with this enabled, permission changes take effect after the next cache flush (generally on the next syscall boundary), so do not rely on `keyctl setperm` for instantaneous revocation.

### TPM2-Backed Keyrings with tpm2-tss

TPM2-backed keyrings bind key material to the TPM chip such that keys cannot be extracted even with root access. The TPM holds the private key internally; operations are performed inside the TPM boundary. The kernel's `trusted` key type supports this natively.

Install prerequisites:

```bash
apt-get install tpm2-tools tpm2-abrmd libtss2-dev  # Debian/Ubuntu
dnf install tpm2-tools tpm2-abrmd tpm2-tss-devel   # RHEL/Fedora
```

Create and load a TPM2-backed trusted key:

```bash
# Create a primary key in the TPM (owner hierarchy, RSA2048)
tpm2_createprimary -C o -g sha256 -G rsa2048 -c /tmp/primary.ctx

# Create a child key sealed to current PCR values
tpm2_create \
  -C /tmp/primary.ctx \
  -g sha256 \
  -G rsa2048 \
  -r /tmp/sealed.priv \
  -u /tmp/sealed.pub \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"

# Load the child key into the TPM
tpm2_load \
  -C /tmp/primary.ctx \
  -r /tmp/sealed.priv \
  -u /tmp/sealed.pub \
  -c /tmp/loaded.ctx

# Flush sensitive context files
rm -f /tmp/primary.ctx

# Load the trusted key into the kernel keyring via the trusted key type
# The kernel trusted key type communicates with the TPM via the tpm subsystem
keyid=$(keyctl add trusted myservice:tls-key \
  "new 32 keyhandle=0x81000001 blobauth=sha256:$(tpm2_getrandom --hex 32)" \
  @s)
keyctl setperm "$keyid" 0x3f000000

# Export the key blob for persistence (the blob is encrypted by the TPM's storage key)
keyctl pipe "$keyid" > /etc/keys/myservice-tls.blob
```

To load the key blob back after a reboot:

```bash
keyid=$(keyctl add trusted myservice:tls-key "load $(cat /etc/keys/myservice-tls.blob)" @s)
keyctl setperm "$keyid" 0x3f000000
```

To use a TPM2-backed asymmetric key through OpenSSL via the PKCS#11 provider, install `tpm2-pkcs11` and configure the provider:

```bash
apt-get install tpm2-pkcs11
# Initialize a token
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --label=myservice --userpin=<pin> --sopin=<sopin>
# Add an RSA key to the token
tpm2_ptool addkey --label=myservice --userpin=<pin> --algorithm=rsa2048

# Test signing via the kernel keyring-backed PKCS#11 path
openssl dgst -sha256 -sign "pkcs11:token=myservice;object=mykey;type=private" \
  -engine pkcs11 /tmp/testfile
```

### IMA Keyring Hardening

The `.ima` and `.evm` keyrings are built-in keyrings created by the kernel at boot. Verify their contents:

```bash
# List keys on the .ima keyring
keyctl list %:.ima

# List keys on the .evm keyring
keyctl list %:.evm

# Show detailed info for each IMA key
for keyid in $(keyctl list %:.ima | awk -F: '{print $1}' | tr -d ' '); do
  echo "=== IMA Key $keyid ==="
  keyctl stat "$keyid"
done
```

Add a trusted IMA CA certificate (must be done early in boot, before the keyring is locked):

```bash
# Add a PEM-format CA certificate to the .ima keyring
# This requires CAP_SYS_ADMIN or running as root during early boot
keyid=$(keyctl padd asymmetric "" %:.ima < /etc/keys/ima-ca.pem)
echo "Loaded IMA CA key: $keyid"

# Lock the .ima keyring so no further keys can be added
# After this call, keyctl add/padd to %:.ima will fail with EPERM
keyctl restrict_keyring %:.ima asymmetric builtin_and_secondary_trusted
```

The kernel configuration required for proper IMA keyring enforcement:

```bash
# Verify in /boot/config-$(uname -r):
grep -E 'CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY|CONFIG_INTEGRITY_TRUSTED_KEYRING|CONFIG_INTEGRITY_ASYMMETRIC_KEYS|CONFIG_SYSTEM_TRUSTED_KEYRING' \
  /boot/config-$(uname -r)
```

Expected output for a hardened system:

```
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
```

With `CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y`, keys added to `.ima` at runtime must themselves be signed by a key already in the kernel's builtin or secondary trusted keyring, preventing arbitrary key injection even before `restrict_keyring` is called.

### Monitoring Upstream for Silent Keyring Fixes

Set up a cron-based monitoring system to detect security-relevant commits in the stable-rc tree before they are released:

```bash
# Clone the stable-rc tree (do this once on a monitoring host)
git clone --bare \
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git \
  /opt/kernel-watch/linux-stable-rc.git

# Create the monitoring script
cat > /usr/local/bin/kernel-keyring-watch.sh << 'EOF'
#!/bin/bash
set -euo pipefail

REPO=/opt/kernel-watch/linux-stable-rc.git
WATERMARK=/var/lib/kernel-watch/last-commit
ALERT_EMAIL=security-team@example.com
BRANCH=linux-6.6.y  # adjust to your LTS branch

cd "$REPO"
git fetch origin 2>/dev/null

LAST=$(cat "$WATERMARK" 2>/dev/null || git rev-list --max-parents=0 origin/"$BRANCH")
NEW=$(git rev-parse origin/"$BRANCH")

if [ "$LAST" = "$NEW" ]; then
  exit 0
fi

HITS=$(git log --oneline "$LAST".."$NEW" \
  --grep="keyring" \
  --grep="key_\|keyctl\|request_key\|key_ref\|use.after.free.*key\|refcount.*key" \
  --regexp-ignore-case \
  -- security/keys/ include/linux/key*.h \
  2>/dev/null || true)

if [ -n "$HITS" ]; then
  echo "$HITS" | mail -s "[ALERT] Kernel keyring commits in stable-rc $BRANCH" "$ALERT_EMAIL"
fi

echo "$NEW" > "$WATERMARK"
EOF

chmod +x /usr/local/bin/kernel-keyring-watch.sh
mkdir -p /var/lib/kernel-watch

# Add to cron — check twice daily
echo "0 6,18 * * * root /usr/local/bin/kernel-keyring-watch.sh" \
  > /etc/cron.d/kernel-keyring-watch
```

Cross-reference identified commits against the NVD to detect unassigned CVEs:

```bash
# Extract commit short hashes from git log output and search NVD API
for commit in $(git -C /opt/kernel-watch/linux-stable-rc.git log \
    --oneline --grep="keyring" \
    --since="30 days ago" \
    -- security/keys/ | awk '{print $1}'); do
  echo "Checking $commit against NVD..."
  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$commit" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
total=d.get('totalResults',0)
if total==0:
    print(f'  No CVE found for commit $commit — possible silent fix')
else:
    for v in d['vulnerabilities']:
        print(f\"  CVE: {v['cve']['id']}\")
"
done
```

Also monitor the linux-kernel-announce mailing list archive:

```bash
# Fetch recent kernel announce messages and grep for keyring
curl -s "https://lore.kernel.org/linux-kernel-announce/?q=keyring&x=A" \
  | grep -o 'subject:[^<]*' | head -20
```

### Kernel Compile-Time Hardening

When building a custom kernel, enable the following options:

```bash
# Verify current kernel's key-related config options
grep -E 'CONFIG_TRUSTED_KEYS|CONFIG_ENCRYPTED_KEYS|CONFIG_KEY_DH_OPERATIONS|CONFIG_PKCS8_PRIVATE_KEY_PARSER|CONFIG_BIG_KEYS|CONFIG_KEYS_COMPAT' \
  /boot/config-$(uname -r)
```

Recommended settings in `.config`:

```
# Enable TPM2-backed trusted keys
CONFIG_TRUSTED_KEYS=y
# Enable encrypted keys (wrapped by master key in keyring)
CONFIG_ENCRYPTED_KEYS=y
# Allow Diffie-Hellman key operations via keyctl dh_compute
CONFIG_KEY_DH_OPERATIONS=y
# Disable PKCS#8 private key parser if not needed (reduces attack surface)
# CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set
# Enable large key storage in tmpfs rather than slab
CONFIG_BIG_KEYS=y
```

Disable `CONFIG_PKCS8_PRIVATE_KEY_PARSER` unless your deployment specifically requires importing PKCS#8-encoded private keys at runtime. The parser adds a code path that handles DER/PEM private key material inside the kernel; removing it eliminates the associated attack surface without affecting TPM2-backed or encrypted key workflows.

## Expected Behaviour

| Signal | Before Hardening | After Hardening |
|---|---|---|
| `keyctl read <key-id>` by unprivileged user in same session | Succeeds; returns raw key material because default permissions include possessor read for all session members | Fails with `keyctl_read: Permission denied`; key bitmask restricts read to possessor only (0x3f000000) |
| IMA bypass via unsigned key injection | Attacker with local access adds self-signed cert to `.ima` keyring; malicious binary passes appraisal | Fails with `EPERM`; `.ima` keyring locked with `restrict_keyring` and `CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y` enforces chain of trust |
| Container reading host session keyring | Container process reads host session keys because container shares host user namespace | Keys inaccessible; container runs in separate user namespace; session keyring scoped to host UID namespace |
| Patch-gap exploitation window | Operator learns of keyring fix when distribution advisory is published — days to weeks after upstream commit | Monitoring script detects commit in stable-rc within 12 hours; emergency kernel update can be triggered before public advisory |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| TPM2 binding for trusted keys | Key material never leaves TPM boundary; root cannot extract raw key bytes | Keys are not portable between machines or after TPM clear/reset; disaster recovery requires re-keying | Store key blobs (encrypted by TPM storage key) in a secure backup; document re-enrollment procedure; use policy-based authorization (PCR values) carefully to avoid locking out recovery paths |
| IMA keyring lockdown via `restrict_keyring` | Prevents post-boot injection of unauthorized signing certificates | Breaks workflows where operators add custom CA certs after boot for module signing or update verification | Load all required CA certs in a systemd service that runs at `sysinit.target` before `local-fs.target`; lock the keyring at the end of that service |
| Monitoring stable-queue and upstream | Detects silent fixes before CVE assignment; reduces patch gap from weeks to hours | Requires engineering time to triage false positives; stable-queue commits for non-security refactors generate noise | Scope the grep pattern to `security/keys/` and `include/linux/key*.h` paths; add secondary filter for UAF/refcount/leak keywords; route alerts to a dedicated oncall rotation |
| Strict `keyctl` ACLs (possessor-only) | Eliminates lateral key access between processes sharing a session | Legacy applications using PKCS#11 keyring integration may call `keyctl read` from a helper process that is not the possessor | Audit legacy app keyring usage with `strace -e keyctl`; use the `user` permission tier instead of possessor-only for keys that legitimately need multi-process access |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| TPM2 key not loadable after reboot (PCR mismatch) | `keyctl add trusted` returns `EPERM` or `EINVAL`; services that depend on the key fail to start | `journalctl -u myservice` shows key load failure; `tpm2_unseal` against the blob fails with authorization error | Boot into recovery, compare current PCR values with `tpm2_pcrread` against expected values; if PCRs changed due to firmware/bootloader update, re-create the key blob with updated PCR policy and store in backup |
| IMA keyring locked before all CA certs loaded | Boot fails or early userspace cannot execute signed binaries; IMA audit log shows `appraise_measurement_failed` for systemd or init | Kernel ring buffer (`dmesg \| grep -i ima`) shows signature verification failures during initrd phase | Boot with `ima_appraise=log` kernel parameter to downgrade to measurement-only mode; re-order the service that loads CA certs to run before `restrict_keyring` is called; use `CONFIG_IMA_APPRAISE_BOOTPARAM=y` to allow boot parameter override |
| Stable-queue monitoring misses a security fix | Patch-gap adversary has working exploit while production systems run unpatched kernel | Only detectable retrospectively when CVE is published or exploitation is observed via audit logs showing unexpected `keyctl` syscalls | Broaden grep patterns in monitoring script; add secondary watch on `linux-hardening@vger.kernel.org` mailing list archive; subscribe to kernel security advisories from distribution vendor directly |
| `keyctl setperm` wrong bitmask locks out owning process | Application fails to read its own key with `EACCES`; service stops functioning | Application logs show `keyctl_read: Permission denied`; `keyctl stat <key-id>` shows zero read bits for all categories | As root, use `keyctl setperm <key-id> 0x3f3f0000` to restore user+possessor read access; audit the permission-setting code path in the application to fix the bitmask calculation before next deployment |

## Related Articles

- [Linux IMA/EVM: Kernel-Level File Integrity Measurement and Appraisal](/articles/linux/linux-ima-evm/)
- [LUKS Full-Disk Encryption with TPM2 Sealing](/articles/linux/luks-tpm2-sealing/)
- [systemd Credentials and Encrypted Configuration Hardening](/articles/linux/systemd-credentials-hardening/)
- [Kernel Module Signing and Hardening](/articles/linux/kernel-module-hardening/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
