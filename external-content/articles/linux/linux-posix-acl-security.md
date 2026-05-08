---
title: "Linux POSIX ACLs: Fine-Grained File Permission Security"
description: "POSIX Access Control Lists extend Unix permissions with named user and group ACEs, ACL masks, and inheritable default ACLs. Essential for shared directories, service isolation, and least-privilege access without group sprawl."
slug: linux-posix-acl-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - acl
  - file-permissions
  - access-control
  - least-privilege
  - xattr
personas:
  - security-engineer
  - sysadmin
article_number: 481
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-posix-acl-security/
---

# Linux POSIX ACLs: Fine-Grained File Permission Security

## The Problem

Unix permission bits have served the same three-class model since the early 1970s: owner, group, and everyone else. For a single-user workstation or a small team all sharing one Unix group, the model is adequate. In a modern multi-team Linux environment, it breaks down quickly.

Consider a concrete scenario: a shared log directory at `/var/log/app` owned by `app:app` with mode `750`. Your developers need to read those logs during on-call. A monitoring service (`promtail`) needs to read them for ingestion. A security scanner (`wazuh-agent`) needs read access too. None of these should write.

Your options with standard permissions:
- Add each service account and each developer to the `app` group. Now every member of that group has read access to every other service's logs too. Group membership is all-or-nothing.
- Change the directory to mode `755` so everyone can read. Now world-readable logs are accessible to any process running on the host.
- Create dedicated subdirectories with different groups, fragmenting your log layout to work around a permission model instead of expressing your intent.

None of these are right. What you actually want is: "give `promtail` read access to this directory, `wazuh-agent` read access, and the `dev-oncall` group read access, without touching the owning group or making files world-readable." That is exactly what POSIX ACLs are for.

POSIX ACLs are available on every major Linux filesystem (ext4, XFS, Btrfs, tmpfs, overlayfs) and have been in the kernel since 2.6. They are implemented as extended attributes (`system.posix_acl_access` and `system.posix_acl_default`), which means they travel with the file on tools that preserve xattrs — and silently vanish on tools that don't, a detail that matters for backups.

## POSIX ACL Fundamentals

A POSIX ACL is an ordered list of Access Control Entries (ACEs). Every file and directory has an **access ACL**; directories can additionally carry a **default ACL** that is inherited by newly created children.

There are six ACE types:

| Tag | Description |
|-----|-------------|
| `user::` | Owning user (maps to traditional owner permission bits) |
| `user:name` | Named user — any UID on the system |
| `group::` | Owning group (maps to traditional group permission bits) |
| `group:name` | Named group — any GID on the system |
| `mask::` | Maximum effective permissions for named users and named groups |
| `other::` | All other users (maps to traditional other permission bits) |

The presence of any named user or named group ACE causes the kernel to compute a **mask** entry. The mask is not optional — once you add a named ACE, the mask controls the ceiling for all named users and the owning group. This surprises most people the first time they set a named ACE and watch an existing group permission stop working.

### Effective Permissions and the Mask

When the kernel evaluates access:

1. If the process UID matches the owning user, use `user::` — the mask does not apply here.
2. If the UID matches a named `user:name` ACE, use `user:name & mask::`.
3. If any GID of the process matches the owning group, use `group:: & mask::`.
4. If any GID matches a named `group:name` ACE, use `group:name & mask::`.
5. Fall through to `other::` — the mask does not apply.

The mask acts as a second gate on everything in the middle. If you grant `group:dev-oncall:r--` but set `mask::---`, the effective permission is `---` regardless of what the ACE says. This is why `getfacl` shows both the raw ACE and the effective permission when they differ:

```
group:dev-oncall:r--		#effective:---
```

## getfacl and setfacl

### Reading ACLs

```bash
# Single file
getfacl /var/log/app/application.log

# Recursive — scan an entire tree
getfacl -R /var/log/app/

# Save to backup file for later restore
getfacl -R /var/log/app/ > /root/acl-backup-app.txt
```

`getfacl` output for a file with named ACEs looks like:

```
# file: var/log/app/application.log
# owner: app
# group: app
user::rw-
user:promtail:r--
user:wazuh-agent:r--
group::---
group:dev-oncall:r--
mask::r--
other::---
```

The mask is automatically computed as the union of all named user, owning group, and named group permissions — in this case all three have `r--`, so the mask is `r--`. If you then granted `user:auditor:rwx`, the mask would expand to `rwx` (union), which would change the effective permissions of the owning group entry if it had previously been restricted.

### Setting ACLs

The `setfacl -m` flag modifies (adds or updates) individual entries without touching the rest:

```bash
# Grant promtail read access to the log directory and all files in it
setfacl -m u:promtail:r /var/log/app/application.log

# Grant dev-oncall group read access
setfacl -m g:dev-oncall:r /var/log/app/application.log

# Multiple entries in one call
setfacl -m u:promtail:r,g:dev-oncall:r /var/log/app/application.log

# Recursive — apply to a directory tree
setfacl -R -m u:promtail:rX /var/log/app/

# Remove a specific named ACE
setfacl -x u:promtail /var/log/app/application.log

# Remove all named ACEs (revert to standard permission bits)
setfacl -b /var/log/app/application.log

# Restore from a getfacl backup
setfacl --restore=/root/acl-backup-app.txt
```

The capital `X` in `-m u:promtail:rX` is a useful shorthand: it grants execute permission only on directories and on files that already have execute set for at least one class. This lets you apply recursive ACLs to a tree containing both regular files and directories without accidentally making all text files executable.

### Checking Effective Permissions

```bash
# Show what permissions a specific user actually has (accounts for all ACEs and mask)
getfacl --omit-header /var/log/app/ | grep "^user:promtail"

# Test access as another user directly
sudo -u promtail ls /var/log/app/
```

## Default ACLs: Inheriting Permissions on New Files

The single most operationally important feature of POSIX ACLs is the **default ACL** on a directory. Any file or subdirectory created inside that directory inherits a copy of the default ACL as its access ACL. Without default ACLs, you must `setfacl` every new file as it is created — which is impractical for log directories that rotate daily.

```bash
# Set a default ACL on the directory itself
setfacl -d -m u:promtail:r /var/log/app/
setfacl -d -m g:dev-oncall:r /var/log/app/

# View the result — default entries are prefixed with "default:"
getfacl /var/log/app/
```

Output:

```
# file: var/log/app
# owner: app
# group: app
user::rwx
group::---
other::---
default:user::rwx
default:user:promtail:r--
default:group::---
default:group:dev-oncall:r--
default:mask::r--
default:other::---
```

New files created under `/var/log/app/` inherit this as their access ACL, modified by the creating process's umask. This is the critical interaction: the default ACL provides a template, but the kernel applies `~umask` to the non-owning-user entries at creation time. If the creating process has `umask 077`, newly created files will have `other::---` regardless of the default ACL's `other` entry — but named user and named group ACEs from the default ACL are not filtered by umask in the same way on most implementations.

The practical guidance: for shared service directories, set `umask 027` or `umask 022` in the service unit's environment, and rely on default ACLs for named user/group grants. Do not trust that `umask 077` will strip ACL-granted access from named entries — test the behavior on your specific kernel version.

```bash
# Set both access and default ACL in one operation
setfacl -m u:promtail:rX,g:dev-oncall:rX /var/log/app/
setfacl -d -m u:promtail:rX,g:dev-oncall:rX /var/log/app/
```

## Security Hardening Use Cases

### Monitoring Service Read-Only Log Access

The motivating example from the introduction. The application writes logs as the `app` user. `promtail` ingests them. Neither should be in the other's group.

```bash
# Directory: read+execute so promtail can list and descend
setfacl -m u:promtail:rX /var/log/app/
setfacl -d -m u:promtail:rX /var/log/app/

# Verify promtail cannot write
sudo -u promtail touch /var/log/app/test 2>&1
# touch: cannot touch '/var/log/app/test': Permission denied
```

### Deploy User Write Access to Specific Directories

A CI/CD pipeline runs as `deploy`. It needs write access to `/srv/app/releases` and `/srv/app/shared/config` but nothing else under `/srv/app`. Adding `deploy` to the `app` group would grant broader access.

```bash
# Grant write+execute to the deploy user for specific subtrees only
setfacl -m u:deploy:rwX /srv/app/releases/
setfacl -d -m u:deploy:rwX /srv/app/releases/
setfacl -m u:deploy:rX /srv/app/shared/
setfacl -m u:deploy:rwX /srv/app/shared/config/
setfacl -d -m u:deploy:rwX /srv/app/shared/config/
```

The deploy user can create releases and update config, but `/srv/app/shared/run/` (holding PID files) or `/srv/app/shared/log/` remain untouched.

### Restricting Developer Access to Production Secrets

A `secrets` directory holds credentials. The application process needs read access. Developers should have no access even if they have shell access to the host, without requiring a separate secrets management daemon.

```bash
# Production secrets: only the app service account reads them
chmod 700 /etc/app/secrets/
setfacl -b /etc/app/secrets/          # Remove any existing ACLs
setfacl -m u:app:r /etc/app/secrets/application-credentials.env
# No named ACEs for humans — standard permission bits enforce the restriction
```

## Auditing ACLs

ACLs accumulate. A directory that has been administered by multiple people over time often carries stale entries — users who have left the organisation, service accounts for decommissioned services. Regular audit is required.

```bash
# Recursive scan: show all files with non-trivial ACLs
getfacl -R /srv/ 2>/dev/null | grep -E "^(# file|user:|group:)" | paste - - -

# Find all files/dirs where ACLs exist (the '+' in ls output indicates an ACL)
find /srv/ -exec ls -ld {} \; 2>/dev/null | grep ' \.'
# More targeted: find files with ACLs using getfacl exit code
find /srv/ -print0 | xargs -0 getfacl --skip-base 2>/dev/null | grep "^# file"

# Check for world-accessible ACL entries
getfacl -R /srv/ 2>/dev/null | grep "^other::r"

# Identify stale named users (UIDs that no longer exist)
getfacl -R /var/log/ 2>/dev/null | grep "^user:[0-9]"
# Numeric UIDs in getfacl output indicate the user account has been deleted
```

The `ls -l` output signals an ACL with a `+` appended to the mode string:

```
-rw-r--r--+ 1 app app 1.2M May  7 08:00 application.log
```

That `+` means "this file has an ACL in addition to the standard permission bits." Always inspect these files with `getfacl` before assuming you understand their access policy from `ls` alone.

## ACLs and Backup Tools

ACLs are stored as extended attributes. Whether they survive a copy operation depends entirely on whether the tool requests xattr preservation.

| Tool | ACL Preservation | Notes |
|------|-----------------|-------|
| `tar` | No by default | Use `tar --acls` to preserve |
| `rsync` | No by default | Use `rsync -A` or `--acls` |
| `cp` | No | Use `cp -p` — preserves mode but NOT ACLs |
| `scp` / `sftp` | No | Never preserves ACLs |
| `dd` | Yes (block-level) | Only when copying entire filesystem block-for-block |
| Btrfs send/receive | Yes | Subvolume snapshots preserve all xattrs |
| LVM snapshots | Yes | Block-level copy |

The consequence is subtle and dangerous: a "backup and restore" workflow using plain `tar` or `rsync` without the ACL flag will produce an identical-looking directory tree (same modes in `ls`) with all ACL grants silently stripped. The monitoring service that was reading your logs will silently fail to ingest anything after a restore.

```bash
# Correct archive creation preserving ACLs
tar --acls -czf /backup/srv-app-$(date +%Y%m%d).tar.gz /srv/app/

# Correct rsync with ACL preservation
rsync -aAX /srv/app/ backup-host:/backup/srv-app/

# Restore from tar preserving ACLs
tar --acls -xzf /backup/srv-app-20260507.tar.gz -C /

# Alternatively: save ACLs separately, restore separately
getfacl -R /srv/app/ > /backup/srv-app-acls-20260507.txt
rsync -a /srv/app/ backup-host:/backup/srv-app/
# On restore:
rsync -a backup-host:/backup/srv-app/ /srv/app/
setfacl --restore=/backup/srv-app-acls-20260507.txt
```

The separate save/restore approach is useful when your primary backup tool does not support xattr preservation — common with older enterprise backup agents.

## Integration with systemd Service Isolation

systemd's `RuntimeDirectory=`, `StateDirectory=`, `CacheDirectory=`, and `LogsDirectory=` directives create and manage directories for service units. Starting with systemd 243, you can attach ACLs to these directories directly in the unit file using `RuntimeDirectoryMode=` combined with `setfacl` in `ExecStartPre=`, or more elegantly through the `ACLs` key available in some systemd builds.

In practice, the most portable approach is a `ExecStartPre` that sets ACLs before the main process starts:

```ini
[Service]
User=app
Group=app
RuntimeDirectory=app
RuntimeDirectoryMode=0750
LogsDirectory=app
LogsDirectoryMode=0750

# Grant promtail read access to the runtime log socket directory
ExecStartPre=+/usr/bin/setfacl -m u:promtail:rX /run/app/
ExecStartPre=+/usr/bin/setfacl -d -m u:promtail:rX /run/app/

# Grant the monitoring group read access to log output
ExecStartPre=+/usr/bin/setfacl -R -m g:monitoring:rX /var/log/app/
ExecStartPre=+/usr/bin/setfacl -d -m g:monitoring:rX /var/log/app/
```

The `+` prefix on `ExecStartPre` runs that command with elevated privileges (root), necessary for `setfacl` calls on directories the `app` user does not own, while the main `ExecStart` process drops to the `app` user. This pattern keeps ACL setup co-located with the service definition rather than scattered across post-install scripts.

For ephemeral runtime directories (`/run/app`) that systemd creates fresh on each boot, setting default ACLs in the service unit is the only reliable mechanism — there is no persistent directory to pre-configure.

## Limitations and What ACLs Do Not Solve

**Filesystem support required.** ACLs require a filesystem mounted with ACL support. On ext4 and XFS, ACL support has been compiled in by default for many years. On older systems, `/etc/fstab` needed an explicit `acl` mount option. Confirm with:

```bash
tune2fs -l /dev/sda1 | grep "Default mount options"
# or
mount | grep "acl"
```

**ACLs are not MAC.** POSIX ACLs are Discretionary Access Control — the owner of a file can grant access to anyone. A compromised `app` process can call `setfacl` to grant a second compromised process access to its files. SELinux and AppArmor provide Mandatory Access Control where the kernel policy overrides discretionary grants. For true service isolation on sensitive systems, ACLs should complement MAC, not replace it.

**No audit trail in the ACL layer.** Setting or removing an ACL generates no automatic log entry. If you need an audit trail of ACL changes, configure `auditd` watches:

```bash
# Watch setxattr syscalls on sensitive directories (ACLs are stored as xattrs)
auditctl -w /etc/app/secrets/ -p wa -k acl-secrets
auditctl -w /var/log/app/ -p wa -k acl-logs
```

**NFS considerations.** NFSv4 has its own ACL model (Windows-compatible, richer than POSIX). When exporting a filesystem with POSIX ACLs over NFSv3, ACLs are exposed via a separate NFS ACL protocol (NFSACL) that clients may or may not implement. Always test ACL behavior on NFS mounts before relying on them for security policy.

**No ACL inheritance from parent at access time.** Default ACLs are a creation-time inheritance mechanism only. If you add a default ACL to a directory after files already exist inside it, those existing files do not retroactively acquire the ACL. You must run `setfacl -R` over the existing tree to bring it into compliance.

## Operational Checklist

Before deploying ACLs in production:

```bash
# 1. Verify ACL support on the target filesystem
mount | grep $(stat -c %m /var/log/app) | grep -q "acl" && echo "ACL enabled" || echo "Check mount options"

# 2. Set access ACL on directory
setfacl -m u:promtail:rX,g:dev-oncall:rX /var/log/app/

# 3. Set matching default ACL for new files
setfacl -d -m u:promtail:rX,g:dev-oncall:rX /var/log/app/

# 4. Verify the mask is correct (should cover granted permissions)
getfacl /var/log/app/

# 5. Confirm effective access for the target user
sudo -u promtail ls /var/log/app/

# 6. Save ACL state for recovery
getfacl -R /var/log/ > /root/acl-backup-$(date +%Y%m%d).txt

# 7. Update backup jobs to include --acls / -A flags
# 8. Add auditd watches on ACL-protected sensitive directories
```

## Summary

POSIX ACLs solve the specific problem that standard Unix permissions cannot: granting precise read or write access to additional named users and groups without changing ownership or making files world-accessible. The key mechanics to internalize are:

- The **mask** controls the ceiling for all named users, the owning group, and named groups — not the file owner, not `other`.
- **Default ACLs** on directories are the mechanism for ensuring new files inherit the correct grants; without them, ACL administration becomes a continuous manual burden.
- ACLs are stored as extended attributes and **silently drop** through tools that do not explicitly request xattr preservation — `tar --acls` and `rsync -A` are mandatory in backup pipelines.
- ACLs are DAC, not MAC. They are the right tool for delegation and least-privilege access patterns, not a substitute for SELinux or AppArmor.

The combination of default ACLs on service directories, ACL-aware backup commands, and periodic `getfacl -R` audits for stale entries gives you fine-grained access control that Unix permissions alone cannot express, without the group sprawl and ownership gymnastics that multi-team environments otherwise require.
