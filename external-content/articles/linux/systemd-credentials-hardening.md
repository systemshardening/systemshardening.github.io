---
title: "systemd Encrypted Service Credentials"
description: "Replace cleartext environment variable secrets with systemd-credentials: TPM2-sealed or password-encrypted service credentials for systemd units on Linux."
slug: systemd-credentials-hardening
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["systemd", "credentials", "tpm2", "secrets", "service-hardening", "encryption"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 327
difficulty: intermediate
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/systemd-credentials-hardening/index.html"
---

# systemd Encrypted Service Credentials

## Problem

The most common way to pass a secret into a systemd service is also one of the most dangerous patterns in Linux operations: placing the secret directly into the unit file or an environment file that the unit references. A unit file containing `Environment=DB_PASSWORD=hunter2` writes that password verbatim into the systemd unit definition, which is stored under `/etc/systemd/system/`, often committed to a configuration management repository, and visible to any process running as the same user via `/proc/<PID>/environ`. The alternative — `EnvironmentFile=/etc/app.env` — trades in-line exposure for a file that is almost always created world-readable by accident, either during automated provisioning or because the permissions were never explicitly set.

Even when file permissions are correct, the secret is still exposed through the process environment. Any child process spawned by the service inherits the full environment of its parent. Some logging frameworks, error reporting agents, and tracing libraries enumerate the environment of the process they instrument and ship those key-value pairs to external collectors. The `ps aux` command on Linux does not expose environment variables by default, but `/proc/<PID>/environ` is readable by any process running under the same UID — including code executing in the service itself, any sidecar process, or a compromised dependency loaded in-process.

The Git problem compounds everything. Twelve-factor application conventions encourage storing configuration in the environment, and infrastructure-as-code pipelines need to record unit files somewhere. The inevitable result is that environment files — or unit files with inline `Environment=` directives — end up committed to version control. Secret scanning tools catch some of these commits, but they are reactive. A credential that reaches a Git history is effectively compromised even if immediately revoked, because the history remains accessible to everyone with repository access and to any attacker who clones the repository in the window before the secret is rotated.

systemd-credentials, introduced in preview form with systemd v250 and reaching stable, production-ready status in v254 (shipped in late 2023), solves this problem at the init system layer. Rather than relying on file permissions or environment isolation, it encrypts secret blobs at rest using one of three sealing mechanisms: TPM2 (hardware-bound — the ciphertext can only be decrypted on the specific machine that sealed it), password or host key (portable — useful for VMs and containers where no TPM2 is present), or a public/private key pair (asymmetric — lets a central secrets management system encrypt credentials that only the target host can decrypt). The encrypted blobs are stored in `/etc/credstore.encrypted/`. At service start, systemd decrypts each blob in-kernel, writes the plaintext into a per-service read-only tmpfs mount, and exposes the path to that mount as `$CREDENTIALS_DIRECTORY`. The plaintext secret is never written to persistent storage, never appears in `/proc/<PID>/environ`, and is destroyed when the service stops.

The contrast with environment variables is stark. With env vars, the secret is visible in the unit file on disk, in the process environment, and in any child process. With systemd-credentials, the ciphertext blob on disk reveals nothing without the TPM2 chip or the host key, and the plaintext only exists for the lifetime of the service in a non-swappable tmpfs mount accessible only to the service.

**Target systems:** systemd ≥ 254 (RHEL 10, Ubuntu 24.04, Fedora 39+, Debian 13). TPM2 chip required for hardware sealing. Software sealing (host key or password) works without a TPM2.

## Threat Model

The following adversaries represent the practical threat space that systemd-credentials is designed to reduce:

1. **Developer accidentally commits EnvironmentFile.** An engineer adds `/etc/myapp.env` to the Ansible role that configures the service, and that file is templated from a Vault lookup. The rendered file is never committed — but the unrendered template is, and the developer later tests locally with a staging credential inline in the template. One `git add -A` later, the credential is in the repository. With systemd-credentials, there is no plaintext environment file to commit. The credential blob in `/etc/credstore.encrypted/` is ciphertext; committing it is harmless because it cannot be decrypted without the sealing TPM2 or host key.

2. **Local attacker reads `/proc/<PID>/environ` of a running service.** A compromised process running as the same UID as the target service (common in shared application servers or in services that load third-party plugins) can open `/proc/<target-pid>/environ` and read every environment variable of the target process. This requires no elevated privilege. With systemd-credentials, the secret is not in the environment — it is in a file in `$CREDENTIALS_DIRECTORY`, which is a tmpfs path accessible only to the service's UID and protected by a `PrivateTmp=yes`-like mount namespace. A process sharing the UID but not the mount namespace cannot reach it.

3. **Off-site backup of `/etc` includes plaintext secrets.** Many backup strategies archive `/etc` in its entirety. If secrets live in `/etc/app.env` or inline in unit files, every backup copy is a copy of the plaintext credentials. With systemd-credentials, the backup contains `/etc/credstore.encrypted/` blobs. On TPM2-sealed hosts, those blobs are useless off-machine. On host-key-sealed systems, the host key also needs to be in the backup for the blobs to be decryptable — and the host key can be stored separately with tighter access controls than the application servers themselves.

4. **Insider with read access to unit files extracts credentials.** A contractor or operations engineer with SSH access to a host can read files under `/etc/systemd/system/` and `/etc/`. With environment files, that access is sufficient to retrieve any application secret. With systemd-credentials, the insider sees only the ciphertext blob and the unit file directive that references it. Decrypting the blob requires access to the TPM2 chip (physical or virtualized) or the host key — neither of which the insider can exfiltrate via SSH alone.

Without systemd-credentials, the blast radius of any of these incidents is immediate and total: every service secret on the host is exposed in plaintext. With systemd-credentials using TPM2 sealing, the blast radius is bounded to the currently running service instances — an attacker would need to compromise a running process with access to `$CREDENTIALS_DIRECTORY`, or gain physical access to the TPM2 chip itself.

## Configuration / Implementation

### Creating a credential

The `systemd-creds` utility handles encryption and decryption. To create a TPM2-sealed credential reading from stdin:

```sh
# Seal to the TPM2 chip present on this machine
printf 'my-secret-password' | systemd-creds encrypt \
    --name=db-password \
    --tpm2-device=auto \
    - \
    /etc/credstore.encrypted/db-password
```

The `--name=` flag binds the credential to the service name — systemd verifies that the credential name in the ciphertext matches the name declared in the unit file, preventing a blob intended for one service from being copied to another. The `--tpm2-device=auto` flag selects the first available TPM2 device. The final two arguments are input (`-` for stdin) and output path.

Verify the credential was created correctly:

```sh
systemd-creds list
# NAME         SECURE   SIZE   FILENAME
# db-password  tpm2     128    /etc/credstore.encrypted/db-password
```

To decrypt and inspect a sealed credential (requires TPM2 access):

```sh
systemd-creds decrypt \
    --name=db-password \
    /etc/credstore.encrypted/db-password \
    -
```

Set correct ownership and permissions on the credstore directory:

```sh
chmod 0700 /etc/credstore.encrypted
chmod 0600 /etc/credstore.encrypted/db-password
# Root owns the files; systemd reads them during service startup as root
chown root:root /etc/credstore.encrypted/db-password
```

### Non-TPM portable credentials

On virtual machines without a TPM2 device, or when credentials need to be provisioned on one machine and deployed to another, use the host key or password sealing modes.

First, set up a host key if one does not exist:

```sh
systemd-creds setup
# Creates /var/lib/systemd/credential.secret (if not present)
```

Encrypt with the host key only (no TPM2 required):

```sh
printf 'my-secret-password' | systemd-creds encrypt \
    --name=db-password \
    --with-key=host \
    - \
    /etc/credstore.encrypted/db-password
```

For credentials that must be transferred across machines — for example, provisioned centrally by a secrets manager — use public key sealing. Generate a host key pair on the target machine:

```sh
systemd-creds generate-key
```

Then on the provisioning machine, encrypt using the public key:

```sh
printf 'my-secret-password' | systemd-creds encrypt \
    --name=db-password \
    --with-key=/path/to/host-public-key.pem \
    - \
    /etc/credstore.encrypted/db-password
```

Only the target host, which holds the private key, can decrypt. This pattern integrates cleanly with CI/CD pipelines: the pipeline encrypts credentials using the public key of each target host before deploying the ciphertext blob.

Combined TPM2-plus-password sealing provides defence in depth — both the TPM2 chip and the password are required to decrypt:

```sh
printf 'my-secret-password' | systemd-creds encrypt \
    --name=db-password \
    --with-key=tpm2+password \
    - \
    /etc/credstore.encrypted/db-password
# systemd-creds will prompt for the password interactively
```

### Unit file integration

Once the credential blob exists in `/etc/credstore.encrypted/`, reference it from the service unit using `LoadCredentialEncrypted=`:

```ini
[Unit]
Description=My Application Service

[Service]
User=myapp
Group=myapp

# Load encrypted credential; systemd decrypts at service start
LoadCredentialEncrypted=db-password:/etc/credstore.encrypted/db-password

# Standard hardening — credentials are in a private mount namespace anyway
PrivateTmp=yes
ProtectSystem=strict
NoNewPrivileges=yes

ExecStart=/usr/bin/myapp
```

The directive syntax is `LoadCredentialEncrypted=<name>:<path>`. The `<name>` is what the service reads; it becomes a filename under `$CREDENTIALS_DIRECTORY`. systemd validates that `<name>` matches the `--name=` used when the blob was sealed.

After `systemctl daemon-reload`, the service can read the credential from the filesystem:

**Shell:**

```sh
#!/bin/sh
DB_PASSWORD=$(cat "${CREDENTIALS_DIRECTORY}/db-password")
exec myapp --db-password="${DB_PASSWORD}"
```

**Python:**

```python
import os
import pathlib

creds_dir = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
db_password = (creds_dir / "db-password").read_text()
```

**Go:**

```go
import (
    "os"
    "path/filepath"
)

credsDir := os.Getenv("CREDENTIALS_DIRECTORY")
data, err := os.ReadFile(filepath.Join(credsDir, "db-password"))
if err != nil {
    log.Fatalf("failed to read credential: %v", err)
}
dbPassword := string(data)
```

In all three cases the secret is read from a file, never from the environment. The file is in a tmpfs mount visible only within the service's mount namespace.

### Unencrypted credentials for test and CI environments

For development environments and CI pipelines where no TPM2 is available and maintaining encrypted blobs is impractical, `SetCredential=` passes a plaintext credential directly in the unit file (or a drop-in override):

```ini
[Service]
# For test/CI only — never use SetCredential= with real secrets in production
SetCredential=db-password:testpassword123
```

This is useful for unit tests and integration tests that run the real service binary but with synthetic credentials. Production unit files should use `LoadCredentialEncrypted=` exclusively. The `SetCredential=` directive appears in `systemctl cat` output and should never be used where the unit file itself is a secret boundary.

### Credential inheritance with systemd-nspawn containers

For systemd-nspawn containers that should inherit credentials from the host, use `ImportCredential=` in the container's unit file:

```ini
[Service]
# Host must have db-password in its own CREDENTIALS_DIRECTORY
ImportCredential=db-password
```

This passes the already-decrypted credential from the host's credential store into the container. The container sees it under its own `$CREDENTIALS_DIRECTORY` without needing its own copy of the encrypted blob.

### Permissions and filesystem layout

Two directories matter:

- `/etc/credstore/` — for plaintext credentials that should be protected by file permissions alone (uncommon; prefer encrypted). Contents are loaded with `LoadCredential=`.
- `/etc/credstore.encrypted/` — for encrypted blobs. Contents are loaded with `LoadCredentialEncrypted=`. Each file should be mode `0600`, owned by root.

```sh
# Create directories with correct permissions
install -d -m 0700 -o root -g root /etc/credstore
install -d -m 0700 -o root -g root /etc/credstore.encrypted
```

At runtime, systemd mounts the per-service credentials directory at a path like `/run/credentials/myapp.service/`. The environment variable `$CREDENTIALS_DIRECTORY` points to this path. The mount is read-only and is not world-accessible.

### Rotating credentials

Credential rotation requires re-encrypting the new secret and restarting the service. There is no hot-reload mechanism — the credentials are decrypted once at service start and written into the tmpfs mount.

```sh
# Step 1: Encrypt the new credential value
printf 'new-secret-password' | systemd-creds encrypt \
    --name=db-password \
    --tpm2-device=auto \
    - \
    /etc/credstore.encrypted/db-password

# Step 2: Reload unit definitions and restart the service
systemctl daemon-reload
systemctl restart myapp.service

# Step 3: Verify the service started cleanly with the new credential
systemctl status myapp.service
journalctl -u myapp.service --since "1 minute ago"
```

Because the rotation requires a service restart, it triggers a brief outage for services without multiple instances. Coordinate rotation with a load balancer or a rolling restart if uptime is critical.

### Verifying the setup

After configuring `LoadCredentialEncrypted=`, verify that:

1. The credential appears in the credential list:

```sh
systemd-creds list
```

2. The service exposes `$CREDENTIALS_DIRECTORY` and the credential file is present:

```sh
# Inspect the running service's environment and credentials
systemctl show myapp.service -p Environment
# Should NOT show db-password in the output

# Check that the credential file exists in the running service's namespace
nsenter --mount --target $(systemctl show -p MainPID --value myapp.service) \
    ls "${CREDENTIALS_DIRECTORY}"
```

3. Confirm no plaintext fallback remains in the unit file:

```sh
systemctl cat myapp.service | grep -i password
# Should return no results
```

## Expected Behaviour

| Signal | Before (env var) | After (systemd-credentials) |
|---|---|---|
| `ps aux` output | Password not shown (kernel hides `/proc/<PID>/cmdline` args) | No change — env vars not shown in cmdline |
| `/proc/<PID>/environ` | `DB_PASSWORD=hunter2` readable by same-UID processes | Not present — secret is a file in a private mount namespace |
| `git log --all -S password` | Finds the credential in EnvironmentFile commits | No match — ciphertext blob is binary, not text |
| Offsite backup of `/etc` | Plaintext secret in backup | Encrypted blob; useless without TPM2 or host key |
| Service restart after rotation | Old value persists until env is refreshed | New plaintext loaded from new blob on each restart |
| `systemctl cat myapp.service` | `EnvironmentFile=/etc/app.env` (or inline secret) visible | `LoadCredentialEncrypted=db-password:/etc/credstore.encrypted/db-password` only |
| Child process environment | Inherits `DB_PASSWORD` automatically | `$CREDENTIALS_DIRECTORY` path inherited; file access still requires mount namespace membership |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| TPM2 binding | Ciphertext is hardware-bound; exfiltrating the file achieves nothing | Credential cannot be decrypted off the original machine | Use `--with-key=host` or public key sealing for portable credentials; keep TPM2-sealed credentials for production hosts only |
| Application code changes | Code reads from a file path — explicit, auditable | Every service must be updated to read from `$CREDENTIALS_DIRECTORY` instead of env vars | Wrapper scripts can bridge old code: read credential from file, export to env within the wrapper process only |
| No dynamic rotation without restart | Forces an explicit, auditable rotation event | Brief service downtime during rotation | Design services with graceful shutdown; pair with load balancer rolling restarts |
| VM migration breaks TPM2-sealed credentials | Provides a hard boundary around machine identity | VM snapshots and live migrations leave credentials undecryptable on the new host | Use host-key or public-key sealing for VMs; reserve TPM2 sealing for bare-metal hosts |
| systemd version requirement | Stable feature in widely available distros (Ubuntu 24.04, RHEL 10) | Not available on RHEL 8/9, Ubuntu 22.04, or older Debian without backporting | Maintain env-var path for older hosts; migrate as OS versions are updated |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| TPM2 PCR mismatch after firmware or kernel update | Service fails to start with `Failed to decrypt credential: No such file or directory` or similar TPM error in journal | `journalctl -u myapp.service` shows TPM2 decryption error; `systemd-creds decrypt` fails interactively | Re-seal the credential with the new PCR values: re-run `systemd-creds encrypt --tpm2-device=auto` after confirming the system is in a trusted state |
| Wrong credential name in `LoadCredentialEncrypted=` | Service starts but `$CREDENTIALS_DIRECTORY/db-password` does not exist; application errors on missing file | Application logs show file-not-found for the credential path; `systemctl status` shows the service running but the app exiting | Correct the name in the unit file to match the `--name=` used during encryption; `daemon-reload` and restart |
| `$CREDENTIALS_DIRECTORY` not set (systemd < 254 or missing directive) | `cat "${CREDENTIALS_DIRECTORY}/db-password"` expands to `cat /db-password`; file not found | Application error at startup; env inspection shows empty `CREDENTIALS_DIRECTORY` | Verify systemd version (`systemctl --version`); ensure `LoadCredentialEncrypted=` is present in the unit file; upgrade systemd if below v254 |
| Credential file wrong permissions (not readable by root at service start) | Service fails to start; journal shows `Failed to load credential` | `ls -la /etc/credstore.encrypted/` shows incorrect owner or mode | `chown root:root` and `chmod 0600` on the credential file; restart |
| Credential file missing from credstore after deployment | Service fails at start with credential load error | `systemd-creds list` does not show expected credential | Re-run provisioning step to create the credential blob; check deployment automation for the step that copies or creates the file |

## Related Articles

- [systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
- [LUKS with TPM2 Sealing](/articles/linux/luks-tpm2-sealing/)
- [UKI and Secure Boot Hardening](/articles/linux/uki-secure-boot-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
