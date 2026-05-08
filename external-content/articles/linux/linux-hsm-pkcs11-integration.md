---
title: "Linux HSM and PKCS#11 Integration: Hardware-Protected Cryptographic Keys"
description: "HSMs and PKCS#11 tokens move private keys off disk and out of memory. This guide covers network HSMs, YubiHSM 2, TPM 2.0, OpenSSL engine and provider configuration, OpenSSH, TLS daemons, and the performance trade-offs engineers actually hit."
slug: linux-hsm-pkcs11-integration
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - hsm
  - pkcs11
  - key-management
  - tpm
  - hardware-security
personas:
  - security-engineer
  - platform-engineer
article_number: 489
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-hsm-pkcs11-integration/
---

# Linux HSM and PKCS#11 Integration: Hardware-Protected Cryptographic Keys

## The Problem

Every TLS certificate deployment, every signing key, every SSH host key has the same structural weakness: the private key material exists somewhere that software can read it. On disk, it is a file. In memory, it is a buffer. In either location, an attacker with sufficient access — root compromise, memory scrape, backup exfiltration, cloud snapshot — can copy it silently and completely. A copy of a private key is indistinguishable from the original. There is no revocation mechanism that acts faster than the attacker's first use.

The cryptographic community has had a hardware answer for three decades: Hardware Security Modules. An HSM is a tamper-resistant device that generates keys internally and refuses to export them in plaintext. All cryptographic operations (sign, decrypt, derive) happen inside the device. The host operating system submits data, the device returns a result. The private key never crosses the hardware boundary. A successful root compromise on the host gains access to the operations the key can perform but not to the key material itself — the attacker cannot exfiltrate the key and use it elsewhere.

The interface between HSM hardware and Linux software is PKCS#11 (also known as Cryptoki), a C API standardized by RSA Security and maintained by OASIS. PKCS#11 providers are shared libraries that wrap the hardware's native protocol. OpenSSL, OpenSSH, GnuTLS, NSS, and most PKI tooling speak PKCS#11, meaning a single hardware investment propagates across the entire cryptographic stack.

This article covers the hardware options available on Linux, the PKCS#11 interface and URI scheme, integration with OpenSSL 3.x (both legacy engine and modern provider), OpenSSH, Nginx/Apache TLS, TPM 2.0, YubiHSM 2, and the latency trade-offs that determine whether HSM integration is practical for your workload.

## HSM Types on Linux

### Network HSMs

Network HSMs are appliances that expose a PKCS#11 interface over a proprietary protocol to clients on the same network segment. The dominant products are **Thales Luna** (formerly SafeNet) and **AWS CloudHSM**. Both provide Linux client packages that install a PKCS#11 shared library; the library handles authentication to the appliance and translates PKCS#11 calls into the vendor protocol.

AWS CloudHSM is the common entry point for cloud deployments: the appliance is managed by AWS, the cluster is Multi-AZ, and the client library (`/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`) is installed on EC2 instances in the same VPC.

```bash
# Install AWS CloudHSM client on Amazon Linux 2 / RHEL 8
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL8/cloudhsm-pkcs11-latest.el8.x86_64.rpm
sudo rpm -ivh cloudhsm-pkcs11-latest.el8.x86_64.rpm

# Configure the cluster endpoint
sudo /opt/cloudhsm/bin/configure-pkcs11 --hsm-ca-cert /path/to/customerCA.crt \
    --cluster-id cluster-xxxxxxxxx

# Verify the PKCS#11 library sees the cluster
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --show-info
```

### USB HSMs: Nitrokey HSM and YubiHSM 2

USB HSMs connect directly to a host and are practical for servers where a network HSM is not justified, development environments, and per-host key isolation. Two products dominate Linux deployments:

**Nitrokey HSM** uses the OpenSC PKCS#11 stack, which is distro-packaged:

```bash
apt install opensc opensc-pkcs11
# List slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots
# Initialize the HSM
sc-hsm-tool --initialize --pin 648219 --so-pin 3537363231383830 --label "production"
```

**YubiHSM 2** uses a separate connector daemon and dedicated PKCS#11 library — covered in depth below.

### TPM 2.0 as a Built-in HSM

Every server shipped since approximately 2016 contains a TPM 2.0 on the motherboard. The TPM can generate and store RSA/EC private keys in persistent NV storage, bind keys to PCR measurements (so they are only usable when the firmware chain matches a known-good state), and perform all standard PKCS#11 operations. The `tpm2-pkcs11` project bridges TPM 2.0 to the PKCS#11 API — covered below.

The TPM is slower than a discrete HSM and does not have the tamper-evident physical properties of a purpose-built device, but it is present on every machine, free, and provides genuine hardware key isolation without an external dependency.

### Smart Cards

Smart cards (and their USB-encapsulated equivalents, PIV tokens such as YubiKey 5) store keys in JavaCard or native chip applets and expose them via `opensc-pkcs11`. They are appropriate for operator authentication (replacing software SSH keys) but not for high-throughput TLS termination because their RSA performance is measured in tens of operations per second.

## PKCS#11: The Bridging Standard

PKCS#11 defines a set of C function calls — `C_Initialize`, `C_OpenSession`, `C_Login`, `C_Sign`, `C_Decrypt` — that abstract over the hardware's native interface. A PKCS#11 provider is a `.so` file that implements these functions. OpenSSL, OpenSSH, and GnuTLS each have a mechanism to load and use this library.

Key providers on Linux:

| Provider library | Hardware |
|---|---|
| `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` | Smart cards, Nitrokey HSM, PIV tokens via OpenSC |
| `/usr/lib/x86_64-linux-gnu/libykcs11.so` | YubiKey (PIV applet), libykcs11 |
| `/usr/lib/libcloudhsm_pkcs11.so` | AWS CloudHSM |
| `/usr/lib/libCryptoki2_64.so` | Thales Luna |
| `libtpm2_pkcs11.so.1` | TPM 2.0 via tpm2-pkcs11 |
| `/usr/lib/x86_64-linux-gnu/libyubihsm_pkcs11.so` | YubiHSM 2 |

The `pkcs11-tool` utility (from the `opensc` package) provides a hardware-agnostic interface to any PKCS#11 provider for key generation, enumeration, and testing:

```bash
# Enumerate all tokens visible to a given module
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-tokens

# Generate a 4096-bit RSA key on the token
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --login --pin 1234 \
    --keypairgen --key-type RSA:4096 \
    --id 01 --label "tls-signing-key"

# Enumerate objects (keys, certificates)
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --login --pin 1234 --list-objects
```

### PKCS#11 URI Syntax

RFC 7512 defines a standard URI scheme for addressing objects inside PKCS#11 tokens. Most modern tooling (OpenSSL 3.x provider, GnuTLS, OpenSSH) accepts PKCS#11 URIs directly:

```
pkcs11:token=production;object=tls-signing-key;type=private
pkcs11:model=YubiHSM;manufacturer=Yubico%20AB;token=server01;id=%01;type=private
pkcs11:library-path=%2Fusr%2Flib%2Flibtpm2_pkcs11.so%2E1;token=my-tpm;object=webserver-key;type=private
```

URI components:

- `token` — label of the token slot
- `object` — label of the key object
- `id` — binary ID (percent-encoded)
- `type` — `private`, `public`, `cert`, `secret-key`
- `manufacturer`, `model` — narrow the slot if multiple modules are present
- `library-path` — override or specify the `.so` explicitly

## OpenSSL Integration

### OpenSSL 3.x: Provider Architecture

OpenSSL 3.0 replaced the legacy engine mechanism with a provider architecture. The correct integration path for new deployments is `pkcs11-provider`, a community-maintained provider that wraps any PKCS#11 library:

```bash
apt install pkcs11-provider   # Ubuntu 24.04+
# or build from source: https://github.com/latchset/pkcs11-provider
```

Configure `/etc/openssl.cnf` to load the provider:

```ini
# /etc/openssl.cnf
HOME = .
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
activate = 1
```

Verify that OpenSSL can reach the hardware key:

```bash
openssl pkey -provider pkcs11 \
    -in "pkcs11:token=production;object=tls-signing-key;type=private" \
    -pubout

# Sign a digest to confirm the hardware operation executes
echo "test" | openssl dgst -sha256 -provider pkcs11 \
    -sign "pkcs11:token=production;object=tls-signing-key;type=private" \
    -out /tmp/sig.bin
```

### OpenSSL Legacy Engine (libengine-pkcs11)

For tooling that targets OpenSSL 1.1.x or has not been updated for the provider interface:

```bash
apt install libengine-pkcs11-openssl
```

```ini
# /etc/openssl.cnf (engine section, OpenSSL 1.1.x or 3.x legacy engine path)
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
MODULE_PATH = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
init = 0
```

Use with OpenSSL CLI:

```bash
openssl s_client -engine pkcs11 \
    -keyform engine \
    -key "pkcs11:token=production;object=tls-signing-key;type=private" \
    -connect host:443
```

## OpenSSH with PKCS#11

### ssh-agent Loading a PKCS#11 Module

`ssh-agent` can load a PKCS#11 module and expose the hardware keys as standard SSH identities. Any process that uses the agent (via `SSH_AUTH_SOCK`) transparently benefits from the hardware protection:

```bash
eval "$(ssh-agent -s)"

# Load the PKCS#11 module — prompts for PIN
ssh-add -s /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
# Enter passphrase for PKCS#11: (enter token PIN)

# Confirm keys are loaded
ssh-add -L
# Output: ssh-rsa AAAAB3N... (YubiKey PIV Slot 9a) pkcs11:...
```

### ssh_config: Per-Host PKCS#11 Provider

For non-interactive use (scripts, CI runners), configure the PKCS#11 provider directly in `~/.ssh/config` or `/etc/ssh/ssh_config`:

```
Host bastion.example.com
    PKCS11Provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
    IdentityFile none
```

OpenSSH iterates all keys exposed by the provider and attempts authentication. No private key file is involved; the key material never leaves the hardware.

For YubiHSM 2 with the dedicated provider:

```
Host *.internal.example.com
    PKCS11Provider /usr/lib/x86_64-linux-gnu/libyubihsm_pkcs11.so
```

### SSH Host Keys in an HSM

Storing SSH host keys in an HSM (rather than `/etc/ssh/ssh_host_ed25519_key`) prevents host impersonation if a compromised attacker exfiltrates the host key. Generate the key on the HSM, export only the public portion, and configure `sshd` with an OpenSSL engine-backed key:

```bash
# Generate RSA key on token, export public cert
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --login --pin 1234 \
    --keypairgen --key-type RSA:4096 \
    --id 02 --label "ssh-host-key"

# sshd_config: point HostKey at a PKCS#11 URI (OpenSSH 9.x with pkcs11-provider)
# HostKey pkcs11:token=production;object=ssh-host-key;type=private
```

Note: direct PKCS#11 URI support in `sshd` for host keys requires OpenSSH 9.0+ with the appropriate compile-time flags. Verify with `sshd -V` and the distro's feature set.

## TLS Daemons: Nginx and Apache

### Nginx with OpenSSL PKCS#11 Provider

Nginx uses OpenSSL for TLS. If OpenSSL is configured with the `pkcs11-provider` (as above), Nginx can reference the private key via PKCS#11 URI in `ssl_certificate_key`:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /etc/nginx/certs/example.com.crt;
    ssl_certificate_key "engine:pkcs11:pkcs11:token=production;object=tls-signing-key;type=private";

    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
}
```

The `engine:pkcs11:` prefix tells Nginx to route the key reference through the OpenSSL engine. For the provider path (OpenSSL 3.x), Nginx 1.25+ supports:

```nginx
ssl_certificate_key "provider:pkcs11:pkcs11:token=production;object=tls-signing-key;type=private";
```

Restart Nginx. On startup, OpenSSL initializes the provider, authenticates to the token (requires the PIN to be available — configure via `pkcs11-module-token-pin` in `openssl.cnf` for unattended operation, or use a PIN file with restricted permissions):

```ini
[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
pkcs11-module-token-pin = file:/etc/ssl/hsm-pin
activate = 1
```

```bash
# PIN file must be mode 0400, owned by the nginx service user
echo -n "yourcomplexpin" > /etc/ssl/hsm-pin
chmod 0400 /etc/ssl/hsm-pin
chown nginx:nginx /etc/ssl/hsm-pin
```

### Apache httpd

Apache uses `mod_ssl`, which also goes through OpenSSL. The configuration is symmetric:

```apache
SSLEngine on
SSLCertificateFile /etc/apache2/certs/example.com.crt
SSLCertificateKeyFile "pkcs11:token=production;object=tls-signing-key;type=private"
```

Apache must be built against an OpenSSL with the PKCS#11 provider loaded, and the provider must be configured in `openssl.cnf` (as above).

## TPM 2.0 as a PKCS#11 Provider

### Setup: tpm2-pkcs11

`tpm2-pkcs11` wraps the TPM 2.0 via `tpm2-tss` and exposes it as a standard PKCS#11 library. Install on Debian/Ubuntu:

```bash
apt install tpm2-pkcs11 tpm2-pkcs11-1 tpm2-tools libtss2-dev
```

Initialize a token store and create a key:

```bash
# Create the PKCS#11 store directory
mkdir -p /var/lib/tpm2_pkcs11

# Initialize a new token
tpm2_ptool init --path /var/lib/tpm2_pkcs11
# Output: Created token label: ...

tpm2_ptool addtoken --pid=1 --sopin=adminpin --userpin=userpin \
    --label="server-tpm" --path=/var/lib/tpm2_pkcs11

# Generate an RSA-2048 key inside the TPM
tpm2_ptool addkey --label="server-tpm" --userpin=userpin \
    --key-label="webserver-key" --algorithm=rsa2048 \
    --path=/var/lib/tpm2_pkcs11

# Verify
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --token-label "server-tpm" --login --pin userpin --list-objects
```

Export the public key for certificate signing:

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 \
    --token-label "server-tpm" --login --pin userpin \
    --read-object --type pubkey --label "webserver-key" \
    -o /tmp/webserver.pub.der

openssl rsa -pubin -inform DER -in /tmp/webserver.pub.der -text -noout
```

### PCR Policy Binding

The TPM's most powerful feature is PCR (Platform Configuration Register) binding. PCRs hold SHA-256 hashes of each firmware component measured at boot. A key can be created with a policy that requires current PCR values to match expected values before the key is usable — the key is only operable on a machine in a known-good boot state:

```bash
# Measure current PCR values (PCRs 0-7 cover firmware, bootloader, kernel)
tpm2_pcrread sha256:0,1,2,3,4,5,6,7

# Create a policy requiring current PCR state
tpm2_startauthsession --session /tmp/pcr_session.ctx
tpm2_policypcr --session /tmp/pcr_session.ctx --pcr-list sha256:0,1,2,7 \
    --policy /tmp/pcr_policy.bin
tpm2_flushcontext /tmp/pcr_session.ctx

# Create a key bound to this policy
# (lower-level tpm2-tools; tpm2_ptool addkey --policy= support varies by version)
tpm2_create -C /tmp/parent.ctx -G rsa2048 -n rsa:null:null \
    -p pcr:sha256:0,1,2,7 -u /tmp/key.pub -r /tmp/key.priv

tpm2_load -C /tmp/parent.ctx -u /tmp/key.pub -r /tmp/key.priv -c /tmp/key.ctx
tpm2_evictcontrol -C o -c /tmp/key.ctx 0x81000001
```

A key bound to PCR values is unusable after a firmware update, kernel upgrade, or any change to the measured boot chain. This is intentional: re-sealing requires an explicit operator step, providing an audit trail for platform changes.

## YubiHSM 2

The YubiHSM 2 is a USB-attached device that provides HSM functionality for 10-100 USD. It is appropriate for small-to-medium deployments that cannot justify a rack-mount appliance. The YubiHSM 2 supports RSA, EC, HMAC, AES-CCM wrapping, and an immutable audit log.

### Connector Daemon

Unlike USB smart cards that speak CCID, the YubiHSM 2 uses a proprietary USB HID protocol exposed to applications via a local HTTP connector daemon:

```bash
apt install yubihsm2-sdk

# Start the connector daemon (listens on localhost:12345 by default)
sudo systemctl enable --now yubihsm-connector

# Verify connectivity
curl http://localhost:12345/connector/status
# status=OK
```

### Key Generation and Management

`yubihsm-shell` provides an interactive and scriptable interface:

```bash
yubihsm-shell --connector http://localhost:12345

# Inside the shell:
connect
session open 1 password
# Session 0 created

# Generate a 2048-bit RSA signing key in domain 1
generate asymmetric-key 0 0 signing-key 1 sign-pkcs,sign-pss rsa2048

# List objects
list objects 0
# ID Type  Domains Capabilities       Label
# 1  asymmetric-key 1 sign-pkcs,sign-pss signing-key

# Export the public key for certificate signing
get public-key 0 1 rsa > /tmp/signing-key.pem
```

The `capabilities` bitmask is critical: keys are created with explicitly restricted permissions. A key that can only `sign-pkcs,sign-pss` cannot decrypt, derive, or export — the hardware enforces least-privilege at the key level.

### Wrapping Keys (Key Export under Wrap)

YubiHSM 2 supports exporting keys encrypted under a wrapping key (AES-256-CCM), enabling backup and migration without ever exposing plaintext key material:

```bash
# Generate a wrap key
generate wrap-key 0 0 backup-wrap 1 export-wrapped,import-wrapped aes256-ccm-wrap

# Export signing-key wrapped under backup-wrap
get wrapped 0 2 asymmetric-key 1 > /tmp/signing-key.wrapped

# Import on a second device
put wrapped 0 2 /tmp/signing-key.wrapped
```

### PKCS#11 Configuration

Set the connector URL and optionally a PIN file, then reference the library:

```bash
# /etc/yubihsm_pkcs11.conf
connector = http://localhost:12345
debug

# Test
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libyubihsm_pkcs11.so \
    --login --login-type user --pin 0001password \
    --list-objects
```

The PKCS#11 URI for a YubiHSM 2 key follows the standard format:

```
pkcs11:manufacturer=Yubico%20AB;model=YubiHSM;token=YubiHSM;object=signing-key;type=private
```

## Performance Considerations

HSM latency is the most common reason teams abandon HSM integration for TLS. Understanding the numbers prevents over-engineering:

| Hardware | RSA-2048 sign (ops/sec) | EC P-256 sign (ops/sec) | Typical TLS handshake overhead |
|---|---|---|---|
| Software (CPU AES-NI) | 10,000–50,000 | 20,000–100,000 | Baseline |
| Thales Luna (PCI-E) | 5,000–20,000 | 10,000–40,000 | +1–5ms per handshake |
| YubiHSM 2 (USB) | 100–300 | 300–600 | +5–20ms per handshake |
| TPM 2.0 (SPI bus) | 15–50 | 30–80 | +20–100ms per handshake |
| YubiKey PIV (USB) | 5–20 | 15–40 | Not suitable for server TLS |

Key observations:

**EC P-256 is significantly faster than RSA-2048 across all hardware.** If the HSM is the bottleneck, switching from RSA-2048 to EC P-256 certificates yields a 2-4x throughput improvement with equivalent or better security.

**Network HSMs are not inherently slower than software for low concurrency.** A PCI-E card with hardware acceleration can sustain higher RSA throughput than a software implementation on a shared server, particularly under concurrent load.

**TPM 2.0 and USB HSMs are latency-bound for high-traffic TLS.** A server handling 1,000 TLS handshakes per second cannot use a TPM as the TLS private key store. Use TPM keys for lower-frequency operations: signing certificates, wrapping keys, authenticating to a secret store, or SSH host keys.

**Session resumption eliminates per-connection HSM calls.** TLS 1.3 session tickets and TLS 1.2 session IDs avoid the full handshake (and the HSM sign operation) on resumed connections. Under realistic production traffic patterns where many connections are resumed, the marginal HSM cost per connection is much lower than the cold-handshake figure.

**Async PKCS#11.** Some high-performance HSM vendors provide asynchronous PKCS#11 extensions (`C_SignUpdate`, vendor-specific batch APIs) that allow pipelining multiple sign requests. These are not part of the PKCS#11 standard but can double or triple throughput on PCI-E appliances.

For workloads that cannot absorb HSM latency (high-frequency TLS termination, bulk signing pipelines), a common architecture is:

1. The HSM holds the long-term CA private key and an intermediate signing key.
2. Short-lived session keys or leaf certificates (validity: hours) are generated in software.
3. The HSM signs only the short-lived certificates — a low-rate operation even at scale.

This hybrid model retains the key-extraction resistance for the operationally critical CA key without routing every TLS handshake through hardware.

## OpenSSL 3.x Provider Configuration Reference

OpenSSL 3.x changed how engines and providers are configured. The legacy `engines` section still works for backward compatibility, but the provider model is the forward path. A complete minimal `openssl.cnf` for PKCS#11 provider integration:

```ini
HOME = .
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
pkcs11-module-token-pin = file:/etc/ssl/hsm-pin
pkcs11-module-cache-pins = true
activate = 1

[algorithm_sect]
default_properties = ?provider=pkcs11
```

Useful `pkcs11-provider` configuration knobs:

- `pkcs11-module-cache-pins = true` — cache the PIN after first use; prevents repeated prompts during multi-key operations
- `pkcs11-module-allow-export = false` — never allow key export through the provider (default); set to `true` only for wrapping workflows
- `pkcs11-module-load-behavior = early` — load the module at process start, not on first use; eliminates latency on first TLS handshake

Verify the provider is loaded correctly:

```bash
openssl list -providers -verbose
# Providers:
#   default
#     ...
#   pkcs11
#     name: PKCS#11 Provider
#     version: 0.4.0
#     status: active
#     ...

# Enumerate keys visible to the provider
openssl storeutl -provider pkcs11 -noout -keys "pkcs11:"
```

## Threat Model

- **Adversary 1 — Root compromise on the application host:** attacker achieves root, attempts to extract TLS private key. With software keys: trivial, copy the file. With HSM: can only use the key for operations the process is authorized to perform; cannot exfiltrate.
- **Adversary 2 — Cloud snapshot / disk image exfiltration:** attacker copies a VM snapshot or disk image. With software keys: private key is on disk, immediately usable. With HSM: no key material on disk; the attacker has a connector configuration and a PIN file, but the HSM itself (physical device or network appliance) is not in the snapshot.
- **Adversary 3 — Memory scrape via ptrace or /proc/pid/mem:** software key in memory can be extracted. HSM: signing operations pass plaintext in and signature out; an attacker who can read the process memory during a TLS handshake sees the data being signed, not the key.
- **Adversary 4 — Physical theft of USB HSM:** a USB device can be physically removed. YubiHSM 2 and Nitrokey HSM require the operator PIN before any operation. Without the PIN, the device is a paperweight. After a configurable number of failed attempts, the device wipes itself.
- **Adversary 5 — PKCS#11 library injection (supply chain):** an attacker replaces the PKCS#11 `.so` with a malicious version that logs sign operations or key material. Defense: hash-verify and signature-check all provider libraries; run on immutable OS images (dm-verity); use `LD_PRELOAD` protection (`suid` bit, namespace isolation).

## Related Articles

- [FIDO2 SSH with sk-* Keys](/articles/linux/fido2-ssh/)
- [LUKS Full Disk Encryption with TPM2](/articles/linux/luks-tpm2-sealing/)
- [dm-verity: Immutable Root Filesystem Integrity](/articles/linux/dm-verity/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
