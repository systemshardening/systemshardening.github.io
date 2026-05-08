---
title: "OpenSSL CMS RCE: Patching CVE-2025-15467 and the AI-Discovered Vulnerability Class"
description: "CVE-2025-15467 is a CVSS 9.8 stack overflow in OpenSSL's CMS parser — the first RCE-class OpenSSL flaw since 2022, discovered entirely by AI. Patch OpenSSL 3.x across your estate, identify CMS-parsing applications, and understand what AI-driven vulnerability discovery means for your patch cadence."
slug: openssl-cms-rce-hardening
date: 2026-05-04
lastmod: 2026-05-04
category: cross-cutting
tags:
  - openssl
  - cve
  - rce
  - cms
  - patch-management
personas:
  - security-engineer
  - platform-engineer
article_number: 437
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/openssl-cms-rce-hardening/
---

## The Problem

CVE-2025-15467 is a stack buffer overflow in OpenSSL's CMS (Cryptographic Message Syntax) AuthEnvelopedData parser, rated CVSS 9.8. Processing a maliciously crafted CMS message — received as part of an S/MIME email, a PKCS#7-signed software update, or a CMS-encoded VPN authentication message — triggers the overflow and enables remote code execution under the privileges of the OpenSSL-linked process. Every version of OpenSSL in the 3.x line is affected: 3.0, 3.3, 3.4, 3.5, and 3.6. This is the first RCE-class vulnerability in OpenSSL since CVE-2022-3602 in October 2022. It was disclosed on January 27, 2026, and fixed in OpenSSL 3.0.17, 3.3.3, 3.4.1, 3.5.1, and 3.6.1.

The technical mechanism is a stack buffer overflow in the `AuthEnvelopedData` code path of the CMS parser. `AuthEnvelopedData` is a CMS content type that provides both confidentiality and authenticated encryption, specified in RFC 5083. When OpenSSL processes an inbound `AuthEnvelopedData` structure, it allocates a fixed-size buffer on the stack to hold intermediate decryption state. A crafted CMS message with a malformed or oversized `AuthEnvelopedData` field causes OpenSSL to write past the end of that stack buffer, overwriting return addresses and adjacent stack frames. This is a classical stack smashing attack against memory that the application itself allocated, with no heap allocator standing between the attacker-controlled write and code execution.

The operational scope is broad because CMS is not a niche format. S/MIME encrypted email is built on CMS. PKCS#7 software signing — used in firmware update pipelines, package management systems, and code signing infrastructure — uses CMS structures internally. Some VPN implementations use CMS-encoded messages for authentication and key exchange. Any OpenSSL-linked application that calls `CMS_decrypt`, `CMS_verify`, `d2i_CMS_bio`, or related CMS parsing functions on untrusted input is a candidate for exploitation.

What makes this disclosure categorically different from the typical OpenSSL CVE is how the vulnerability was found. AISLE Research's autonomous AI analysis system identified all 12 CVEs in the January 2026 OpenSSL release batch, including CVE-2025-15467. No human researchers found them first. OpenSSL is among the most intensively reviewed codebases in the history of open source software — thousands of researchers, security auditors, and cryptography specialists have examined it for decades. An autonomous AI system found a RCE-class flaw they all missed and found eleven more in the same release.

The operational implication is structural: if AI tooling can identify 12 vulnerabilities in a codebase with that level of human scrutiny, the implicit assumption embedded in many patch cadences — that code with extensive human review is unlikely to produce critical CVEs at high frequency — no longer holds. Critical infrastructure maintainers should anticipate a higher rate of AI-assisted CVE disclosure against well-reviewed code. A quarterly "emergency patch" model may be insufficient when AI analysis pipelines can produce coordinated multi-CVE releases against any widely deployed library. Patch cadences, SLAs, and vulnerability response processes need to be designed for a world where the gap between code publication and exploitation-quality CVE disclosure is shorter than human analysis can close.

The fixed versions are: OpenSSL 3.0.17, 3.3.3, 3.4.1, 3.5.1, and 3.6.1. OpenSSL 1.1.x is not affected. If your estate runs OpenSSL 1.x, CVE-2025-15467 does not apply — though 1.x has been end-of-life since September 2023, and there are other reasons to be running 3.x.

## Threat Model

**Network-reachable email gateways parsing S/MIME messages**: an email gateway or MTA that automatically parses and processes inbound S/MIME encrypted messages using OpenSSL's CMS API is reachable from the internet by design. An attacker crafts a malformed `AuthEnvelopedData` structure and sends it as an S/MIME email to any address the gateway accepts. The gateway calls `CMS_decrypt` or `d2i_CMS_bio` on the message, the stack overflow fires, and the attacker achieves RCE under the gateway process's operating system user — typically a system account with access to mail queues, TLS private keys, and potentially adjacent internal services. Postfix with S/MIME plugin configurations, Dovecot with S/MIME decryption enabled, and email security appliances that do inline CMS inspection are all in scope.

**PKCS#7-signed software update clients**: build pipelines, package verification tools, and embedded update clients that verify PKCS#7/CMS signatures on update packages before applying them parse CMS structures as part of the verification flow. An attacker who can insert a crafted update package into the distribution pipeline — via a compromised update server, a supply chain attack on an upstream repository, or a network interception position — can trigger the overflow in the update client, achieving RCE on the machine being updated. The process running the update client typically has elevated privileges to write system files, making this an immediate privilege escalation path as well as a code execution primitive.

**VPN servers processing CMS authentication messages**: some VPN implementations use CMS-encoded structures for client authentication. A malicious VPN client that sends a crafted `AuthEnvelopedData` structure during the authentication handshake can trigger the overflow on the VPN server, which is network-reachable by design and typically has significant access to the internal network it fronts. This attack requires no credentials — the crafted CMS message is processed before authentication succeeds.

**Transitive exposure via library dependencies**: a service that links against a library that in turn links against OpenSSL and calls CMS parsing functions is vulnerable even if the application developer never writes a line of OpenSSL code. A Go service using a C extension for document handling, a Python application with a C extension that parses S/MIME attachments, or any compiled binary that dynamically links libssl and exposes its CMS processing to external input is in scope. The transitive case is particularly difficult to inventory because the CMS parsing surface is not visible in the application's own code.

## Hardening Configuration

### Step 1: Inventory All Systems Running OpenSSL 3.x

Before patching, build a complete inventory. Patching without knowing what you have guarantees you will miss something.

Check the OpenSSL version on each host:

```bash
openssl version
```

On Debian and Ubuntu, check the installed package version:

```bash
dpkg -l libssl3
dpkg -l libssl-dev
```

On RHEL, AlmaLinux, Rocky Linux, and Fedora:

```bash
rpm -q openssl-libs
rpm -q openssl
```

For running containers, inspect the OpenSSL version inside each image without pulling them all locally. For images you have locally:

```bash
docker run --rm <image>:tag openssl version
```

For scanning a registry without pulling every image, use `trivy` against the registry directly, filtering on CVE-2025-15467:

```bash
trivy image --severity CRITICAL --vuln-type os <image>:tag 2>/dev/null | grep CVE-2025-15467
```

Build the inventory in a spreadsheet or configuration management database before proceeding to patching. Any host running OpenSSL 3.0.0 through 3.0.16, 3.3.0 through 3.3.2, 3.4.0, 3.5.0, or 3.6.0 is vulnerable. OpenSSL versions below 3.0.0 are not affected by CVE-2025-15467.

### Step 2: Patch to Fixed Versions

On Debian and Ubuntu:

```bash
apt-get update
apt-get upgrade libssl3 libssl-dev
```

On RHEL 9 and clones (AlmaLinux 9, Rocky Linux 9):

```bash
dnf update openssl-libs openssl
```

On RHEL 8 and clones:

```bash
dnf update openssl-libs openssl
```

Verify the installed version after upgrading:

```bash
openssl version
```

The output must show one of: `OpenSSL 3.0.17`, `OpenSSL 3.3.3`, `OpenSSL 3.4.1`, `OpenSSL 3.5.1`, or `OpenSSL 3.6.1`. A version string of `OpenSSL 3.4.0` or any lower 3.x patch level means the package upgrade did not succeed.

After upgrading the package, identify all processes that have loaded the old library version into memory and are still running with the pre-patch code:

```bash
lsof | grep libssl | grep -v "3.0.17\|3.3.3\|3.4.1\|3.5.1\|3.6.1"
```

Any process shown in that output needs to be restarted. The package upgrade on disk does not affect a process that has already loaded the old shared library — the old code remains mapped into the process's address space until the process exits or is restarted. Restart each identified service through its normal restart mechanism:

```bash
systemctl restart <service-name>
```

For services where a restart requires change management approval — databases, VPNs, load balancers — schedule the restart and document the window during which the host is patched on disk but still running the vulnerable code in memory. That window is an accepted risk requiring explicit approval, not an oversight.

### Step 3: Identify CMS-Parsing Applications

Patching the OpenSSL library is necessary but not sufficient for prioritisation. Not every OpenSSL consumer calls the CMS API — a web server doing TLS termination links against OpenSSL but may never call `CMS_decrypt`. CMS-parsing applications are the highest-urgency targets because they process the specifically vulnerable code path.

Search for binaries on the system that reference CMS parsing symbols:

```bash
grep -rl "CMS_decrypt\|CMS_verify\|d2i_CMS" /usr/lib/ /usr/bin/ /usr/local/bin/ 2>/dev/null
```

For compiled binaries where `grep` on the binary itself is needed:

```bash
find /usr/bin /usr/sbin /usr/local/bin -type f -executable | \
  xargs -I{} sh -c 'strings {} 2>/dev/null | grep -l "CMS_decrypt\|CMS_verify\|SMIME"'
```

Known categories of CMS-parsing applications to audit explicitly:

- **S/MIME email servers and clients**: Postfix with S/MIME plugins, Dovecot with S/MIME decryption, Thunderbird, Evolution, any email security appliance doing inline S/MIME inspection
- **Document signing and verification services**: tools calling `openssl smime`, document management systems with PDF or XML digital signature support backed by OpenSSL
- **VPN daemons using PKCS#7 authentication**: inspect VPN daemon configuration for CMS or PKCS#7 references in authentication settings
- **Code signing verification tools**: CI/CD pipeline steps that verify PKCS#7-signed artifacts before deploying them
- **Firmware and package update clients**: any update mechanism that calls `openssl verify` or uses the OpenSSL CMS API for package signature verification

For each identified application, confirm it is running the patched OpenSSL version:

```bash
ldd $(which <binary>) | grep libssl
```

The path shown must point to a library that is the patched version, not the vulnerable one.

### Step 4: Disable CMS Processing Where Not Required

For services that link OpenSSL but have no operational requirement to process CMS messages, confirm CMS processing is not reachable. For email gateways, configure perimeter filtering to strip or reject S/MIME messages from untrusted external senders before they reach the CMS parser:

```bash
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination"
```

For Postfix, if S/MIME decryption via a milter is not required, disable the milter:

```bash
postconf -e "smtpd_milters ="
postconf -e "non_smtpd_milters ="
```

This does not disable legitimate inbound encrypted mail for users — it removes the inline CMS parsing at the gateway layer. Users who need to read S/MIME email do so in their mail client, which can be patched independently and which processes only messages explicitly opened by the user.

### Step 5: Container Image Remediation

Rebuild all container images with the patched OpenSSL. A `docker pull` of an existing image does not update the packages inside it — rebuilding from a patched base image, or running the package upgrade inside the build, is required.

Update the base image reference to a version that carries the patched OpenSSL, then rebuild:

```bash
docker build --no-cache -t <image>:patched .
```

Scan rebuilt images to confirm CVE-2025-15467 is resolved:

```bash
trivy image --severity CRITICAL <image>:patched
```

```bash
grype <image>:patched | grep CVE-2025-15467
```

A clean scan output with no CVE-2025-15467 findings confirms the image carries the patched library. Prioritise internet-facing images first — any container reachable from the internet that processes CMS input is an immediate risk. Internal-only images are lower priority but must be queued for rebuild before the patching window closes.

For environments with a container image registry, scan all images currently in the registry, not only the images you recently built:

```bash
trivy registry --severity CRITICAL <registry-host>/<repository> 2>/dev/null | grep CVE-2025-15467
```

Images in a registry that are not actively running may be used by future deployments, rollbacks, or CI pipelines. Identify and rebuild or retire them.

## Expected Behaviour After Hardening

After patching, `openssl version` on every host returns a fixed version in the `3.0.17`, `3.3.3`, `3.4.1`, `3.5.1`, or `3.6.1` series. No process shown by `lsof | grep libssl` is mapped to a pre-patch library path. `grype` and `trivy` scans against container images return no CVE-2025-15467 findings. `ldd` output for CMS-parsing binaries references the patched library.

After completing the CMS identification step, the outcome is a confirmed list of every service in the estate that parses CMS messages, with documentation that each is running the patched OpenSSL version and has been restarted since the upgrade. Any service that cannot yet be restarted is documented with an accepted risk date and owner.

For services where CMS processing was disabled at the network perimeter, confirm the filtering rule is active and logging rejections by sending a test S/MIME message from an external address and verifying it is rejected or stripped before reaching the parser.

## Trade-offs and Operational Considerations

Patching OpenSSL requires service restarts, and service restarts require change management coordination. Web servers, databases, VPN concentrators, and load balancers that link against OpenSSL cannot be updated in place — they must restart to load the new library. This creates an interval during which the package is patched on disk but the running process is still vulnerable. Document that interval, assign an owner, and set a deadline. For high-availability services, a rolling restart that keeps the service available while cycling instances through the upgrade is the standard approach.

Disabling S/MIME processing at the email gateway affects legitimate encrypted email. The correct scope is inbound mail from untrusted external senders — mail that arrives via SMTP from the open internet and would otherwise be fed to the CMS parser automatically, without any user action. Inbound mail from trusted relay hosts, mail processed in response to an explicit user action in a patched mail client, and outbound S/MIME signing are all out of scope for this control. A blanket disable of S/MIME at the gateway breaks legitimate encrypted communication flows and should not be applied without confirming there are no users or processes that depend on it.

The AI-driven discovery dimension of this CVE carries a forward-looking operational implication. AISLE Research's January 2026 release produced 12 CVEs in a single coordinated disclosure against one of the most reviewed codebases in open source. This is not the last such batch. Autonomous analysis pipelines improve over time, can be parallelised across targets, and do not have the review-fatigue or scope constraints that human researchers face. Organisations that currently operate on a monthly patching cycle for non-critical updates and a two-week emergency cycle for critical CVEs should evaluate whether those SLAs remain appropriate for a threat environment where AI-driven disclosure can produce multiple CVSS 9.x CVEs against critical infrastructure libraries in a single release.

The practical recommendation is to treat OpenSSL patch releases as requiring the same urgency as a zero-day for as long as the disclosure environment remains as active as it was in January 2026. Subscribe to the OpenSSL security mailing list at `openssl-announce@openssl.org` and configure automated alerts from your vulnerability management platform for any CVE with a package match against `openssl` or `libssl3`. The window between disclosure and exploitation narrows as tooling matures.

## Failure Modes

Container images rebuilt on x86_64 CI but the `aarch64` image served to AWS Graviton instances still contains the old OpenSSL. Multi-architecture builds require that every architecture variant is rebuilt from the patched base — rebuilding the x86_64 manifest does not update the arm64 manifest in the same image tag. Verify each architecture explicitly:

```bash
docker manifest inspect <image>:patched | jq '.manifests[] | {arch: .platform.architecture, digest: .digest}'
```

Then scan each digest individually to confirm the patched OpenSSL is present in all architecture variants.

CMS identification scanning covers installed packages and dynamically linked binaries but misses statically linked OpenSSL in Go binaries and certain C applications compiled with `-static`. A Go binary that imports `crypto/tls` from the standard library does not use the system OpenSSL and is not affected. But a Go binary that uses `cgo` and statically links a vendored OpenSSL does not appear in `lsof libssl` output and is not updated by `apt-get upgrade libssl3`. Detect statically linked OpenSSL:

```bash
strings /usr/local/bin/<binary> | grep -i "openssl\|3\.0\.\|3\.3\.\|3\.4\." | head -10
```

The `strings` output from a statically linked OpenSSL binary will include the OpenSSL version string. If it shows a vulnerable version, the binary must be rebuilt against the patched OpenSSL source, not updated via a package manager.

Services patched but old library still loaded in memory remain vulnerable after the package upgrade. The `lsof | grep libssl` check is the canonical way to find these processes, but it requires root access on each host and does not work well across large fleets. A better approach at fleet scale is to query your process monitoring system — `prometheus node_exporter` with the `process` collector, or a CMDB agent — for processes that have been running continuously since before the patch window started. Any such process that links OpenSSL has not yet loaded the patched version. Require a restart as a condition of closing the patch ticket.

## Related Articles

- [rust-openssl Buffer Overflow](/articles/cross-cutting/rust-openssl-buffer-overflow/)
- [Go x509 PKI Security](/articles/cross-cutting/go-x509-pki-security/)
- [Post-Quantum Migration](/articles/cross-cutting/post-quantum-migration/)
- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [SBOM Supply Chain Compromise Detection](/articles/observability/sbom-supply-chain-compromise-detection/)
