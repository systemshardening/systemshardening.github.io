---
title: "Disclosing Vulnerabilities in Open Source Networking Software: Nginx, HAProxy, and Envoy"
description: "Nginx, HAProxy, and Envoy underpin the internet's HTTP infrastructure — a critical vulnerability in any of them requires rapid coordinated response. This guide covers how to report vulnerabilities to each project's security team, what to expect during the disclosure process, how to track CVEs in networking software you depend on, and how to apply emergency patches when a critical disclosure drops."
slug: oss-network-software-disclosure
date: 2026-05-08
lastmod: 2026-05-08
category: network
tags:
  - open-source-security
  - nginx
  - haproxy
  - envoy
  - responsible-disclosure
personas:
  - security-engineer
  - network-engineer
article_number: 683
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/oss-network-software-disclosure/
---

# Disclosing Vulnerabilities in Open Source Networking Software: Nginx, HAProxy, and Envoy

Nginx, HAProxy, and Envoy sit at the boundary between the internet and every application behind them. A remote code execution vulnerability in your reverse proxy is not a single-service incident — it is a total compromise of your perimeter. Every upstream connection, every forwarded header, every TLS termination passes through these processes. When a critical CVE drops in any of them, the question is not whether you need to patch but how quickly you can do it without dropping production traffic.

This guide covers the disclosure landscape for all three projects: how to report a vulnerability you find, what happens during the embargo period, how to track advisories as a consumer, and how to execute an emergency patch with zero downtime when a critical issue becomes public.

## Why Networking Software Vulnerabilities Are Critical-Path

Most application vulnerabilities affect a single service. A SQL injection in a user-facing application touches that application's data. A vulnerability in Nginx, HAProxy, or Envoy touches everything behind them simultaneously.

The blast radius differs by vulnerability class:

**Remote code execution on the proxy host** gives an attacker control of the machine terminating TLS for all your services. They can read decrypted traffic in flight, forge upstream requests, pivot to internal networks, and exfiltrate certificate private keys. A single CVE can compromise your entire application portfolio in one exploitation event.

**Request smuggling vulnerabilities** are subtler but affect traffic integrity rather than just the proxy host. When a front-end proxy and a back-end server disagree about where one HTTP request ends and the next begins, an attacker can prefix crafted content onto another user's request. This has historically enabled authentication bypasses, cache poisoning, and SSRF in applications that trusted headers injected by the proxy. HAProxy has seen several notable request smuggling CVEs precisely because of the parsing complexity involved in handling both HTTP/1.1 keep-alive and HTTP/2.

**Memory corruption in C/C++ code** is a particular concern for Envoy, which is written in C++. Buffer overflows, use-after-free vulnerabilities, and integer overflows in header parsing or protocol state machines can be exploited remotely without authentication. Nginx is also C, though its more conservative codebase has produced fewer critical memory corruption issues than Envoy's larger, more complex feature set.

**DoS vulnerabilities** in these components can take down all services simultaneously, which in some operational contexts is as damaging as an RCE.

## The Disclosure Landscape

Each project handles security disclosures differently, and the differences matter when you are either reporting a vulnerability or waiting for a patch as a consumer.

Nginx is now maintained by F5 following its acquisition of NGINX, Inc. This means the commercial organisation has significant resources for security response but also that the process is partly corporate rather than purely community-driven. HAProxy is maintained as an independent open source project with a small dedicated security team. Envoy is a CNCF graduated project with a formal security process shaped by its use as the data plane for Istio, AWS App Mesh, and other enterprise service meshes.

Patch cadence varies considerably. Nginx follows a stable and mainline branch model, with security fixes backported to the stable branch. HAProxy maintains multiple LTS branches and patches them when vulnerabilities are discovered. Envoy follows a monthly release cycle with security-only releases issued out-of-band when required.

## Nginx Security Disclosures

### Reporting a Vulnerability

Send vulnerability reports to **security@nginx.org**. F5 maintains this address and manages the triage process. Your report should include the Nginx version (output of `nginx -v`), the build configuration if relevant (output of `nginx -V`), a description of the vulnerability class, reproduction steps, and your assessment of impact. You do not need to include a working exploit, but you should describe what a successful attacker could achieve.

Nginx uses a private disclosure process with an embargo period. The security team will acknowledge your report and work with you on an embargo date before publishing a public advisory. CVE assignment for Nginx vulnerabilities typically goes through MITRE or the F5 security team depending on the nature of the issue.

### Tracking Nginx Advisories as a Consumer

The canonical advisory list is published at **nginx.org/en/security_advisories.html**. This page lists every security advisory with CVE identifiers, affected versions, and severity. It does not have an RSS feed, which makes automated monitoring harder than it should be.

Common vulnerability patterns in Nginx to watch for:

- **HTTP/2 implementation**: Nginx's HTTP/2 stack has been a consistent source of DoS vulnerabilities. The HTTP/2 protocol's complexity around stream multiplexing and flow control creates attack surface for resource exhaustion.
- **SSL/TLS handling**: Vulnerabilities in how Nginx handles TLS session resumption, OCSP stapling, or certificate verification.
- **Rewrite module**: The rewrite engine processes regular expressions that can trigger vulnerabilities in edge cases.
- **Upstream module**: How Nginx proxies requests to upstream servers, including header injection possibilities.

Subscribe to the **oss-security@openwall.com** mailing list. When a Nginx CVE becomes public, it is almost always announced there. This is the fastest way to learn about new disclosures without actively polling the advisory page.

### Patching Nginx

For distributions using APT:

```bash
# Check current version
nginx -v

# Update Nginx to latest available in repository
sudo apt-get update && sudo apt-get install --only-upgrade nginx

# Verify the new version
nginx -v

# Test configuration before reload
sudo nginx -t

# Zero-downtime reload
sudo systemctl reload nginx
```

For RPM-based distributions:

```bash
sudo yum update nginx
# or
sudo dnf upgrade nginx
```

After updating, verify binary integrity if your distribution provides package signatures. For critical vulnerabilities, confirm the exact version string matches the patched release listed in the advisory before reloading production traffic.

## HAProxy Security Disclosures

### Reporting a Vulnerability

Report vulnerabilities to **security@haproxy.org**. The HAProxy security team prefers an initial report via email before any details are shared publicly. The team is small but responsive — expect acknowledgement within 48 hours for critical issues.

For severe vulnerabilities, the HAProxy project uses a private GitHub repository for coordinating the fix before public disclosure. You may be invited to participate in this process if your report requires extended coordination.

### Tracking HAProxy Advisories

HAProxy does not publish a single advisory page comparable to Nginx. Advisories are announced on the **haproxy-announce mailing list** and on the project's GitHub releases. Subscribe to:

- The haproxy-announce list at haproxy.org
- GitHub notifications for the haproxy/haproxy repository

HAProxy's CVE history includes several serious request smuggling vulnerabilities. HTTP request smuggling has been a recurring theme because HAProxy implements complex HTTP/1.1 parsing that must interoperate with both legacy backends and modern frontends. Key patterns to watch:

- **Header parsing logic**: Discrepancies in how HAProxy interprets Content-Length versus Transfer-Encoding headers.
- **HTTP/2 to HTTP/1.1 translation**: Protocol downgrade edge cases that can confuse backend servers about request boundaries.
- **Memory corruption in header processing**: Less common than in Envoy but has occurred in the past.

### HAProxy Patching: LTS vs Stable

HAProxy maintains several simultaneous branches. At any given time there is a current stable release and one or more LTS (Long-Term Support) branches that receive only security and critical bug fixes. Production deployments should run either the current stable branch or an LTS branch — never a branch that has reached end-of-life.

For binary package updates:

```bash
# Debian/Ubuntu — HAProxy package from distribution repos or haproxy.debian.net
sudo apt-get update && sudo apt-get install --only-upgrade haproxy

# Verify version
haproxy -v

# Validate configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Reload with zero downtime
sudo systemctl reload haproxy
```

For environments compiling from source — common in high-performance deployments needing specific compile-time options — you must follow the project's build documentation and rebuild against the patched release tarball. Verify the tarball's GPG signature before building:

```bash
gpg --verify haproxy-3.x.y.tar.gz.asc haproxy-3.x.y.tar.gz
```

## Envoy Security Disclosures

### Reporting a Vulnerability

Envoy follows the CNCF security process. Send reports to **envoy-security@googlegroups.com**. This is a private group monitored by the Envoy security team, which includes maintainers from Google, Lyft, and other major contributors.

Envoy is a CNCF graduated project and participates in the CNCF security audits program. The project has undergone multiple third-party security audits, and findings from those audits are published at cncf.io. This means Envoy's security posture is comparatively well-scrutinised for an open source proxy, but it also means the issue list is public and historically significant.

### Tracking Envoy Advisories

Envoy publishes security advisories directly on GitHub: **github.com/envoyproxy/envoy/security/advisories**. This is the most reliable source for Envoy CVEs and includes detailed technical descriptions, affected versions, and patched versions. You can enable GitHub notifications for security advisories on this repository.

Envoy's C++ codebase creates a different vulnerability profile than HAProxy or Nginx:

- **Memory corruption vulnerabilities** appear more frequently than in the other two projects. C++ memory management, combined with Envoy's use of complex data structures for connection tracking and filter chains, creates exposure to buffer overflows, use-after-free conditions, and heap corruption.
- **Protocol parsing edge cases** in Envoy's HTTP/1, HTTP/2, HTTP/3, and gRPC implementations.
- **Filter chain vulnerabilities**: Envoy's extensible filter architecture means vulnerabilities can exist in specific filters that only affect deployments using those filters.
- **Dependency vulnerabilities**: Envoy bundles BoringSSL and other third-party libraries. A vulnerability in a bundled dependency requires an Envoy release to get the fix to consumers.

### Emergency Envoy Patching

Envoy follows a roughly monthly release cadence with security-only releases issued out-of-band. In containerised environments, patching Envoy means updating the container image:

```bash
# Pull the patched release image
docker pull envoyproxy/envoy:v1.33.1

# Or use a specific digest for pinning
docker pull envoyproxy/envoy@sha256:<digest-of-patched-release>
```

For Kubernetes deployments, update the image in your deployment manifest and perform a rolling restart:

```yaml
# Update image in deployment
kubectl set image deployment/envoy envoy=envoyproxy/envoy:v1.33.1

# Monitor rollout
kubectl rollout status deployment/envoy

# Rollback if issues arise
kubectl rollout undo deployment/envoy
```

Pin to a specific image digest in your manifests rather than a tag. Tags are mutable; digests are not. This makes rollback deterministic — you have an exact, reproducible reference to the previous working image.

## Tracking CVEs Across All Three Projects

### OSV.dev and Grype

The Open Source Vulnerabilities database at **osv.dev** aggregates CVEs for open source software including Nginx, HAProxy, and Envoy. You can query it by package name to see all known vulnerabilities and which versions are affected.

Grype scans container images for vulnerabilities in installed packages, including web server binaries embedded in application images:

```bash
# Scan a container image for vulnerable Nginx/HAProxy/Envoy installations
grype your-app-image:latest

# Output matching known CVEs in Nginx specifically
grype nginx:1.26.0 --output table
```

This is critical for containerised deployments. An application image built on `nginx:1.24` as a base image does not automatically update when a new Nginx release patches a CVE. You must rebuild or rebase the image. Grype integrated into your CI pipeline catches this before deployment.

### GitHub Dependabot for Container Images

GitHub Dependabot supports container image vulnerability alerts when your repository references container images in Dockerfiles or Kubernetes manifests. Enable this in your repository settings. Dependabot will open pull requests updating base image references when a vulnerability is found in the image.

### Mailing Lists

Subscribe to **oss-security@openwall.com**. This is a public mailing list where security researchers announce vulnerabilities in open source software. Nginx, HAProxy, and Envoy disclosures frequently appear here when the embargo lifts. This gives you early notice without requiring you to monitor multiple project-specific channels.

## Emergency Patch Response Process

When a critical advisory drops, you need a documented decision tree to avoid making patching decisions under pressure:

**Critical (CVSS 9.0+, RCE or authentication bypass)**: Patch within hours. Begin rollout in staging immediately; do not wait for a maintenance window. Production patch within the same business day.

**High (CVSS 7.0-8.9, request smuggling or privilege escalation)**: Patch within 24 hours. Assess exploitability in your environment — request smuggling requires a specific topology of front-end proxy to back-end server. If your deployment matches the vulnerable configuration, treat as Critical.

**Medium (CVSS 4.0-6.9, DoS or information disclosure)**: Patch within 7 days as part of your normal change management process.

**Low**: Include in next scheduled maintenance window.

### Zero-Downtime Patching for Load Balancers

For Nginx deployed as a reverse proxy:

```bash
# 1. Confirm new version available
apt-cache policy nginx

# 2. Install update
sudo apt-get install --only-upgrade nginx

# 3. Test configuration
sudo nginx -t

# 4. Send reload signal (no dropped connections)
sudo nginx -s reload

# 5. Verify new worker processes running patched version
nginx -v
ps aux | grep nginx
```

The `nginx -s reload` approach sends a SIGQUIT to old worker processes after new workers start accepting connections. Existing connections complete normally. This is safe for production.

For HAProxy, `systemctl reload haproxy` sends a SIGUSR2 to gracefully restart worker processes. In multi-process mode, HAProxy performs a hitless reload where new processes take over listening sockets while existing processes drain their connections.

For Envoy in Kubernetes, use rolling updates with a pod disruption budget to prevent all Envoy pods from restarting simultaneously.

### Keeping the Previous Version Available

Before any emergency patch, verify you can roll back:

- For package manager deployments, hold the old package version in your local cache or repository mirror
- For container deployments, ensure the previous image digest is still accessible in your registry
- For source-compiled deployments, keep the previous binary in a known location

Do not overwrite the previous binary during the patch. Rename it or keep the package downgrade path available until the patch is confirmed stable in production.

### Validation After Patching

After applying a patch:

1. Confirm the version string matches the patched release in the advisory
2. Run basic connectivity tests from outside the network
3. Check access logs for unexpected error rates in the first 15 minutes
4. Monitor backend error rates — a misconfigured proxy can cause upstream connection failures
5. Verify SSL/TLS handshakes complete normally if the CVE touched TLS handling

## How to Report a Vulnerability if You Find One

If you discover a potential vulnerability during authorised testing on infrastructure you own or operate:

**What to include in your initial report:**
- Software name and exact version string (`nginx -v`, `haproxy -v`, `envoy --version`)
- Operating system and distribution
- Description of the vulnerability class (memory corruption, request smuggling, etc.)
- Step-by-step reproduction instructions on a clean installation
- Your assessment of what a successful attack would achieve
- Whether you believe the issue is already known or being exploited

You do not need to include a working exploit in the initial report. A clear reproduction case is sufficient to begin the coordinated disclosure process.

**Expected response timelines:**
- Nginx (F5): acknowledge within 5 business days, coordinated disclosure typically within 90 days
- HAProxy: acknowledge within 48-72 hours for critical issues, disclosure timeline negotiated per issue
- Envoy: acknowledge within 7 days, embargo period typically 90 days for complex issues

Do not disclose publicly during the embargo period. If you receive no response after twice the stated acknowledgement window, you may escalate using the CNCF security contact (for Envoy) or the oss-security mailing list with a 7-day notice.

## Reference Table

| Project | Reporting Channel | Typical Ack | Patch Cadence | Consumer Monitoring |
|---|---|---|---|---|
| Nginx | security@nginx.org | 5 business days | Stable branch backports | nginx.org/en/security_advisories.html, oss-security |
| HAProxy | security@haproxy.org | 48-72 hours | LTS + stable branch | haproxy-announce list, GitHub releases |
| Envoy | envoy-security@googlegroups.com | 7 days | Monthly + out-of-band | github.com/envoyproxy/envoy/security/advisories |

## Trade-offs

**Immediate public disclosure vs embargo period**: Researchers who discover vulnerabilities face pressure to disclose quickly to protect users, while vendors and projects want time to prepare patches. The 90-day embargo standard (established by Google Project Zero) balances these interests. For infrastructure software like proxies, a shorter embargo can leave users exposed if patch distribution is slow. Coordinated disclosure with the project team is almost always the right approach.

**Package manager updates vs manual builds**: Binary packages from distribution repositories lag behind upstream releases by days to weeks. For critical CVEs, you may need to install packages from upstream repositories (nginx.org packages, haproxy.debian.net) rather than waiting for distribution backports. However, distribution-packaged binaries benefit from distribution-specific hardening (PIE, RELRO, stack canaries) that you must configure manually in source builds.

**Version pinning vs automatic security updates**: Pinning versions gives you predictable, tested deployments. Automatic updates from package repositories or container registries get you security patches faster but can introduce regressions. The middle path: automatic updates in staging with a 24-hour bake period before automatic promotion to production, combined with rollback automation.

## Failure Modes

**Security announcement missed due to no subscription**: If you are not subscribed to oss-security or project-specific announcement channels, you may learn about a CVE days or weeks after disclosure — from a news article rather than the source. By that point, exploitation may already be widespread. Treat advisory subscriptions as infrastructure: assign ownership to a team member, include it in onboarding, and verify subscriptions are active quarterly.

**Patch applied without testing causing regression**: Emergency patches applied directly to production without staging validation can cause service outages. The correct procedure is always staging first, even if the staging bake period is only 30 minutes for a critical CVE. A configuration syntax error, changed behaviour in a patched module, or header handling change can break application functionality in ways that are not apparent from connectivity tests alone.

**Rollback not prepared before patching**: If you patch production and discover a regression, the recovery time is determined by how quickly you can roll back. If the previous package is not pinned, if the previous container image digest is not noted, or if you did not test the rollback procedure, recovery takes much longer than it should. Prepare rollback before you apply the patch, not after you discover the problem.

**Containerised Nginx version not updated because base image was not rebuilt**: Application teams frequently build on `nginx:stable` or `nginx:1.26` base images and do not rebuild when Nginx releases a security patch. The tag `nginx:stable` does not automatically pull the latest stable image into running containers. You must explicitly pull, rebuild your application image on top of the new base, and redeploy. Grype scanning in CI is the control that catches this: if your pipeline scans images for CVEs before deployment, a critical Nginx CVE in a base image will block deployment until the image is rebuilt.

**Missing filter-specific Envoy vulnerabilities**: Envoy's advisory page lists all CVEs, but some affect only specific filters. If your advisory monitoring process only checks the CVSS score and not the affected components, you may deprioritise a vulnerability that is actually Critical in your specific deployment configuration. Read the advisory technical details, not just the severity rating.

---

The three projects covered here represent the majority of open source HTTP proxy infrastructure running in production today. Each has a security process that works — but only if you participate in it, as a consumer subscribing to announcements and as a researcher reporting what you find. The infrastructure teams that patch within hours of a critical disclosure are the ones who have already solved the monitoring, decision tree, and deployment automation problems before the CVE drops.
