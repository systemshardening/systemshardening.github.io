---
title: "Container Security Across the SDLC: From Dockerfile to Production"
description: "Container security requires controls at every SDLC stage — secure base images, Dockerfile linting, vulnerability scanning in CI, image signing, admission control, and runtime monitoring in production. This guide maps security controls to SDLC phases and provides an integrated view of container security for teams building and operating containerised applications."
slug: container-security-sdlc
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - container-security
  - sdlc
  - shift-left
  - devsecops
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 616
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/container-security-sdlc/
---

# Container Security Across the SDLC: From Dockerfile to Production

## Problem

Most container security programmes are reactive. A production vulnerability scan finds a critical CVE in a base image that has been running for eleven months. The fix requires rebuilding every image in the fleet, retesting, and redeploying — work that interrupts two teams for a week. The CVE was fixable eleven months ago in one line of a Dockerfile.

The underlying problem is not the scanner. It is that the scanner is the only control, placed at the wrong end of the lifecycle. Container security done correctly is a set of controls distributed across every phase of the software development lifecycle — with the heaviest investment at the phases where cost of remediation is lowest.

This guide maps each control to its SDLC phase, explains the threat it mitigates, and provides configuration that can be adopted incrementally.

**Target systems:** Teams building containerised applications deployed to Kubernetes or equivalent container orchestration platforms. Controls are tool-specific where a dominant tool exists; the patterns apply to equivalent alternatives.

## Threat Model

The threats container security controls must address:

- **Supply chain compromise.** A base image or package pulled from a public registry contains malware or a backdoored dependency. The application ships the compromise into production.
- **Vulnerable dependencies.** Known CVEs in the OS layer, language runtime, or application packages are exploited by an attacker with network access.
- **Container escape.** A container process exploits a kernel vulnerability or misconfigured privilege to break out to the host, gaining access to other containers or the underlying node.
- **Privilege escalation within the container.** An unprivileged process elevates to root inside the container, expanding the blast radius of a compromise.
- **Image tampering.** An image is modified between build and deploy — either through a registry compromise or a supply chain attack on the CI pipeline — and the change is not detected.
- **Runtime process injection.** An attacker with initial access spawns unexpected processes, opens network connections, or reads sensitive files — activity that is detectable but only if runtime monitoring is in place.
- **Accumulated CVE debt.** Base images age without updates. A base image that was clean at build time accumulates critical CVEs over months. Without automated update workflows, the debt grows silently.

---

## Phase 1: Development

The development phase is where the security debt of the entire fleet is set. The Dockerfile written by an engineer on a Tuesday afternoon determines the attack surface of every container running that image for the next six to twelve months. Two controls make the most difference here.

### Dockerfile Linting with Hadolint

Hadolint is a Dockerfile linter that enforces best practices at write-time, before any image is built.

```bash
# Install
brew install hadolint          # macOS
apt-get install hadolint       # Debian/Ubuntu

# Run against a Dockerfile
hadolint Dockerfile

# Integrate into a pre-commit hook
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint
        args: [--failure-threshold, warning]
EOF
```

The rules hadolint enforces that matter most:

- **DL3006** — `WARN: Always tag the version of the image explicitly.` Prevents implicit `latest` pulls that change silently.
- **DL3008** — `WARN: Pin versions in apt-get install.` Prevents non-reproducible builds.
- **DL3009** — `INFO: Delete the apt-get lists after installing.` Reduces final image size and removes package list metadata.
- **DL3025** — `WARN: Use arguments JSON notation for CMD and ENTRYPOINT.` Prevents shell injection through the entry point.
- **SC2086** — `INFO: Double quote to prevent globbing and word splitting.` Catches shell scripting errors in `RUN` directives.

```dockerfile
# hadolint-clean Dockerfile pattern
FROM debian:12.5-slim AS builder

# Pin package versions; clean up after install
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.1-10+deb12u5 \
    ca-certificates=20230311 \
  && rm -rf /var/lib/apt/lists/*

# Non-root USER
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app
COPY --chown=appuser:appgroup . .

USER appuser

ENTRYPOINT ["/app/server"]
```

### Minimal Base Image Selection

90% of container vulnerabilities live in the base image layer. Choosing a minimal base image is the highest-leverage security decision in the Dockerfile.

| Base Image | Typical CVE Count | Notes |
|---|---|---|
| `ubuntu:24.04` | 50–100 | Full OS, large attack surface |
| `debian:12-slim` | 20–40 | Reduced package set |
| `alpine:3.19` | 5–15 | Minimal, musl libc |
| `gcr.io/distroless/base` | 0–5 | No shell, no package manager |
| `scratch` | 0 | Empty — statically compiled binaries only |

For Go, Rust, and other statically linked languages, a two-stage build produces scratch or distroless runtime images:

```dockerfile
FROM golang:1.22.3-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

The distroless nonroot image runs as UID 65532 by default — no root, no shell, no package manager. An attacker who achieves code execution inside this container has almost no tools available.

---

## Phase 2: Build and CI

The CI pipeline is where security gates with enforcement power live. Two categories of control belong here: vulnerability scanning that can fail the build, and SBOM generation that creates an auditable record.

### Vulnerability Scanning with Trivy

Trivy is the most complete open source scanner for container images — it covers OS packages, language packages (pip, npm, go.sum, Cargo.lock), and IaC files.

```yaml
# .github/workflows/container-security.yml
name: Container Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t app:${{ github.sha }} .

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1          # Fail the build on CRITICAL/HIGH
          ignore-unfixed: true  # Only fail on CVEs with available fixes

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif
```

`ignore-unfixed: true` is the most important option. Without it, scanners fail pipelines on CVEs that have no fix available, which trains engineers to ignore scanner failures. Only fail on what can actually be fixed.

### SBOM Generation

A Software Bill of Materials is a machine-readable list of every component in an image. It becomes the auditable record that answers "were we running log4shell?" after a disclosure.

```yaml
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: app:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attach SBOM to release
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: sbom.spdx.json
```

Store the SBOM alongside the image digest, not the tag. Tags are mutable; digests are not.

### Base Image Pinning by Digest

Tags are not immutable. `FROM debian:12-slim` resolves to a different image each time the base image is updated — which is good for security patches, but makes builds non-reproducible and makes supply chain attacks harder to detect. Pin by digest for production builds:

```dockerfile
# Pin by digest — immutable reference
FROM debian@sha256:36e591f228bb9b99348f584e83f16e012c33ba5cad44ef5981a1d7c0a93eca22
```

Use Renovate or Dependabot to automate digest updates when a new base image is published:

```json
// renovate.json
{
  "dockerfile": {
    "enabled": true,
    "pinDigests": true
  }
}
```

---

## Phase 3: Registry

The registry is the distribution point. Controls here enforce quality gates on what can be stored and what identities can pull images.

### Image Signing with Cosign

Cosign (part of the Sigstore project) attaches a cryptographic signature to an image digest. Admission controllers can then verify the signature before allowing the image to run.

```bash
# Generate a key pair (or use keyless with OIDC)
cosign generate-key-pair

# Sign the image after pushing
cosign sign --key cosign.key registry.example.com/app@sha256:<digest>

# Verify locally
cosign verify --key cosign.pub registry.example.com/app@sha256:<digest>
```

Keyless signing (Sigstore Fulcio + Rekor) eliminates key management by using short-lived OIDC tokens tied to the CI identity. The signature is logged to a public transparency log:

```yaml
# In GitHub Actions — keyless cosign sign
      - name: Sign image
        env:
          COSIGN_EXPERIMENTAL: "1"
        run: |
          cosign sign --yes \
            registry.example.com/app@${{ steps.build.outputs.digest }}
```

### Registry Vulnerability Policy Enforcement

Most managed registries (ECR, Artifact Registry, Harbor) support blocking pushes or pulls of images above a CVE severity threshold. In Harbor:

```yaml
# Harbor vulnerability policy via API
policy:
  action: prevent         # Block pull, not just warn
  rules:
    - severity: Critical
      cve_allowlist: []   # No exceptions
```

Combined with admission control (Phase 4), this creates a two-layer gate: the registry rejects non-compliant images at push; the admission controller rejects them at deploy.

---

## Phase 4: Admission Control

Admission controllers run in the Kubernetes API server path. Every create or update of a Pod, Deployment, StatefulSet, or CronJob passes through configured admission webhooks before the API server accepts the object. This is the enforcement layer for runtime security policy.

### Kyverno Policies

Kyverno policies are written in YAML and apply to Kubernetes resources — no Rego required.

```yaml
# Enforce non-root containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-run-as-non-root
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Containers must run as non-root."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
```

```yaml
# Require read-only root filesystem
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-readonly-rootfs
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Root filesystem must be read-only."
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true
```

```yaml
# Enforce signed images using Cosign verification
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/your-org/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

A comprehensive Pod security context that passes all policies:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

---

## Phase 5: Runtime

Controls in Phases 1–4 reduce the probability of a compromise. Runtime controls detect the compromise when it happens. Assume breach: build detection capability that would catch a container escape, a crypto miner, or a reverse shell.

### Falco Detection Rules

Falco is a runtime security tool that consumes kernel system call events and matches them against rules. A container that spawns a shell, reads `/etc/shadow`, or opens an unexpected outbound connection generates an alert.

```yaml
# Custom Falco rule — detect shell spawned inside container
- rule: Shell Spawned in Container
  desc: >
    A shell was spawned inside a container. Containers with no legitimate
    shell use should never trigger this.
  condition: >
    container
    and proc.name in (shell_binaries)
    and not proc.pname in (shell_binaries)
    and not container.image.repository in (allowed_shell_images)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name image=%container.image.repository
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, T1059]

# Detect crypto mining by network port
- rule: Outbound Connection to Crypto Mining Pool
  desc: Container connected to a known mining pool port.
  condition: >
    container
    and fd.sport in (3333, 4444, 5555, 7777, 8333, 9999, 14444)
    and evt.type = connect
  output: >
    Crypto mining connection from container
    (container=%container.name image=%container.image.repository
    connection=%fd.name)
  priority: CRITICAL
  tags: [container, crypto-mining, T1496]

# Detect container escape attempts
- rule: Container Escape via Privileged Mount
  desc: A process in a container attempted to mount the host filesystem.
  condition: >
    container
    and evt.type = mount
    and evt.arg.dev startswith "/dev/"
    and not container.privileged
  output: >
    Container escape attempt via mount
    (container=%container.name user=%user.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape, T1611]
```

### Network Policies

NetworkPolicies restrict the ingress and egress of every Pod. Default-deny with explicit allow is the correct baseline:

```yaml
# Default deny all ingress and egress in a namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]

---
# Allow specific egress to database only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
```

A container that has been compromised and attempts to connect to a command-and-control server will have the egress blocked — provided the NetworkPolicy is in place before the compromise.

---

## Phase 6: Monitoring and Drift Detection

The final layer closes the loop: detecting when the running state of the fleet has drifted from the expected state.

### Image Drift Detection

Image drift occurs when the image running in a Pod is not the image that was built and signed by the CI pipeline. This can indicate a supply chain attack, a manual `docker pull` that bypassed CI, or a Pod restart that picked up a new tag resolution.

Kyverno can enforce that running images match their expected digest:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-integrity
spec:
  rules:
    - name: check-image-digest
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences: ["registry.example.com/*"]
          required: true
          mutateDigest: true   # Rewrite tag to digest at admission
```

`mutateDigest: true` rewrites the image reference in the Pod spec from a tag to the resolved digest at admission time. If the image is later updated in the registry, restarted Pods will fail admission until the Deployment manifest is explicitly updated — preventing silent drift.

### Automated Base Image Updates

Accumulated CVE debt is the slow version of the supply chain threat. A base image that was clean at build time gains critical CVEs over months as the upstream distribution patches vulnerabilities. The only scalable answer is automated base image updates.

Renovate configuration for automated base image tracking:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "dockerfile": {
    "enabled": true,
    "pinDigests": true
  },
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "matchPackageNames": ["debian", "alpine", "gcr.io/distroless/**"],
      "automerge": false,
      "reviewers": ["security-team"],
      "labels": ["security", "base-image-update"],
      "schedule": ["every week on monday"]
    }
  ]
}
```

Renovate opens a pull request when a new base image digest is available. The PR triggers the full CI pipeline — Dockerfile linting, vulnerability scanning, SBOM generation, and image signing — before the update is merged. The security team reviews the diff; the automation handles the rest.

---

## Controls-to-Threats Mapping

| Control | Phase | Threat Mitigated |
|---|---|---|
| Hadolint linting | Development | Dockerfile misconfigurations, privilege escalation |
| Non-root USER | Development | Privilege escalation within container |
| Minimal base image | Development | Vulnerability surface (OS layer) |
| Digest pinning | Build/CI | Supply chain tampering, non-reproducible builds |
| Trivy scanning + build gate | Build/CI | Known CVEs in OS and language packages |
| SBOM generation | Build/CI | Audit trail for post-disclosure investigation |
| Cosign image signing | Registry | Image tampering between build and deploy |
| Registry vulnerability policy | Registry | Deployment of non-compliant images |
| Kyverno non-root policy | Admission | Privilege escalation, runtime escape |
| Kyverno read-only rootfs | Admission | Filesystem modification after compromise |
| Kyverno image signature verification | Admission | Unsigned/tampered images reaching runtime |
| Seccomp RuntimeDefault | Admission | Syscall-level attack surface reduction |
| Capabilities drop ALL | Admission | Linux capability abuse |
| Falco shell detection | Runtime | Post-compromise detection |
| Falco crypto mining detection | Runtime | Resource abuse, cryptojacking |
| Falco escape detection | Runtime | Container escape attempts |
| NetworkPolicy default-deny | Runtime | Lateral movement, C2 egress |
| Image drift detection | Monitoring | Silent image swap, supply chain |
| Automated base image updates | Monitoring | Accumulated CVE debt |

---

## Shift-Left Prioritisation

The cost of remediating a vulnerability increases by approximately 10x at each phase transition. A CVE caught by hadolint costs one engineer a few minutes. The same CVE caught in production scans costs multiple teams multiple days of coordinated work.

The practical implication: invest the majority of security effort in Phases 1 and 2. A distroless base image with weekly automated updates eliminates the majority of the CVE surface before any scanner runs. A Dockerfile that passes hadolint and runs as non-root eliminates most of the privilege escalation surface before any admission controller is needed.

Phases 3–6 are not redundant — they catch what Phases 1–2 miss, and they provide defence in depth when a supply chain attack bypasses earlier controls. But they should not be the primary line of defence.

A programme that only has runtime monitoring (Phase 6) finds compromises after they happen. A programme that only has CI scanning (Phase 2) ships vulnerable images when scanning is bypassed. An integrated programme with controls at every phase detects bypasses at the next phase and reduces the probability that any single control failure leads to a production incident.

---

## Security Debt Measurement

Track the following metrics monthly to quantify container security debt and measure improvement:

- **Mean age of base images in production.** Base images older than 90 days have high probability of unpatched critical CVEs.
- **Percentage of images with critical CVEs at time of deploy.** Measures CI scanning effectiveness.
- **Percentage of deployments using signed images.** Measures supply chain control coverage.
- **Time from CVE publication to base image update.** Measures automated update pipeline latency.
- **Number of Falco critical alerts per week.** Measures runtime anomaly rate (declining trend expected as policies mature).

These metrics expose where security debt is accumulating. A rising mean base image age means automated updates are not running. A high percentage of critical CVEs at deploy time means the CI gate is being bypassed or ignored.

Container security is not a product to deploy — it is a set of practices to maintain across the lifecycle. The Dockerfile written today determines the security posture of the fleet for the next year. The automation built today determines whether that posture degrades silently or improves continuously.
