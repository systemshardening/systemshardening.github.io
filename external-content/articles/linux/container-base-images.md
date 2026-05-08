---
title: "Hardening Container Base Images: From ubuntu:latest to a Minimal, Signed, Scannable Image"
description: "ubuntu:latest ships with over 200 packages. At any given point, a vulnerability scan with Trivy will report 50 or more CVEs, most of which are in..."
slug: "container-base-images"
date: 2026-01-26
lastmod: 2026-01-26
category: "linux"
tags: ["containers", "docker", "base-images", "distroless", "cosign", "trivy", "hardening"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 9
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Chainguard"
    id: 44
    category: "hardened-images"
premium_pack: "hardened-dockerfile-templates"
published: true
layout: article.njk
permalink: "/articles/linux/container-base-images/index.html"
---

# Hardening Container Base Images: From ubuntu:latest to a Minimal, Signed, Scannable Image

## Problem

`ubuntu:latest` ships with over 200 packages. At any given point, a vulnerability scan with [Trivy](https://trivy.dev) will report 50 or more CVEs, most of which are in packages your application never uses. This is the default starting point for most container deployments:

- A larger image means a larger attack surface. Every installed binary is a potential tool for an attacker who gains code execution inside the container.
- Shells (`/bin/bash`, `/bin/sh`) let an attacker run arbitrary commands interactively after gaining initial access.
- Package managers (`apt`, `apk`) let an attacker install additional tools (curl, wget, netcat) for lateral movement.
- Running as root by default means a container escape gives the attacker root on the host.
- Unsigned images mean you cannot verify that the image you are pulling is the one that was built. Supply chain attacks can inject malicious layers.

Most teams know they should use smaller images. Fewer teams actually do it, because the migration from `ubuntu:latest` to a minimal image breaks build processes, requires understanding the differences between musl and glibc, and demands changes to debugging workflows.

**Target environments:** [Docker](https://www.docker.com), [containerd](https://containerd.io), [Kubernetes](https://kubernetes.io). Languages covered: Go, Python, Node.js, Java.

## Threat Model

- **Adversary:** Attacker who has achieved remote code execution inside a container (through an application vulnerability, a compromised dependency, or a deserialization flaw) and is attempting to escalate privileges, exfiltrate data, or move laterally.
- **Access level:** Code execution as the container process user (ideally non-root, but often root in unhardened deployments).
- **Objective:** Install tools for reconnaissance, establish a reverse shell, access secrets mounted in the container, or escape the container to the host.
- **Blast radius:** Single container initially. With a shell and root access, the attacker can read mounted secrets, query the Kubernetes API (if a service account is mounted), and attempt container escape to the node.

## Configuration

### Base Image Comparison

| Base Image | Size | Shell | Package Manager | C Library | CVEs (typical) | Best For |
|-----------|------|-------|----------------|-----------|----------------|----------|
| `ubuntu:24.04` | 78 MB | Yes | apt | glibc | 50-100 | Development, not production |
| `alpine:3.20` | 7 MB | Yes (busybox) | apk | musl | 5-15 | Small images where musl is acceptable |
| `gcr.io/distroless/static` | 2 MB | No | No | None | 0-2 | Statically compiled binaries (Go, Rust) |
| `gcr.io/distroless/base` | 20 MB | No | No | glibc | 2-5 | Binaries needing glibc (Python, Java) |
| `scratch` | 0 MB | No | No | None | 0 | Fully static binaries with no OS dependency |
| `cgr.dev/chainguard/static` | 2 MB | No | No | None | 0 | Zero-CVE, daily rebuilt, signed |

### Multi-Stage Build: Go Application

```dockerfile
# Build stage - full toolchain
FROM golang:1.23-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 produces a static binary that runs on scratch/distroless
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server ./cmd/server

# Runtime stage - minimal image, no shell, no package manager
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /app/server /server

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/server"]
```

### Multi-Stage Build: Python Application

```dockerfile
# Build stage - install dependencies
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage - distroless Python
FROM gcr.io/distroless/python3-debian12:nonroot

COPY --from=builder /install /usr/local
COPY --from=builder /app /app

WORKDIR /app
COPY . .

USER nonroot:nonroot
EXPOSE 8000

ENTRYPOINT ["python3", "app.py"]
```

### Multi-Stage Build: Node.js Application

```dockerfile
# Build stage
FROM node:22-bookworm-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Runtime stage
FROM gcr.io/distroless/nodejs22-debian12:nonroot

COPY --from=builder /app/node_modules /app/node_modules
COPY . /app

WORKDIR /app

USER nonroot:nonroot
EXPOSE 3000

ENTRYPOINT ["app.js"]
```

### Multi-Stage Build: Java Application

```dockerfile
# Build stage
FROM eclipse-temurin:21-jdk-jammy AS builder

WORKDIR /app
COPY . .
RUN ./gradlew build --no-daemon -x test

# Runtime stage - distroless Java
FROM gcr.io/distroless/java21-debian12:nonroot

COPY --from=builder /app/build/libs/app.jar /app.jar

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["app.jar"]
```

### Running as Non-Root

Every runtime image should use a non-root user. Use numeric UIDs for Kubernetes compatibility with `runAsNonRoot`:

```dockerfile
# Numeric UID/GID for K8s runAsNonRoot enforcement
USER 65532:65532
```

Distroless images include a `nonroot` user (UID 65532) by default. For Alpine-based images, create one:

```dockerfile
FROM alpine:3.20
RUN addgroup -S appgroup && adduser -S appuser -G appgroup -u 65532
USER 65532:65532
```

### Removing Shells and Package Managers

For Alpine-based images where you want to keep the small size but remove attack tools:

```dockerfile
FROM alpine:3.20 AS runtime

# Install only what the application needs
RUN apk add --no-cache ca-certificates tzdata \
    && rm -rf /sbin/apk /usr/bin/apk \
    && rm -rf /lib/apk /etc/apk \
    && rm -rf /bin/sh /bin/ash /bin/busybox

# The shell removal above means you cannot use shell-form CMD.
# Use exec form only:
ENTRYPOINT ["/app/server"]
```

### Image Signing with Cosign

Sign images after building to establish a chain of trust from build to deployment:

```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Keyless signing (uses Sigstore transparency log)
# Requires OIDC identity (GitHub Actions, GitLab CI, or local browser)
cosign sign registry.example.com/myapp:v1.2.3

# Key-based signing (for air-gapped environments)
cosign generate-key-pair
cosign sign --key cosign.key registry.example.com/myapp:v1.2.3

# Verify before deployment
cosign verify registry.example.com/myapp:v1.2.3 \
    --certificate-identity=github-actions@example.com \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

In Kubernetes, enforce signature verification with a policy engine:

```yaml
# Kyverno policy to require cosign signatures
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validatingAdmissionPolicy: true
  rules:
    - name: verify-signature
      match:
        resources:
          kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["registry.example.com/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "github-actions@example.com"
                    issuer: "https://token.actions.githubusercontent.com"
```

### Scanning with Trivy in CI

Add vulnerability scanning to your CI pipeline and fail builds on critical findings:

```yaml
# GitHub Actions example
- name: Scan image with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: "registry.example.com/myapp:${{ github.sha }}"
    format: "table"
    exit-code: "1"
    severity: "CRITICAL,HIGH"
    ignore-unfixed: true
```

For accepted risks, create a `.trivyignore` file:

```
# .trivyignore - accepted vulnerabilities with justification
# CVE-2024-1234: Not exploitable in our configuration (no network exposure)
CVE-2024-1234
# CVE-2024-5678: Fix not yet available upstream, monitoring for update
CVE-2024-5678
```

## Expected Behaviour

After migrating from `ubuntu:latest` to a hardened base image:

- `docker image ls` shows image size reduced from 200-500 MB to 2-30 MB depending on the base
- `trivy image myapp:latest` reports zero critical/high CVEs (for distroless/Chainguard bases)
- `docker exec -it container /bin/sh` fails with "executable file not found" (no shell in distroless)
- Container runs as non-root: `docker exec container whoami` returns `nonroot` or the numeric UID
- `cosign verify` succeeds for signed images and fails for unsigned/tampered images
- Application starts and serves traffic identically to the ubuntu-based version

## Trade-offs

| Decision | Benefit | Cost | Mitigation |
|----------|---------|------|------------|
| Distroless base | No shell, no package manager, minimal CVEs | Cannot exec into the container for debugging | Use Kubernetes ephemeral debug containers: `kubectl debug -it pod/myapp --image=busybox --target=myapp` |
| Alpine base | 7 MB, includes shell for debugging | Uses musl libc; some Go binaries with CGO and some Python packages with C extensions fail | Test thoroughly. For Go, use `CGO_ENABLED=0`. For Python, use glibc-based distroless instead. |
| scratch base | Zero OS packages, zero CVEs | Must statically compile everything. No CA certificates, no timezone data, no user database. | Copy needed files from builder: `COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs/` |
| Removing shells | Attacker cannot get interactive access | Breaks shell-form CMD/ENTRYPOINT. Cannot use shell scripts in the container. | Use exec-form only. Move all shell logic to the build stage. |
| Non-root user | Reduces impact of container escape | Application cannot bind to ports below 1024 | Bind to ports above 1024 (8080, 3000) and use Kubernetes service to expose on 80/443. |
| Image signing | Verifiable supply chain | Adds a signing step to CI. Keyless signing requires OIDC provider. | Integrate cosign into CI pipeline. Use keyless for simplicity in GitHub Actions/GitLab CI. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Missing shared library in minimal image | Container crashes immediately on startup with "not found" or "no such file or directory" | `docker logs` shows the dynamic linker error. `ldd` on the binary in the build stage shows which libraries are needed. | Add the missing library to the runtime image, or compile statically (`CGO_ENABLED=0` for Go). |
| musl/glibc incompatibility on Alpine | Application crashes with segfaults or DNS resolution fails | `dmesg` in the container shows segfault. DNS lookups return unexpected results (musl DNS resolver differs from glibc). | Switch to a glibc-based image (distroless, slim-bookworm) or recompile dependencies against musl. |
| Non-root user cannot write to required path | Application fails with "permission denied" writing to `/app/data` or similar | Application logs show write errors. `ls -la` in the build stage shows root-owned directories. | In the Dockerfile, `RUN chown -R 65532:65532 /app/data` before switching to the non-root user. |
| Cosign verification fails in production | Kubernetes rejects pods if policy engine requires signatures and verification fails | Pod events show admission webhook rejection with signature verification error | Check that the signing identity matches the verification policy. Re-sign the image if the OIDC token expired during build. |
| Trivy blocks deployment on unfixed CVE | CI pipeline fails even though no fix is available upstream | Trivy output shows CVE with "no fixed version" | Add the CVE to `.trivyignore` with a comment explaining the accepted risk. Set `--ignore-unfixed` in CI. |

## When to Consider a Managed Alternative

**Transition point:** When you maintain internal base images across more than 3 teams, or when vulnerability scanning every image in every pipeline generates 100+ CVE alerts per week without prioritization, leading to alert fatigue.

**What managed providers handle:**

[Chainguard](https://www.chainguard.dev) provides pre-hardened container images that are rebuilt daily from source, contain zero known CVEs at build time, and are signed with Sigstore. Instead of maintaining your own base image hardening pipeline, you pull `cgr.dev/chainguard/python:latest` and get a minimal, signed, scanned image with no effort.

[Snyk](https://snyk.io) Container provides prioritized vulnerability management that distinguishes between CVEs that are exploitable in your configuration and those that are not. This reduces alert volume from hundreds of CVEs to the handful that actually matter for your deployment.

[Docker Scout](https://docs.docker.com/scout/) integrates scanning directly into Docker Desktop and Docker Hub, providing vulnerability visibility without adding a separate scanning tool to your pipeline.

**What you still control:** Base image selection and Dockerfile structure remain your decisions regardless of tooling. A managed scanning tool tells you about vulnerabilities; you still need to build minimal images, run as non-root, and remove unnecessary packages.

**Automation path:** For self-managed infrastructure, integrate Trivy scanning and cosign signing into your CI pipeline using the examples in this article. For fleet-wide base image governance, the premium Dockerfile template pack provides hardened, tested base images for Go, Python, Node.js, and Java with CI integration examples.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
