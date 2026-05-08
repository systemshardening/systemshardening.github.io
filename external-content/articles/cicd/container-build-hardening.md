---
title: "Container Build Hardening: BuildKit Secrets, Rootless Builds, and Multi-Stage Security"
description: "Most Dockerfiles leak secrets into image layers, run builds as root, and produce images larger than necessary. BuildKit secrets, rootless mode, multi-stage builds, and Hadolint fix all three."
slug: "container-build-hardening"
date: 2026-04-30
lastmod: 2026-04-30
category: "cicd"
tags: ["docker", "buildkit", "container", "supply-chain", "hardening"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 250
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/container-build-hardening/index.html"
---

# Container Build Hardening: BuildKit Secrets, Rootless Builds, and Multi-Stage Security

## Problem

Container images accumulate security debt during the build process. Common patterns that produce vulnerable images:

- **Secrets in `RUN` instructions.** `RUN npm install && API_KEY=secret curl https://...` writes the secret into the image layer, even if a later `RUN` removes it. Every layer is preserved in the image manifest; anyone who pulls the image can read the secret.
- **Root build processes.** Builds run as root by default. A compromised build step (via a malicious dependency or build script) executes with root privileges on the build host.
- **Oversized images with build tools.** The same image that compiles the application ships the compiler, package manager, source code, and test fixtures to production. More packages = larger CVE surface.
- **Pinned base images by tag, not digest.** `FROM python:3.12` changes meaning when the `3.12` tag is updated. A new base image with a different digest is silently pulled on the next build.
- **No Dockerfile linting.** Common Dockerfile mistakes (`apt-get` without `--no-install-recommends`, `COPY . .` before dependency install, secrets via `ARG`) are introduced silently.
- **Build cache poisoning.** Shared BuildKit cache is accessible to all pipelines. A malicious pipeline contaminates the cache, affecting downstream builds.

**Target systems:** Docker 24+ with BuildKit enabled (default); BuildKit 0.15+ standalone; GitHub Actions, GitLab CI, Tekton; Hadolint 2.12+; Trivy 0.50+ for post-build scanning.

## Threat Model

- **Adversary 1 — Secret extraction from image layer:** An attacker pulls an image (from a registry with read access) and inspects all layers. They find an API key or private key written into a `RUN` instruction.
- **Adversary 2 — Malicious build dependency:** A compromised npm/pip package executes code during `npm install`. Without rootless builds, this code runs as root on the build host, potentially accessing the host filesystem.
- **Adversary 3 — Cache poisoning:** A shared build cache is contaminated by a previous malicious build. A subsequent legitimate build uses the poisoned cache layer, producing a backdoored image.
- **Adversary 4 — Base image supply chain compromise:** An attacker pushes a malicious image to a public registry under a popular tag. The build pulls `FROM ubuntu:latest`, which now contains a backdoor. Tag-pinned builds are vulnerable to tag reassignment; digest-pinned builds are not.
- **Adversary 5 — Build-time credential leak via ARG:** A Dockerfile uses `ARG GITHUB_TOKEN` and `RUN git clone https://$GITHUB_TOKEN@github.com/...`. The ARG value is captured in the image metadata and visible to anyone with docker inspect access.
- **Access level:** Adversary 1 has registry read access. Adversary 2 is a transitive dependency. Adversary 3 has write access to the shared cache. Adversary 4 has access to the upstream registry. Adversary 5 has docker inspect access.
- **Objective:** Extract credentials, execute code on the build host, produce backdoored images.
- **Blast radius:** A secret in an image layer persists for the image's lifetime and is exposed to every registry user. A rootful build compromise can compromise the build host. A tag-pinned base image attack affects all builds using that tag.

## Configuration

### Step 1: Enable BuildKit

BuildKit is the default backend for Docker 23.0+. For older versions or standalone use:

```bash
# Enable BuildKit for Docker daemon globally.
cat >> /etc/docker/daemon.json <<'EOF'
{
  "features": {
    "buildkit": true
  }
}
EOF
systemctl restart docker

# Or per-build via environment variable.
DOCKER_BUILDKIT=1 docker build .

# Use docker buildx for advanced BuildKit features.
docker buildx create --name secure-builder --use
docker buildx inspect --bootstrap
```

### Step 2: Use BuildKit Secrets — Never ARG or ENV for Credentials

BuildKit's secret mount passes credentials to `RUN` instructions without writing them into any layer:

```dockerfile
# BAD: secret written into image layer.
ARG GITHUB_TOKEN
RUN git clone https://$GITHUB_TOKEN@github.com/myorg/private-repo.git

# BAD: even if the ARG is cleared later, it's captured in the layer cache.
RUN unset GITHUB_TOKEN   # Does nothing; the previous layer already recorded it.

# GOOD: BuildKit secret mount.
# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder

# The secret is mounted into /run/secrets/github_token for the duration
# of this RUN instruction only. It is never written to any layer.
RUN --mount=type=secret,id=github_token \
    git clone https://$(cat /run/secrets/github_token)@github.com/myorg/private-repo.git /src
```

Passing the secret at build time:

```bash
# Pass the secret from an environment variable (never from a file in the repo).
GITHUB_TOKEN=$(vault kv get -field=token secret/ci/github) \
  docker buildx build \
  --secret id=github_token,env=GITHUB_TOKEN \
  --tag myapp:v1.2.3 .

# Or from a file (generated at runtime, not committed).
vault kv get -field=token secret/ci/github > /tmp/github_token
docker buildx build \
  --secret id=github_token,src=/tmp/github_token \
  --tag myapp:v1.2.3 .
rm /tmp/github_token
```

For `pip install` from a private PyPI or `npm install` from a private registry:

```dockerfile
# npm private registry authentication via BuildKit secret.
RUN --mount=type=secret,id=npm_token \
    npm config set //registry.npmjs.org/:_authToken=$(cat /run/secrets/npm_token) && \
    npm ci && \
    npm config delete //registry.npmjs.org/:_authToken

# pip with private index.
RUN --mount=type=secret,id=pip_token \
    pip install \
    --index-url https://$(cat /run/secrets/pip_token)@pypi.internal/simple/ \
    -r requirements.txt
```

### Step 3: Multi-Stage Builds for Minimal Production Images

Separate the build environment (compilers, dev tools, source) from the runtime image (only the compiled binary):

```dockerfile
# syntax=docker/dockerfile:1

##############
# Build stage
##############
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy dependency files first — layer cache hit if they don't change.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build a statically linked binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -extldflags=-static" \
    -o /out/app ./cmd/app

##############
# Security scan stage (optional; scan before shipping)
##############
FROM aquasec/trivy:latest AS scanner
COPY --from=builder /out/app /app
RUN trivy fs --exit-code 1 --severity HIGH,CRITICAL /app

##############
# Runtime stage
##############
FROM scratch AS runtime
# scratch: empty image; only what we copy in exists.

# Copy only the binary and necessary certs.
COPY --from=builder /out/app /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Non-root user (UID must be numeric for scratch-based images).
USER 65534:65534

EXPOSE 8080
ENTRYPOINT ["/app"]
```

For applications that need a minimal base (not scratch):

```dockerfile
# distroless: no shell, no package manager, no OS utilities.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
```

The production image contains: the binary + CA certificates. No compiler, no shell, no package manager. An attacker who achieves code execution via the application cannot pivot using shell commands.

### Step 4: Pin Base Images by Digest

Tags are mutable. Digest references are immutable:

```dockerfile
# BAD: tag can be reassigned.
FROM golang:1.22-alpine

# GOOD: digest-pinned; this exact image layer is used every time.
FROM golang:1.22-alpine@sha256:f368c4dc7df0b91be4f03f7fe00b13b12fa1e29a66c5c1fdeb6cf68d3c00cd83

FROM gcr.io/distroless/static-debian12:nonroot@sha256:39ae7f0201fee13573d9...
```

Update digests on a schedule using Renovate or Dependabot:

```yaml
# renovate.json — auto-update Dockerfile base image digests.
{
  "extends": ["config:base"],
  "dockerfile": {
    "enabled": true
  },
  "packageRules": [
    {
      "matchManagers": ["dockerfile"],
      "automerge": true,
      "automergeType": "pr",
      "matchUpdateTypes": ["digest"]
    }
  ]
}
```

### Step 5: Rootless BuildKit

Run BuildKit itself without root privileges on the build host:

```bash
# Install rootless Docker (runs the Docker daemon as a non-root user).
dockerd-rootless-setuptool.sh install

# Or run BuildKit standalone rootlessly.
curl -sSfL https://github.com/moby/buildkit/releases/latest/download/buildkit-v0.15.0.linux-amd64.tar.gz \
  | tar -C /usr/local -xzf -

# Run rootless buildkitd (as a non-root user).
buildkitd --addr unix:///run/user/$(id -u)/buildkit/buildkitd.sock &

# Build using rootless buildkitd.
buildctl --addr unix:///run/user/$(id -u)/buildkit/buildkitd.sock \
  build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --output type=image,name=myapp:v1.2.3,push=true
```

In Kubernetes CI (Tekton, Argo Workflows), run BuildKit as a sidecar without privileged mode:

```yaml
# Tekton Task: rootless BuildKit in a Pod.
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: buildkit-build
spec:
  steps:
    - name: build
      image: moby/buildkit:v0.15.0-rootless
      securityContext:
        seccompProfile:
          type: Unconfined    # Required for rootless user namespaces.
        runAsUser: 1000
        runAsGroup: 1000
        # NOT privileged.
      env:
        - name: BUILDKITD_FLAGS
          value: "--oci-worker-no-process-sandbox"
      command: ["buildctl-daemonless.sh"]
      args:
        - build
        - --frontend
        - dockerfile.v0
        - --local
        - context=/workspace/source
        - --local
        - dockerfile=/workspace/source
        - --output
        - type=image,name=$(params.image),push=true
```

### Step 6: Lint Dockerfiles with Hadolint

Hadolint checks Dockerfiles against best practices and security rules:

```bash
# Install Hadolint.
docker run --rm -i hadolint/hadolint < Dockerfile

# Or install the binary.
curl -sL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
  -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# Run on a Dockerfile.
hadolint Dockerfile

# Common findings and their security implications:
# DL3008: Pin versions in apt-get install (reproducibility)
# DL3009: Delete apt-get lists after install (image size; fewer CVE targets)
# DL3020: Use COPY instead of ADD (ADD can untar and fetch URLs unexpectedly)
# DL4006: Set SHELL option -o pipefail (exit codes from pipes are lost otherwise)
# SC2086: Double quote variables to prevent word splitting
```

Add to CI:

```yaml
# .github/workflows/lint.yml
- name: Lint Dockerfile
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: Dockerfile
    failure-threshold: error   # Fail CI on error-level findings; warn on warnings.
    ignore: DL3008             # If you intentionally don't pin apt packages.
```

### Step 7: Post-Build Vulnerability Scanning

Scan the built image before pushing to the registry:

```yaml
# .github/workflows/build-scan-push.yml
- name: Build image
  run: |
    docker buildx build \
      --cache-from type=registry,ref=ghcr.io/${{ github.repository }}:buildcache \
      --cache-to type=registry,ref=ghcr.io/${{ github.repository }}:buildcache,mode=max \
      --tag ghcr.io/${{ github.repository }}:${{ github.sha }} \
      --output type=docker \
      .

- name: Scan image for vulnerabilities
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
    format: sarif
    output: trivy-results.sarif
    exit-code: 1                      # Fail the build on CRITICAL findings.
    ignore-unfixed: true              # Don't fail on CVEs with no fix available.
    severity: CRITICAL,HIGH

- name: Upload Trivy SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy-results.sarif

- name: Push image (only if scan passed)
  run: docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### Step 8: Telemetry

```
container_build_duration_seconds{repo, stage}              histogram
container_build_secret_leak_detected_total{repo}           counter
container_image_cve_count{severity, image}                 gauge
container_base_image_digest_staleness_days{image}          gauge
hadolint_violations_total{rule, severity, repo}            counter
buildkit_cache_hit_rate{builder}                           gauge
```

Alert on:

- `container_image_cve_count{severity="CRITICAL"}` > 0 — a shipped image has a critical CVE; rebuild with updated base image.
- `container_base_image_digest_staleness_days` > 30 — base image digest hasn't been updated in a month; may miss security patches.
- `hadolint_violations_total{severity="error"}` — Dockerfile linting errors in a merged PR; retroactively fix and enforce in pre-merge checks.

## Expected Behaviour

| Signal | Default Dockerfile practices | Hardened build |
|--------|------------------------------|---------------|
| Secret in `RUN` instruction | Persists in image layer; readable by anyone with pull access | BuildKit secret mount; never written to any layer |
| Build process runs as | root | Non-root user (rootless BuildKit; `USER nonroot` in Dockerfile) |
| Production image contains | Compiler, package manager, source, binary | Binary + CA certs only (multi-stage + distroless) |
| Base image tag reassigned | Next build uses attacker's image | Digest pin; tag reassignment has no effect |
| Dockerfile mistake | Silently produces a larger, less secure image | Hadolint fails CI before merge |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Multi-stage + scratch/distroless | Minimal CVE surface; no shell for attackers | Harder to debug (no shell in running container) | Use ephemeral debug containers: `kubectl debug -it pod/xxx --image=busybox` |
| BuildKit secrets | No credential persistence in layers | Slightly more complex build syntax | Well-supported in all modern CI platforms; one-time setup. |
| Digest pinning | Reproducible builds; immune to tag attacks | Digest must be updated manually or via Renovate | Automate via Renovate digest PR; merging is a 10-second operation. |
| Rootless BuildKit | Compromised build step cannot root the host | Some syscall restrictions (no `mknod`, limited namespaces) | Most application builds work fine; test build requirements in rootless mode. |
| Trivy blocking on CRITICAL | Prevents shipping known-vulnerable images | Breaks builds when no fix is available | Use `ignore-unfixed: true` for CVEs with no upstream fix; file a tracking issue. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Secret accidentally in ARG | Secret visible in `docker history` / layer metadata | `docker history --no-trunc image:tag | grep SECRET` | Rebuild immediately; rotate the exposed secret; remove the old image tag from registry. |
| BuildKit secret mount file missing | Build fails: `secret not found: github_token` | CI build error | Verify the secret is passed via `--secret`; check CI secret configuration. |
| Distroless image missing dependency | Application crashes at runtime with missing shared library | Runtime crash; `ldd /app` in debug container | Copy required `.so` files from builder stage; or switch to a minimal base with glibc. |
| Rootless BuildKit user namespace unavailable | Build fails with user namespace errors | Build error: `failed to create user namespace` | Enable user namespaces: `sysctl -w kernel.unprivileged_userns_clone=1` (on supported kernels). |
| Trivy false positive blocks release | Valid image flagged; release blocked | Build blocked on CVE with no fix | Use Trivy `.trivyignore` file to allowlist specific CVE IDs with justification; review quarterly. |
| Base image digest stale | New CVE in base image affects production | `container_base_image_digest_staleness_days` alert | Merge Renovate digest update PR; rebuild and redeploy. |

## Related Articles

- [Container Registry Security](/articles/cicd/container-registry-security/)
- [SBOM Generation and Verification](/articles/cicd/sbom/)
- [Sigstore Keyless Signing and Cosign Verification](/articles/cicd/sigstore-keyless-signing/)
- [Dependency Pinning and Integrity Verification](/articles/cicd/dependency-pinning/)
- [Container Base Image Hardening](/articles/linux/container-base-images/)
