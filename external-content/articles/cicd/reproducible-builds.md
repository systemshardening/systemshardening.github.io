---
title: "Reproducible Builds for Container Images: Achieving Deterministic Output"
description: "Two builds from the same source code should produce the same container image. In practice, they almost never do."
slug: "reproducible-builds"
date: 2026-01-23
lastmod: 2026-01-23
category: "cicd"
tags: ["reproducible-builds", "containers", "supply-chain", "docker", "buildah", "ko"]
personas: ["devops-engineer", "security-engineer"]
article_number: 54
difficulty: "advanced"
estimated_reading_time: 15
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "reproducible-build-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/reproducible-builds/index.html"
---

# Reproducible Builds for Container Images: Achieving Deterministic Output

## Problem

Two builds from the same source code should produce the same container image. In practice, they almost never do. Timestamps embedded in image layers, non-deterministic package manager ordering, floating base image tags, and build-tool metadata all contribute to different image digests from identical inputs. This makes it impossible to independently verify that a deployed image was actually built from the claimed source code.

Without reproducible builds, you must trust the build system. If the CI runner is compromised, it can inject code during the build process, and the resulting image will have a different digest that nobody questions because digests are always different. Reproducible builds remove this trust requirement: anyone with the source code and the build instructions can rebuild the image and verify they get the same result.

Achieving full reproducibility requires controlling every source of non-determinism: timestamps, file ordering, package versions, base image digests, and build tool versions.

## Threat Model

- **Adversary:** Compromised CI runner, malicious build tool plugin, or supply chain attacker who modifies the build process to inject code.
- **Objective:** Insert backdoors or malicious code into container images without detection.
- **Blast radius:** Every deployment that uses the tampered image. Without reproducibility, there is no way to detect the tampering by rebuilding from source.

## Configuration

### Pinning Base Images by Digest

Never use floating tags like `python:3.12` or `ubuntu:24.04`. These tags are mutable and can point to different images over time.

```dockerfile
# BAD: floating tag - different image content each time the tag updates
FROM python:3.12-slim

# GOOD: pinned by digest - immutable reference to a specific image
FROM python:3.12-slim@sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab
```

Automate digest updates with Renovate or Dependabot:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "docker": {
    "pinDigests": true,
    "enabled": true
  },
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "matchPackagePatterns": ["*"],
      "pinDigests": true,
      "schedule": ["every monday"]
    }
  ]
}
```

### Stripping Timestamps with [Docker](https://www.docker.com) BuildKit

Docker BuildKit supports the `SOURCE_DATE_EPOCH` environment variable, which overrides timestamps in the build process:

```dockerfile
# Dockerfile - reproducible build
FROM golang:1.22@sha256:abc123... AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build with stripped debug info and fixed build paths
RUN CGO_ENABLED=0 GOFLAGS="-trimpath" \
    go build -ldflags="-s -w -buildid=" -o /app/server ./cmd/server

FROM scratch
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

```bash
# Build with fixed timestamp (use git commit timestamp for reproducibility)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

docker buildx build \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --output type=oci,dest=image.tar,rewrite-timestamp=true \
  --no-cache \
  --tag myapp:$(git rev-parse HEAD) \
  .
```

### Reproducible Builds with ko (Go Applications)

`ko` builds Go applications into container images without a Dockerfile, and produces reproducible output by default:

```yaml
# .ko.yaml
defaultBaseImage: cgr.dev/chainguard/static:latest@sha256:def456...
builds:
  - id: server
    main: ./cmd/server
    env:
      - CGO_ENABLED=0
    flags:
      - -trimpath
    ldflags:
      - -s -w -buildid=
```

```bash
# ko produces deterministic images by default
# Same source + same config = same digest
KO_DOCKER_REPO=ghcr.io/your-org/myapp \
  ko build ./cmd/server --bare --tags=$(git rev-parse --short HEAD)
```

### Reproducible Builds with [Buildah](https://buildah.io)

```bash
#!/bin/bash
# build-reproducible.sh

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

# Buildah supports timestamp clamping natively
buildah build \
  --timestamp "$SOURCE_DATE_EPOCH" \
  --layers=false \
  --no-cache \
  --tag myapp:$(git rev-parse HEAD) \
  .
```

### Pinning Package Manager Dependencies

Package managers are a major source of non-determinism. Pin every dependency by exact version and verify checksums.

```dockerfile
# Python: use pip with hashed requirements
FROM python:3.12-slim@sha256:abc123...

COPY requirements.txt .
# --require-hashes ensures every package matches a known hash
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .
```

```text
# requirements.txt with hashes (generate with pip-compile --generate-hashes)
flask==3.0.2 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
werkzeug==3.0.1 \
    --hash=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

```dockerfile
# Alpine: pin packages by exact version
FROM alpine:3.20@sha256:def456...
RUN apk add --no-cache \
    curl=8.7.1-r0 \
    openssl=3.3.0-r2 \
    ca-certificates=20240226-r0
```

### Verification Workflow

Build the image twice (ideally on different machines) and compare digests:

```yaml
# .github/workflows/verify-reproducibility.yml
name: Verify Reproducible Build
on:
  push:
    branches: [main]

jobs:
  build-1:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Build image
        id: build
        run: |
          SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
          export SOURCE_DATE_EPOCH
          docker buildx build \
            --output type=oci,dest=image.tar,rewrite-timestamp=true \
            --no-cache .
          DIGEST=$(sha256sum image.tar | awk '{print $1}')
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"

  build-2:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Build image
        id: build
        run: |
          SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
          export SOURCE_DATE_EPOCH
          docker buildx build \
            --output type=oci,dest=image.tar,rewrite-timestamp=true \
            --no-cache .
          DIGEST=$(sha256sum image.tar | awk '{print $1}')
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"

  verify:
    needs: [build-1, build-2]
    runs-on: ubuntu-latest
    steps:
      - name: Compare digests
        run: |
          if [ "${{ needs.build-1.outputs.digest }}" != "${{ needs.build-2.outputs.digest }}" ]; then
            echo "FAILURE: Builds are not reproducible"
            echo "Build 1: ${{ needs.build-1.outputs.digest }}"
            echo "Build 2: ${{ needs.build-2.outputs.digest }}"
            exit 1
          fi
          echo "SUCCESS: Both builds produced identical images"
          echo "Digest: ${{ needs.build-1.outputs.digest }}"
```

### Multi-Architecture Reproducibility

Multi-arch builds add complexity because each architecture produces a different binary:

```bash
# Build for multiple architectures with fixed timestamps
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=image-multiarch.tar,rewrite-timestamp=true \
  --no-cache \
  --tag myapp:$(git rev-parse HEAD) \
  .

# The manifest list digest should be reproducible
# even though each platform image has a different content digest
```

## Expected Behaviour

- Building the same commit twice produces an image with the same digest
- All base images are pinned by digest with automated update PRs
- All package manager dependencies are pinned by exact version with hash verification
- Build timestamps are set to the git commit timestamp, not the build time
- Go binaries are built with `-trimpath` and empty `-buildid`
- CI includes a reproducibility verification job that builds twice and compares

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Digest-pinned base images | No automatic security patches from upstream | Vulnerable base images persist until Renovate PR is merged | Renovate checks daily. Merge security updates within 24 hours. |
| Hashed dependency pinning | More verbose requirements files; manual updates | Stale dependencies with known vulnerabilities | Automated dependency update tooling (Renovate, Dependabot). |
| Timestamp stripping | Loses build-time metadata useful for debugging | Cannot determine when an image was actually built from the image alone | Store build metadata in OCI annotations or provenance attestations instead. |
| Dual-build verification | Doubles CI build time for verification jobs | Verification only runs in CI, not locally | Run verification on main branch merges only, not every PR. |
| `--no-cache` builds | Slower builds since no layer caching | CI costs increase due to longer build times | Use `--no-cache` only for release builds. Allow caching for development builds. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Non-deterministic package ordering | Different digests from same source | Verification job fails (digest mismatch) | Sort package installation commands alphabetically. Use `--no-cache` to avoid layer reuse issues. |
| Floating base image tag | Digest changes when base image is updated | Verification job fails; image scan shows different OS packages | Pin base image by digest. |
| Build tool version difference | Different BuildKit or Docker versions produce different layers | Verification fails across different runner types | Pin build tool versions in CI. Use identical runner images. |
| SOURCE_DATE_EPOCH not propagated | Timestamps still embedded in image layers | Digest mismatch between builds at different times | Verify SOURCE_DATE_EPOCH is exported and passed to all build stages. |
| Go module cache non-determinism | `go mod download` produces different artifacts | Build verification fails intermittently | Use `GOFLAGS="-mod=vendor"` to vendor dependencies and commit the vendor directory. |

## When to Consider a Managed Alternative

Full reproducibility requires strict control over the build environment, which is difficult with shared CI runners. Chainguard provides pre-built, reproducible base images that are rebuilt daily with security patches. For Go applications, `ko` achieves reproducibility with minimal configuration. [Snyk](https://snyk.io) Container can verify build provenance even when full reproducibility is not achievable. For teams where reproducible builds are a compliance requirement but the engineering investment is prohibitive, SLSA Build L3 provenance (covered in article #50) provides build integrity guarantees without requiring bit-for-bit reproducibility.

**Premium content pack:** Reproducible build templates for Docker, Buildah, and ko. Includes Dockerfiles for Python, Go, Node.js, and Java with pinned dependencies, timestamp stripping, and verification workflows for GitHub Actions and GitLab CI.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation](/articles/cicd/terraform-security/)
