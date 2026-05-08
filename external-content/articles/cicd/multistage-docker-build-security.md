---
title: "Securing Docker Multi-Stage Builds to Minimise Attack Surface in Production Images"
description: "Single-stage Dockerfiles ship compilers, package caches, and debug tools straight to production. Multi-stage builds with distroless or scratch final images, digest-pinned bases, and Hadolint linting keep the attack surface to the absolute minimum."
slug: multistage-docker-build-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - docker
  - multistage-builds
  - container-hardening
  - minimal-images
  - dockerfile-security
personas:
  - security-engineer
  - platform-engineer
article_number: 537
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/multistage-docker-build-security/
---

# Securing Docker Multi-Stage Builds to Minimise Attack Surface in Production Images

## Why Single-Stage Builds Are a Security Liability

A typical single-stage Dockerfile installs a compiler, downloads dependencies, builds an application, and then ships the entire filesystem — compiler, package manager, source code, test utilities, and all — as the production image. Every tool present in a running container is an asset available to an attacker who achieves code execution.

The concrete risks are:

- **CVE surface from unused packages.** A Go binary needs nothing but glibc (or nothing at all) to run. Shipping `golang:1.22` to production bundles the Go toolchain, git, curl, and the Alpine or Debian base, each of which carries its own CVE backlog. Container scanners will report every one of them.
- **Build tools as post-exploitation aids.** If a container is compromised through an application vulnerability, the presence of `curl`, `wget`, `bash`, and a package manager makes lateral movement, data exfiltration, and persistence dramatically easier. A minimal image with none of these tools forces the attacker to bring their own binaries, which is detectable.
- **Package caches and intermediate files.** `apt-get install` writes package archives to `/var/cache/apt`. `npm install` writes a full node_modules tree. `pip install` writes wheel caches. Even if a subsequent `RUN rm -rf /var/cache/apt` is added, it creates a new layer — the data still exists in the earlier layer and is readable by anyone who inspects the image with `docker history` or layer-aware tools.
- **Source code in the image.** The source tree, configuration files with default credentials, and `.env` files copied with `COPY . .` all end up in the final image unless explicitly excluded. Source exposure enables vulnerability research against your exact codebase.
- **Developer credentials and configuration.** Build tools pull credentials from `~/.gitconfig`, SSH agents, and environment variables. Without explicit discipline these leak into layers.

Multi-stage builds solve all of these by making the build environment structurally separate from the runtime image. The compiler never reaches production. Neither does the package cache, the source tree, or any intermediate artefact that wasn't explicitly copied to the final stage.

**Target systems:** Docker 17.05+ (multi-stage support); Docker 20.10+ with BuildKit enabled (default in 23.0+); Hadolint 2.12+; dive 0.12+; distroless images from `gcr.io/distroless`.

## Threat Model

- **Adversary 1 — CVE exploitation via installed tooling:** An attacker exploits a known CVE in a package (curl, libssl, git) that was included only because it was a build-time dependency. In a minimal image the package is absent and the attack path does not exist.
- **Adversary 2 — Post-exploitation lateral movement:** A remote code execution vulnerability in the application is exploited. The attacker attempts to download a reverse shell or pivot to adjacent services. Without a shell, wget, or curl in the image, standard post-exploitation tooling cannot execute.
- **Adversary 3 — Layer scraping for secrets:** An attacker with registry read access downloads the image and iterates layers with `docker history --no-trunc` or a tool like Dive, searching for credentials, tokens, or internal hostnames committed to a build-time `RUN` instruction or leftover in a cache directory.
- **Adversary 4 — Base image supply chain attack via tag mutation:** A public registry tag (`FROM golang:1.22`) is silently updated to point to a malicious image. The next build pulls the new image without any warning.
- **Access level:** Adversary 1 and 2 have application-level code execution. Adversary 3 has registry read access. Adversary 4 controls upstream image tags.
- **Blast radius:** Unmitigated, a compromised container with a full toolchain can be used as a pivot point. An image containing a secret exposes that secret to every registry consumer. A tag-mutated base image silently backdoors every subsequent build.

## Configuration

### Step 1: Structure the Builder Stage and Final Stage

The core principle is that the builder stage exists solely to produce a deployable artefact. The final stage copies only that artefact and nothing else.

```dockerfile
# syntax=docker/dockerfile:1

# --- Builder stage ---
# Uses a full SDK image. All build tools, caches, and source stay in this stage.
FROM golang:1.22@sha256:a6c6e2b1b3f2b4a9e0d4c3b8e7f1a2c5d4e6b9a1c8d2f3e4b5a7c9d0e1f2a3b4 AS builder

WORKDIR /build

# Copy dependency manifests first to take advantage of layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a statically linked binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /build/app ./cmd/server

# --- Final stage ---
# Distroless contains no shell, no package manager, no /bin/sh.
FROM gcr.io/distroless/static-debian12@sha256:b5b2d2a6b3c7e9f0a1d4c8e2b3f5a6d7c9e0b1f2a4c5d8e9b0a2c3d4e5f6a7b8

# Copy only the compiled binary.
COPY --from=builder /build/app /app

# Non-root user. distroless images ship with uid 65532 (nonroot).
USER nonroot:nonroot

ENTRYPOINT ["/app"]
```

What stays behind in the builder stage and never reaches production: the Go toolchain, the module download cache under `$GOPATH/pkg/mod`, the full source tree, any `_test.go` files, build scripts, and the `go.sum` file. The final image contains exactly one file: the compiled binary.

### Step 2: Choose the Right Final Base Image

The choice of final base image determines the attack surface floor.

**`scratch` — for fully static binaries**

`scratch` is Docker's empty image. There is no filesystem, no shell, no libc. The only thing that exists is what you `COPY` in. It is the smallest possible attack surface.

```dockerfile
FROM scratch
COPY --from=builder /build/app /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 65534:65534
ENTRYPOINT ["/app"]
```

Constraints: the binary must be fully statically compiled (`CGO_ENABLED=0`). TLS certificate bundles must be explicitly copied if the application makes outbound HTTPS calls. There is no `/etc/passwd`, so numeric UIDs must be used.

**`gcr.io/distroless` — for applications with runtime dependencies**

Google's distroless images provide a minimal OS layer without interactive tooling. The key variants:

| Image | Use case |
|---|---|
| `gcr.io/distroless/static-debian12` | Statically compiled Go binaries needing TLS certs and timezone data |
| `gcr.io/distroless/base-debian12` | Binaries requiring glibc |
| `gcr.io/distroless/java21-debian12` | JVM applications |
| `gcr.io/distroless/python3-debian12` | Python applications |
| `gcr.io/distroless/nodejs20-debian12` | Node.js applications |

None of these images contain a shell (`/bin/sh` does not exist), a package manager, or common utilities like `curl` or `wget`. Running `docker exec -it <container> /bin/sh` fails with `exec: /bin/sh: stat /bin/sh: no such file or directory`. This is the intended behaviour.

Distroless images do include a `nonroot` user at uid `65532`, which avoids the friction of adding user entries manually.

**For Java with Jlink**

Java applications can use `jlink` to produce a custom JRE containing only the modules the application requires, then copy that into a distroless base:

```dockerfile
FROM eclipse-temurin:21@sha256:c4b1e2d3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2 AS jlink-builder
RUN $JAVA_HOME/bin/jlink \
    --add-modules java.base,java.logging,java.sql,java.net.http \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --output /custom-jre

FROM gcr.io/distroless/base-debian12@sha256:d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3
COPY --from=jlink-builder /custom-jre /opt/java
COPY --from=builder /app.jar /app.jar
USER nonroot:nonroot
ENTRYPOINT ["/opt/java/bin/java", "-jar", "/app.jar"]
```

### Step 3: Pin Base Images by Digest, Not Tag

Image tags are mutable. `FROM golang:1.22` today may reference a different image tomorrow if the upstream maintainer pushes an update. Pinning by SHA-256 digest makes builds reproducible and immune to tag mutation attacks:

```dockerfile
# Mutable — vulnerable to tag reassignment.
FROM golang:1.22

# Immutable — the exact image layer set is cryptographically identified.
FROM golang:1.22@sha256:a6c6e2b1b3f2b4a9e0d4c3b8e7f1a2c5d4e6b9a1c8d2f3e4b5a7c9d0e1f2a3b4
```

Retrieve the current digest for any image:

```bash
# Pull and inspect the digest.
docker pull golang:1.22
docker inspect --format='{{index .RepoDigests 0}}' golang:1.22
# golang@sha256:a6c6e2b1b3f2b4a9e0d4c3b8e7f1a2c5d4e6b9a1c8d2f3e4b5a7c9d0e1f2a3b4

# Or use crane (part of the Google go-containerregistry toolset).
crane digest golang:1.22
```

Renovate and Dependabot both understand digest pins and will open automated PRs when upstream images are updated, giving you the reproducibility of digest pinning without the maintenance burden of manually tracking updates.

### Step 4: Verify No Build Artefacts Leak into the Final Stage

After building the image, use `docker history` and `dive` to confirm the final stage contains only what was intended.

**docker history — quick layer inspection**

```bash
docker build -t myapp:latest .
docker history --no-trunc myapp:latest
```

Each row shows the command that created a layer. For a correctly built minimal image the history should contain only `COPY`, `USER`, and `ENTRYPOINT` instructions. Any `RUN apt-get`, `RUN go build`, or `RUN npm install` in the history of the final image indicates a mistake — either the wrong base was used or build commands were run in the final stage instead of the builder stage.

**dive — layer-by-layer filesystem analysis**

`dive` renders an interactive view of every layer and the files it adds, modifies, or removes. It also reports the wasted space caused by files that are added in one layer and deleted in another (a common pattern in naive single-stage Dockerfiles):

```bash
# Install dive.
curl -Lo dive.deb https://github.com/wagoodman/dive/releases/download/v0.12.0/dive_0.12.0_linux_amd64.deb
dpkg -i dive.deb

# Interactive analysis.
dive myapp:latest

# Non-interactive CI check. Fails if wasted space exceeds threshold.
CI=true dive --ci-config .dive-ci.yaml myapp:latest
```

A `.dive-ci.yaml` configuration for CI gating:

```yaml
rules:
  lowestEfficiency: 0.95   # Fail if image efficiency drops below 95%.
  highestWastedBytes: 20MB # Fail if wasted bytes exceed 20 MB.
  highestUserWastedPercent: 0.20
```

Run `dive` in CI after every image build. A multi-stage build that accidentally runs `RUN apt-get install` in the final stage will immediately appear as wasted bytes.

### Step 5: Set a Non-Root USER in the Final Stage

Containers run as root by default. Even in a distroless image, running as root means a container escape vulnerability gives the attacker root on the host (if the container runtime is misconfigured) or root within the container namespace.

```dockerfile
FROM gcr.io/distroless/static-debian12@sha256:b5b2d2a6b3c7e9f0a1d4c8e2b3f5a6d7c9e0b1f2a4c5d8e9b0a2c3d4e5f6a7b8

COPY --from=builder /build/app /app

# distroless ships uid 65532 as "nonroot". Use it.
USER nonroot:nonroot

ENTRYPOINT ["/app"]
```

For scratch-based images, where `/etc/passwd` does not exist, use numeric UIDs directly:

```dockerfile
FROM scratch
COPY --from=builder /build/app /app
# 65534 is "nobody" — a conventional unprivileged uid.
USER 65534:65534
ENTRYPOINT ["/app"]
```

Kubernetes `PodSecurityAdmission` with the `restricted` profile will reject containers running as root, so setting a non-root USER in the Dockerfile aligns build-time and runtime policy.

### Step 6: Control File Permissions with COPY --chmod

Each `COPY` followed by a `RUN chmod` creates two layers — one for the file and one for the permission change. The `--chmod` flag on `COPY` sets permissions in a single instruction, keeping the final stage lean:

```dockerfile
# Two layers — file layer + permission layer.
COPY --from=builder /build/app /app
RUN chmod 0555 /app

# One layer — permission set at copy time (requires BuildKit).
COPY --chmod=0555 --from=builder /build/app /app
```

`0555` (read and execute for owner, group, world; no write) is the appropriate permission for an application binary that should never be modified at runtime.

### Step 7: Lint the Dockerfile with Hadolint

Hadolint parses Dockerfiles and reports violations of best practices. Key rules relevant to multi-stage build security:

| Rule | Description |
|---|---|
| DL3007 | `latest` tag used — use a specific tag or digest |
| DL3008 | `apt-get install` without pinned package versions |
| DL3009 | `apt-get lists` not deleted after install |
| DL3013 | `pip install` without `--no-cache-dir` |
| DL3020 | `ADD` used instead of `COPY` (ADD can fetch URLs, expanding attack surface) |
| DL3025 | `CMD` form used instead of `ENTRYPOINT` JSON form |
| DL4006 | `SHELL` changed without setting `pipefail` option |

```bash
# Run locally.
hadolint Dockerfile

# Run in CI (exit non-zero on any warning or error).
hadolint --failure-threshold warning Dockerfile

# Ignore specific rules with justification.
hadolint --ignore DL3008 Dockerfile
```

Integrate Hadolint into the CI pipeline as a mandatory pre-build gate. A Dockerfile that passes Hadolint is not automatically safe, but it rules out the most common structural mistakes.

```yaml
# GitHub Actions example.
- name: Lint Dockerfile
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: Dockerfile
    failure-threshold: warning
```

### Step 8: Minimise Layer Count in the Final Stage

Each instruction in a Dockerfile creates a layer. More layers mean more metadata, more surface for inspection, and marginally more overhead. In the final stage, combine related instructions and keep the total number of layers to the minimum required.

```dockerfile
# Final stage — target: three layers maximum.
FROM gcr.io/distroless/static-debian12@sha256:b5b2d2a6b3c7e9f0a1d4c8e2b3f5a6d7c9e0b1f2a4c5d8e9b0a2c3d4e5f6a7b8

# Layer 1: copy the binary with correct permissions in one instruction.
COPY --chmod=0555 --from=builder /build/app /app

# Layer 2: copy static assets if needed.
COPY --chmod=0444 --from=builder /build/config /config

# USER and ENTRYPOINT do not create filesystem layers.
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

The builder stage can have as many layers as useful — the layer cache speeds up incremental builds. It is only the final stage that ships to production and should be kept minimal.

### Step 9: Consider a Read-Only Root Filesystem

The Dockerfile cannot enforce a read-only root filesystem — that is a container runtime or Kubernetes concern — but the image should be designed to work with one. If the application writes nothing to the container filesystem at runtime, add documentation or a runtime configuration that enforces `readOnlyRootFilesystem: true`.

For applications that must write temporary files, designate specific writable paths and mount them as `emptyDir` volumes rather than making the entire filesystem writable:

```yaml
# Kubernetes PodSpec excerpt.
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

This is not a Dockerfile concern, but designing the application and image with a read-only root filesystem in mind prevents a class of persistence attacks where an attacker writes a backdoor to the container filesystem.

## Verification

After building the hardened image, run through the following checklist:

```bash
# 1. Confirm image size is in the expected range for a minimal image.
docker images myapp:latest --format "{{.Size}}"
# A static Go binary in distroless/static should be well under 20 MB.

# 2. Confirm no shell is present.
docker run --rm myapp:latest /bin/sh
# Should fail: exec: "/bin/sh": stat /bin/sh: no such file or directory

# 3. Confirm the process does not run as root.
docker run --rm myapp:latest id
# For distroless images this will fail (no id binary), which is expected.
# Inspect via runtime tools:
docker inspect myapp:latest | jq '.[0].Config.User'
# Should return "nonroot:nonroot" or "65534:65534"

# 4. Confirm no unexpected layers.
docker history myapp:latest
# Final stage should show only COPY, USER, ENTRYPOINT.

# 5. Run dive CI check.
CI=true dive myapp:latest

# 6. Scan for CVEs.
trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:latest
# A distroless/static image with a clean Go binary should report zero CVEs.
```

## Common Mistakes

**Running package installation in the final stage.** A `RUN apk add ca-certificates` in the final stage is a common workaround for missing TLS certificates. Copy the certificates from the builder stage instead: `COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/`.

**Copying the entire build context.** `COPY . .` in the builder stage copies the local `.git` directory, `.env` files, and local secrets into the build context. Use a `.dockerignore` file to exclude them:

```
.git
.env
*.local
node_modules
__pycache__
```

**Using `COPY --from=0` instead of named stages.** Numeric stage indices break if a stage is inserted earlier in the Dockerfile. Always name builder stages (`AS builder`) and reference them by name.

**Forgetting the `--no-install-recommends` flag in Debian-based builder stages.** Even though the builder stage does not ship to production, a clean builder reduces the CVE scan noise on intermediate image builds and speeds up the install step. Use `apt-get install -y --no-install-recommends` in all `apt-get` instructions.

**Using a distroless image but copying dynamic binaries.** A binary compiled with `CGO_ENABLED=1` or a Python script copied into `distroless/static` will fail at runtime with a dynamic linker error. Match the binary type to the distroless variant: static binaries to `distroless/static`, CGO binaries to `distroless/base`, Python scripts to `distroless/python3`.

## Summary

Multi-stage builds are the primary mechanism for eliminating build-time attack surface from production container images. The security posture of a well-constructed multi-stage build is materially better than a single-stage equivalent: the compiler is absent, the package cache is absent, the source tree is absent, and the binary is the only thing that ships.

The compounding controls covered here — distroless or scratch final bases, digest-pinned FROM instructions, non-root USER, `COPY --chmod` for minimal-layer permission setting, `docker history` and `dive` for artefact verification, and Hadolint for static Dockerfile analysis — form a defence-in-depth approach that addresses supply chain, runtime exploitation, and secret exposure threat vectors simultaneously.

Trivy or Grype scanning in CI closes the loop: a distroless image containing a statically compiled binary with no system packages will consistently report zero or near-zero CVEs, giving the pipeline a verifiable, auditable signal that the build process produced a minimal image.
