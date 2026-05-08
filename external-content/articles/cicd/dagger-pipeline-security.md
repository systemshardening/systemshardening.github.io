---
title: "Dagger Pipeline Security"
description: "Harden Dagger CI/CD pipeline-as-code deployments by securing the engine API socket, scoping container privileges, protecting secrets, and tracking silent security fixes in Dagger releases."
slug: dagger-pipeline-security
date: 2026-05-02
lastmod: 2026-05-02
category: cicd
tags: ["dagger", "pipeline-security", "container", "api-security", "secrets", "supply-chain"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 346
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cicd/dagger-pipeline-security/index.html"
---

# Dagger Pipeline Security

## Problem

Dagger is a pipeline-as-code platform where CI/CD pipelines are written in Go, Python, TypeScript, or PHP using the Dagger SDK. Instead of YAML-driven CI definitions, pipelines are real programs: functions that call the Dagger SDK to construct a directed acyclic graph of containerised build steps. This graph is submitted to the Dagger Engine, a Docker-based runtime that executes each step inside an isolated container, caches intermediate layers, and produces reproducible outputs that behave identically locally and in CI. The value proposition is significant — no more "works on my machine" CI failures, and pipelines that can be debugged with a single `dagger call` on a developer laptop.

The security model rests on the Dagger Engine, which runs as a privileged Docker container on the host. The engine exposes a GraphQL API over a Unix domain socket; the Dagger SDK connects to this socket and translates SDK method calls into GraphQL operations. Pipeline steps themselves execute as containers within the engine runtime, with privilege levels configured per-step. Secrets are passed to the engine using the `Secret` type, which is designed to prevent plaintext exposure in logs and API responses — the engine holds the secret value and injects it into containers only when needed, never returning the plaintext to the SDK caller.

The attack surface breaks into four distinct areas. First, the Dagger engine socket: any process that can connect to the engine's Unix socket has full pipeline execution capability — it can run arbitrary containers with the engine's Docker daemon access, read mounted volumes, and interact with the engine's secret store. If this socket is exposed beyond the intended client process (through permissive file permissions, or by the engine inadvertently binding a TCP listener), the blast radius extends to every process on the host. Second, pipeline steps that execute with elevated privileges: Dagger provides a `WithPrivileged` method in the SDK that grants a step full container privileges, equivalent to Docker's `--privileged` flag, enabling breakout to the host filesystem and Docker daemon. Third, secrets passed through the Dagger `Secret` type: while the type prevents secrets from appearing in log output, the secret value is still accessible to the container process via environment variables or mounted files. A malicious or compromised pipeline step can read the secret from its environment and exfiltrate it over the network. Fourth, Dagger modules: the Dagger ecosystem on `daggerverse.dev` allows any pipeline to import reusable modules with a single line of configuration. Imported modules execute with full pipeline engine access. There is no security vetting process, no mandatory code review, and no signature requirement for module publication.

Dagger's open-source release cadence introduces an additional challenge that is central to operating it securely. Dagger iterated from v0.9 to v0.13 in a single year, with changelog entries that mix features, performance improvements, and bug fixes without consistently flagging security-relevant changes. Several security-significant issues have been fixed in point releases without CVEs or advisories, making passive monitoring of release notes insufficient.

The engine API socket binding issue is the clearest example. In certain deployment configurations, the Dagger engine bound its API listener to `0.0.0.0` rather than `127.0.0.1`, meaning any process on the same host — or on the same network if no firewall was in place — could connect to the engine and execute pipeline steps. The fix appeared in a point release with a commit message describing it as a networking configuration correction; no CVE was filed and no security advisory was issued. An operator relying on GitHub release notes alone would not have known a security-relevant change had occurred.

A second silent fix addressed privilege inheritance on Dagger pipeline steps. In certain engine configurations, the `--privileged` flag from the host engine was inherited by child step containers even when the pipeline author did not explicitly call `WithPrivileged`. This silently granted steps host-level access beyond what the pipeline intended. The fix was merged without a security advisory.

A third issue involved the digest pinning mechanism in `dagger.json`. When a Dagger module is imported, its source is pinned by content digest in `dagger.json`, providing a supply chain integrity guarantee. A bug caused digest verification to be skipped for certain module versions, meaning an attacker who could manipulate a module's published content at the source could serve a different version than the one the pipeline author pinned. This was resolved in a pull request titled "fix module digest verification" — again, no CVE, no advisory.

Tracking these fixes requires active monitoring rather than passive release note consumption. Subscribe to `https://github.com/dagger/dagger/releases` via GitHub's watch feature. Watch for commits to the `engine/` and `auth/` directories in the Dagger repository, which are the most likely locations for socket-binding, privilege, and authentication changes. Use the GitHub API to filter commits by security-relevant keywords:

```bash
gh api repos/dagger/dagger/commits \
  --jq '.[] | select(.commit.message | test("socket|privilege|secret|auth|fix"; "i")) | {sha: .sha[0:8], msg: .commit.message[0:80]}'
```

Verify that all modules in `dagger.json` are pinned to a full SHA-256 digest, and audit module source code before importing any new module. Enable Renovate or Dependabot to track `dagger.json` module digest updates.

**Target systems:** Dagger Engine 0.11+, Docker Engine 25+, GitHub Actions / GitLab CI.

## Threat Model

1. **Engine socket exposure via 0.0.0.0 binding.** An attacker on the same CI runner host — another CI job, a rogue process, or a container with host network access — connects to the Dagger engine API port. Because the engine has no authentication on the socket by default, the attacker submits a pipeline step that mounts the engine's secret store, reads registry credentials and API keys stored as `Secret` objects, and exfiltrates them over HTTP. This scenario is directly enabled by the historical socket-binding misconfiguration.

2. **Malicious Dagger module from daggerverse.dev.** A platform engineer imports a Dagger module for Go linting from `daggerverse.dev`. The module was published by a single contributor six months ago, has not been reviewed, and contains a step that reads all environment variables and `Secret`-type values accessible to the pipeline, then sends them to an attacker-controlled endpoint via an outbound HTTPS request. Because the module executes inside the Dagger engine with the same access as first-party pipeline steps, it can access any secret the engine holds for the current pipeline run.

3. **Patch-gap attacker.** An attacker monitors the public Dagger GitHub repository and identifies the commit that fixed the `0.0.0.0` socket binding. The attacker extracts the affected version range from the commit diff and scans public CI runner IP ranges with `curl http://<runner-ip>:<engine-port>/query` to identify runners still operating unfixed Dagger versions. Runners on shared or self-hosted infrastructure that have not updated are discovered and exploited to exfiltrate CI secrets. This attack is exclusively enabled by the absence of a CVE or advisory that would have triggered automated update tooling.

4. **Unintentional privilege escalation via WithPrivileged inheritance.** A pipeline step is intended to run a Docker build inside the Dagger engine using a Docker-in-Docker pattern. The pipeline author does not call `WithPrivileged` explicitly, expecting the engine to enforce least privilege. Due to the privilege inheritance bug (now fixed, but exploitable on unpatched engines), the step receives host-level privileges. The step reads host filesystem paths mounted into the engine container, accesses Docker socket credentials, and poisons the shared Docker image layer cache with a backdoored base image used by subsequent pipeline runs.

The blast radius in all four scenarios extends beyond the immediately compromised pipeline. Dagger engines are often reused across pipeline runs within a session, meaning secrets from one run's secret store may still be accessible in a subsequent run. Registry credentials typically grant push access, making image poisoning a secondary consequence of initial secret exfiltration. On shared persistent runners, host credential files and Docker configuration are accessible to any container that achieves privilege escalation.

## Configuration / Implementation

### Engine Socket Hardening

The Dagger engine socket should be accessible only to the process that invoked it. Explicitly specify a Unix socket path when initialising the engine and restrict permissions immediately after the socket is created:

```bash
# Initialise Dagger engine with explicit Unix socket binding
dagger engine init --listen unix:///run/dagger/engine.sock

# Restrict socket permissions to owner only
chmod 600 /run/dagger/engine.sock

# Set the SDK to connect via the Unix socket (not a TCP address)
export DAGGER_ENGINE_HOST=unix:///run/dagger/engine.sock
```

Verify that no TCP listener is present for the engine port after startup:

```bash
# Confirm no TCP listener on the default engine port (typically 8080 or 2746)
ss -tlnp | grep -E '8080|2746'
# Expected: no output

# Confirm the Unix socket exists and has restrictive permissions
ls -la /run/dagger/engine.sock
# Expected: srw------- (mode 600)
```

In CI environments where the Dagger engine runs as a Docker container, ensure the container does not publish ports:

```bash
# Bad: publishes engine API to all interfaces on the host
docker run --rm -d --name dagger-engine \
  -p 8080:8080 \
  registry.dagger.io/engine:v0.13.0

# Good: no port publishing; access via exec or named socket
docker run --rm -d --name dagger-engine \
  -v /run/dagger:/run/dagger \
  registry.dagger.io/engine:v0.13.0
```

### Privilege Scoping for Pipeline Steps

Avoid `WithPrivileged` in pipeline code unless the step genuinely requires host-level access. For the vast majority of build steps, running as a non-root user with no additional capabilities is correct:

```go
// Go SDK: build step scoped to nonroot user with no-new-privileges
package main

import (
    "context"
    "dagger.io/dagger"
)

func main() {
    ctx := context.Background()
    client, err := dagger.Connect(ctx)
    if err != nil {
        panic(err)
    }
    defer client.Close()

    _, err = client.Container().
        From("golang:1.22-alpine").
        WithUser("nonroot").
        WithSecurityOpts([]string{"no-new-privileges"}).
        WithExec([]string{"go", "build", "./..."}).
        Sync(ctx)
    if err != nil {
        panic(err)
    }
}
```

Audit all Dagger pipeline files for privilege escalation calls before merging:

```bash
# Find WithPrivileged calls across all pipeline files
grep -r "WithPrivileged\|privileged" .dagger/

# Find AsService calls that might expose internal ports — review each
grep -r "AsService\|WithExposedPort" .dagger/
```

In CI, add this audit as a pipeline gate:

```bash
# Fail the pipeline if any WithPrivileged call is present without explicit approval
if grep -r "WithPrivileged" .dagger/ | grep -v "// approved-privileged"; then
    echo "ERROR: Unapproved WithPrivileged call detected"
    exit 1
fi
```

### Secret Handling Best Practices

Pass secrets to Dagger using the `Secret` type, never as plain string arguments or environment variables set with `WithEnvVariable`:

```go
// Go SDK: correct secret handling
func buildWithSecret(ctx context.Context, client *dagger.Client) {
    // Correct: secret injected via SetSecret, accessible to container but not logged
    registryPassword := client.SetSecret("registry-password", os.Getenv("REGISTRY_PASSWORD"))

    _, err := client.Container().
        From("alpine:3.19").
        WithSecretVariable("REGISTRY_PASSWORD", registryPassword).
        WithExec([]string{"sh", "-c", "docker login -u user -p $REGISTRY_PASSWORD registry.example.com"}).
        Sync(ctx)

    // Incorrect: secret value appears in Dagger API call logs and GraphQL traces
    // WithEnvVariable("REGISTRY_PASSWORD", os.Getenv("REGISTRY_PASSWORD"))
}
```

Verify no secrets are passed as pipeline arguments exposed in `dagger.json` or `--help` output:

```bash
# Check what arguments a pipeline function exposes — secrets must not appear here
dagger call build --help

# Review dagger.json for any hardcoded values that should be secrets
cat dagger.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d, indent=2))"
```

Secrets mounted as files should use a dedicated tmpfs or in-memory path and be cleaned up after the step:

```go
// Mount secret as a file rather than environment variable for tools that read from disk
_, err := client.Container().
    From("alpine:3.19").
    WithMountedSecret("/run/secrets/api-key", apiKeySecret).
    WithExec([]string{"some-tool", "--key-file", "/run/secrets/api-key"}).
    Sync(ctx)
```

### Dagger Module Security

Pin all imported modules by SHA-256 content digest in `dagger.json`, not by tag or branch:

```json
{
  "name": "my-pipeline",
  "sdk": "go",
  "dependencies": [
    {
      "name": "golang",
      "source": "github.com/purpleclay/daggerverse/golang@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      "pin": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    }
  ]
}
```

Before importing any module from `daggerverse.dev`, review the source code:

```bash
# Clone the module repository and review before importing
gh repo clone purpleclay/daggerverse
cd daggerverse/golang
# Review: Does the module make outbound network calls?
grep -r "http\|curl\|wget\|net/http" .
# Review: Does the module access environment variables beyond what it needs?
grep -r "os.Getenv\|env\." .
```

Assess module trustworthiness:
- Prefer modules with multiple contributors and recent commit activity
- Reject modules with no tests, no CI, or a single anonymous contributor
- Use a private Dagger module registry for sensitive pipelines rather than importing from `daggerverse.dev`

For sensitive pipelines, host internal modules in a private repository and reference them directly:

```json
{
  "dependencies": [
    {
      "name": "internal-builder",
      "source": "github.com/your-org/internal-dagger-modules/builder@sha256:<digest>",
      "pin": "sha256:<digest>"
    }
  ]
}
```

### Monitoring Dagger Releases for Silent Fixes

Do not rely solely on release notes. Use the GitHub API to identify security-relevant commits across Dagger releases:

```bash
# Scan recent Dagger releases for security keywords in release body text
gh api repos/dagger/dagger/releases \
  --jq '.[0:5] | .[] | {tag: .tag_name, body: .body}' \
  | grep -i "fix\|security\|socket\|privilege\|secret"

# Monitor commits to security-relevant engine directories
gh api "repos/dagger/dagger/commits?path=engine/&per_page=20" \
  --jq '.[] | select(.commit.message | test("socket|privilege|secret|auth|fix"; "i")) | {sha: .sha[0:8], msg: .commit.message[0:80], date: .commit.author.date}'

# Monitor the auth directory specifically
gh api "repos/dagger/dagger/commits?path=auth/&per_page=20" \
  --jq '.[] | {sha: .sha[0:8], msg: .commit.message[0:80]}'
```

Configure Renovate or Dependabot to track Dagger Engine version and module digest updates:

```json
// renovate.json — track Dagger engine version in CI workflow files
{
  "customManagers": [
    {
      "customType": "regex",
      "fileMatch": ["\\.github/workflows/.*\\.ya?ml$"],
      "matchStrings": ["registry\\.dagger\\.io/engine:(?<currentValue>[^\\s\"]+)"],
      "datasourceTemplate": "docker",
      "depNameTemplate": "registry.dagger.io/engine"
    }
  ]
}
```

### CI Runner Isolation

Run Dagger in ephemeral CI runners, not shared persistent runners. On GitHub Actions:

```yaml
# .github/workflows/pipeline.yml
jobs:
  build:
    runs-on: ubuntu-24.04   # Ephemeral GitHub-hosted runner; destroyed after job
    steps:
      - uses: actions/checkout@v4
      - name: Run Dagger pipeline
        env:
          DAGGER_ENGINE_HOST: unix:///run/dagger/engine.sock
        run: |
          dagger call build
```

When Dagger must access Docker, prefer Docker-in-Docker (DinD) over mounting the host Docker socket. Mounting `/var/run/docker.sock` into the Dagger engine container grants the engine (and any pipeline step it runs) full control over the host Docker daemon, including access to all images, volumes, and running containers:

```yaml
# GitLab CI: Docker-in-Docker isolation
build:
  image: registry.dagger.io/engine:v0.13.0
  services:
    - name: docker:25-dind
      alias: docker
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_VERIFY: "1"
    DOCKER_CERT_PATH: /certs/client
    DAGGER_ENGINE_HOST: unix:///run/dagger/engine.sock
  script:
    - dagger call build
```

## Expected Behaviour

| Signal | Default Dagger Config | Hardened Config |
|---|---|---|
| Engine socket accessible from network | Possible if engine binds to `0.0.0.0` (historical bug); no auth required | Socket at `unix:///run/dagger/engine.sock`, mode 600; no TCP listener; `ss -tlnp` shows nothing |
| Privileged step container escape | Step inherits engine privileges in unpatched versions; no explicit block | `WithUser("nonroot")` and `WithSecurityOpts(["no-new-privileges"])` on all steps; CI gate rejects `WithPrivileged` without approval comment |
| Secret value in log output | Possible if secret passed via `WithEnvVariable` with plaintext string | All secrets use `client.SetSecret` and `WithSecretVariable`; Dagger engine masks value in GraphQL traces |
| Malicious module execution | Module imported by name/tag with no digest verification; executes on import | Module pinned by SHA-256 digest in `dagger.json`; source reviewed before import; digest verified on each `dagger install` |
| Patch-gap exploit window | No CVE/advisory means automated update tools do not trigger; runners stay unpatched for weeks | GitHub API commit monitoring script runs in CI on a schedule; Renovate tracks engine image version; runner updates within 24 hours of fix commit |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Socket restriction to Unix path (mode 600) | Eliminates network-reachable engine API; prevents cross-process socket access | Breaks remote Dagger engine use cases where multiple hosts share an engine | Use Dagger Cloud or a dedicated engine host with mTLS rather than raw socket exposure |
| Privilege scoping (`WithUser("nonroot")`) | Prevents privilege escalation to host from pipeline steps | Some build tools (rpm, dpkg, certain Docker builds) require root inside the container | Run privileged steps in a separate isolated pipeline stage; document and approve each `WithPrivileged` call |
| Module digest pinning in `dagger.json` | Guarantees bit-for-bit reproducibility; prevents module tampering after pinning | Requires manual digest lookup on first import; `dagger install` must be re-run to update digests | Use `dagger install <module>` which writes the digest automatically; Renovate tracks digest updates |
| Ephemeral CI runners | Engine state does not persist between runs; secrets from run N are not accessible in run N+1 | Cold start overhead: Dagger engine initialisation and layer cache rebuilding adds 2–5 minutes per run | Use Dagger Cache Volumes backed by an external cache service (e.g., S3) to warm the layer cache without persisting the engine |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Socket permission too restrictive (mode 600, wrong owner) | Pipeline fails immediately with `permission denied` connecting to `/run/dagger/engine.sock` | `dagger call` exits non-zero; error message contains `connect: permission denied` or `no such file or directory` | Verify socket owner matches the CI user with `ls -la /run/dagger/engine.sock`; adjust with `chown` or ensure engine is started by the same user that runs `dagger call` |
| Secret passed via `WithEnvVariable` instead of `WithSecretVariable` | Secret value appears in Dagger GraphQL API trace output and potentially in CI log artifacts | Grep CI log output for known secret prefixes; `grep -i "AKIA\|ghp_\|glpat" <ci-log-file>` | Rotate the exposed credential immediately; update pipeline code to use `client.SetSecret` and `WithSecretVariable`; audit all `WithEnvVariable` calls for secret-like values |
| Module digest mismatch in `dagger.json` | `dagger install` or `dagger call` fails with digest verification error; pipeline does not run | Error message: `module digest mismatch: expected sha256:... got sha256:...`; pipeline exits before any step runs | Do not override the digest check; investigate why the module content changed (upstream compromise or legitimate update); re-pin after verifying the new source is trustworthy |
| Dagger engine version incompatible with SDK version | Pipeline fails with GraphQL schema errors or unrecognised API methods | `dagger call` exits with `field ... not found on type ...` or `unknown directive`; SDK version visible in `go.mod` or `package.json` | Pin SDK and engine version together; update both in the same PR; check the Dagger compatibility matrix in the release notes for the SDK version in use |

## Related Articles

- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [BuildKit Rootless Security](/articles/cicd/buildkit-rootless-security/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Securing CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
