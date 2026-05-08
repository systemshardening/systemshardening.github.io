---
title: "Docker BuildKit Cache Security: Preventing Cache Poisoning in CI/CD"
description: "BuildKit's cache backends — inline, registry, S3, and GitHub Actions — each carry distinct poisoning risks. This guide covers cache attack surface mapping, registry access controls, secrets in ARG vs --secret, multi-stage isolation, and provenance verification after cache-assisted builds."
slug: buildkit-cache-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - buildkit
  - docker
  - cache-poisoning
  - container-build
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 534
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/buildkit-cache-security/
---

# Docker BuildKit Cache Security: Preventing Cache Poisoning in CI/CD

## Problem

BuildKit's cache is one of the most effective performance tools in a CI/CD pipeline — and one of the most quietly dangerous. A cold Go module download that takes four minutes becomes a two-second cache hit. That speed comes from storing intermediate build layers in a location that multiple builds, multiple pipelines, and potentially multiple teams can read from. Every entity that can write to that location can inject content into future builds without triggering a rebuild.

Cache poisoning in this context is not a theoretical attack. It is a direct consequence of how build caches work: if a cache entry exists for a given key, BuildKit trusts it and skips re-execution. An attacker who can write a crafted entry for a key that a legitimate build will later request has effectively pre-positioned code in the output image. The build succeeds with a green check. No source code changed. No dependency was bumped. The malicious layer simply appeared, indistinguishable from a legitimate cached result.

The attack surface spans the full cache lifecycle. The `--cache-from` flag instructs BuildKit to pull cache from a registry. If that registry is compromised, or if an attacker can push to it, every pipeline using that registry cache is affected. The GitHub Actions `type=gha` cache backend stores compressed layer tarballs in the Actions cache service, keyed by strings that include branch names — branch names that any contributor with push access can control. S3-backed caches are as secure as the bucket policy, and overly permissive write policies are common in development environments that were never hardened for production use.

Build secrets compound the problem. The most common way developers pass credentials into a build — `ARG GITHUB_TOKEN` followed by `RUN git clone https://${GITHUB_TOKEN}@github.com/...` — embeds the secret in the image layer history. Anyone who can pull the image and run `docker history --no-trunc` can read it. This is not a BuildKit-specific failure; it is a consequence of how OCI image layers work. BuildKit provides `--secret` as a correct alternative, but the wrong pattern is prevalent and not rejected by the build system.

Multi-stage builds offer a partial mitigation for both cache isolation and secret leakage. Secrets used in an early stage do not propagate to later stages if the final `COPY --from=` instructions are scoped correctly. But cache entries for early stages still exist in the cache backend, and those entries may reference a stage that processed sensitive data.

**Target systems:** BuildKit v0.12+, Docker Buildx v0.12+, GitHub Actions with `docker/build-push-action` v4+, GitLab CI with Docker-in-Docker or BuildKit daemon, S3-compatible cache backends (AWS S3, MinIO), GHCR and ECR as registry cache targets.

## Threat Model

1. **Attacker with write access to the cache registry poisons a layer.** The cache registry namespace (`myrepo/cache:buildcache`) has write permissions that are broader than the production image namespace. A CI job on a feature branch has write access to the cache ref. The attacker crafts a build that populates the cache with a malicious layer for a frequently reused step — for example, the `apt-get install` stage of a base image. The next production build pulls from that cache, incorporates the malicious layer, and produces a backdoored image without any code change in the repository.

2. **Branch-controlled cache key poisoning in GitHub Actions.** The GitHub Actions `type=gha` cache backend keys entries by the string passed to `cache-to`. If the cache key includes a value derived from `github.ref` or `github.head_ref`, a contributor who can create a branch with a carefully chosen name can collide with or shadow an existing cache entry used by the main branch build. The poisoned entry is then read back by a privileged workflow.

3. **S3 cache bucket with excessive write permissions.** A shared S3 bucket used as a BuildKit cache backend is configured with `s3:PutObject` permissions granted to all IAM roles in the account, or to a `*` principal within the VPC. A compromised build runner, a developer workstation with ambient AWS credentials, or a misconfigured IRSA binding can write arbitrary objects into the bucket under keys that match expected cache paths. Versioning is disabled, so the poisoned object replaces the legitimate one without recovery path.

4. **`ARG`-based secret leakage into image layers.** A Dockerfile passes a GitHub PAT as a build argument to clone a private dependency. The PAT is captured in the layer created by the `RUN git clone` instruction. The image is pushed to a registry that developers use for local testing. Six months later, the developer's access is revoked, but the PAT is still readable from any pulled copy of the image by anyone with registry read access.

5. **`--cache-from` pointing to an uncontrolled registry.** A developer sets `--cache-from type=registry,ref=docker.io/thirdparty/baseimage` to accelerate builds using a public image's cache manifest. The third-party image owner pushes a new manifest with a crafted cache entry. BuildKit pulls and applies it during the next build, incorporating a malicious layer into the output.

**Blast radius without controls:** A poisoned cache entry propagates to every build that reuses the affected cache key until the cache is explicitly invalidated. In a monorepo with a shared base image stage, that can mean every application image built by the organization. Secret leakage from `ARG` persists in every pushed copy of the affected image for the image's lifetime.

## Configuration / Implementation

### Mapping your cache backends

Before hardening anything, enumerate which cache backends each pipeline actually uses. BuildKit supports four: inline (embedded in the image manifest), registry (a separate image ref), GitHub Actions (the `type=gha` backend), and S3. Each has a different write-access boundary.

```bash
# Search CI configuration for cache-to and cache-from directives
grep -r 'cache-to\|cache-from\|BUILDKIT_INLINE_CACHE' \
  .github/ .gitlab-ci.yml Makefile docker-compose*.yml \
  --include="*.yml" --include="*.yaml" --include="Makefile" 2>/dev/null

# For docker-compose files that build images
grep -r 'cache_from\|cache_to' . --include="*.yml" --include="*.yaml"
```

Classify each cache reference by who can write to it. Registry caches are only as secure as the registry namespace access controls. S3 caches depend on the bucket policy. The `type=gha` cache is controlled by GitHub's cache service scoped to the repository — but branch permissions matter.

### Registry cache: restricting write access

The most common registry cache pattern pushes to a dedicated ref in GHCR or ECR. The security invariant is: **only the CI system that produces release artifacts should be able to write to the cache ref.** Developer workstations, feature-branch jobs, and third-party forks should have read-only access at most.

On GHCR, this means using a dedicated bot or machine account whose PAT has `write:packages` scope only for the cache namespace, and ensuring that `GITHUB_TOKEN` in fork PRs does not inherit write access to the cache ref:

```yaml
# .github/workflows/build.yml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write   # only granted to the main branch job

    steps:
      - uses: actions/checkout@v4

      - name: Set up Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # Pull cache from the locked main-branch ref; write only on main
      - name: Build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          provenance: true
          sbom: true
          cache-from: type=registry,ref=ghcr.io/${{ github.repository }}/cache:main
          cache-to: ${{ github.ref == 'refs/heads/main' && format('type=registry,ref=ghcr.io/{0}/cache:main,mode=max', github.repository) || '' }}
```

The `cache-to` expression is empty for all non-main branches. Feature-branch builds read from the main-branch cache but cannot overwrite it. Fork PRs receive a `GITHUB_TOKEN` with no `write:packages` permission by default, so even the read-only pull requires the cache ref to be public or the token to be explicitly scoped.

On ECR, create a separate repository for cache images and apply a resource policy that grants `ecr:PutImage` and `ecr:InitiateLayerUpload` only to the CI role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CacheWriteOnlyCIRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ci-builder-role"
      },
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage"
      ]
    },
    {
      "Sid": "CacheReadAllBuilders",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:DescribeImages"
      ]
    }
  ]
}
```

### GitHub Actions cache security

The `type=gha` backend uses the Actions cache service, which scopes entries to the repository and branch. The security risks are specific to how cache keys are constructed.

Cache keys that include user-controlled data — branch names, PR titles, commit message substrings — can be manipulated. If your cache key is `buildkit-${{ github.ref_name }}-${{ hashFiles('Dockerfile') }}`, an attacker who creates a branch named `main` in a fork does not collide (fork caches are isolated), but in a repository where contributors have push access to arbitrary branch names, a branch named to match an existing key can shadow the cached entry.

Use a fixed, content-addressed component in every cache key:

```yaml
- name: Build with GHA cache
  uses: docker/build-push-action@v5
  with:
    context: .
    cache-from: type=gha,scope=buildkit-main
    cache-to: type=gha,scope=buildkit-main,mode=max
```

The `scope` parameter isolates cache entries by an explicit label rather than a derived branch name. Combine this with a `paths` hash of the files that determine cache validity:

```yaml
- name: Compute cache key
  id: cache-key
  run: |
    echo "key=buildkit-$(sha256sum Dockerfile go.sum | sha256sum | cut -c1-16)" >> "$GITHUB_OUTPUT"

- name: Build
  uses: docker/build-push-action@v5
  with:
    context: .
    cache-from: type=gha,scope=${{ steps.cache-key.outputs.key }}
    cache-to: type=gha,scope=${{ steps.cache-key.outputs.key }},mode=max
```

Restrict which workflows can write to the Actions cache by using environment protection rules. Cache writes from jobs that run in a protected environment require a reviewer approval, preventing automated feature-branch builds from contaminating the shared cache.

### S3 cache backend: bucket policy and encryption

The BuildKit S3 cache backend (`type=s3`) stores layer blobs and a manifest index in an S3-compatible bucket. A misconfigured bucket is the most common source of persistent cache poisoning in self-hosted CI.

Minimum required controls:

1. **Restrict `s3:PutObject` to the CI IAM role.** No other principal should be able to write to the cache prefix.
2. **Enable versioning** so a poisoned object can be rolled back without wiping the entire cache.
3. **Enable server-side encryption** (SSE-S3 or SSE-KMS) at the bucket level.
4. **Block public access** at the bucket and account level.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-buildkit-cache",
        "arn:aws:s3:::my-buildkit-cache/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "AllowCIRoleReadWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ci-builder-role"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-buildkit-cache",
        "arn:aws:s3:::my-buildkit-cache/*"
      ]
    },
    {
      "Sid": "AllowOtherRolesReadOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-buildkit-cache",
        "arn:aws:s3:::my-buildkit-cache/*"
      ]
    }
  ]
}
```

Enable versioning and SSE-KMS via the AWS CLI:

```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket my-buildkit-cache \
  --versioning-configuration Status=Enabled

# Enable SSE-KMS encryption
aws s3api put-bucket-encryption \
  --bucket my-buildkit-cache \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Block all public access
aws s3api put-public-access-block \
  --bucket my-buildkit-cache \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

Invoke the S3 backend in builds:

```bash
docker buildx build \
  --cache-from type=s3,region=us-east-1,bucket=my-buildkit-cache,prefix=myapp/ \
  --cache-to type=s3,region=us-east-1,bucket=my-buildkit-cache,prefix=myapp/,mode=max \
  --tag myrepo/myapp:latest \
  .
```

To recover from a suspected poisoning event, roll back the cache manifest to the last known-good version:

```bash
# List object versions for the cache manifest
aws s3api list-object-versions \
  --bucket my-buildkit-cache \
  --prefix myapp/index.json \
  --query 'Versions[*].{VersionId:VersionId,LastModified:LastModified}' \
  --output table

# Restore a specific version
aws s3api copy-object \
  --bucket my-buildkit-cache \
  --copy-source "my-buildkit-cache/myapp/index.json?versionId=<known-good-version-id>" \
  --key myapp/index.json
```

### Cache backend comparison

| Backend | Write access boundary | Poisoning recovery | Encryption | Use case |
|---|---|---|---|---|
| `type=inline` | Anyone who can push the image | Pull a clean image | Registry TLS + encryption at rest | Single-image builds, no shared cache |
| `type=registry` | Registry namespace access control | Delete + repush the cache ref | Registry TLS + encryption at rest | Shared CI caches with IAM-controlled registries |
| `type=gha` | GitHub Actions cache service (repo-scoped) | Delete via API or cache key rotation | GitHub-managed | GitHub Actions pipelines with branch-aware scoping |
| `type=s3` | S3 bucket policy + IAM roles | Object versioning rollback | SSE-S3 or SSE-KMS | Self-hosted CI with fine-grained IAM control |

### Secrets in ARG vs --secret

`ARG` values are captured in the build metadata of the layer created by the `RUN` instruction that consumes them. This is a property of how BuildKit records the command string in the layer's config, not a bug that can be patched with a `RUN unset`. The value persists in the image and is visible to anyone with `docker inspect` or `docker history --no-trunc` access.

```dockerfile
# INSECURE: ARG value appears in docker history
ARG GITHUB_TOKEN
RUN git clone https://${GITHUB_TOKEN}@github.com/myorg/private-repo.git /src
```

```bash
# The token is readable from the image
docker history --no-trunc myrepo/myapp:latest | grep GITHUB_TOKEN
# => /bin/sh -c git clone https://ghp_xxxxxxxxxxxx@github.com/...
```

The `--secret` flag mounts a value as a tmpfs file that is available only within the scope of the `RUN --mount=type=secret` instruction. It does not appear in the layer command string, the image config, or any layer filesystem.

```dockerfile
# syntax=docker/dockerfile:1.6
FROM alpine AS builder

# Secret is mounted at /run/secrets/github_token, not in layer history
RUN --mount=type=secret,id=github_token \
    git clone https://$(cat /run/secrets/github_token)@github.com/myorg/private-repo.git /src

FROM alpine
COPY --from=builder /src/dist /app
```

```bash
# Pass the secret at build time
docker buildx build \
  --secret id=github_token,env=GITHUB_TOKEN \
  --tag myrepo/myapp:latest \
  .

# Verify: secret should not appear in history
docker history --no-trunc myrepo/myapp:latest | grep -i token
# No output expected

# Verify: secret should not exist in any layer filesystem
docker create --name tmp-inspect myrepo/myapp:latest
docker export tmp-inspect | tar -tv | grep -i github_token
docker rm tmp-inspect
# No output expected
```

If you need to pass a secret as a file (for example, an `.npmrc` or `pip.conf`):

```bash
docker buildx build \
  --secret id=npmrc,src="${HOME}/.npmrc" \
  --tag myrepo/myapp:latest \
  .
```

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci --ignore-scripts
```

### Multi-stage builds as cache isolation

Multi-stage builds divide a Dockerfile into named stages. Each stage has its own cache entries. The final image contains only the filesystem state explicitly copied from earlier stages — not their cache entries, environment variables, or secrets.

Use this structure to isolate the stages that require sensitive access from the stages that produce the final artifact:

```dockerfile
# syntax=docker/dockerfile:1.6

# Stage 1: dependency fetch — needs secrets, builds a cache entry
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    --mount=type=cache,id=npm-cache-myapp,target=/root/.cache/npm \
    npm ci --ignore-scripts

# Stage 2: compilation — no secrets, no network needed
FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN --network=none node_modules/.bin/tsc --outDir dist

# Stage 3: runtime image — contains only compiled output
FROM node:22-alpine AS runtime
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=deps /app/node_modules ./node_modules
USER node
CMD ["node", "dist/server.js"]
```

The `deps` stage cache entry contains the fetched dependencies but not the secret — the secret was never written to any filesystem path within the layer. The `runtime` stage has no dependency on the `deps` cache entry other than the explicit `COPY --from=deps`. A poisoned `deps` cache entry would cause a build failure (corrupt `node_modules`) rather than silently embedding malicious content in the runtime image, provided you add an integrity check:

```dockerfile
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    --mount=type=cache,id=npm-cache-myapp,target=/root/.cache/npm \
    npm ci --ignore-scripts && \
    # Verify integrity after install — fails if node_modules was tampered with
    npm audit --audit-level=high
```

### Verifying provenance after cache-assisted builds

A build that used a cache backend is harder to reason about than a clean build. You cannot inspect the source of a cache hit the way you can inspect a Dockerfile instruction. Provenance attestations capture what actually happened, including the cache source.

Enable provenance generation in all builds:

```bash
docker buildx build \
  --provenance=true \
  --sbom=true \
  --cache-from type=registry,ref=ghcr.io/myorg/cache:main \
  --tag ghcr.io/myorg/myapp:latest \
  --push \
  .
```

Inspect the provenance attestation to verify which cache sources were used:

```bash
# Pull and decode the provenance attestation
docker buildx imagetools inspect ghcr.io/myorg/myapp:latest \
  --format '{{ json .Provenance.SLSA }}'
```

The SLSA provenance includes a `materials` list that enumerates all inputs to the build, including cache references. If a cache source appears that is not in your expected allow-list, the build should be treated as suspect.

For release builds, disable the cache entirely and verify the resulting image digest against the provenance before promoting:

```bash
# Release build: no cache, pull fresh base images
docker buildx build \
  --no-cache \
  --pull \
  --provenance=true \
  --sbom=true \
  --tag ghcr.io/myorg/myapp:${{ github.ref_name }} \
  --push \
  .

# Sign the image with Cosign
cosign sign \
  --key cosign.key \
  ghcr.io/myorg/myapp:${{ github.ref_name }}

# Verify before deployment
cosign verify \
  --key cosign.pub \
  ghcr.io/myorg/myapp:${{ github.ref_name }}
```

For continuous builds (non-release), establish a baseline digest for the cache ref and alert when it changes unexpectedly:

```bash
# Record the current cache manifest digest
CURRENT_DIGEST=$(docker buildx imagetools inspect \
  ghcr.io/myorg/cache:main \
  --format '{{ .Manifest.Digest }}')

# Compare against the last recorded digest (stored in CI environment or secret)
if [ "$CURRENT_DIGEST" != "$EXPECTED_DIGEST" ]; then
  echo "Cache manifest digest changed unexpectedly: $CURRENT_DIGEST"
  echo "Expected: $EXPECTED_DIGEST"
  exit 1
fi
```

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| Feature branch writes to cache ref | Any workflow can push to the shared cache ref; feature branch jobs overwrite main-branch cache entries | `cache-to` is empty for non-main branches; only the main workflow has `write:packages` permission; feature branches read-only |
| ARG-based secret in history | `docker history --no-trunc` shows the token value in the RUN instruction command string; crane export reveals no secret file | `docker history` shows `RUN --mount=type=secret,...` with no secret value; no secret file present in any layer |
| S3 cache object replaced by non-CI principal | Any IAM principal in the account can overwrite cache objects; no version history; poisoned object silently used | Only `ci-builder-role` has `s3:PutObject`; versioning enabled; unauthorized write is denied; previous version recoverable |
| Release build uses cached layer | Release image silently incorporates layers from the shared cache; cache source not recorded | `--no-cache --pull` produces a fully clean build; SLSA provenance lists no cache materials; image signed and digest verified before deployment |
| GHA cache key collision | Cache key derived from `github.ref_name`; attacker with push access creates a branch whose name collides with the main cache scope | Cache key uses `scope=` with a content-addressed hash of `Dockerfile` and lock files; collision requires preimage attack on SHA-256 |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `--no-cache` on release builds | Eliminates all cache poisoning risk for release artifacts; build is fully reproducible from source | Build time reverts to cold state; dependency download adds minutes to release pipeline | Accept the cost for releases; use cached builds for PR validation only; use reproducible builds tooling to verify outputs match |
| Registry cache with strict write ACL | Prevents unauthorized cache writes; clear audit trail of who wrote what | Requires registry namespace design upfront; developers cannot warm the cache manually from their workstations | Provide a read-only cache ref that developers can pull from; require cache writes to go through CI only |
| S3 versioning | Enables rollback after poisoning without wiping the entire cache | Storage cost increases (previous versions are retained); adds latency to S3 lifecycle policy evaluation | Set a lifecycle rule to expire non-current versions after 30 days; keep latest 3 versions for rapid rollback |
| Provenance attestations | Records exact cache sources used in a build; enables post-hoc forensics | Increases image manifest size; adds a few seconds to push time; requires tooling to consume attestations | Enable by default for all production builds; use `docker buildx imagetools inspect` in deployment pipelines to gate on provenance content |
| Multi-stage cache isolation | Secrets used in build stages do not propagate to runtime images; clear separation of concerns | More complex Dockerfiles; additional COPY instructions add overhead; cache entries per-stage multiply storage requirements | Treat stage count as a security control, not a complexity trade-off; document stage purposes in Dockerfile comments |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `cache-to` writes silently ignored on fork PRs | PRs from forks appear to build normally but the cache is never updated; PR build times do not improve after the first run | `docker/build-push-action` output shows `cache-to` export skipped or 403 from registry; `GITHUB_TOKEN` in fork PR lacks `write:packages` | Expected and correct behaviour; do not attempt to grant fork PRs cache write access; document that cache warm-up happens on main branch merges only |
| S3 cache key collision between projects | Two repositories using the same S3 bucket without a `prefix=` parameter write to the same key namespace; one project's cache overwrites the other's | Build failures or unexpected behavior after an unrelated project's build writes to the bucket; S3 access logs show writes from unexpected CI roles | Always set `prefix=<project-slug>/` in the S3 cache backend URL; enforce this via a CI template or Makefile wrapper |
| Provenance attestation missing from image | Deployment pipeline fails the provenance check gate; `cosign verify-attestation` returns no attestation found | `docker buildx imagetools inspect` shows no `attestation` manifest entry; BuildKit version does not support provenance; `--provenance` flag was omitted | Ensure `docker/setup-buildx-action` pins a BuildKit version ≥ 0.11; explicitly pass `--provenance=true` in all build commands; do not use `docker build` (non-Buildx) for production images |
| `--secret` mount fails with permission denied | Build exits with `failed to read secret`: the secret file exists but the process inside the build container cannot read it | Build log shows `permission denied` on the secret mount path; `id` inside the failing RUN shows UID mismatch | Add `uid=<expected-uid>` to the `--mount=type=secret` instruction to match the UID of the process that reads the secret; verify the source file on the host is readable by the user running `buildkitd` |
| Cache hit rate drops to zero after key rotation | Builds revert to cold state; build times spike; pipeline SLA breached | Build logs show no cache hits; `docker buildx imagetools inspect` on the cache ref shows the manifest was updated but layers are missing | Key rotation is expected to clear the cache; pre-warm the cache with a manual build run against the new key before enabling it for all pipelines; keep the old cache ref available read-only for a transition window |

## Related Articles

- [BuildKit Rootless Build Security](/articles/cicd/buildkit-rootless-security/)
- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [Artifact Integrity Verification](/articles/cicd/artifact-integrity/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
- [SLSA Provenance](/articles/cicd/slsa-provenance/)
