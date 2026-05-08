---
title: "Monitoring CI/CD Pipelines for Security Anomalies and Pipeline Tampering"
description: "A compromised pipeline ships malicious code to production at scale. Learn what to monitor, which signals betray tampering, and how to wire audit logs, egress anomalies, and build provenance into a detection strategy."
slug: cicd-pipeline-anomaly-detection
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - pipeline-monitoring
  - anomaly-detection
  - audit-logs
  - supply-chain-security
  - siem
personas:
  - security-engineer
  - platform-engineer
article_number: 531
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/cicd-pipeline-anomaly-detection/
---

# Monitoring CI/CD Pipelines for Security Anomalies and Pipeline Tampering

## Why Pipelines Are the Highest-Value Target in Your Stack

A CI/CD pipeline is, by design, a privileged automated process with access to source code, signing keys, deployment credentials, and production infrastructure. When a developer commits a change, the pipeline builds it, tests it, signs the artifact, and pushes it to production — often with no human approval step between the git push and the production deployment. That automation is the entire value proposition of CI/CD. It is also the reason that a compromised pipeline is among the worst security incidents an organization can face.

The threat comes from two directions. The first is the insider threat: a developer, a platform engineer, or a service account with write access to pipeline configuration can modify workflow definitions to exfiltrate secrets, disable security checks, or inject malicious code into artifacts before they are signed and shipped. Because the modified artifact is signed by your own key, downstream consumers — and your own admission controllers — have no reason to reject it. The second is the supply chain attack: an attacker compromises a third-party action, a build dependency, or a pipeline plugin, and the malicious code executes inside your build environment with access to every secret the job uses. The March 2026 Trivy Action compromise — in which a threat actor force-pushed credential-stealing payloads to 76 release tags of a widely-deployed GitHub Actions security scanner — demonstrated how quickly a single upstream compromise can propagate into thousands of downstream pipelines.

Neither threat is hypothetical. Both threats share a common property: if you are not actively monitoring your pipelines for behavioral anomalies, you will not know the compromise happened until after the malicious artifact is in production.

## The Attack Surface in a Modern Pipeline

Before defining what to monitor, it helps to enumerate what an attacker can manipulate:

**Pipeline definition files.** In GitHub Actions, these are `.github/workflows/*.yml`. In GitLab CI, `.gitlab-ci.yml`. In Tekton, `Pipeline` and `Task` custom resources. In Jenkins, `Jenkinsfile`. These files define every step that executes. An attacker who can modify a workflow file can add a step that exfiltrates secrets to an external server, disables a SAST scan, modifies the build artifact before signing, or replaces a legitimate artifact with a backdoored one.

**Secrets and credentials.** CI/CD platforms store secrets separately from code (GitHub Actions Secrets, GitLab CI Variables, HashiCorp Vault, AWS Secrets Manager). A pipeline job accesses secrets only when it explicitly requests them. Unexpected secret access — a job reading a secret it has never accessed before — is a meaningful signal.

**Build dependencies.** Every `npm install`, `pip install`, `go mod download`, or `bundle install` introduces transitive dependencies. A new transitive dependency that appears without a corresponding code change deserves scrutiny. An attacker who has injected a malicious package into a registry can cause it to be pulled during the dependency resolution phase.

**Runner environment and network.** The CI runner has outbound internet access (unless explicitly restricted). A build that makes outbound connections to unexpected IP addresses or domains is performing work beyond what the pipeline definition describes.

**Artifacts.** The output of a build — container images, binaries, packages — should be deterministically produced from a known input. An artifact whose hash changes without a corresponding change in source code, dependencies, or build tooling is anomalous.

## Signal 1: Pipeline Definition Changes

The most direct form of pipeline tampering is a change to the workflow definition file. The signal is straightforward: treat every commit that modifies a pipeline definition as a high-fidelity security event, not just a code change.

What to watch for:

- A workflow file is modified outside normal working hours for the repository's team.
- The modification removes a step that runs security scanning (`trivy`, `semgrep`, `checkov`, `snyk`).
- The modification adds a `curl` or `wget` step that was not present before.
- The modification changes a pinned commit SHA to a mutable tag name (`uses: some-action@v1` replacing `uses: some-action@abc123def`).
- The modification elevates `permissions` at the workflow level (e.g., adding `contents: write` to a workflow that previously had `contents: read`).
- The modification adds a new `environment` or changes which `environment` a deployment job targets.

GitHub exposes these events through the audit log API. The event type `workflows.created` and `workflows.updated` are emitted when workflow files change. Pair these with the push events (`git.push`) that carried the change. GitLab CI emits equivalent events through its audit event API.

At the repository governance layer, branch protection rules requiring review for changes to `.github/workflows/` provide a human gate. But branch protection can itself be modified by organization owners. Monitor `protected_branch.update_policy` and `organization.update_member_repository_permission` events for unexpected permission changes that could weaken this control.

## Signal 2: Unexpected Secret Access

CI/CD platforms emit audit events when a secret is accessed. GitHub's audit log includes `secret_scanning.*` and organization-level secret events. For Vault-backed secrets, the Vault audit log records every secret read operation with the calling identity, the path, and the timestamp.

Anomalous patterns to alert on:

- A job reads a secret it has never accessed in its prior 30 days of run history.
- A secret associated with a production environment is accessed by a job running against a development branch.
- Secret access occurs during a workflow triggered by a pull request from a fork (fork-based pull requests should never have access to repository secrets; if they do, `pull_request_target` is misconfigured).
- A service account reads a large number of distinct secrets in a short time window (bulk enumeration pattern, consistent with a compromised runner enumerating available credentials).

Establishing the baseline requires at least 30 days of historical access data per job. Most SIEM platforms support this baseline calculation via aggregation over a sliding window. The detection rule is: `secret_path NOT IN (historical_secret_paths_for_job_id)`.

## Signal 3: Egress Anomalies — Builds Contacting Unexpected Destinations

A build job should contact a predictable, bounded set of external destinations: your package registry, your artifact store, your container registry, and a handful of well-known package mirrors (npmjs.com, pypi.org, pkg.go.dev). Any outbound connection outside that set is anomalous and warrants investigation.

Capturing this signal requires network-layer instrumentation. Options by platform:

**Self-hosted runners:** Route all runner traffic through a transparent proxy (Squid, mitmproxy) and log all outbound CONNECT and GET requests. Alert on connections to IPs or domains outside your allowlist.

**GitHub-hosted runners:** GitHub does not expose per-job network logs. You can instrument this at the workflow layer by running a step that captures `ss -tnp` state before and after the primary build step and diffs the connection table. More complete coverage requires migrating sensitive jobs to self-hosted runners where you control network observability.

**Kubernetes-based runners (Tekton, GitHub Actions with ARC):** Apply a `NetworkPolicy` that allows only explicitly permitted egress destinations. The policy's deny log (via a CNI plugin that supports logging, such as Cilium or Calico) produces the anomaly signal.

What to alert on:

- Any outbound TCP connection to an IP that has not been seen in prior runs of the same pipeline.
- DNS queries for domains that do not match known package registry patterns.
- Outbound connections on ports other than 443 and 80 (e.g., a connection to port 4444 or a high-numbered port used for C2 callbacks).
- Connection attempts immediately following dependency installation steps (consistent with a post-install hook exfiltrating secrets).
- Data volumes substantially higher than the historical baseline for the same pipeline stage (a stage that normally sends 2 MB outbound suddenly sending 50 MB is exfiltrating something).

## Signal 4: Build Time Anomalies

Build duration is a surprisingly reliable behavioral baseline. A pipeline job that takes 4 minutes 30 seconds across 200 consecutive runs and then suddenly takes 11 minutes is doing more work than it used to. The most common benign explanations are a new test suite, a larger dependency tree, or a slow external service. The malicious explanation is that the job is doing extra work: scanning environment variables, establishing a reverse shell, mining cryptocurrency, or uploading artifacts to an attacker-controlled destination.

Instrument build duration per job, per branch, per day-of-week and hour-of-day (to control for runner load variation). Alert when a job's duration exceeds the 99th percentile of its historical distribution by more than a threshold you calibrate to your environment (typically 2x the 99th percentile is a reasonable starting point for a high-signal alert).

Combine duration anomalies with network anomalies: a build that takes longer than usual AND makes unusual outbound connections is a much stronger signal than either indicator alone.

## Signal 5: Artifact Hash Changes Without Source Changes

A deterministic build process should produce the same artifact from the same inputs. If the source code, the dependency lock file, the build tooling version, and the build environment are identical, the output artifact hash should be identical. This is the premise behind reproducible builds.

In practice, many builds are not fully reproducible (embedded timestamps, non-deterministic linker behavior). But you can still detect gross anomalies: if a build is triggered by the exact same commit SHA as a prior build, and produces an artifact with a different hash, the build process itself has changed in a way that was not reflected in a source commit.

This check is most useful at the pipeline level. After every build, record the tuple `(commit_sha, dependency_lock_hash, builder_image_digest, artifact_hash)`. On the next build of the same commit, compare. A divergence in `artifact_hash` when all other tuple elements are identical is an anomaly requiring investigation.

For container images, `docker buildx imagetools inspect` retrieves the digest of a previously built image for comparison. For Go binaries, `go build` with `-trimpath` and fixed `GOFLAGS` produces reproducible output. For npm packages, `npm pack --dry-run` computes the tarball hash from the workspace state.

## Signal 6: Unexpected Transitive Dependency Additions

A compromised package maintainer, a typosquatting attack, or a dependency confusion attack can introduce a malicious package into your dependency tree without any change to your direct dependencies. The signal is a new package appearing in `package-lock.json`, `go.sum`, `Pipfile.lock`, or `Cargo.lock` without a corresponding change to the direct dependency manifest (`package.json`, `go.mod`, `Pipfile`, `Cargo.toml`).

Detect this by diffing lock files between builds. If `package-lock.json` contains new entries in `node_modules/` that are not transitively reachable from the current `package.json`, the dependency tree has been unexpectedly expanded. This can happen via a compromised upstream package adding a new transitive dependency in a patch release.

Wire this check into your pipeline as a gate: after `npm ci` or equivalent, diff the generated lock file against the committed lock file and fail the build if they diverge. This detects both unauthorized lock file modifications and situations where your dependency tooling resolves a different set of packages than the committed lock file specifies.

## Shipping Audit Logs to a SIEM

Individual signal sources — GitHub audit log, Vault audit log, proxy logs, build duration metrics — are only useful if they are centralized and correlated. The architecture for this is:

1. **GitHub Audit Log streaming:** Enable the GitHub Enterprise audit log streaming feature to forward all audit events to an S3 bucket, Azure Blob Storage, or a direct HTTPS endpoint. From there, ingest into Elastic (via the Elastic GitHub integration or a Logstash pipeline) or Splunk (via the Splunk Add-on for GitHub). The audit log includes all `workflow.*`, `secret.*`, `protected_branch.*`, and `org.*` events.

2. **Build metadata:** Emit structured JSON from each pipeline step to a log aggregator. Include: `run_id`, `job_id`, `workflow_name`, `triggered_by`, `branch`, `commit_sha`, `step_name`, `duration_seconds`, `exit_code`. Most CI platforms support structured output via step summary or artifact upload.

3. **Network logs:** Forward proxy access logs (Squid: `access.log`; Cilium: flow logs) to the same SIEM. Join on `run_id` or the runner's IP address to correlate network activity with specific pipeline runs.

4. **Artifact hashes:** Write `(commit_sha, artifact_hash, build_timestamp, run_id)` to an append-only store (S3 with Object Lock, a write-protected database table) after each build. Query this store at deploy time to verify the artifact hash matches the expected hash for the commit being deployed.

In Elastic, the core detection rules are:

```
# Alert: workflow modified outside business hours
event.action: "workflows.updated" AND NOT (hour_of_day >= 8 AND hour_of_day <= 18 AND day_of_week IN ("Mon","Tue","Wed","Thu","Fri"))

# Alert: secret accessed by a job that has never accessed it before
event.action: "secret.access" AND NOT (job_id, secret_name) IN (historical_access_pairs_last_30d)

# Alert: build duration exceeds 2x 99th percentile
metric.build_duration_seconds > (2 * p99_duration_by_job_id)
```

In Splunk, the equivalent detection uses `streamstats` and `eventstats` to compute per-job historical baselines inline.

## Alerting on Pipeline Changes Outside Working Hours

Time-of-day gating on pipeline definition changes is one of the simplest and highest-signal detection rules available. Attackers who have compromised a developer's credentials often operate outside the victim's working hours to reduce the chance of the change being noticed immediately. A workflow file modification pushed at 3:00 AM local time for a team whose last 200 commits were all between 08:00 and 20:00 is an outlier that warrants immediate investigation.

Build the baseline from the `author.date` field of commits to `.github/workflows/` over the past 90 days. Calculate the interquartile range of commit hours. Flag any commit to a pipeline definition file whose timestamp falls outside the 99th percentile of that distribution.

Integrate this alert with your on-call rotation. Pipeline tampering is a P1-equivalent incident: a compromised pipeline can affect every artifact built from the moment of compromise forward. The response is to quarantine the pipeline (disable the workflow or set the protected branch to require manual approval for all merges) and begin artifact audit — reviewing every artifact produced since the suspicious commit for signs of tampering.

## Build Provenance Verification at Deploy Time

The final control is deploy-time provenance verification. Even if a malicious artifact passes all in-pipeline controls, a deploy-time check that verifies the artifact's SLSA provenance attestation against the expected build parameters will catch an artifact that was built outside the authorized pipeline.

SLSA provenance attestation records: the builder identity (the GitHub Actions runner, identified by the OIDC token), the source repository and commit SHA, the workflow that produced the artifact, and the artifact digest. This attestation is signed by the builder's OIDC-derived key (via Sigstore's keyless signing) and stored in a transparency log (Rekor).

At deploy time, before the artifact is allowed into the cluster or the production environment, verify:

```bash
# Using slsa-verifier
slsa-verifier verify-artifact \
  --provenance-path artifact.intoto.jsonl \
  --source-uri github.com/your-org/your-repo \
  --source-tag v1.2.3 \
  ./your-binary
```

Or for container images using cosign:

```bash
cosign verify \
  --certificate-identity "https://github.com/your-org/your-repo/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  your-registry/your-image:v1.2.3
```

If the artifact was built by anything other than the authorized workflow at the authorized commit, verification fails and the deploy is blocked. This is the backstop that makes all the earlier detection controls meaningful: even if an anomaly is missed in monitoring, the artifact cannot be deployed unless it has valid provenance from the authorized build system.

In Kubernetes, enforce this at the admission controller layer using Kyverno or OPA/Gatekeeper policies that reject any image whose cosign signature and provenance attestation do not match the expected builder identity and source repository.

## Operationalizing the Detection Program

The controls above require instrumentation investment before they produce reliable signals. A practical sequencing:

**Week 1-2:** Enable GitHub audit log streaming to your SIEM. Build the first two detection rules: workflow definition changes outside business hours, and unexpected secret access. These are the highest-signal, lowest-noise rules.

**Week 3-4:** Add build duration baselines. Run the pipeline for 30 days without alerting to establish the baseline distribution, then activate the alert.

**Month 2:** Instrument egress. For self-hosted runners, deploy the proxy. For Kubernetes runners, deploy Cilium with network policy and flow log export. Build the egress allowlist from 30 days of observed traffic before activating the anomaly alert.

**Month 3:** Add artifact hash comparison for all builds against the same commit SHA. Add lock file drift detection as a pipeline gate.

**Month 4+:** Implement SLSA provenance attestation for your highest-value pipelines (production release pipelines first). Add deploy-time verification. Expand SLSA coverage to all pipelines over the subsequent quarter.

The goal is not to alert on everything — alert fatigue in pipeline monitoring is as dangerous as alert fatigue elsewhere. The goal is to have high-confidence, low-noise signals that a human will actually act on, covering the highest-risk pipeline events: definition tampering, secret abuse, egress anomalies, and artifact integrity.

## Summary

A CI/CD pipeline that ships to production without tampering detection is an unmonitored privilege escalation path. The signals that betray pipeline compromise — workflow definition changes outside business hours, unexpected secret access patterns, outbound connections to unexpected destinations, build duration outliers, artifact hash changes with no source change, and new transitive dependencies — are all measurable, baselining is tractable with 30 days of history, and the detection rules are straightforward to implement in any modern SIEM.

The architectural principle is defense in depth across the pipeline lifecycle: detect tampering at the definition layer (audit log monitoring), at the execution layer (egress and duration monitoring), at the artifact layer (hash comparison and provenance attestation), and at the deploy layer (provenance verification at admission). No single control is sufficient. The combination makes it substantially harder for an attacker — insider or external — to compromise your pipeline and have that compromise go undetected long enough to deliver malicious artifacts to production.
