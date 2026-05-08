---
title: "Software Bill of Materials (SBOM) Generation and Consumption in CI/CD"
description: "SBOM generation is easy, run Syft, get a list of every package in your container image."
slug: "sbom"
date: 2026-04-19
lastmod: 2026-04-19
category: "cicd"
tags: ["sbom", "syft", "grype", "supply-chain", "vulnerability", "compliance"]
personas: ["devops-engineer", "security-engineer"]
article_number: 58
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Anchore"
    id: 98
    category: "supply-chain"
premium_pack: "sbom-pipeline-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/sbom/index.html"
---

# Software Bill of Materials (SBOM) Generation and Consumption in CI/CD

## Problem

SBOM generation is easy, run [Syft](https://github.com/anchore/syft), get a list of every package in your container image. SBOM consumption is hard: when a new critical CVE drops, you need to query SBOMs across every deployed image within minutes to answer "are we affected?" Without consumption infrastructure, SBOMs are compliance artifacts that collect dust.

## Threat Model

- **Adversary:** Any attacker exploiting a known vulnerability. SBOMs enable rapid response: "which images contain the vulnerable package?" Within minutes, not hours.

## Configuration

### Generation with Syft

```yaml
# CI step: generate SBOM for every built image
- name: Generate SBOM
  run: |
    # Install Syft
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

    # Generate SBOM in SPDX format
    syft ghcr.io/your-org/your-app:${{ github.sha }} \
      -o spdx-json=sbom-spdx.json

    # Also generate CycloneDX format (wider tool support)
    syft ghcr.io/your-org/your-app:${{ github.sha }} \
      -o cyclonedx-json=sbom-cdx.json

- name: Attach SBOM to image as OCI artifact
  run: |
    cosign attach sbom \
      --sbom sbom-spdx.json \
      ghcr.io/your-org/your-app@${{ steps.build.outputs.digest }}
```

### Vulnerability Scanning Against SBOM

```bash
# Scan SBOM with Grype (Anchore's vulnerability scanner)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan the SBOM (not the image - faster, works offline)
grype sbom:./sbom-cdx.json --fail-on critical

# Output: list of CVEs found in packages listed in the SBOM
# Exit code 1 if critical CVEs found
```

### SBOM Storage and Querying

```bash
# Store SBOMs alongside images in the OCI registry:
# Already done above with cosign attach sbom

# For querying across all images:
# Option 1: Store SBOMs in a queryable database
# Option 2: Keep SBOMs in S3 with metadata index

# Query: "which images contain log4j?"
# Scan all stored SBOMs:
for sbom in s3://sbom-storage/*.json; do
  if grype sbom:$sbom --only-fixed --output json | jq -e '.matches[] | select(.vulnerability.id | contains("CVE-2021-44228"))' > /dev/null 2>&1; then
    echo "AFFECTED: $sbom"
  fi
done
```

### Admission Policy: Require SBOM

```yaml
# Kyverno policy: block images without SBOM attestation
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom
spec:
  validationFailureAction: Audit  # Start in audit mode
  rules:
    - name: check-sbom-attestation
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      verifyImages:
        - imageReferences:
            - "ghcr.io/your-org/*"
          attestations:
            - type: https://spdx.dev/Document
              # Verifies an SBOM attestation exists for the image
```

### Continuous Monitoring

```bash
# Scheduled re-scan of all deployed image SBOMs
# New CVEs are published daily - yesterday's clean image may be vulnerable today.

# Cron job or CI schedule:
# 1. List all images running in production
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u > running-images.txt

# 2. For each image, fetch SBOM and scan
while read image; do
  cosign verify-attestation --type spdxjson "$image" 2>/dev/null | \
    jq -r '.payload' | base64 -d | \
    grype --fail-on critical 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "VULNERABLE: $image"
  fi
done < running-images.txt
```

## Expected Behaviour

- Every container image has an SBOM attached as an OCI artifact
- `grype sbom:./sbom.json` passes (no critical CVEs) at build time
- SBOMs queryable across all deployed images within minutes
- "Are we affected by CVE-X?" answered in under 10 minutes
- Continuous re-scanning catches new CVEs in already-deployed images

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| SBOM generation per build | Adds 30-60 seconds to CI pipeline | Minimal impact on build time | Run SBOM generation in parallel with other CI steps. |
| SBOM attached to OCI registry | Registry storage for SBOM artifacts | Minimal storage (SBOMs are <1MB typically) | Registry garbage collection handles cleanup for deleted images. |
| Daily re-scanning | Catches new CVEs in deployed images | Alert fatigue from low-severity CVEs | Scan only for critical/high severity. Filter known-accepted CVEs via `.grype.yaml`. |
| Admission policy (require SBOM) | Blocks images without SBOMs | Old images without SBOMs cannot be redeployed | Start in audit mode. Backfill SBOMs for existing images. Switch to enforce when coverage is 100%. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Syft fails to scan image | No SBOM generated; CI step fails | CI build failure at SBOM generation step | Check image accessibility. Verify Syft version supports the image format. |
| cosign attach fails | SBOM not stored in registry | Next step (Grype scan of SBOM) fails; admission policy may reject | Retry cosign attach. Check registry permissions. |
| Grype false positive | Build blocked for a CVE that doesn't affect the application | CI failure on Grype step; review shows the CVE is not reachable | Add to `.grype.yaml` ignore list with justification. Use [Snyk](https://snyk.io) for reachability analysis. |
| SBOM query too slow | "Are we affected?" takes hours instead of minutes | Response time exceeds SLA during incident | Pre-index SBOMs in a queryable database (Anchore #98). |

## When to Consider a Managed Alternative

SBOM consumption at scale (querying across 100+ images) requires indexing infrastructure.

- **[Anchore](https://anchore.com):** Enterprise SBOM management with policy engine, continuous monitoring, and API-queryable SBOM database.
- **[Snyk](https://snyk.io):** SBOM-integrated vulnerability management with reachability analysis.
- **[Aqua](https://www.aquasec.com):** SBOM-aware admission control and continuous monitoring.

**Premium content pack:** SBOM pipeline templates. Syft CI integration, Grype scanning workflows, cosign attestation attachment, Kyverno admission policies, and continuous re-scanning cron job configurations.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
