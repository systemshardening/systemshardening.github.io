---
title: "Internal Developer Platform Security"
description: "Harden Internal Developer Platforms built on Backstage, Port, or Cortex by securing plugin trust models, service catalog secrets, scaffolding templates, and open source IDP CVE tracking."
slug: platform-engineering-security
date: 2026-05-02
lastmod: 2026-05-02
category: cross-cutting
tags: ["platform-engineering", "backstage", "idp", "service-catalog", "scaffolding", "supply-chain"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 341
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cross-cutting/platform-engineering-security/index.html"
---

# Internal Developer Platform Security

## Problem

An Internal Developer Platform (IDP) is the self-service control plane for an engineering organisation. Platforms built on Backstage (the CNCF-hosted open source option), Port, Cortex, or OpsLevel give developers a single portal to discover services, provision cloud infrastructure, trigger CI/CD pipelines, view runbooks, and navigate documentation. Backstage is by far the dominant choice — deployed by thousands of organisations and backed by active development from Spotify, Red Hat, VMware, and hundreds of community contributors. The appeal is real: an IDP cuts the cognitive load on developers and reduces toil for platform teams. The security implications are almost always an afterthought.

The attack surface of an IDP is unusually broad for a single application. First, the service catalog is a complete map of the organisation's infrastructure. A Backstage catalog populated by a mature platform team contains every service name, its owning team, its Kubernetes namespace, links to the secrets manager entries it uses, PagerDuty escalation policies, runbook URLs, and dependency graphs showing which services call which. For an attacker, read access to the catalog is equivalent to weeks of reconnaissance work delivered in a single API response.

Second, scaffolding templates provision real infrastructure. A Backstage `template.yaml` can call GitHub Actions workflows, create AWS IAM roles, push Helm charts to a repository, register DNS records, or write configuration files to a service's source tree. These templates run with the credentials of the Backstage backend — typically a GitHub App token with broad repository permissions and an AWS IAM role with provisioning rights. A malicious template, or a legitimate template with a user-controlled parameter exploited via path traversal, executes with those same credentials.

Third, Backstage plugins run as Node.js code inside the Backstage backend process. The plugin model gives community-developed code access to every integration the platform has configured: GitHub tokens, PagerDuty API keys, AWS credentials, Kubernetes service account tokens, and database connections. Installing a plugin from the Backstage Plugin Marketplace is not equivalent to `npm install` of a utility library — it is granting that code full access to every secret the backend holds.

Fourth, and perhaps most practically dangerous: Backstage's default authentication configuration allows guest access with no credentials required. This setting exists to make local development frictionless. Organisations frequently deploy Backstage to an internal network, assume network-level controls are sufficient, and never lock down the application's own auth layer. The result is a fully authenticated view of the organisation's infrastructure available to any user on the corporate network — or to any attacker who has breached the perimeter.

The open source security track record of Backstage is instructive and underappreciated. Backstage is developed at high velocity: the repository sees hundreds of commits per week from a distributed contributor base. Security vulnerabilities have emerged and been fixed with minimal public disclosure. The catalog ingestion pipeline had a ReDoS (Regular Expression Denial of Service) vulnerability — the fix appeared as a minor version bump with the commit message "fix regex performance in entity processor" and no CVE was filed. The `@backstage/plugin-scaffolder-backend` had a path traversal vulnerability where scaffold actions accepting user-controlled `targetPath` parameters could write files outside the intended workspace directory; the fix PR was titled "fix path validation in scaffolder" and was public for a week before the release that included it, giving any attacker following the repository advance knowledge of the unfixed behaviour. Several community plugins carry transitive dependencies with published CVEs that go unpatched because the plugin author is a solo contributor who does not monitor `npm audit`. The Backstage Plugin Marketplace has no security vetting process: plugins are listed based on a registry pull request, not a security review.

Tracking Backstage security posture requires deliberate process. Watch `https://github.com/backstage/backstage/security/advisories` for official advisories. Run `yarn backstage-cli versions:check` regularly to surface outdated core packages. Run `npm audit` against the Backstage monorepo in CI. Subscribe to `backstage-security@googlegroups.com` for early notifications. Check plugin dependencies specifically with `npm audit --workspace=plugins/*` since the monorepo structure means top-level audit results can miss plugin-scoped vulnerabilities.

**Target systems:** Backstage 1.25+, Node.js 20+, Kubernetes deployment.

## Threat Model

1. **Catalog reconnaissance attacker.** An attacker with Backstage guest access — either a legitimate internal user acting maliciously or an external attacker who has breached the corporate network — queries the catalog API to enumerate every service, its owning team, linked secrets manager paths, runbook URLs, and infrastructure topology. The catalog does not require authentication in default Backstage configuration. This reconnaissance requires no elevated privilege and produces a complete picture of the environment in minutes.

2. **Malicious plugin installer.** A developer or platform team member installs a Backstage plugin from the marketplace that is either intentionally malicious or has been compromised via a supply chain attack on its npm package. Once loaded into the Backstage backend, the plugin code runs in the same Node.js process as all other plugins and has access to the full integration configuration — GitHub App tokens, AWS credentials, Kubernetes service account tokens, and PagerDuty API keys. The plugin exfiltrates these credentials to an external endpoint on each backend startup.

3. **Patch-gap scaffolder attacker.** A security researcher or attacker reads the public fix PR for the `@backstage/plugin-scaffolder-backend` path traversal vulnerability before the patched version is released. They identify organisations running unpatched Backstage instances and craft a scaffold template that uses a `targetPath` parameter set to `../../.ssh/authorized_keys` (relative to the scaffolder workspace), writing an attacker-controlled SSH public key into the Backstage pod's filesystem — or, in environments where the scaffolder has broader filesystem access, into a mounted volume. The attack window is the gap between the fix being public and the organisation upgrading.

4. **Insider template injection.** An employee with access to the platform repository submits a scaffold template that, when executed by developers using the self-service portal, provisions cloud resources (EC2 instances, S3 buckets) using the Backstage backend's AWS credentials and exfiltrates the executing developer's GitHub token from the scaffolder environment. Because scaffold template runs are often not audited, the provisioning may go unnoticed until a cloud billing anomaly surfaces it.

The blast radius of a compromised Backstage backend is proportional to the integrations configured. In a mature deployment, a single compromised backend process holds the credentials to push code to every repository, modify cloud infrastructure, acknowledge and resolve incidents in PagerDuty, and read secrets from Vault or AWS Secrets Manager. The IDP is designed to have broad access so developers can self-serve — that same breadth makes it a high-value target that warrants controls commensurate with a production secrets management system.

## Configuration / Implementation

### Authentication Hardening

The single highest-impact change for most Backstage deployments is disabling guest access and enforcing organisation-scoped authentication.

```yaml
# app-config.yaml
auth:
  environment: production
  providers:
    github:
      production:
        clientId: ${AUTH_GITHUB_CLIENT_ID}
        clientSecret: ${AUTH_GITHUB_CLIENT_SECRET}
        signIn:
          resolvers:
            - resolver: usernameMatchingUserEntityName
    okta:
      production:
        clientId: ${AUTH_OKTA_CLIENT_ID}
        clientSecret: ${AUTH_OKTA_CLIENT_SECRET}
        audience: ${AUTH_OKTA_DOMAIN}
        signIn:
          resolvers:
            - resolver: emailMatchingUserEntityProfileEmail

# Explicitly deny guest access — this is the critical setting
# Remove or set to false; do not leave as 'true' in any environment
# that has network reachability from untrusted hosts
```

With the `@backstage/plugin-permission-backend` installed, apply group-based policy to restrict catalog reads and scaffold template execution:

```typescript
// packages/backend/src/plugins/permission.ts
import { createRouter } from '@backstage/plugin-permission-backend';
import {
  AuthorizeResult,
  PolicyDecision,
} from '@backstage/plugin-permission-common';
import { BackstageIdentityResponse } from '@backstage/plugin-auth-node';

export async function createPermissionRouter(env: PluginEnvironment) {
  return createRouter({
    config: env.config,
    logger: env.logger,
    discovery: env.discovery,
    identity: env.identity,
    policy: {
      async handle(request, user): Promise<PolicyDecision> {
        // Only members of platform-admins group can run scaffold templates
        if (request.permission.name === 'scaffolder.task.create') {
          const groups = user?.identity.ownershipEntityRefs ?? [];
          if (!groups.includes('group:default/platform-admins') &&
              !groups.includes('group:default/platform-engineers')) {
            return { result: AuthorizeResult.DENY };
          }
        }
        return { result: AuthorizeResult.ALLOW };
      },
    },
  });
}
```

Restrict Backstage admin role to the platform team by ensuring the `superUser` permission or equivalent admin flag in your permission policy is gated on group membership, not just authentication.

### Plugin Trust Model

Every Backstage plugin installed from the community marketplace runs in the backend process with access to all configured integrations. Treat plugin installation as a privileged operation.

Audit installed plugins and their version staleness:

```bash
# List all installed core and plugin packages and flag outdated versions
yarn backstage-cli versions:check

# Audit the full monorepo for known CVEs
npm audit

# Audit only plugin workspaces (catches plugin-specific transitive vulns)
npm audit --workspace=plugins/*

# Check for fixable issues in the Backstage monorepo structure
yarn backstage-cli repo fix --check
```

Gate who can add plugins to the Backstage app by adding a CODEOWNERS rule:

```
# .github/CODEOWNERS
# Only platform-security team can approve changes to installed plugins
packages/app/package.json        @your-org/platform-security
packages/backend/package.json    @your-org/platform-security
plugins/                         @your-org/platform-security
```

Before installing any community plugin, verify: the plugin repository has had a commit in the last 90 days, the author responds to issues, and `npm audit` on the plugin's directory shows no high or critical vulnerabilities. Prefer plugins from the `@backstage` namespace (maintained by the Backstage core team) over community plugins for privileged integrations such as Kubernetes, AWS, and secrets management.

### Scaffolding Template Security

Scaffold templates are the most operationally dangerous component of Backstage because they execute actions with the backend's credentials in response to developer input. Every template must be reviewed before it is added to the catalog.

Restrict scaffolder allowed hosts to prevent SSRF via the `fetch:plain` action:

```yaml
# app-config.yaml
scaffolder:
  # Prevent fetch:plain from reaching internal network endpoints
  allowedHosts:
    - github.com
    - raw.githubusercontent.com
    - your-internal-artifact-registry.example.com
  # Disable scaffolder actions that are not used
  disabledActions:
    - fs:delete
    - debug:log
    - catalog:fetch
```

In template files, audit every action that accepts user-controlled parameters for path traversal and injection risk:

```yaml
# template.yaml — UNSAFE pattern
steps:
  - id: write-config
    name: Write config
    action: fs:write
    input:
      path: ${{ parameters.targetPath }}/config.yaml  # user-controlled path — path traversal risk
      content: ${{ parameters.configContent }}         # user-controlled content — injection risk

# template.yaml — SAFE pattern
steps:
  - id: write-config
    name: Write config
    action: fs:write
    input:
      # Prefix with a fixed base path; targetPath should be a filename only, validated upstream
      path: ./output/${{ parameters.serviceName | lower | replace(" ", "-") }}/config.yaml
      content: ${{ parameters.configContent }}
```

Require all `template.yaml` files to go through a PR reviewed by the `platform-security` team before merging. Add a CODEOWNERS rule for the catalog templates directory:

```
# .github/CODEOWNERS
catalog-templates/    @your-org/platform-security
```

Validate template syntax and action usage in CI:

```bash
# Lint all template files using the Backstage scaffolder dry-run (if your version supports it)
yarn backstage-cli package lint --since origin/main

# Use a custom script to flag disallowed patterns in templates
grep -rn "targetPath.*parameters\." catalog-templates/ && echo "WARN: user-controlled targetPath found"
grep -rn "fetch:plain" catalog-templates/ && echo "INFO: Review fetch:plain hosts against allowedHosts config"
```

### Service Catalog Secret Hygiene

Catalog files (`catalog-info.yaml`) should never contain secrets, credentials, or values that provide direct access to systems. They frequently contain annotation values that are mistaken for safe metadata.

Run `gitleaks` on catalog files in CI to prevent accidental secret inclusion:

```yaml
# .github/workflows/catalog-secret-scan.yml
name: Catalog secret scan
on:
  pull_request:
    paths:
      - "**catalog-info.yaml"
      - "**/catalog-info.yaml"

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run gitleaks on catalog files
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          args: detect --source . --include-path "**catalog-info.yaml" --verbose
```

Use the Backstage `substitutions` mechanism to reference secrets by name rather than embedding values:

```yaml
# app-config.yaml — reference secrets from environment, not hardcoded
integrations:
  github:
    - host: github.com
      token: ${GITHUB_TOKEN}   # injected from Kubernetes secret at runtime

catalog:
  locations:
    - type: url
      target: https://github.com/your-org/catalog/blob/main/all.yaml
```

Apply the permissions plugin to restrict catalog entity reads. Services containing sensitive annotations (on-call contacts, infrastructure links) should only be readable by members of the owning team and the platform team:

```typescript
// In your permission policy
if (request.permission.name === 'catalog.entity.read') {
  const entity = await catalogClient.getEntityByRef(request.resourceRef);
  const owners = entity?.relations
    ?.filter(r => r.type === 'ownedBy')
    .map(r => r.targetRef) ?? [];
  const userGroups = user?.identity.ownershipEntityRefs ?? [];
  const isOwner = owners.some(o => userGroups.includes(o));
  const isPlatformTeam = userGroups.includes('group:default/platform-team');
  if (!isOwner && !isPlatformTeam) {
    return { result: AuthorizeResult.DENY };
  }
}
```

### Dependency and Plugin CVE Monitoring

Add dependency scanning to the Backstage repository CI pipeline and configure automated updates:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule:
      interval: weekly
      day: monday
    # Group Backstage core packages to avoid cascading PRs
    groups:
      backstage-core:
        patterns:
          - "@backstage/*"
    ignore:
      # Pin major version upgrades to manual review
      - dependency-name: "@backstage/*"
        update-types: ["version-update:semver-major"]
```

Run `npm audit` as a blocking CI step:

```yaml
# .github/workflows/security.yml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: yarn install --frozen-lockfile
      - name: Audit dependencies
        run: npm audit --audit-level=high
      - name: Check plugin workspace dependencies
        run: npm audit --workspace=plugins/* --audit-level=high
```

Subscribe to the Backstage security advisory feed and create an internal process to evaluate each advisory within 48 hours. When an advisory is published for a package used in your deployment, create a ticket and track the upgrade to closure.

### Network Isolation

The Backstage backend should not have direct network access to production databases, internal cluster APIs, or other sensitive systems. Use proxy services with audit logging as intermediaries.

Apply a Kubernetes NetworkPolicy to restrict Backstage pod egress:

```yaml
# backstage-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backstage-egress
  namespace: backstage
spec:
  podSelector:
    matchLabels:
      app: backstage
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - ports:
        - port: 53
          protocol: UDP
    # Allow GitHub (replace with your actual integration IPs or use FQDN-based policy with Cilium)
    - ports:
        - port: 443
          protocol: TCP
    # Allow internal artifact registry
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: registry
      ports:
        - port: 5000
          protocol: TCP
    # Deny all other egress by omission
```

Enable outgoing request audit logging if your Backstage version supports it, or add a sidecar proxy (such as Squid or Envoy) to log and filter all HTTP/S requests made by the Backstage backend.

### Audit Logging

Install the `@backstage/plugin-auditor` or equivalent audit logging integration to capture security-relevant events:

```yaml
# app-config.yaml
auditor:
  enabled: true
  events:
    - auth.login
    - auth.logout
    - catalog.entity.read
    - catalog.entity.create
    - catalog.entity.update
    - scaffolder.task.create
    - scaffolder.task.complete
    - permission.evaluate
```

Ship audit logs to your SIEM and configure alerts for:

- Scaffold template runs outside business hours (07:00–19:00 local time)
- Scaffold template runs by users not in the platform-engineers or developers groups
- More than 50 catalog entity reads in a single session (potential automated reconnaissance)
- Any catalog entity mutation by a non-platform-team member
- Authentication failures above baseline threshold

```bash
# Example: query audit logs for scaffold runs outside business hours (adjust for your SIEM query language)
# In Elasticsearch/OpenSearch:
# GET backstage-audit-*/_search
# { "query": { "bool": { "must": [
#   { "match": { "event": "scaffolder.task.create" } },
#   { "range": { "@timestamp": { "lt": "now/d+7h", "gte": "now/d" } } }
# ] } } }
```

## Expected Behaviour

| Signal | Default Backstage Config | Hardened Config |
|---|---|---|
| Unauthenticated user reads service catalog | Full catalog contents returned with no auth check; all entity metadata, annotations, and links visible | 401 Unauthorized; authentication required before any catalog API response |
| Malicious plugin installed by developer | Plugin code executes in backend process; GitHub tokens, AWS credentials, Kubernetes SA tokens all accessible via `process.env` and integration configs | Plugin installation requires CODEOWNERS approval from platform-security team; `npm audit` runs in CI before merge; plugin surface is reviewed against allowlist of accepted actions |
| Scaffolder template with path traversal `targetPath` | File written to attacker-controlled path; in worst case, writes to mounted volumes or SSH config directories | `allowedHosts` restricts fetch actions; `targetPath` parameters are validated and prefixed with fixed base path; scaffolder runs in isolated workspace with restricted filesystem access |
| Plugin CVE published for installed `@backstage/*` package | No automatic notification; upgrade depends on platform team noticing advisory or running manual audit | Dependabot opens upgrade PR within 24 hours of advisory publication; `npm audit` CI step fails until resolved; `backstage-security@googlegroups.com` subscription triggers manual review |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Strict plugin vetting via CODEOWNERS | Prevents malicious or vulnerable plugins from reaching production Backstage | Slows platform iteration; developers who want a new integration plugin must wait for security review | Define a 48-hour SLA for plugin reviews; build a pre-approved plugin allowlist to fast-track common integrations |
| Enforcing authentication (disabling guest access) | Eliminates unauthenticated catalog reconnaissance; closes the most common attack vector | Breaks the open-door culture in organisations where Backstage was marketed as "anyone can browse"; requires all developers to have an SSO account linked | Phase rollout: read-only guest access first (catalog browse, no scaffold), then full auth enforcement; communicate the change with a developer experience team |
| Scaffold action restrictions (`disabledActions`, `allowedHosts`) | Prevents SSRF and reduces blast radius of malicious templates | Breaks existing templates that relied on now-disabled actions; developers work around restrictions by creating manual provisioning steps | Audit all templates before disabling actions; provide equivalent safe alternatives; document the restriction rationale in the developer portal itself |
| Dependency monitoring and `npm audit` CI gate | Catches known CVEs in Backstage packages and plugins before deployment | `npm audit` generates false positives (vulnerabilities in dev-only code paths, unfixed upstream deps); noisy PRs from Dependabot can overwhelm the platform team | Use `--audit-level=high` to filter low-severity noise; configure Dependabot to group Backstage packages; add a `.nsprc` or audit-resolve file to document accepted false positives |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Auth misconfiguration locks out developers | After disabling guest access, developers with misconfigured SSO accounts receive 401 on Backstage login; platform team gets flooded with access requests | Spike in support tickets immediately after auth config rollout; monitoring on Backstage auth failure rate | Maintain a break-glass guest read-only account accessible to platform admins only; document rollback procedure for `auth.allowGuestAccess`; test auth config in staging before production rollout |
| Disabled scaffold action breaks existing template | Developers report "Action not found" error when running a previously working template; CI pipelines that trigger scaffolding begin failing | Developer complaints in platform team Slack channel; failed scaffold task events in audit log | Maintain an inventory of templates and the actions they use before disabling any action; run a dry-run validation across all templates before applying `disabledActions` config; restore the action temporarily and provide a safe alternative |
| `npm audit` false positive blocks valid plugin | CI pipeline fails on a vulnerability in a dev-only transitive dependency that is not reachable in production code | CI failure on a plugin PR with no actual security risk; `npm audit` report shows vulnerability in `devDependencies` subtree | Use `npm audit --omit=dev` to exclude dev dependencies from the blocking check; document accepted false positives in an audit-resolution file tracked in git; escalate genuine ambiguous cases to the security team for manual review |
| Backstage backend restart required after config change | Config change to `app-config.yaml` (e.g., adding a new `disabledActions` entry) does not take effect until the pod is restarted; operators assume the change is live when it is not | Disabled action is still accessible after config change; developers can still run scaffold templates that should be blocked | Use Kubernetes rolling restart after config changes: `kubectl rollout restart deployment/backstage -n backstage`; add a post-deploy verification step that confirms the config endpoint reflects the expected values; use a ConfigMap with `--watch` flag if your Backstage version supports live reload |

## Related Articles

- [Repository Policy as Code](/articles/cicd/repo-policy-as-code/)
- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
- [Software Supply Chain and Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [API Key Lifecycle Management](/articles/cross-cutting/api-key-lifecycle/)
- [DevSecOps Maturity Model](/articles/cross-cutting/devsecops-maturity-model/)
