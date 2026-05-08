---
title: "API Schema Security Scanning: Detecting Auth Gaps, Injection Risks, and Data Exposure in OpenAPI and Protobuf"
description: "OpenAPI and Protobuf definitions are the authoritative contract for an API's behaviour — and they encode security properties like authentication requirements, input validation constraints, and sensitive field exposure. Scanning schemas at commit time catches broken object-level auth, missing input constraints, and PII exposure before the API is deployed. This guide covers schema linting, custom security rules, and CI integration for REST and gRPC APIs."
slug: api-schema-security-scanning
date: 2026-05-08
lastmod: 2026-05-08
category: network
tags:
  - api-security
  - openapi
  - schema-scanning
  - sast
  - grpc-security
personas:
  - security-engineer
  - platform-engineer
article_number: 643
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/api-schema-security-scanning/
---

# API Schema Security Scanning: Detecting Auth Gaps, Injection Risks, and Data Exposure in OpenAPI and Protobuf

## Problem

An OpenAPI file is not just documentation. It is the authoritative specification of what your API accepts, what it returns, and who is allowed to call it. When a developer adds an endpoint to the spec without declaring a security requirement, they are not making a documentation error — they are documenting an unauthenticated endpoint. The schema is correct. The security posture is wrong. If that schema is deployed as-is, the implementation will follow it.

This distinction matters because it creates a shift-left opportunity that most teams do not exploit. The security properties encoded in OpenAPI and Protobuf definitions are:

- **Authentication requirements.** `securitySchemes` declares the available authentication mechanisms. Security requirements on individual operations declare which mechanisms apply. An operation with no security requirement is documented as publicly accessible. Tools can detect this in seconds.
- **Input validation constraints.** OpenAPI supports `maxLength`, `minLength`, `pattern`, `minimum`, `maximum`, and `enum` on all scalar fields. An operation that accepts a `username` string with no `maxLength` is specifying that unbounded input is valid. This is a constraint gap that persists into the implementation if the schema is used to generate validation code.
- **Response schema scope.** A response schema that returns 40 fields when the endpoint's documented function only needs 5 is exposing data unnecessarily. Overly broad response schemas can be detected before a single line of implementation code is written.
- **Sensitive field handling.** Fields named `password`, `ssn`, `credit_card`, or `cvv` appearing in response schemas — rather than only in request schemas with `writeOnly: true` — indicate data exposure risks that schema linting can flag automatically.
- **Deprecated security schemes.** An OpenAPI spec that defines an HTTP Basic authentication scheme without any TLS requirement annotation is advertising a scheme that transmits credentials in cleartext. This is detectable at the schema level.

The alternative to schema-time detection is runtime detection — DAST tools scanning a deployed API, penetration testers probing endpoints, or security reviews after the feature is already in production. Each of these costs significantly more in remediation effort than a linting rule that rejects the schema before it merges. A failed CI check at PR review costs one engineer one hour. A broken authentication finding from a penetration test costs a sprint.

The tooling ecosystem for schema security scanning has matured. Vacuum, Spectral, buf, oasdiff, and semgrep all have capabilities applicable to this problem. None of them require access to a running API. They operate entirely on the schema file.

## Threat Model

**Developer adds an endpoint without declaring an authentication security requirement.** The developer creates an `/admin/users/{id}` path in `openapi.yaml`, correctly describes the request and response schemas, but omits the `security` field on the operation. In OpenAPI, the absence of `security` at the operation level means the path-level or global security requirement applies — unless neither exists, in which case the endpoint is unauthenticated. If the team is using code generation from the schema, the generated server stub will not include authentication middleware. Schema linting with a rule that requires `security` on all operations catches this at PR time.

**API returning sensitive fields that are not required by the endpoint's function.** A `/users/{id}/profile` endpoint returns a response schema that includes `email`, `name`, `avatar_url`, and also `password_hash`, `recovery_codes`, and `internal_notes`. The developer copied a schema from the database model and did not remove internal fields. A linting rule that flags response schemas containing fields matching sensitive patterns — `password`, `hash`, `secret`, `recovery`, `ssn`, `cvv` — catches this before the endpoint is deployed.

**gRPC service with no authentication requirement on sensitive RPCs.** A Protobuf service definition includes an `ExportPaymentHistory` RPC that returns a `PaymentHistoryResponse` containing account numbers and transaction amounts. The proto file has no authentication annotations, no proto-gen-validate constraints on the request message's user ID field, and no comments indicating that this RPC requires elevated authorization. buf lint rules and custom plugins can flag this class of issue against the `.proto` file before the service is built.

**Security downgrade via PR.** A developer refactors an OpenAPI spec and inadvertently removes the `security` requirement from three existing endpoints while restructuring the file. This is a regression, not a new omission. oasdiff security-focused diff detection on the PR catches the removal of security requirements and fails the check before merge.

## Configuration

### OpenAPI Security Scanning with Vacuum

[Vacuum](https://github.com/daveshanley/vacuum) is a high-performance OpenAPI linter built in Go. It runs in milliseconds against large specs, supports custom rulesets, and produces structured JSON output suitable for CI integration.

**Install Vacuum:**

```bash
# Install via Go.
go install github.com/daveshanley/vacuum@latest

# Or download the binary directly.
curl -L https://github.com/daveshanley/vacuum/releases/latest/download/vacuum_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin vacuum
```

**Run against an OpenAPI spec with default rules:**

```bash
vacuum lint openapi.yaml
```

**Run with a custom ruleset:**

```bash
vacuum lint -r custom-rules.yml openapi.yaml
```

Security-relevant built-in rules in Vacuum include:

- `oas3-security-schemes` — verifies that security schemes defined in `components/securitySchemes` are well-formed.
- `oas3-operation-security-defined` — checks that security requirements on operations reference schemes that are actually declared.
- `no-http-basic` — flags HTTP Basic as a security scheme.

These built-in rules cover scheme validity but do not enforce that every operation has a security requirement. That requires a custom rule.

**Custom Vacuum rule to require security on all operations:**

```yaml
# custom-rules.yml
rules:
  no-unauthenticated-endpoints:
    description: "All endpoints must declare a security requirement"
    severity: error
    given: "$.paths.*.*"
    then:
      field: security
      function: truthy
```

This rule uses JSONPath `$.paths.*.*` to select every operation across every path. The `truthy` function asserts that the `security` field is present and non-empty. An empty `security` array — `security: []` — explicitly overrides a global security requirement with no security, so a refined rule should also reject that:

```yaml
rules:
  no-unauthenticated-endpoints:
    description: "All operations must declare a non-empty security requirement"
    severity: error
    given: "$.paths.*.*"
    then:
      field: security
      function: length
      functionOptions:
        min: 1
```

Run this in CI and any operation added without a security requirement fails the build.

### Spectral for OWASP-Aligned Security Linting

[Spectral](https://github.com/stoplightio/spectral) is a ruleset-based OpenAPI linter from Stoplight. Its advantage over Vacuum for security use cases is an actively maintained [OWASP API Security Top 10 ruleset](https://github.com/stoplightio/spectral-owasp-rules) that can be applied directly.

**Install Spectral and the OWASP ruleset:**

```bash
npm install -g @stoplight/spectral-cli
npm install -g @stoplight/spectral-owasp-rules
```

**`.spectral.yml` using the OWASP ruleset:**

```yaml
extends:
  - "@stoplight/spectral-owasp-rules"
rules: {}
```

**Run Spectral:**

```bash
spectral lint openapi.yaml --ruleset .spectral.yml
```

**Custom Spectral rule to detect missing `maxLength` on string inputs:**

```yaml
rules:
  string-input-max-length:
    description: "String request body properties must define maxLength to prevent unbounded input"
    severity: warn
    given: "$.paths.*.*.requestBody.content.*.schema.properties.*[?(@.type == 'string')]"
    then:
      field: maxLength
      function: defined
```

**Custom Spectral rule to detect sensitive fields in response schemas:**

```yaml
rules:
  no-sensitive-fields-in-responses:
    description: "Response schemas must not expose password, secret, or key fields"
    severity: error
    given: "$.paths.*.*.responses.*.content.*.schema.properties"
    then:
      function: pattern
      functionOptions:
        notMatch: "^(password|secret|api_key|private_key|cvv|ssn|credit_card|recovery_code|password_hash)$"
      field: "@key"
```

**GitHub Actions integration using `stoplightio/spectral-action`:**

```yaml
# .github/workflows/api-schema-security.yml
name: API Schema Security Scan

on:
  pull_request:
    paths:
      - "openapi.yaml"
      - "openapi/**/*.yaml"

jobs:
  spectral-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stoplightio/spectral-action@latest
        with:
          file_glob: "openapi.yaml"
          spectral_ruleset: ".spectral.yml"
```

This runs on every PR that modifies the OpenAPI spec. A severity of `error` fails the check. A severity of `warn` surfaces the finding without blocking.

### buf Lint for Protobuf and gRPC Security

[buf](https://buf.build) provides a modern toolchain for Protobuf development, including a linter, a breaking change detector, and a registry. buf lint operates on `.proto` files and enforces configurable rules.

**Install buf:**

```bash
curl -sSL https://github.com/bufbuild/buf/releases/latest/download/buf-Linux-x86_64 \
  -o /usr/local/bin/buf && chmod +x /usr/local/bin/buf
```

**`buf.yaml` with security-relevant linting enabled:**

```yaml
version: v2
lint:
  use:
    - DEFAULT
    - COMMENTS
  except:
    - PACKAGE_VERSION_SUFFIX
  enum_zero_value_suffix: _UNSPECIFIED
  rpc_allow_google_protobuf_empty_requests: false
  rpc_allow_google_protobuf_empty_responses: false
```

The `COMMENTS` rule group enforces that all RPCs, messages, and fields have documentation comments. This is relevant to security because undocumented RPCs are harder to review for authentication requirements during code review.

The `rpc_allow_google_protobuf_empty_requests: false` setting prevents the pattern of RPCs that accept no input — a pattern that often indicates a public endpoint with no user-specific authorization context.

**buf breaking change detection to catch security regressions:**

```yaml
# buf.yaml — breaking change detection section
breaking:
  use:
    - FILE
  ignore_unstable_packages: false
```

Run breaking change detection against the base branch:

```bash
buf breaking --against ".git#branch=main"
```

buf will flag removals of fields, changes to field types, and modifications to RPC signatures. From a security perspective, the most critical detectable regression is the removal of required authentication metadata from an RPC definition. If your team annotates authentication requirements as proto field options or comments, custom buf lint plugins can enforce their presence.

**proto-gen-validate for input validation constraints:**

[proto-gen-validate](https://github.com/bufbuild/protovalidate) provides validation annotations for Protobuf message fields. A proto file without validation constraints on user-supplied fields is the Protobuf equivalent of an OpenAPI spec without `maxLength`.

```protobuf
syntax = "proto3";

import "buf/validate/validate.proto";

message CreateUserRequest {
  string username = 1 [(buf.validate.field).string = {
    min_len: 3,
    max_len: 64,
    pattern: "^[a-zA-Z0-9_-]+$"
  }];
  string email = 2 [(buf.validate.field).string.email = true];
}
```

A custom buf lint plugin can check that all RPC request messages import and use `buf/validate/validate.proto` for fields that accept user-supplied strings.

### semgrep Rules for OpenAPI YAML

[semgrep](https://semgrep.dev) can match structural patterns in YAML files. This makes it effective for finding classes of missing security properties that resist expression as JSONPath rules.

**Custom semgrep rule to detect OpenAPI paths with no `security` field:**

```yaml
# rules/openapi-missing-security.yml
rules:
  - id: openapi-operation-missing-security
    patterns:
      - pattern: |
          paths:
            ...:
              $METHOD:
                ...
      - pattern-not: |
          paths:
            ...:
              $METHOD:
                security: ...
    message: "OpenAPI operation '$METHOD' has no security requirement declared"
    languages: [yaml]
    severity: ERROR
    metadata:
      category: security
      owasp: "API2:2023 Broken Authentication"
```

**semgrep rule to detect HTTP (non-HTTPS) server URLs:**

```yaml
rules:
  - id: openapi-http-server-url
    pattern: |
      servers:
        - url: "http://..."
    message: "OpenAPI server URL uses HTTP, not HTTPS. TLS is required for production APIs."
    languages: [yaml]
    severity: ERROR
```

**semgrep rule to detect sensitive field names in response schemas:**

```yaml
rules:
  - id: openapi-sensitive-response-field
    patterns:
      - pattern: |
          responses:
            ...:
              ...:
                properties:
                  $FIELD: ...
      - metavariable-regex:
          metavariable: $FIELD
          regex: "^(password|password_hash|secret|api_secret|cvv|ssn|credit_card|pin|private_key|recovery_codes?)$"
    message: "Response schema exposes sensitive field '$FIELD'. Remove or mark as writeOnly."
    languages: [yaml]
    severity: ERROR
```

Run semgrep in CI:

```bash
semgrep --config rules/ openapi.yaml --json | jq '.results[] | {path, message, severity}'
```

### Detecting Sensitive Data Exposure in Schemas

The patterns to match on field names for PII and credential detection:

| Pattern | Risk | Recommended Schema Treatment |
|---|---|---|
| `password`, `passwd` | Credential exposure in responses | `writeOnly: true`, never in response schema |
| `ssn`, `social_security` | PII — regulated under HIPAA/GDPR | `x-sensitivity: pii`, `writeOnly: true` |
| `credit_card`, `card_number`, `pan` | PCI DSS scope | Masked in responses, `x-sensitivity: pci` |
| `cvv`, `cvc`, `security_code` | Must never be stored or returned | Remove from all schemas |
| `private_key`, `signing_key` | Credential material | Never in API schemas |
| `recovery_code`, `backup_code` | Account takeover risk | `writeOnly: true` |
| `api_key`, `api_secret` | Credential exposure | Return only on initial creation with `writeOnly` |

The `writeOnly: true` property in OpenAPI indicates a field that is accepted in requests but never returned in responses. Schema validators should enforce this property for all sensitive fields that legitimately belong in request schemas (passwords on user creation, for example).

The `x-sensitivity` extension is not part of the OpenAPI standard but is a common convention. Teams can define their own sensitivity taxonomy — `pii`, `pci`, `secret` — and write linting rules that require `x-sensitivity` annotations on fields matching sensitive patterns.

### Schema Diff Security Review with oasdiff

[oasdiff](https://github.com/Tufin/oasdiff) performs structural comparison between two OpenAPI documents and can detect security-relevant changes: authentication scheme removals, security requirement downgrades, and new unauthenticated endpoints.

**Install oasdiff:**

```bash
go install github.com/tufin/oasdiff@latest
```

**Detect breaking changes between the base and PR branch versions:**

```bash
oasdiff breaking openapi-main.yaml openapi-pr.yaml
```

**Fail a CI step when authentication requirements are removed:**

```bash
# In CI, check out the base branch version and the PR version.
git show origin/main:openapi.yaml > openapi-main.yaml

BREAKING=$(oasdiff breaking openapi-main.yaml openapi.yaml --format json)

# Check for security-related breaking changes.
echo "$BREAKING" | jq -e '
  .[] | select(
    .id == "api-security-removed" or
    .id == "api-global-security-removed" or
    .id == "endpoint-security-removed"
  )
' && echo "ERROR: Authentication removed from endpoint" && exit 1
```

oasdiff breaking change IDs relevant to security include `endpoint-security-removed` (a security requirement was removed from a specific operation), `api-global-security-removed` (the global security requirement was removed), and `api-security-scheme-deleted` (a security scheme was removed from `components/securitySchemes`).

**Full GitHub Actions workflow combining Spectral, semgrep, and oasdiff:**

```yaml
name: API Schema Security

on:
  pull_request:
    paths:
      - "openapi.yaml"
      - "openapi/**"

jobs:
  schema-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install tools
        run: |
          npm install -g @stoplight/spectral-cli @stoplight/spectral-owasp-rules
          go install github.com/tufin/oasdiff@latest
          pip install semgrep

      - name: Spectral OWASP lint
        run: spectral lint openapi.yaml --ruleset .spectral.yml --fail-severity error

      - name: semgrep custom rules
        run: semgrep --config rules/openapi-security.yml openapi.yaml --error

      - name: oasdiff security regression check
        run: |
          git show origin/${{ github.base_ref }}:openapi.yaml > /tmp/openapi-base.yaml
          oasdiff breaking /tmp/openapi-base.yaml openapi.yaml \
            | grep -E "security-removed|security-scheme-deleted" \
            && echo "Security regression detected" && exit 1 || true
```

## Expected Behaviour

The following table maps schema security issues to the recommended linting tool, rule, and CI gate action.

| Schema Security Issue | Tool | Rule | CI Gate Action |
|---|---|---|---|
| Operation missing `security` requirement | Vacuum / Spectral | `no-unauthenticated-endpoints` / `oas3-operation-security-defined` | Block PR merge |
| String field with no `maxLength` in request body | Spectral | `string-input-max-length` | Warning / notify |
| Sensitive field name in response schema | Spectral / semgrep | `no-sensitive-fields-in-responses` | Block PR merge |
| HTTP (non-HTTPS) server URL | semgrep | `openapi-http-server-url` | Block PR merge |
| Security requirement removed from existing endpoint | oasdiff | `endpoint-security-removed` | Block PR merge |
| Empty `security: []` on operation (explicit unauthenticated) | Vacuum | `no-unauthenticated-endpoints` | Block PR merge |
| Missing HTTP Basic scheme annotation | Vacuum | `no-http-basic` | Block PR merge |
| Proto RPC with no validation constraints | buf / protovalidate | Custom plugin | Warning / notify |
| Proto field without `buf.validate` annotation | proto-gen-validate | Custom buf lint | Warning / notify |
| Breaking change to proto RPC signature | buf breaking | `FILE` rule group | Block PR merge |

## Trade-offs

**False positives for intentionally public endpoints.** Some endpoints are legitimately unauthenticated: health checks (`/healthz`), public documentation (`/openapi.json`), and unauthenticated OAuth initiation endpoints (`/oauth/authorize`). Rules that require `security` on all operations will flag these. The correct response is to mark intentional exceptions explicitly — an `x-public: true` extension or an empty `security: []` with an accompanying `x-security-rationale` comment — and update lint rules to accept annotated exceptions rather than silently allowing all unauthenticated operations. This makes the security decision visible and reviewable.

**Maintaining custom rules as the API evolves.** A custom Spectral rule that works perfectly for `openapi.yaml` at v1 may produce false positives or miss issues when the spec structure changes in v2. Rules that depend on specific JSONPath assumptions about schema structure are fragile. Prefer rules that operate at the operation or property level rather than deeply nested paths. Test rules against deliberately flawed schemas to verify they catch what they claim to catch.

**Schema linting not covering generated OpenAPI.** Many teams generate their OpenAPI spec from code annotations — FastAPI's automatic schema generation, Springdoc, or grpc-gateway. In these cases, the canonical source of truth is not the YAML file but the source code annotations. Linting a generated spec is still valuable, but schema security rules must run on the generated output, not the source annotations. This requires generating the spec as part of the CI pipeline before running lint, not committing a manually maintained YAML. If the generated spec and the checked-in spec diverge, a CI step that regenerates and diffs the spec catches that inconsistency.

**gRPC tooling maturity.** The OpenAPI tooling ecosystem (Spectral, Vacuum, oasdiff) is significantly more mature than the equivalent Protobuf/gRPC tooling. buf lint covers structural and style issues well but requires custom plugin development for security-specific checks like authentication annotation enforcement. Custom buf plugins require Go development. Teams without Go expertise may find semgrep patterns against `.proto` files easier to maintain in the short term — semgrep's generic YAML and plaintext matching works on `.proto` files — while accepting the trade-off of less structural awareness.

## Failure Modes

**Linting rules not covering generated OpenAPI.** The most common failure mode in schema security scanning is running lint against a stale or manually curated OpenAPI file while the actual API is generated from code annotations that produce a different spec. The lint passes because the checked-in spec has no issues. The deployed API has unauthenticated endpoints because the generated spec — which no one lints — is different. Fix: make schema generation a CI step and lint the output, not the committed file.

**buf lint missing custom plugin installation.** buf lint's built-in rules do not check for authentication annotations or protovalidate usage. Custom plugins address this but must be compiled, published, and referenced in `buf.yaml`. If the plugin binary is missing from the CI environment, buf either skips the plugin silently or fails to start. Configure CI to explicitly verify plugin availability before running lint, and pin plugin versions in `buf.yaml` to prevent silent drift.

**Spectral version incompatibilities.** Spectral's ruleset format has changed significantly between major versions. Custom rules written for Spectral v5 use a different function API than v6. OWASP ruleset packages are versioned independently from the Spectral CLI. Pin all Spectral versions in `package.json` or the CI tool installation step. A Spectral upgrade that silently disables a security rule because of a format incompatibility is worse than a lint failure — it produces a false sense of security.

**oasdiff missing security-removal detection on restructured specs.** oasdiff's breaking change detection works by comparing operation-level security requirements between two spec versions. If a PR restructures the spec file significantly — flattening `$ref` references, reorganising paths, or renaming security schemes — oasdiff may interpret the diff as adding and removing operations rather than modifying existing ones. This can cause security regressions to be missed. Mitigate this by running oasdiff with `--composed` mode for multi-file specs and by complementing oasdiff with Spectral rules that verify the current spec state independently of the diff.

**semgrep pattern matching on YAML anchors and references.** OpenAPI specs frequently use YAML anchors (`&anchor`) and `$ref` references to avoid repetition in response schemas. A semgrep pattern matching on `responses.*.content.*.schema.properties` will not match properties defined via `$ref: '#/components/schemas/UserResponse'`. semgrep's YAML mode does not resolve references. This means sensitive field detection in response schemas via semgrep only catches direct field definitions. Supplement with Spectral, which resolves `$ref` references before applying rules.
