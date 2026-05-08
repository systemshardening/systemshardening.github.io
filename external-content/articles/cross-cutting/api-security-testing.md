---
title: "API Security Testing: DAST, Fuzzing, and Automated Security Validation for REST and gRPC"
description: "API security vulnerabilities — broken object-level authorisation, mass assignment, injection — are best caught by automated testing against a running service. This guide covers OWASP API Top 10 coverage with DAST tools, property-based fuzzing with Schemathesis, authentication bypass testing, and integrating API security tests into CI/CD."
slug: api-security-testing
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - api-security
  - dast
  - fuzzing
  - security-testing
  - owasp
personas:
  - security-engineer
  - platform-engineer
article_number: 600
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/api-security-testing/
---

# API Security Testing: DAST, Fuzzing, and Automated Security Validation for REST and gRPC

## Problem

APIs are the attack surface that grows fastest and is tested least. Every new microservice, mobile backend, or partner integration exposes endpoints that handle authentication, authorisation, and user data — and almost none of those endpoints receive the same scrutiny as a web UI.

The OWASP API Security Top 10 reads like a catalogue of what static analysis cannot find:

- **BOLA (Broken Object-Level Authorisation):** User A requests `/api/orders/4821` and receives User B's order. The code is syntactically correct; the authorisation check is simply absent or insufficient.
- **Broken Authentication:** Endpoints accept expired tokens. JWTs are validated without checking the signature algorithm. Token refresh endpoints skip rate limiting.
- **Excessive Data Exposure:** The endpoint returns a full user object including `password_hash`, `internal_notes`, and `stripe_customer_id` when the client only needed `display_name`.
- **Mass Assignment:** The registration endpoint accepts `{"username": "alice", "role": "admin"}` and silently upgrades the account.
- **Security Misconfiguration:** CORS allows any origin. The `/debug/env` endpoint is reachable in production. HTTP is accepted alongside HTTPS.
- **Injection:** GraphQL queries, REST query parameters, and JSON body fields are concatenated into SQL or shell commands without sanitisation.

None of these vulnerabilities show up in a `git grep` or a SAST scan. They require a running service and real HTTP requests. Dynamic Application Security Testing (DAST), property-based fuzzing, and structured authorisation testing are the tools that find them before attackers do.

**Target systems:** REST APIs documented with OpenAPI 3.x or Swagger, gRPC services with protobuf definitions, GraphQL APIs. CI/CD pipelines running against staging or ephemeral environments.

## Threat Model

- **Adversary 1 — Insecure Direct Object Reference (IDOR):** An authenticated attacker increments or guesses object IDs in REST paths or query parameters to access resources owned by other users. Automated BOLA testing is required because the pattern is consistent enough to script but too tedious for manual review across hundreds of endpoints.
- **Adversary 2 — Authentication downgrade:** An attacker replays an expired token, removes the `Authorization` header, or substitutes a token from a different tenant. These cases must be tested exhaustively across every protected endpoint, not just the ones the developer considered sensitive.
- **Adversary 3 — Injection via unexpected input:** An attacker sends SQL metacharacters, OS command separators, or format string tokens in API parameters. Property-based fuzzers generate these inputs systematically without requiring the tester to know which parameters are vulnerable.
- **Adversary 4 — Mass assignment privilege escalation:** An attacker includes undocumented fields in POST/PUT bodies to elevate privileges, set internal flags, or modify fields the application does not expose in its schema.
- **Adversary 5 — Enumeration via error differentiation:** A 404 for a non-existent resource versus a 403 for a resource that exists but belongs to another user leaks object existence. Systematic ID enumeration testing finds these distinctions.

## Configuration

### Step 1: OpenAPI-Driven Fuzzing with Schemathesis

Schemathesis generates test cases directly from an OpenAPI or GraphQL schema. It applies property-based testing — generating edge-case inputs according to the schema types — and checks for crashes, 500 errors, response schema violations, and other anomalies.

Install Schemathesis in a virtual environment or container:

```bash
pip install schemathesis
```

Run a basic scan against a staging API:

```bash
schemathesis run https://staging.api.example.com/openapi.json \
  --checks all \
  --hypothesis-max-examples 200 \
  --base-url https://staging.api.example.com \
  --request-timeout 10 \
  --output-truncation-limit 500
```

For authenticated endpoints, provide a static token or use a CLI authentication flow:

```bash
schemathesis run https://staging.api.example.com/openapi.json \
  --checks all \
  --header "Authorization: Bearer $API_TEST_TOKEN" \
  --hypothesis-max-examples 500
```

Schemathesis supports stateful testing — chaining requests where the output of one becomes the input of the next, which is necessary for multi-step workflows:

```bash
schemathesis run https://staging.api.example.com/openapi.json \
  --stateful=links \
  --checks all \
  --hypothesis-max-examples 300 \
  --header "Authorization: Bearer $API_TEST_TOKEN"
```

The `--checks all` flag enables every built-in check: `not_a_server_error` (no 5xx), `status_code_conformance`, `content_type_conformance`, `response_schema_conformance`, `use_after_free`, and `ensure_resource_availability`. Any 500-class response or response that does not match the declared schema is a finding.

For saving results as JUnit XML for CI integration:

```bash
schemathesis run https://staging.api.example.com/openapi.json \
  --checks all \
  --header "Authorization: Bearer $API_TEST_TOKEN" \
  --junit-xml ./reports/schemathesis-results.xml \
  --hypothesis-max-examples 300
```

Reproduce a specific failure using the generated seed value printed in the output:

```bash
schemathesis run https://staging.api.example.com/openapi.json \
  --hypothesis-seed=12345 \
  --checks all \
  --header "Authorization: Bearer $API_TEST_TOKEN"
```

### Step 2: OWASP ZAP for Active REST API Scanning

OWASP ZAP provides active scanning — it sends crafted attack payloads, not just schema-generated inputs — and targets injection, XSS in API responses, and server-side issues. Use the headless Docker image for CI integration.

Import the OpenAPI spec and run an active scan:

```bash
docker run --rm \
  -v $(pwd)/reports:/zap/reports \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t https://staging.api.example.com/openapi.json \
  -f openapi \
  -r /zap/reports/zap-api-report.html \
  -J /zap/reports/zap-api-report.json \
  -z "-config globalexcludeurl.url_list.url\(0\).regex=.*/health.*"
```

For authenticated scanning, provide the auth token via an environment variable and a ZAP config file:

```bash
# zap-config.prop
replacer.full_list(0).description=auth_header
replacer.full_list(0).enabled=true
replacer.full_list(0).matchtype=REQ_HEADER
replacer.full_list(0).matchstr=Authorization
replacer.full_list(0).regex=false
replacer.full_list(0).replacement=Bearer ${API_TEST_TOKEN}
```

```bash
docker run --rm \
  -v $(pwd)/reports:/zap/reports \
  -v $(pwd)/zap-config.prop:/zap/zap-config.prop \
  -e API_TEST_TOKEN="$API_TEST_TOKEN" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t https://staging.api.example.com/openapi.json \
  -f openapi \
  -z "-configfile /zap/zap-config.prop" \
  -r /zap/reports/zap-api-report.html
```

ZAP's active scanner checks for SQL injection, command injection, path traversal, server-side template injection, and XML injection in every parameter it can identify from the OpenAPI spec.

### Step 3: Nuclei API Templates for Known Vulnerability Patterns

Nuclei applies signature-based detection using community-maintained templates. For APIs, the most relevant template categories are `exposures`, `misconfigurations`, `cves`, and `takeovers`.

```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Run API-focused templates against the staging base URL
nuclei -u https://staging.api.example.com \
  -tags api,token,exposure,misconfiguration \
  -header "Authorization: Bearer $API_TEST_TOKEN" \
  -o reports/nuclei-api-findings.json \
  -json \
  -rate-limit 50 \
  -timeout 10
```

Nuclei detects common API misconfigurations: exposed Swagger UI in production, debug endpoints (`/actuator`, `/debug/vars`, `/_debug`, `/api/v1/env`), API keys in responses, and known CVEs in popular API frameworks.

For targeted injection fuzzing using nuclei's fuzzing mode:

```bash
nuclei -u https://staging.api.example.com \
  -tags fuzz \
  -fuzzing-type replace \
  -header "Authorization: Bearer $API_TEST_TOKEN" \
  -o reports/nuclei-fuzz-findings.json \
  -json
```

### Step 4: BOLA and IDOR Testing

Broken Object-Level Authorisation is the most prevalent API vulnerability class and requires dedicated testing logic. The test pattern is straightforward: authenticate as two different users, use User A's token to access resources owned by User B.

A shell script for systematic IDOR testing:

```bash
#!/usr/bin/env bash
# bola-test.sh — test object-level authorisation across a resource collection.

BASE_URL="https://staging.api.example.com"
USER_A_TOKEN="$(get_token user_a@example.com)"
USER_B_TOKEN="$(get_token user_b@example.com)"

# Get a list of User B's resource IDs
B_RESOURCE_IDS=$(curl -s -H "Authorization: Bearer $USER_B_TOKEN" \
  "$BASE_URL/api/v1/orders" | jq -r '.[].id')

FAILURES=0

for RESOURCE_ID in $B_RESOURCE_IDS; do
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER_A_TOKEN" \
    "$BASE_URL/api/v1/orders/$RESOURCE_ID")

  if [[ "$HTTP_STATUS" == "200" ]]; then
    echo "BOLA FOUND: User A can read User B resource $RESOURCE_ID (HTTP $HTTP_STATUS)"
    FAILURES=$((FAILURES + 1))
  elif [[ "$HTTP_STATUS" == "403" || "$HTTP_STATUS" == "404" ]]; then
    echo "OK: $RESOURCE_ID returned $HTTP_STATUS"
  else
    echo "UNEXPECTED: $RESOURCE_ID returned $HTTP_STATUS"
  fi
done

echo ""
echo "BOLA test complete. Failures: $FAILURES"
exit $FAILURES
```

Run this script for every resource type that has per-user ownership: orders, documents, messages, profile data, settings. Extend the pattern to test write operations (PUT, PATCH, DELETE) and nested resource paths (`/api/v1/users/{userId}/invoices/{invoiceId}`).

### Step 5: Authentication Bypass Testing

Every protected endpoint must be tested without a token, with an expired token, with a syntactically valid but unsigned JWT, and with a token from a different tenant.

```bash
#!/usr/bin/env bash
# auth-bypass-test.sh — systematically probe authentication enforcement.

BASE_URL="https://staging.api.example.com"
ENDPOINTS=(
  "/api/v1/users/me"
  "/api/v1/orders"
  "/api/v1/admin/users"
  "/api/v1/payments"
  "/api/v1/internal/metrics"
)

# Test 1: No token at all
echo "=== Test: No Authorization header ==="
for EP in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$EP")
  if [[ "$STATUS" != "401" && "$STATUS" != "403" ]]; then
    echo "FAIL (no token): $EP returned $STATUS — expected 401/403"
  else
    echo "PASS: $EP returned $STATUS"
  fi
done

# Test 2: Expired token (generate one with exp in the past)
EXPIRED_TOKEN="$(generate_expired_jwt)"
echo ""
echo "=== Test: Expired token ==="
for EP in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $EXPIRED_TOKEN" "$BASE_URL$EP")
  if [[ "$STATUS" == "200" ]]; then
    echo "FAIL (expired token): $EP returned $STATUS — expired tokens must be rejected"
  else
    echo "PASS: $EP returned $STATUS"
  fi
done

# Test 3: Token with alg:none (algorithm confusion)
NONE_ALG_TOKEN="$(craft_none_alg_jwt user_id=test@example.com)"
echo ""
echo "=== Test: JWT with alg:none ==="
for EP in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $NONE_ALG_TOKEN" "$BASE_URL$EP")
  if [[ "$STATUS" == "200" ]]; then
    echo "FAIL (alg:none): $EP returned $STATUS — unsigned tokens must be rejected"
  else
    echo "PASS: $EP returned $STATUS"
  fi
done

# Test 4: Cross-tenant token (tenant_b token against tenant_a resources)
TENANT_B_TOKEN="$(get_token_for_tenant tenant_b)"
echo ""
echo "=== Test: Cross-tenant token ==="
for EP in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TENANT_B_TOKEN" \
    -H "X-Tenant-ID: tenant_a" "$BASE_URL$EP")
  if [[ "$STATUS" == "200" ]]; then
    echo "FAIL (cross-tenant): $EP returned $STATUS"
  else
    echo "PASS: $EP returned $STATUS"
  fi
done
```

### Step 6: Mass Assignment Testing

Mass assignment vulnerabilities occur when the API blindly binds request body fields to model attributes. The test is to send fields that should be read-only or server-controlled and verify they are ignored.

```bash
#!/usr/bin/env bash
# mass-assignment-test.sh — probe for fields that should not be writable.

BASE_URL="https://staging.api.example.com"
USER_TOKEN="$(get_token regular_user@example.com)"
USER_ID="$(get_user_id regular_user@example.com)"

# Test 1: Attempt to set role to admin at registration
echo "=== Test: role escalation at registration ==="
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser_mass","email":"testmass@example.com","password":"TestP@ss1","role":"admin"}')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
RETURNED_ROLE=$(echo "$BODY" | jq -r '.role // "none"')
if [[ "$RETURNED_ROLE" == "admin" ]]; then
  echo "FAIL: Created user has role=$RETURNED_ROLE — mass assignment via role field"
else
  echo "PASS: role field not accepted (returned: $RETURNED_ROLE, HTTP $STATUS)"
fi

# Test 2: Attempt to set is_verified on profile update
echo ""
echo "=== Test: is_verified flag via profile update ==="
RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$BASE_URL/api/v1/users/$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"display_name":"Legit Update","is_verified":true,"subscription_tier":"enterprise"}')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
IS_VERIFIED=$(echo "$BODY" | jq -r '.is_verified // "absent"')
TIER=$(echo "$BODY" | jq -r '.subscription_tier // "absent"')
if [[ "$IS_VERIFIED" == "true" || "$TIER" == "enterprise" ]]; then
  echo "FAIL: mass assignment accepted — is_verified=$IS_VERIFIED, tier=$TIER"
else
  echo "PASS: privileged fields not accepted (HTTP $STATUS)"
fi
```

### Step 7: gRPC Security Testing

gRPC services expose protobuf-serialised endpoints over HTTP/2. Standard HTTP scanners cannot exercise them without a client that speaks protobuf. Use `grpcurl` for enumeration and targeted probing, and write custom test clients for malformed protobuf fuzzing.

Enumerate gRPC services (requires server reflection enabled):

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext staging.grpc.example.com:50051 list

# Describe a service
grpcurl -plaintext staging.grpc.example.com:50051 describe com.example.UserService

# Call a method with test data
grpcurl -plaintext \
  -H "Authorization: Bearer $API_TEST_TOKEN" \
  -d '{"user_id": "00000000-0000-0000-0000-000000000001"}' \
  staging.grpc.example.com:50051 \
  com.example.UserService/GetUser
```

Test BOLA on gRPC by iterating over object IDs with different caller identities — the same pattern applies regardless of transport:

```bash
# bola-grpc-test.sh
for USER_ID in $(cat test-user-ids.txt); do
  RESPONSE=$(grpcurl -plaintext \
    -H "Authorization: Bearer $USER_A_TOKEN" \
    -d "{\"user_id\": \"$USER_ID\"}" \
    staging.grpc.example.com:50051 \
    com.example.UserService/GetUserProfile 2>&1)
  if echo "$RESPONSE" | grep -q '"email"'; then
    echo "BOLA: User A can read profile of $USER_ID"
  fi
done
```

Test authentication enforcement by calling without a token and with a malformed token:

```bash
# No auth header
grpcurl -plaintext \
  -d '{"user_id": "123"}' \
  staging.grpc.example.com:50051 \
  com.example.UserService/GetUser

# Should return: "Code: Unauthenticated" or similar
# If it returns data, the endpoint is unauthenticated
```

For fuzzing gRPC with malformed protobuf, use the `ghz` load testing tool's random payload capabilities or write a Go test client using the `google.golang.org/grpc` library to send arbitrary field values, intentionally overflow string fields, and send unexpected field numbers.

### Step 8: Injection Fuzzing via API Parameters

Beyond what Schemathesis generates from schema types, targeted injection testing requires sending known-bad payloads into every parameter. The `ffuf` HTTP fuzzer handles this efficiently against REST endpoints.

```bash
# Install ffuf
go install github.com/ffuf/ffuf/v2@latest

# SQL injection wordlist targeting API query params
ffuf -u "https://staging.api.example.com/api/v1/search?q=FUZZ" \
  -w /usr/share/wordlists/sqlmap/payloads.txt \
  -H "Authorization: Bearer $API_TEST_TOKEN" \
  -fc 400,422 \
  -mc 200,500 \
  -t 10 \
  -rate 20 \
  -o reports/ffuf-sqli.json \
  -of json

# Command injection probes in JSON body
ffuf -u "https://staging.api.example.com/api/v1/reports" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_TEST_TOKEN" \
  -d '{"name":"FUZZ","format":"pdf"}' \
  -w /usr/share/wordlists/command-injection.txt \
  -fc 400,422 \
  -mc 200,500 \
  -t 5 \
  -rate 10 \
  -o reports/ffuf-cmdi.json \
  -of json
```

A 500 response to an injection payload is a signal worth investigating manually — it may indicate unhandled exception paths that expose stack traces, or worse, that the payload reached an interpreter.

### Step 9: CI/CD Integration

Run API security tests against an ephemeral staging environment on every pull request merge to the main branch. The pipeline should fail on critical findings, warn on medium findings, and produce structured reports as artefacts.

```yaml
# .github/workflows/api-security-test.yml
name: API Security Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  api-security:
    runs-on: ubuntu-latest
    environment: staging

    services:
      api:
        image: ghcr.io/example/api:${{ github.sha }}
        ports:
          - 8080:8080
        env:
          DATABASE_URL: ${{ secrets.STAGING_DATABASE_URL }}
          JWT_SECRET: ${{ secrets.STAGING_JWT_SECRET }}
        options: >-
          --health-cmd "curl -f http://localhost:8080/health"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Schemathesis
        run: pip install schemathesis

      - name: Obtain test token
        id: auth
        run: |
          TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/token \
            -H "Content-Type: application/json" \
            -d '{"email":"ci-tester@example.com","password":"${{ secrets.CI_TEST_PASSWORD }}"}' \
            | jq -r '.access_token')
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: Run Schemathesis fuzzing
        run: |
          schemathesis run http://localhost:8080/openapi.json \
            --checks all \
            --header "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            --hypothesis-max-examples 300 \
            --junit-xml reports/schemathesis.xml \
            --exitcode-on-failure 1
        continue-on-error: true

      - name: Install nuclei
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          nuclei -update-templates

      - name: Run nuclei API templates
        run: |
          nuclei -u http://localhost:8080 \
            -tags api,exposure,misconfiguration \
            -header "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            -o reports/nuclei.json \
            -json \
            -severity medium,high,critical \
            -rate-limit 20
        continue-on-error: true

      - name: Run BOLA tests
        run: |
          chmod +x scripts/bola-test.sh
          scripts/bola-test.sh http://localhost:8080
        env:
          USER_A_EMAIL: ci-user-a@example.com
          USER_B_EMAIL: ci-user-b@example.com
          TEST_PASSWORD: ${{ secrets.CI_TEST_PASSWORD }}

      - name: Run auth bypass tests
        run: |
          chmod +x scripts/auth-bypass-test.sh
          scripts/auth-bypass-test.sh http://localhost:8080

      - name: Upload security reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: api-security-reports
          path: reports/
          retention-days: 30

      - name: Check for failures
        run: |
          NUCLEI_CRITICALS=$(jq '[.[] | select(.info.severity=="critical")] | length' \
            reports/nuclei.json 2>/dev/null || echo "0")
          if [[ "$NUCLEI_CRITICALS" -gt 0 ]]; then
            echo "Pipeline failed: $NUCLEI_CRITICALS critical findings from nuclei"
            exit 1
          fi
```

## Verification

After running the full test suite against staging:

**Schemathesis:**
- Zero `not_a_server_error` findings (no 5xx responses to generated inputs)
- Zero `response_schema_conformance` failures (responses match declared OpenAPI schema)
- Review any `status_code_conformance` failures — unexpected 4xx patterns may indicate missing error handling

**ZAP:**
- No High or Critical alerts in the JSON report
- Review Medium alerts for false positives before dismissing

**Nuclei:**
- No critical or high severity findings
- Confirm any `exposure` findings are not present in production (check separately)

**BOLA test:**
- Exit code 0 — zero cross-user resource accesses succeeded

**Auth bypass test:**
- All endpoints return 401 or 403 for missing, expired, or unsigned tokens
- No endpoint returns 200 for a cross-tenant token

**Mass assignment test:**
- Role field not reflected back in registration response
- Privileged fields (is_verified, subscription_tier) not accepted in update endpoints

**gRPC:**
- Unauthenticated calls return `Code: Unauthenticated`
- Cross-user object access returns `Code: PermissionDenied`

## Hardening Checklist

- [ ] OpenAPI/Swagger spec is current, complete, and covers all endpoints including internal ones
- [ ] Schemathesis runs in CI with `--checks all` and at least 200 examples per operation
- [ ] ZAP active scan runs against staging on every main branch build
- [ ] Nuclei API and misconfiguration templates run in CI
- [ ] BOLA test covers every resource type with per-user ownership
- [ ] Auth bypass test covers every protected endpoint (no token, expired token, alg:none, cross-tenant)
- [ ] Mass assignment test sends undocumented fields to every write endpoint
- [ ] gRPC services tested with grpcurl for enumeration, authentication enforcement, and BOLA
- [ ] Injection fuzzing covers query parameters, path parameters, and JSON body fields
- [ ] CI pipeline fails on critical findings; artefacts retained for 30 days
- [ ] `/actuator`, `/debug`, `/_internal` and similar diagnostic endpoints absent from production
- [ ] Swagger UI and OpenAPI spec endpoints disabled or access-controlled in production
- [ ] CORS policy reviewed — no wildcard origins on endpoints that return user data
- [ ] 500 errors in fuzzing reports triaged within one sprint

## References

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [Schemathesis documentation](https://schemathesis.readthedocs.io/)
- [OWASP ZAP API scanning](https://www.zaproxy.org/docs/docker/api-scan/)
- [Nuclei templates — API category](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposed-panels)
- [grpcurl](https://github.com/fullstorydev/grpcurl) — gRPC command-line client
- [ffuf — Fast web fuzzer](https://github.com/ffuf/ffuf)
- [PortSwigger — Testing for IDOR](https://portswigger.net/web-security/access-control/idor)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
