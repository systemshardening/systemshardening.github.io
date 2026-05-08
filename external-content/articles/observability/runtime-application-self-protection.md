---
title: "Runtime Application Self-Protection (RASP): In-Process Security Monitoring and Blocking"
description: "RASP instruments the application runtime itself — JVM agents, Python function hooks, Go middleware — giving it full execution context to detect and block SQL injection, command injection, and path traversal at the exact point they occur, not at the network perimeter. This article covers how RASP works, open-source and commercial options, implementing lightweight Python and Java RASP, performance trade-offs, and how RASP fits as a defence-in-depth layer alongside input validation and WAFs."
slug: runtime-application-self-protection
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - rasp
  - runtime-security
  - waf
  - application-security
  - injection-prevention
personas:
  - security-engineer
  - platform-engineer
article_number: 553
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/runtime-application-self-protection/
---

# Runtime Application Self-Protection (RASP): In-Process Security Monitoring and Blocking

## Problem

A Web Application Firewall (WAF) inspects HTTP traffic at the network boundary. It sees raw bytes: an HTTP request, a URL, headers, and a body. It does not know whether the query string `id=1 OR 1=1--` will reach a SQL database, a cache key lookup, or a log file. It applies pattern matching against a signature database and makes a probabilistic decision. The result: false positives that block legitimate traffic, and false negatives that let subtly-encoded injections through.

Runtime Application Self-Protection (RASP) takes a fundamentally different approach. Instead of sitting outside the application, RASP instruments the application itself. When a SQL query is about to be sent to the database driver, RASP intercepts it at that exact call site — with full knowledge of the query string, the parameters, the calling function, and the execution context. It is not guessing whether an HTTP request might cause SQL injection. It is watching the SQL query being constructed and executed in real time.

The distinction matters in practice:

- A WAF sees `GET /search?q='; DROP TABLE users--`. It applies regex patterns and may or may not block it depending on encoding, chunked transfer, or header manipulation.
- RASP sees `cursor.execute("SELECT * FROM products WHERE name='" + q + "'")` — the literal unsanitised string concatenation at the database call site. There is no ambiguity about intent.

The same logic applies to command injection, path traversal, SSRF, and deserialization attacks. RASP observes these at the OS syscall level, the file system API, or the network socket — wherever the dangerous operation actually happens. This article covers how RASP instrumentation works across language runtimes, open-source and commercial implementations, how to build lightweight RASP hooks in Python and Java, performance impact, blocking vs detection mode, and how RASP fits within a layered security architecture.

**Target systems:** Java applications (Spring Boot, Jakarta EE), Python web services (Flask, FastAPI, Django), Go services, Kubernetes-deployed workloads running instrumented runtimes.

## Threat Model

- **Adversary 1 — SQL injection via indirect path:** An attacker submits `1 UNION SELECT username, password FROM admin_users--` as a product ID. The WAF does not flag it because it is URL-encoded and arrives in a JSON body rather than a query parameter. The application's input validation checks the field is numeric — but uses a regex that passes for `1 UNION SELECT...` because it anchors incorrectly. RASP, watching the database driver call, detects that the resulting query has a UNION clause where none should exist and blocks execution before the query is sent.
- **Adversary 2 — Command injection via a library function:** A PDF generation endpoint passes a user-supplied filename to a shell command via a third-party library. The developer does not call `subprocess.run` directly — they call `pdf_library.render(filename)`. The WAF and code review both miss this. RASP intercepts the eventual `execve` or `subprocess` call and detects the injection.
- **Adversary 3 — Path traversal in a file download endpoint:** An attacker sends `filename=../../../../etc/passwd`. The application normalises the path and checks it starts with `/app/uploads` — but the normalisation is flawed. RASP, intercepting the `open()` call, checks the resolved path against an allowlist of permitted directories and blocks the read.
- **Adversary 4 — Deserialization RCE:** An attacker exploits a Java deserialization gadget. The WAF does not understand Java serialisation format. RASP, instrumented in the JVM, hooks the `ObjectInputStream.readObject` call and blocks deserialization of classes not on the allowlist.
- **Access level:** Adversaries operate through standard HTTP — no privileged access required. Exploitation succeeds because the application has a vulnerability. RASP is the last in-process line of defence before the vulnerable operation executes.
- **Blast radius without RASP:** Database contents exfiltrated, OS command execution, arbitrary file reads, or full RCE depending on the attack vector.

## RASP vs WAF: Architecture Comparison

| Dimension | WAF | RASP |
|-----------|-----|------|
| Location | Network perimeter (before the app) | Inside the application process |
| Context available | HTTP request/response only | Full runtime state: call stack, query parameters, resolved paths |
| SQL injection detection | Pattern-match on HTTP payload | Inspect the actual SQL string at the driver call |
| Encoding bypass risk | High — many encoding variations evade patterns | Low — the decoded, evaluated string is inspected at execution |
| False positive cause | Legitimate requests matching attack patterns | Misconfigured allowlists on safe operations |
| Performance impact | Adds network hop latency | Adds in-process instrumentation overhead (1–5%) |
| Language awareness | None | Full — knows Java/Python/Go semantics |
| Deployment coupling | Independent of app | Requires instrumentation per language/framework |

WAFs and RASP are complementary. A WAF reduces noise and blocks obvious attacks at low cost. RASP catches what the WAF misses and provides ground-truth context. Neither replaces input validation and parameterised queries.

## How RASP Instrumentation Works

### JVM Agents (Java, Kotlin, Scala, Clojure)

The JVM provides a standard Java Agent API (`java.lang.instrument`) that allows attaching a JAR to a JVM process. The agent uses a `ClassFileTransformer` to rewrite bytecode as classes are loaded. RASP agents use this to inject hooks at specific call sites — before a method executes, after it returns, or around it entirely.

Byte-buddy is the most common library for this. A RASP agent targeting `java.sql.Statement.executeQuery` rewrites the class bytecode to call the RASP check function before the actual database call:

```java
// RASP agent using Byte-Buddy: intercept JDBC executeQuery.
// Agent premain: attached with -javaagent:/path/to/rasp-agent.jar
public class RaspAgent {
    public static void premain(String args, Instrumentation inst) {
        new AgentBuilder.Default()
            // Target java.sql.Statement and all implementations.
            .type(isSubTypeOf(Statement.class))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder
                    .method(named("executeQuery").or(named("execute")).or(named("executeUpdate")))
                    .intercept(MethodDelegation.to(SqlInterceptor.class))
            )
            .installOn(inst);
    }
}

public class SqlInterceptor {
    @RuntimeType
    public static Object intercept(
            @SuperCall Callable<?> zuper,
            @Argument(0) String sql) throws Exception {
        // Check the actual SQL string before execution.
        if (RaspPolicyEngine.isSqlInjection(sql)) {
            RaspEvent event = new RaspEvent("sql-injection", sql, Thread.currentThread().getStackTrace());
            RaspEventSink.record(event);
            if (RaspConfig.isBlockingMode()) {
                throw new SecurityException("RASP: SQL injection blocked. Request ID: " + RequestContext.getId());
            }
        }
        return zuper.call();   // Execute original method.
    }
}
```

The `premain` hook runs before `main()` — the agent is attached at JVM startup via the `-javaagent` flag. For containers, this means adding the flag to the JVM command, not modifying application code.

### Python: AST Hooks and Function Wrapping

Python does not have a bytecode rewriting API as straightforward as the JVM agent API, but it offers two practical approaches: wrapping built-in functions at import time, and using `sys.meta_path` import hooks to modify modules as they load.

The simplest production-viable approach is function wrapping. Because Python functions are first-class objects, the original function can be replaced with a wrapper that runs the RASP check and then calls the original:

```python
# rasp_hooks.py — lightweight RASP via function wrapping.
import sqlite3
import subprocess
import builtins
import os
import functools
from rasp_policy import is_sql_injection, is_command_injection, is_path_traversal
from rasp_events import record_event, is_blocking_mode

# --- SQL injection hook: wrap sqlite3.Cursor.execute ---

_original_cursor_execute = sqlite3.Cursor.execute

@functools.wraps(_original_cursor_execute)
def _hooked_cursor_execute(self, sql, parameters=()):
    if is_sql_injection(sql):
        record_event("sql-injection", {"sql": sql})
        if is_blocking_mode():
            raise SecurityError(f"RASP: SQL injection detected in query: {sql[:80]}...")
    return _original_cursor_execute(self, sql, parameters)

sqlite3.Cursor.execute = _hooked_cursor_execute

# --- Command injection hook: wrap subprocess.run and subprocess.Popen ---

_original_subprocess_run = subprocess.run

@functools.wraps(_original_subprocess_run)
def _hooked_subprocess_run(args, **kwargs):
    cmd = args if isinstance(args, str) else " ".join(str(a) for a in args)
    # Shell=True with user-controlled input is almost always a command injection.
    if kwargs.get("shell") and is_command_injection(cmd):
        record_event("command-injection", {"cmd": cmd, "shell": True})
        if is_blocking_mode():
            raise SecurityError(f"RASP: Command injection blocked: {cmd[:80]}")
    return _original_subprocess_run(args, **kwargs)

subprocess.run = _hooked_subprocess_run

# Also patch Popen directly (many libraries use it internally).
_original_popen_init = subprocess.Popen.__init__

def _hooked_popen_init(self, args, **kwargs):
    cmd = args if isinstance(args, str) else " ".join(str(a) for a in args)
    if kwargs.get("shell") and is_command_injection(cmd):
        record_event("command-injection", {"cmd": cmd, "shell": True})
        if is_blocking_mode():
            raise SecurityError(f"RASP: Command injection blocked: {cmd[:80]}")
    return _original_popen_init(self, args, **kwargs)

subprocess.Popen.__init__ = _hooked_popen_init

# --- Path traversal hook: wrap builtins.open ---

_original_open = builtins.open
_ALLOWED_BASE_DIRS = frozenset(["/app/uploads", "/app/static", "/tmp/rasp-safe"])

@functools.wraps(_original_open)
def _hooked_open(file, mode="r", **kwargs):
    resolved = os.path.realpath(file) if isinstance(file, (str, bytes)) else None
    if resolved and is_path_traversal(resolved, _ALLOWED_BASE_DIRS):
        record_event("path-traversal", {"path": resolved})
        if is_blocking_mode():
            raise SecurityError(f"RASP: Path traversal blocked: {resolved}")
    return _original_open(file, mode, **kwargs)

builtins.open = _hooked_open
```

Install these hooks as early as possible in the application's entry point — before any web framework initialises, so all subsequent calls from framework code and third-party libraries are intercepted:

```python
# app.py — entry point
import rasp_hooks   # Must be first import; patches builtins and stdlib.
from fastapi import FastAPI
# ... rest of application initialisation
```

### Go: Middleware and Interface Wrapping

Go does not support runtime bytecode injection. RASP for Go relies on middleware (for HTTP-level checks) and wrapping database driver interfaces. The `database/sql` package uses a driver interface, which can be wrapped at registration time:

```go
// rasp/sql.go — wrap the database/sql driver with RASP checks.
package rasp

import (
    "context"
    "database/sql/driver"
    "fmt"
    "regexp"
)

// RaspDriver wraps any database/sql driver.
type RaspDriver struct {
    Wrapped driver.Driver
}

type RaspConn struct {
    Wrapped driver.Conn
}

type RaspStmt struct {
    Wrapped driver.Stmt
    Query   string
}

func (d RaspDriver) Open(name string) (driver.Conn, error) {
    conn, err := d.Wrapped.Open(name)
    if err != nil {
        return nil, err
    }
    return RaspConn{Wrapped: conn}, nil
}

func (c RaspConn) Prepare(query string) (driver.Stmt, error) {
    if err := checkSQLInjection(query); err != nil {
        RecordEvent("sql-injection", map[string]string{"query": query})
        if IsBlockingMode() {
            return nil, fmt.Errorf("RASP: SQL injection blocked")
        }
    }
    stmt, err := c.Wrapped.Prepare(query)
    if err != nil {
        return nil, err
    }
    return RaspStmt{Wrapped: stmt, Query: query}, nil
}

// Heuristic: detect unparameterised queries with injected SQL operators.
var sqlInjectionPatterns = regexp.MustCompile(
    `(?i)(\bOR\b\s+['"\d]|UNION\s+SELECT|;\s*DROP\s+TABLE|--\s*$|\/\*.*\*\/)`)

func checkSQLInjection(query string) error {
    if sqlInjectionPatterns.MatchString(query) {
        return fmt.Errorf("injection pattern detected")
    }
    return nil
}
```

## SQL Injection Detection at the Driver Level

Detecting SQL injection at the driver level (rather than at the HTTP layer) lets RASP make decisions based on the actual query structure. The core detection logic needs to distinguish between legitimate queries and injected ones.

Effective techniques at this layer:

**Structural analysis:** Parse the SQL and compare the query structure against a template. If the application always runs `SELECT id, name FROM products WHERE category = ?`, and the executed query has an extra `UNION SELECT` clause, that structural deviation is unambiguous.

**Parameterisation enforcement:** Reject any query that uses string concatenation rather than parameterised placeholders. Any query containing single-quoted string literals where a parameter placeholder should appear is a policy violation.

**Token-count analysis:** Parse the SQL token stream. If the token count exceeds the expected count by more than a threshold, the query has been expanded — likely by injection.

The regex approach shown in the Go example above is a starting point but will miss encoded variants. Production RASP implementations use a proper SQL parser (e.g., `sqlparse` in Python, JSqlParser in Java) to do structural comparison.

## Command Injection Detection at the OS Level

At the `subprocess.run` or `execve` level, the detection strategy changes. The RASP hook knows:

- Whether `shell=True` was used (if so, the command string is passed to `/bin/sh -c`, which is the common exploitation path)
- The full command string after all application-level string construction
- The calling stack frame

The detection policy: if `shell=True` and the command string contains characters that are meaningful to the shell (`|`, `;`, `&&`, `||`, backticks, `$()` subshell), and those characters appear in a section of the string that originated from an external input source, flag it.

The "originated from external input" tracking is the hard part — it requires taint tracking, which is available in some commercial RASP implementations but expensive to implement from scratch. A practical lightweight alternative: if `shell=True`, flag all commands for review and require them to be in an allowlist. Most applications have a small, fixed set of shell commands they legitimately invoke.

## Open-Source and Commercial RASP Tools

**OpenRASP (Baidu):** Open-source RASP for Java, PHP, and Python. Java implementation uses a Java agent; PHP uses an extension. Includes a management console. Actively maintained on GitHub. The detection logic covers SQL injection, command injection, SSRF, XXE, file operation attacks, and deserialization. The Java agent performs bytecode instrumentation at class load time using ASM. Production deployments exist at scale.

**Sqreen / Datadog Application Security Management (ASM):** Commercial. Sqreen was acquired by Datadog and integrated as Datadog ASM. Agent-based, language-specific agents for Java, Python, Ruby, Go, Node.js, PHP, .NET. Integrates with the Datadog APM agent — traces from the application already flow to Datadog, and ASM enriches them with security signals. Blocking mode is available. Well-suited for organisations already on Datadog.

**Contrast Security:** Commercial, enterprise-focused. The most complete RASP implementation: taint tracking propagates through the application, so the "originated from external input" problem is solved. Supports Java, .NET, Python, Ruby, Go, Node.js. The instrumentation is invasive — Contrast rewrites a large fraction of the standard library. The accuracy is high; the performance overhead is correspondingly higher than simpler hook-based approaches.

**IAST (Interactive Application Security Testing) overlap:** Tools like Contrast Security and Seeker blur the line between RASP and IAST — they instrument for both runtime protection and vulnerability detection during testing. Running Contrast in test mode against your test suite surfaces vulnerabilities without manual code review.

## Performance Impact and Latency

RASP adds instrumentation overhead. The magnitude depends on implementation and check complexity:

| Instrumentation point | Typical overhead | Notes |
|-----------------------|-----------------|-------|
| JVM bytecode rewriting (agent attach) | 200–500ms at startup | One-time cost; does not affect per-request latency |
| Per-JDBC-call SQL check (regex) | 5–20 µs per query | Negligible for most applications |
| Per-JDBC-call SQL check (parser) | 50–200 µs per query | Relevant if queries are very frequent |
| Python function wrapper overhead | 1–3 µs per call | CPython function call overhead |
| Go middleware per-request | 1–5 µs per request | One HTTP check; negligible |
| Full taint tracking (Contrast-style) | 5–15% CPU overhead | Track every data flow through the application |

The practical guidance: regex-based RASP hooks at key call sites add less than 1% overhead for most web applications. Parser-based checks at the database driver add measurable latency only if the application issues hundreds of queries per request. Full taint tracking is the most accurate and the most expensive — use it in staging and for high-value production services; profile first.

To measure your own overhead:

```bash
# Baseline latency without RASP agent.
wrk -t4 -c100 -d30s http://localhost:8080/api/products

# Repeat with RASP agent attached.
JAVA_OPTS="-javaagent:/opt/rasp/rasp-agent.jar" java -jar app.jar &
wrk -t4 -c100 -d30s http://localhost:8080/api/products
```

Compare p50, p95, and p99 latencies. If p99 increases by more than 10%, profile which hooks are on the hot path and consider switching from parser-based to regex-based checks for those specific call sites.

## Blocking Mode vs Detection-Only Mode

RASP deployments typically start in detection-only mode and graduate to blocking mode after a tuning period.

**Detection-only mode:** Every policy violation is recorded as a security event (with call stack, request context, timestamp) and logged to a SIEM or the RASP management console. No request is blocked. This mode has zero false-positive impact on users. Use it to establish a baseline of false positives before enabling blocking.

**Blocking mode:** Violations cause the RASP to throw an exception or return an error response, aborting the dangerous operation. The request receives a 403 or 500 depending on where in the stack the block occurs. Blocking mode eliminates the vulnerability in real time — but a false positive blocks a legitimate user.

A graduated rollout:

1. Deploy in detection-only mode. Run for one to two weeks. Collect all events.
2. Triage events: true positives (actual attacks or vulnerable code paths), false positives (legitimate operations that matched a RASP rule incorrectly).
3. Add allowlist entries for false-positive patterns. Adjust rule thresholds.
4. Enable blocking mode for high-confidence rules (SQL injection at the driver, command injection with `shell=True`) first.
5. Keep detection-only for lower-confidence rules (path traversal on paths that are complex to allowlist) until tuned further.

## False Positive Management

False positives in RASP come from two sources: overly broad detection patterns, and legitimate application behaviours that resemble attacks.

Common false-positive categories:

- **Legitimate dynamic SQL in admin tools or ORMs:** Some ORMs construct SQL dynamically in ways that look like injection (e.g., dynamic ORDER BY clause built from a column name). Detect these by adding the specific SQL template to the allowlist.
- **Shell commands in batch processing:** A background job that calls `subprocess.run(["convert", user_file, output_file], shell=False)` is safe — `shell=False` means the arguments are passed directly to `execve` without shell interpretation. The RASP hook should not flag `shell=False` commands unless the argument itself contains shell metacharacters.
- **Path traversal in legitimate file management:** An admin interface that navigates directories will read paths like `/app/data/../config`. If the resolved path is within the allowed directory, the RASP should permit it.

Track false positive rate as a metric:

```
rasp_events_total{rule, verdict}       counter   # verdict: blocked / detected / allowlisted
rasp_false_positives_total{rule}       counter   # incremented by ops team triage
rasp_allowlist_entries_total{rule}     gauge
```

Alert if `rasp_false_positives_total` for any rule exceeds a threshold — it indicates either a rule that needs refinement or a change in application behaviour.

## Telemetry

```
rasp_events_total{rule, mode, verdict}           counter
rasp_blocked_requests_total{rule}                counter
rasp_detection_latency_seconds{rule}             histogram
rasp_agent_active                                gauge   # 0 = agent not attached; alert immediately
rasp_allowlist_hits_total{rule}                  counter
rasp_policy_reload_timestamp_seconds             gauge
```

Alert on:

- `rasp_agent_active == 0` — the RASP agent is not running in a pod that should have it; a deployment may have been rolled out without the agent flag.
- `rasp_events_total{verdict="blocked"}` spike — active exploitation attempt in progress; correlate with source IP and user account.
- `rasp_detection_latency_seconds` p99 exceeding threshold — a RASP rule is on a hot code path; profile and optimise.
- `rasp_allowlist_hits_total` zero for more than 24 hours on a production service — the allowlist may not be loading correctly.

## Expected Behaviour

| Attack | WAF only | RASP (detection) | RASP (blocking) |
|--------|----------|-----------------|-----------------|
| SQL injection via JSON body (URL-encoded) | May miss if encoding not in signatures | Event logged with full SQL context | Request aborted before DB call |
| Command injection via third-party library | Not visible — library abstracts the HTTP layer | Event logged with full command and call stack | `execve` call blocked |
| Path traversal with double encoding | May miss depending on normalisation | Event logged with resolved path | `open()` call blocked |
| Deserialization gadget | No visibility into serialised payload | JVM hook fires before class instantiation | Deserialization aborted |
| Parameterised query (legitimate) | N/A | No event (parameterised; no injection pattern) | No block |

## RASP as a Defence-in-Depth Layer

RASP is not a replacement for input validation, parameterised queries, or a WAF. Each layer catches different things and has different failure modes:

- **Input validation** rejects malformed input before it reaches business logic. It is the fastest and cheapest defence. It fails when validation logic has gaps or encoding issues.
- **Parameterised queries / prepared statements** prevent SQL injection at the database protocol level by separating query structure from data. They are the most reliable defence against SQL injection specifically but do not address command injection or path traversal.
- **WAF** blocks known-bad traffic at the network edge before it reaches the application. It is effective against commodity attacks but blind to application context.
- **RASP** intercepts dangerous operations at the exact execution point, with full application context. It catches what all the above layers miss — but it runs inside the application process and can be bypassed by an attacker who has achieved code execution.

The correct architecture has all four layers. RASP's unique value is its position inside the application: it fires on every dangerous operation regardless of how the input arrived or how many layers it passed through to get there.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| In-process instrumentation | Full context; no encoding bypasses | Agent must be bundled per language runtime | Use a well-maintained agent (OpenRASP, Datadog ASM); test in staging first |
| Detection-only mode (initial) | Zero user impact during tuning | Attacks not blocked during tuning period | Ensure other layers (WAF, parameterised queries) are in place |
| Parser-based SQL analysis | High accuracy; no regex bypass | 50–200 µs per query overhead | Profile hot paths; use regex for low-severity rules |
| Blocking mode | Actual attack prevention | False positives block legitimate users | Two-week detection-only period; allowlist before enabling blocking |
| Taint tracking | Eliminates false negatives from unknown input paths | 5–15% CPU overhead | Use in staging for IAST; selective production use for critical services |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Agent not attached at startup | RASP provides no protection; all events silenced | `rasp_agent_active == 0` alert | Fix JVM flags / Python import order; redeploy |
| Rule throws unhandled exception | Application request fails with 500 | Error rate spike coinciding with RASP deployment | Wrap all RASP hooks in try/except; log and allow-through on internal error |
| Allowlist too broad | Legitimate injections are allowed through | Manual review of allowlisted events against attacks | Tighten allowlist; move to structural matching rather than string matching |
| High hook latency on hot path | p99 latency regression after RASP deployment | `rasp_detection_latency_seconds` p99 alert | Profile; replace parser-based check with faster rule for that call site |

## Related Articles

- [Application Security Logging](/articles/observability/application-security-logging/)
- [Container Escape Detection](/articles/observability/container-escape-detection/)
- [eBPF and Tetragon for Runtime Security](/articles/observability/ebpf-tetragon/)
- [Falco Security Rules](/articles/observability/falco-security-rules/)
- [Process Tree Security Analysis](/articles/observability/process-tree-security-analysis/)
