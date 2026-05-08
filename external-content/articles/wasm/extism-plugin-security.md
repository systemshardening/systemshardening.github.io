---
title: "Extism Plugin Security: Host/Guest Trust Boundaries and Capability Isolation"
description: "Extism provides a universal plugin system built on WebAssembly. The host/guest security model limits what plugins can access, but misconfigured host functions, overpermissive memory sharing, and unverified plugin binaries break the sandbox. Securing Extism means controlling what the host exposes, not just what WASM provides."
slug: "extism-plugin-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "wasm"
tags: ["extism", "wasm", "plugin-system", "host-guest", "capability", "sandbox"]
personas: ["platform-engineer", "security-engineer"]
article_number: 286
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/wasm/extism-plugin-security/index.html"
---

# Extism Plugin Security: Host/Guest Trust Boundaries and Capability Isolation

## Problem

Extism is a plugin framework built on WebAssembly. It allows applications to load and execute user-provided or third-party WASM modules — plugins — within the host application's process. The WebAssembly sandbox provides memory isolation by default: a plugin cannot read host memory it was not explicitly given access to.

The security model breaks when:

- **Host functions expose too much.** Extism's power comes from host functions — functions the host exposes to plugins. A host function that reads arbitrary files (`read_file(path)`), executes shell commands, or performs unrestricted HTTP requests turns a sandboxed plugin into an application-level backdoor. The WASM sandbox isolates memory, but host functions are native code executing outside the sandbox.
- **Plugin I/O is not validated.** Plugins receive input via the Extism PDK (Plugin Development Kit) and return output. If the host passes user-controlled data to a plugin as input without validation, and the host trusts plugin output without validation, a malicious plugin can exploit both directions.
- **Plugin binaries are not verified.** The host loads a plugin from a path or URL. If that path can be modified (supply chain attack, path traversal, race condition), or if the URL can be redirected (DNS spoofing, MITM), a different WASM binary executes with the same host function access as the legitimate plugin.
- **Concurrent plugins share state via host.** Multiple plugin instances running concurrently in different goroutines/threads access a shared host-side state (e.g., a database connection pool or a shared configuration map). Without synchronisation and access control, one plugin can influence another's behaviour through the shared state.
- **Resource limits absent.** A plugin that allocates unbounded memory or enters an infinite loop consumes host process resources. Extism provides per-call timeout support, but it requires explicit configuration.

**Target systems:** Extism 1.0+ (Go, Rust, Python, Node.js hosts); Zellij (terminal multiplexer plugin system, Extism-based); Wasm-based plugin architectures using Extism PDK; self-hosted Extism plugin registries.

## Threat Model

- **Adversary 1 — Malicious plugin via supply chain:** An attacker substitutes a legitimate plugin binary with a malicious one — through a compromised plugin registry, a path traversal vulnerability in the plugin loader, or a DNS spoofing attack against a URL-based plugin source. The malicious plugin calls host functions to exfiltrate data or execute code.
- **Adversary 2 — Host function abuse:** A plugin (user-provided or compromised) calls host functions that were intended for internal use. A `log(message)` host function that writes to the filesystem can be used to write arbitrary content to arbitrary paths if the path is not restricted.
- **Adversary 3 — Plugin output injection:** A malicious plugin returns crafted output that the host processes without sanitisation. If the host uses plugin output in SQL queries, shell commands, or HTML templates, it becomes an injection vector.
- **Adversary 4 — Cross-plugin information leakage:** Two plugins running concurrently access shared host state. Plugin A (untrusted, user-provided) reads state written by Plugin B (trusted, internal) by timing host function calls or by exploiting a race condition in shared state management.
- **Adversary 5 — Resource exhaustion via plugin:** A plugin allocates all available memory or runs an infinite computation. The host process is OOM-killed or becomes unresponsive, affecting all users of the application.
- **Access level:** Adversaries 1 and 2 need the ability to supply or influence the loaded plugin. Adversary 3 needs the ability to run a plugin. Adversaries 4 and 5 need plugin execution access.
- **Objective:** Execute arbitrary code on the host, exfiltrate data, inject malicious output, deny service.
- **Blast radius:** A plugin with access to unrestricted host functions has the same access as the host application — filesystem, network, memory. A malicious plugin in this position is a full application compromise.

## Configuration

### Step 1: Principle of Least Privilege for Host Functions

Only expose the minimum set of host functions a plugin needs. Each host function is a potential attack surface:

```go
// Go host — registering host functions for plugins.
package main

import (
    "context"
    "fmt"
    extism "github.com/extism/go-sdk"
)

// GOOD: Expose only specific, scoped functions.
func buildRestrictedHostFunctions() []extism.HostFunction {
    return []extism.HostFunction{
        // Allow plugins to log messages — but only to the application logger,
        // not to arbitrary file paths.
        extism.NewHostFunctionWithStack(
            "log_message",
            func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
                message, _ := p.ReadString(stack[0])
                // Sanitize: strip control characters, truncate.
                message = sanitizeLogMessage(message)
                if len(message) > 1024 {
                    message = message[:1024] + "...[truncated]"
                }
                appLogger.Info("plugin log", "message", message)
            },
            []extism.ValueType{extism.ValueTypeI64},  // Input: message offset.
            []extism.ValueType{},                      // No output.
        ),

        // Allow plugins to make HTTP requests — but only to approved hosts.
        extism.NewHostFunctionWithStack(
            "http_get",
            func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
                urlStr, _ := p.ReadString(stack[0])
                // ENFORCE: only allow approved hosts.
                if !isApprovedHost(urlStr) {
                    p.SetError(fmt.Errorf("http_get: host not in allowlist: %s", urlStr))
                    stack[0] = 0
                    return
                }
                // Perform the request.
                response, err := restrictedHTTPClient.Get(urlStr)
                // ... write response to plugin memory.
            },
            []extism.ValueType{extism.ValueTypeI64},
            []extism.ValueType{extism.ValueTypeI64},
        ),
    }
}

// BAD: Do not expose these host functions.
var dangerousHostFunctions = []string{
    "exec_command",        // Shell execution from plugin.
    "read_file",           // Arbitrary filesystem read.
    "write_file",          // Arbitrary filesystem write.
    "open_tcp_socket",     // Unrestricted network.
    "eval_javascript",     // JS eval from plugin.
    "get_all_env_vars",    // Exposes all environment variables.
}
```

### Step 2: Plugin Binary Verification

Verify plugin binaries before loading:

```go
// plugin_loader/loader.go
import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "os"

    extism "github.com/extism/go-sdk"
)

type PluginManifest struct {
    Name           string `yaml:"name"`
    Path           string `yaml:"path"`
    ExpectedSHA256 string `yaml:"sha256"`
    AllowedFunctions []string `yaml:"allowed_functions"`
}

func LoadVerifiedPlugin(manifest PluginManifest, hostFunctions []extism.HostFunction) (*extism.Plugin, error) {
    // 1. Verify binary hash.
    f, err := os.Open(manifest.Path)
    if err != nil {
        return nil, fmt.Errorf("plugin not found: %w", err)
    }
    defer f.Close()

    h := sha256.New()
    if _, err = io.Copy(h, f); err != nil {
        return nil, err
    }
    actualHash := hex.EncodeToString(h.Sum(nil))

    if actualHash != manifest.ExpectedSHA256 {
        return nil, fmt.Errorf(
            "plugin integrity check failed: %s\nexpected: %s\nactual:   %s",
            manifest.Path, manifest.ExpectedSHA256, actualHash,
        )
    }

    // 2. Filter host functions to only those the plugin is allowed to use.
    allowedSet := make(map[string]struct{})
    for _, fn := range manifest.AllowedFunctions {
        allowedSet[fn] = struct{}{}
    }
    var filteredFunctions []extism.HostFunction
    for _, fn := range hostFunctions {
        if _, ok := allowedSet[fn.Name]; ok {
            filteredFunctions = append(filteredFunctions, fn)
        }
    }

    // 3. Load plugin with restricted host functions.
    ctx := context.Background()
    plugin, err := extism.NewPlugin(
        ctx,
        extism.Manifest{
            Wasm: []extism.Wasm{
                extism.WasmFile{Path: manifest.Path},
            },
        },
        extism.PluginConfig{
            EnableWasi: false,          // Disable WASI unless explicitly needed.
        },
        filteredFunctions,
    )
    return plugin, err
}
```

### Step 3: Per-Call Timeouts and Memory Limits

```go
// Enforce resource limits per plugin call.
func callPluginWithLimits(
    plugin *extism.Plugin,
    functionName string,
    input []byte,
    timeoutMs int,
    maxOutputBytes int,
) ([]byte, error) {
    ctx, cancel := context.WithTimeout(
        context.Background(),
        time.Duration(timeoutMs)*time.Millisecond,
    )
    defer cancel()

    // Call the plugin function.
    exit, output, err := plugin.CallWithContext(ctx, functionName, input)
    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            return nil, fmt.Errorf("plugin call timed out after %dms", timeoutMs)
        }
        return nil, fmt.Errorf("plugin call failed (exit=%d): %w", exit, err)
    }

    // Enforce output size limit.
    if len(output) > maxOutputBytes {
        return nil, fmt.Errorf(
            "plugin output exceeds limit: %d bytes (max %d)",
            len(output), maxOutputBytes,
        )
    }

    return output, nil
}
```

```go
// Plugin configuration with memory limits.
plugin, err := extism.NewPlugin(
    ctx,
    extism.Manifest{
        Wasm: []extism.Wasm{extism.WasmFile{Path: pluginPath}},
        Memory: &extism.MemoryOptions{
            MaxPages: 256,    // 256 × 64KiB = 16 MiB maximum.
        },
    },
    extism.PluginConfig{
        EnableWasi: false,
    },
    hostFunctions,
)
```

### Step 4: Input and Output Validation

Never trust plugin input or output without validation:

```go
// Always validate input before passing to plugins.
type PluginInput struct {
    UserID    string `json:"user_id" validate:"required,uuid4"`
    Query     string `json:"query"   validate:"required,max=1000"`
    Timestamp int64  `json:"ts"      validate:"required,gt=0"`
}

func processWithPlugin(plugin *extism.Plugin, rawInput []byte) ([]byte, error) {
    // 1. Validate input structure.
    var input PluginInput
    if err := json.Unmarshal(rawInput, &input); err != nil {
        return nil, fmt.Errorf("invalid input: %w", err)
    }
    if err := validate.Struct(input); err != nil {
        return nil, fmt.Errorf("input validation failed: %w", err)
    }

    // 2. Marshal the validated input (prevents passing raw user input).
    validatedInput, _ := json.Marshal(input)

    // 3. Call plugin with validated input and timeout.
    output, err := callPluginWithLimits(plugin, "process", validatedInput, 5000, 1_000_000)
    if err != nil {
        return nil, err
    }

    // 4. Validate and sanitize plugin output before use.
    var pluginOutput PluginOutput
    if err := json.Unmarshal(output, &pluginOutput); err != nil {
        return nil, fmt.Errorf("plugin returned invalid output: %w", err)
    }
    if err := validate.Struct(pluginOutput); err != nil {
        return nil, fmt.Errorf("plugin output validation failed: %w", err)
    }

    // 5. Sanitise text fields before using in downstream contexts.
    pluginOutput.ResultText = html.EscapeString(pluginOutput.ResultText)

    return json.Marshal(pluginOutput)
}
```

### Step 5: Plugin Isolation — One Instance Per Tenant

Never share a plugin instance between tenants. Each plugin instance has its own memory space; sharing enables cross-tenant data leakage if host functions access tenant-scoped state:

```go
// plugin_pool/pool.go — per-tenant plugin instances.
import "sync"

type TenantPluginPool struct {
    mu        sync.RWMutex
    instances map[string]*extism.Plugin   // tenantID → plugin instance.
    manifest  PluginManifest
    hostFuncs []extism.HostFunction
}

func (p *TenantPluginPool) GetOrCreate(tenantID string) (*extism.Plugin, error) {
    p.mu.RLock()
    if plugin, ok := p.instances[tenantID]; ok {
        p.mu.RUnlock()
        return plugin, nil
    }
    p.mu.RUnlock()

    p.mu.Lock()
    defer p.mu.Unlock()

    // Double-check after acquiring write lock.
    if plugin, ok := p.instances[tenantID]; ok {
        return plugin, nil
    }

    // Create per-tenant host functions with tenant context baked in.
    // This ensures host functions can only access this tenant's data.
    tenantHostFuncs := buildTenantScopedHostFunctions(tenantID, p.hostFuncs)
    plugin, err := LoadVerifiedPlugin(p.manifest, tenantHostFuncs)
    if err != nil {
        return nil, err
    }

    p.instances[tenantID] = plugin
    return plugin, nil
}

func buildTenantScopedHostFunctions(tenantID string, base []extism.HostFunction) []extism.HostFunction {
    // Replace generic host functions with tenant-scoped versions.
    // The tenant ID is captured in the closure — the plugin cannot
    // access other tenants' data through these functions.
    var scoped []extism.HostFunction
    for _, fn := range base {
        scoped = append(scoped, scopeToTenant(fn, tenantID))
    }
    return scoped
}
```

### Step 6: Approved HTTP Allowlist for Plugin Network Access

If plugins need HTTP access, implement a strict allowlist:

```go
// host_functions/http.go
var approvedHosts = map[string]bool{
    "api.openai.com":           true,
    "api.internal.example.com": true,
    "lookup.example.com":       true,
}

func isApprovedHost(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil {
        return false
    }
    // Must be HTTPS.
    if u.Scheme != "https" {
        return false
    }
    // Host must be in the allowlist (no wildcards).
    return approvedHosts[u.Hostname()]
}

// Restricted HTTP client: short timeout, no redirects to unapproved hosts.
var restrictedHTTPClient = &http.Client{
    Timeout: 5 * time.Second,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        if !isApprovedHost(req.URL.String()) {
            return fmt.Errorf("redirect to unapproved host: %s", req.URL.Host)
        }
        return nil
    },
}
```

### Step 7: Plugin Registry with Signature Verification

For production plugin distribution, use a signed plugin registry:

```go
// plugin_registry/registry.go
import (
    "github.com/sigstore/cosign/v2/pkg/cosign"
    "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

type PluginRegistry struct {
    baseURL    string
    publicKey  string   // Cosign public key for signature verification.
    httpClient *http.Client
}

func (r *PluginRegistry) FetchAndVerify(pluginName, version string) ([]byte, error) {
    // 1. Download plugin binary.
    url := fmt.Sprintf("%s/plugins/%s/%s/plugin.wasm", r.baseURL, pluginName, version)
    resp, err := r.httpClient.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    pluginBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB limit.
    if err != nil {
        return nil, err
    }

    // 2. Download signature bundle.
    sigURL := url + ".bundle"
    // ... fetch sigBundle ...

    // 3. Verify cosign signature.
    verifier, err := cosign.LoadPublicKey(context.Background(), r.publicKey)
    if err != nil {
        return nil, fmt.Errorf("load verifier: %w", err)
    }
    // Verify blob signature.
    // On failure: do not return the plugin bytes.
    if err := cosign.VerifyBlobSignature(context.Background(), pluginBytes, sigBundle, verifier); err != nil {
        return nil, fmt.Errorf("plugin signature verification failed for %s@%s: %w", pluginName, version, err)
    }

    return pluginBytes, nil
}
```

### Step 8: Telemetry

```
extism_plugin_calls_total{plugin, function, status}             counter
extism_plugin_call_duration_ms{plugin, function}                histogram
extism_plugin_timeout_total{plugin, function}                   counter
extism_plugin_memory_pages_used{plugin, tenant}                 gauge
extism_host_function_calls_total{function, plugin, status}      counter
extism_plugin_integrity_failures_total{plugin}                  counter
extism_plugin_output_oversized_total{plugin}                    counter
extism_plugin_blocked_host_requests_total{plugin, host}         counter
```

Alert on:

- `extism_plugin_integrity_failures_total` non-zero — a plugin binary failed verification; stop loading the plugin and investigate the source.
- `extism_plugin_timeout_total` spike — plugins are timing out; either a runaway computation or an upstream service the plugin calls is slow.
- `extism_plugin_blocked_host_requests_total` non-zero — a plugin attempted to call a host not on the allowlist; investigate for data exfiltration attempt.
- `extism_plugin_memory_pages_used` approaching limit — plugin is near its memory limit; may indicate malicious behaviour or a memory leak.
- `extism_host_function_calls_total{status="error"}` spike — host functions are failing for a plugin; may indicate a plugin attempting to abuse host functions beyond permitted scope.

## Expected Behaviour

| Signal | Unconfigured Extism | Hardened Extism |
|--------|--------------------|--------------------|
| Plugin reads host filesystem | Possible via host function | No `read_file` host function; blocked |
| Plugin makes outbound HTTP to C2 | Possible via host function | HTTP host function enforces allowlist; blocked |
| Tampered plugin binary loaded | Executed without detection | SHA256 or cosign check fails; load rejected |
| Plugin runs infinite loop | Host process hangs | Per-call timeout kills execution after N ms |
| Cross-tenant data access via shared plugin | Possible if instance shared | Per-tenant instances with scoped host functions |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-tenant plugin instances | Memory isolation between tenants | Higher memory usage; instance startup overhead | Pool instances with LRU eviction; pre-warm common plugins |
| No WASI | Removes WASI-provided capabilities (filesystem, network, env) | Plugins cannot use WASI stdlib | Use host functions for specific approved I/O |
| Input/output validation | Prevents injection via plugin I/O | Validation overhead; schemas must be maintained | Define plugin I/O schemas at plugin development time |
| HTTP allowlist in host function | Blocks C2 and exfiltration | Requires updating allowlist for new approved hosts | Store allowlist in configuration; reload without restart |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Plugin binary hash mismatch after legitimate update | Plugin fails to load after deployment | `extism_plugin_integrity_failures_total` alert; deployment fails | Update expected hash alongside binary in deployment; use signed registry |
| Memory limit too low for complex plugin | Plugin exits with OOM inside WASM | Plugin call fails with memory error | Profile plugin memory usage in staging; increase `MaxPages` |
| Timeout too short for slow upstream | Plugin times out when calling approved external API | `extism_plugin_timeout_total` spike | Increase timeout for that plugin; investigate upstream latency |
| Host function allowlist outdated | Plugin cannot reach required new endpoint | Connection error in plugin; blocked request alert | Add endpoint to allowlist; review security implications |
| Plugin instance pool memory leak | Host process OOM over time | Memory growth metric; eventual OOM kill | Add TTL to plugin instances; refresh pool periodically |

## Related Articles

- [WasmEdge Security](/articles/wasm/wasmedge-security/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
- [Spin Framework Security](/articles/wasm/spin-framework-security/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
