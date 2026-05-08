---
title: "WASM Binary Analysis: Security Testing and Reverse Engineering Defences"
description: "Security engineers use wasm-decompile, Ghidra, and Binary Ninja to audit WASM modules for hardcoded credentials, unsafe imports, and vulnerable patterns. This guide covers WASM analysis tooling for defenders, supply chain binary diffing, and realistic IP-protection options for proprietary WASM code."
slug: wasm-binary-analysis-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - binary-analysis
  - reverse-engineering
  - security-testing
  - ip-protection
personas:
  - security-engineer
  - platform-engineer
article_number: 581
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-binary-analysis-security/
---

# WASM Binary Analysis: Security Testing and Reverse Engineering Defences

## Problem

WebAssembly was designed for portability and speed, not for confidentiality. The binary format is a structured, validatable representation of a stack-based virtual machine — a significant step above native machine code in analysability. Every WASM module exposes a typed import/export table, a declared function count, a readable data section, and a control flow structure that decompilation tools can reconstruct into something close to the original source.

An organisation that embeds proprietary algorithms, licence checks, or cryptographic key derivation into a WASM module and ships it to end-users has, in practical terms, handed over a high-fidelity description of that logic to any analyst with the right tooling and an hour to spare. At the same time, defenders use the exact same tools to audit incoming modules for hardcoded credentials, deprecated API use, debug information leakage, and supply chain tampering. The tooling does not distinguish intent.

This article covers the analyst's toolkit, what can be extracted from a WASM binary and what cannot, how defenders use those same tools to verify security properties, what defenders can realistically do to raise the cost of analysis, and why WASM obfuscation has hard structural limits. It also addresses how to detect analysis-evasion patterns in incoming modules and how to use binary diffing as a supply chain control.

**Target tools:** WABT 1.0.36+ (`wasm2wat`, `wasm-objdump`, `wasm-decompile`), Binaryen 116+ (`wasm-opt`), wasm-tools 1.220+ (Bytecode Alliance), Ghidra 11+ with the community WASM plugin, Binary Ninja 4.x with WASM support, twiggy 0.7+.

## Threat Model

Four distinct scenarios drive the analysis in this article:

- **Competitor extracting proprietary logic.** A competitor downloads a WASM module implementing a custom pricing engine. Using `wasm-decompile` and Ghidra, they reconstruct the discount calculation logic and replicate it in their own product.
- **Security researcher bypassing a licence check.** A WASM-based software licence gate validates a token before enabling features. The analyst reads the export table, locates the validation function, and patches the WASM bytecode to always return a success value.
- **Supply chain attacker inserting a malicious module.** An attacker distributes a modified WASM module carrying an encrypted payload that decrypts and executes at runtime, evading static analysis.
- **Security auditor verifying a third-party module.** A security engineer needs to confirm that a received module contains no hardcoded credentials, calls no deprecated APIs, and carries no debug information that should not be present in production.

Adversaries 1–2 have the WASM binary only. Adversary 3 has registry push access to a dependency. Adversary 4 is an internal role with legitimate access to the received file. The first two adversaries represent offensive analysis; the last two represent the defensive application of the same tools.

## What Analysts Extract from a WASM Binary

Understanding the analyst's view is a prerequisite to building a meaningful defence.

### The Import and Export Table

Every WASM module declares its interface in structured sections readable by any conforming parser. Exports name the functions and globals the host can call; imports name the functions and memory the module requires from the host.

```bash
# Convert to text format for inspection.
wasm2wat --no-check payment-engine.wasm -o payment-engine.wat

# Dump the import/export summary.
wasm-objdump -x payment-engine.wasm | head -80
# Export[3]:
#  - func[14] <validateLicenceToken> -> "validateLicenceToken"
#  - func[27] <computeDiscount>      -> "computeDiscount"
#  - func[31] <encryptPayload>       -> "encryptPayload"
# Import[6]:
#  - func[0] env.__stack_pointer -> "env"."__stack_pointer"
#  - func[1] wasi_snapshot_preview1.fd_write -> "wasi_snapshot_preview1"."fd_write"
```

Exported function names, if retained, immediately reveal the module's internal structure. Even without a name section, the export table entries are always present — they are required for the host to call the module. An attacker who sees an export named `validateLicenceToken` knows exactly which function to target without any further analysis.

### Type Signatures

WASM is strongly typed at the bytecode level. Every function carries a type index pointing to the type section, which declares parameter and return value types. This information cannot be stripped — it is required for validation.

```bash
wasm-objdump -x payment-engine.wasm | grep -A 3 "Type\["
# Type[14]:  (i32, i32, i32) -> i32
# Type[15]:  (i64) -> i32
# Type[27]:  () -> void
```

An analyst who knows an exported function's name and reads its type signature has substantially narrowed the space of possible interpretations. A function that takes three `i32` arguments and returns an `i32` is likely an integer computation; a function taking an `i32` pointer and returning nothing likely writes to memory. Type information is structural intelligence that survives all stripping.

### String Literals in the Data Section

The WASM data section holds initialisation data copied into linear memory at startup. This is where compilers place string literals, error messages, and format strings. It survives even aggressive name stripping, because it is required for correct execution.

```bash
# Extract readable strings from the data section.
wasm-objdump -x --section=data payment-engine.wasm | strings -n 6
# licence key invalid
# api.payments.internal:8443
# AES-256-GCM
# /home/builduser/projects/payment-engine/src/core.rs
# DEBUG: raw token value: %s
```

A single `strings` pass over the data section can expose hardcoded API endpoints (including internal infrastructure hostnames), error messages that confirm control flow branches, cryptographic algorithm identifiers, build paths that reveal internal directory structures and developer usernames, and residual debug format strings that should not be present in production. This information is not removable through stripping: it is part of the module's functional data.

### Control Flow Structure

`wasm-decompile` (WABT) and the Ghidra WASM plugin reconstruct higher-level pseudocode from WASM bytecode. The result is not source code, but it closely tracks the original logic structure.

```bash
wasm-decompile payment-engine.wasm -o decompiled.dcmp
head -60 decompiled.dcmp
# function computeDiscount(a:int, b:int):int {
#   var c:int = g_a;
#   g_a = c + -16;
#   var d:int = 0;
#   if (a > 1000) goto B_a;
#   ...
# }
```

Loops, conditionals, and arithmetic are all faithfully represented. An experienced analyst reading decompiled WASM output can reconstruct the business logic of most functions within the time it would take to review a code review diff. Ghidra's WASM plugin adds cross-reference analysis, allowing the analyst to trace every call site of a given function and every memory region that function touches. Binary Ninja's WASM support provides an interactive disassembly view with type inference, making it feasible to annotate and rename functions as understanding grows — the same iterative workflow used for native binary analysis, but with significantly less ambiguity.

## Security Testing with WASM Analysis Tools

The same analysis capability is the primary mechanism for security verification of received WASM modules. Security engineers applying these tools defensively are auditing for the same properties a malicious analyst would exploit.

### Auditing for Hardcoded Credentials

```bash
# Scan the data section for strings matching credential patterns.
wasm-objdump -x --section=data target.wasm | strings -n 8 | \
  grep -Ei '(password|passwd|secret|api.?key|token|bearer|auth).*=\s*[a-z0-9+/]{8,}'

# Match against a known-bad list (internal domains, rotated keys).
wasm-objdump -x --section=data target.wasm | strings -n 8 | \
  grep -F -f /etc/security/wasm-ioc-strings.txt
```

Any match is a security finding. Hardcoded credentials in a WASM data section are visible to every user who downloads the module. There is no practical way to restrict that visibility once the module is distributed to clients.

### Detecting Calls to Deprecated or Unsafe Imports

Imports are fully enumerated in the import section. Security policy can require that specific imports are absent:

```bash
# Check whether the module imports a deprecated WASI preview-1 function.
wasm-objdump -x target.wasm | awk '/^  - func.*->/ {print $NF}' | \
  grep -F 'wasi_unstable.path_open'
# Any output is a policy violation: wasi_unstable imports must not appear in production.

# Check for debug or logging imports that should be absent from production builds.
wasm-objdump -x target.wasm | awk '/^  - func.*->/ {print $NF}' | \
  grep -Ei '(debug|trace|log_raw|__wbg_log)'
```

This check is deterministic. The import section is a complete list — a WASM module cannot call a host function it has not declared as an import. The binary cannot hide an import it actually uses.

### Verifying Absence of Debug Information

A production module must not carry debug sections. The check is mechanical and suitable for CI gating:

```bash
#!/bin/bash
# verify-no-debug.sh
WASM="${1:?usage: $0 <file.wasm>}"
FAIL=0

for section in name .debug_info .debug_line .debug_str .debug_abbrev producers; do
  if wasm-objdump -h "$WASM" 2>/dev/null | grep -q "\"${section}\""; then
    echo "FAIL: section '${section}' present in ${WASM}"
    FAIL=1
  fi
done

[ "$FAIL" -eq 0 ] && echo "PASS: no debug sections in ${WASM}"
exit "$FAIL"
```

A supplier-delivered module that fails this check was either built carelessly or was built from a debug configuration. Either outcome is grounds for rejection until the build is corrected and re-attested.

### Confirming Export Surface Stability

For modules with a known-good canonical build, the export list and import list should be stable across versions unless explicitly changed. Drift is a security signal:

```bash
# Record the baseline export surface.
wasm-objdump -x canonical.wasm | grep '^  - func' | sort > baseline-exports.txt

# Check an incoming module against the baseline.
wasm-objdump -x received.wasm | grep '^  - func' | sort > received-exports.txt

diff baseline-exports.txt received-exports.txt
# Any new export not present in the baseline requires explanation.
```

## Protecting Proprietary WASM: Realistic Options

Defenders have real tools to raise the cost of analysis. None of them prevents analysis — raising cost is the achievable goal, not preventing it entirely.

### Name Stripping

The name section is an optional custom section. Removing it forces analysts to work with generated identifiers (`$func14`, `$local3`) instead of meaningful names. This is the highest-value, lowest-cost defensive step.

```bash
# Strip all names with wasm-strip (WABT).
wasm-strip --strip=names module.wasm

# Or with wasm-opt (Binaryen) — combine with other optimisation passes.
wasm-opt -O0 --strip-debug --strip-producers module.wasm -o module-stripped.wasm

# Or in the Rust release profile (Cargo.toml):
# [profile.release]
# strip = "symbols"
```

After stripping, decompiled output uses anonymous identifiers. An analyst must re-derive the purpose of each function by reading the code rather than reading its name. For a module with hundreds of functions, this adds meaningful work. For a module with three exports implementing a well-known algorithm, it adds very little — the algorithm is recognisable from its structure regardless of names.

### Dead Code Elimination with wasm-opt

`wasm-opt`'s dead code elimination removes functions that the linker included but that are unreachable from any export. This shrinks the attack surface and removes analytical footholds — functions that call into interesting subsystems but that the module never actually exercises at runtime.

```bash
wasm-opt -O3 --dce module.wasm -o module-opt.wasm
# --dce: Dead Code Elimination pass
# -O3:  also enables function inlining, merging small functions
#       into their callers and reducing the number of distinct analysis targets.
```

After aggressive optimisation and inlining, the number of distinct functions visible to an analyst can drop by 30–60%, and the remaining functions are denser. Both effects increase the time cost of analysis.

### Combining Stripping and Optimisation in the Build Pipeline

```makefile
build-prod:
	cargo build --release --target wasm32-unknown-unknown
	wasm-opt -O3 \
	  --strip-debug \
	  --strip-dwarf \
	  --strip-producers \
	  --dce \
	  --flatten \
	  --rereloop \
	  target/wasm32-unknown-unknown/release/$(MODULE).wasm \
	  -o dist/$(MODULE).wasm
	./scripts/verify-no-debug.sh dist/$(MODULE).wasm
```

`--flatten` and `--rereloop` restructure the control flow graph into a less legible form without changing semantics. The result is valid, correct WASM that decompiles into harder-to-follow pseudocode. Expect 5–15% runtime overhead from control flow flattening; profile on representative workloads before enabling in latency-sensitive paths.

## The Hard Limits of WASM Obfuscation

This is the constraint defenders must internalise: WASM obfuscation is categorically weaker than native code obfuscation, and it is not a security boundary.

Native machine code for x86-64 or ARM has no enforced structure. An obfuscator can insert junk instructions, use indirect jumps through computed addresses, flatten control flow into a single dispatcher loop, and in some contexts use self-modifying code. Static analysis tools must recover control flow from first principles, and for heavily obfuscated native code they often fail or produce incomplete results.

WASM bytecode is structurally constrained by its validation rules. The specification requires:

- **Structured control flow.** Every branch target is a block, loop, or if-end delimiter. There are no arbitrary jumps. Any conforming WASM validator can reconstruct the full control flow graph in linear time. An analyst does not need to guess where control flow goes; the binary encodes it completely.
- **Typed operand stack.** Every instruction's stack effect is statically defined. A decompiler knows the exact type of every value on the stack at every point in the function.
- **No self-modification.** Code and data segments are separate and the execution model forbids a module from modifying its own bytecode at runtime.
- **Complete interface enumeration.** Every external interface is declared in the import and export sections. Nothing is hidden.

Because of these constraints, a decompiler for WASM can always produce a correct and complete control flow graph. The decompiled output may be noisy after heavy optimisation, but the analyst knows the decompilation is complete. For native code, an analyst must account for potentially undetected code paths. For WASM, they do not — structured control flow is a guarantee of the format.

The practical ceiling for WASM obfuscation is: name stripping, control flow flattening, constant encoding, and instruction scheduling noise. These measures raise the analyst's time investment from hours to days for a complex module. They do not prevent analysis. An organisation that needs true confidentiality for algorithm logic must keep that logic server-side, where the bytecode is never delivered to the client. That is the only reliable boundary.

### Virtualisation-Based Obfuscation

Some tools add an obfuscation layer by compiling WASM to a custom bytecode and shipping an interpreter for that bytecode inside the output WASM module. The analyst must first reverse the interpreter, then reverse the custom bytecode — an additional layer of indirection.

The structural problem with these tools is that the interpreter is itself WASM bytecode, subject to all the same analysis constraints. Once an analyst reverses the interpreter (a one-time investment per tool version), all modules produced by that tool are as open to analysis as unvirtualised WASM. Virtualisation is a cost multiplier, not a confidentiality guarantee. It also introduces performance overhead of 3–10x, making it unsuitable for most production workloads.

For a security team reviewing incoming WASM modules: a module that uses heavy obfuscation or virtualisation is a signal worth noting. Legitimate production modules rarely pay a 5–10x performance cost for obfuscation. Such a module warrants additional scrutiny of its runtime behaviour.

## Detecting Analysis-Evasion in Incoming WASM Modules

When reviewing third-party WASM modules before deployment, specific patterns suggest intentional evasion and are red flags regardless of the stated functionality of the module.

### Encrypted Payloads That Decrypt at Runtime

A module whose data section is mostly high-entropy content combined with code that XOR- or AES-decrypts a large memory block at startup is implementing a runtime-unpacking pattern. This is the primary evasion technique against static analysis. Such a module cannot be analysed for its actual behaviour until it is executed in a controlled environment — and deploying it in production to see what it does is not an acceptable security review process.

```bash
# Measure entropy of the data section.
# High entropy indicates encryption or compression.
wasm-objdump -x --section=data suspect.wasm | xxd -r -p | \
  python3 -c "
import sys, math, collections
data = sys.stdin.buffer.read()
counts = collections.Counter(data)
total = len(data)
if total == 0:
    print('No data section content.')
    sys.exit(0)
entropy = -sum((c/total)*math.log2(c/total) for c in counts.values())
print(f'Entropy: {entropy:.3f} bits/byte (max 8.0)')
"
# A typical WASM data section (strings, constants) scores 3.5–5.5 bits/byte.
# Output consistently above 7.5 bits/byte on a large block is suspicious.
```

Supplement entropy measurement with a check for a decryption loop near the module entry point:

```bash
# Look for XOR operations on a large counter near the start function.
wasm2wat suspect.wasm | grep -n 'i32.xor\|memory.copy' | head -20
# A cluster of XOR operations in a counted loop body near function 0
# is characteristic of a runtime decryptor.
```

A module with a high-entropy data section and an XOR loop in its initialisation path should not be deployed. It is intentionally opaque to static analysis — which is itself the red flag, regardless of any claimed legitimate purpose.

### Suspicious Import Patterns

A module that imports primitives beyond what its stated purpose requires warrants scrutiny:

```bash
wasm-objdump -x suspect.wasm | grep '^\s*- func.*->'
# A module described as "image resize filter" that imports wasi:io/streams
# and wasi:filesystem/types is expected.
# The same module importing a custom host function named "exec", "eval",
# or "load_module" is not.
```

Custom host imports with generic or capability-expanding names that are not documented in the module's specification should be treated as findings requiring explanation.

### Size Anomalies

A module with a small declared function count but a large binary size has a high data-to-code ratio. This is unusual for legitimate modules and consistent with an embedded payload:

```bash
FUNC_COUNT=$(wasm-objdump -h suspect.wasm | awk '/Function/ {print $4}')
FILE_SIZE=$(stat -c%s suspect.wasm)
DATA_SIZE=$(wasm-objdump -h suspect.wasm | awk '/Data/ {print $4}')
echo "Functions: $FUNC_COUNT | Data: $DATA_SIZE bytes | Total: $FILE_SIZE bytes"
# A module with 12 functions and 800 KB of data is suspicious.
```

## Binary Diffing for Supply Chain Security

For modules built from a known source under a reproducible build configuration, the canonical binary should be deterministic: the same source, compiler version, and flags produce byte-identical output. Binary diffing compares a received module against the expected canonical binary to detect tampering at the function or instruction level.

```bash
# Byte-level comparison for reproducible builds.
sha256sum canonical.wasm received.wasm
# Matching hashes confirm the module is unmodified.

# When hashes differ: structural diff with wasm-tools.
wasm-tools diff canonical.wasm received.wasm
# Reports: added functions, removed functions, changed function bodies,
#          changed imports/exports, changed data sections.

# Instruction-level diff using the text format.
wasm2wat canonical.wasm -o canonical.wat
wasm2wat received.wasm  -o received.wat
diff canonical.wat received.wat
# Human-readable diff of the WAT text — shows exactly which instructions changed.
```

For non-reproducible builds where metadata such as timestamps or build IDs are embedded, normalise before diffing:

```bash
# Strip non-semantic custom sections to reduce noise before comparison.
wasm-opt -O0 --strip-producers canonical.wasm -o canonical-norm.wasm
wasm-opt -O0 --strip-producers received.wasm  -o received-norm.wasm
diff <(wasm2wat canonical-norm.wasm) <(wasm2wat received-norm.wasm)
```

Structural differences in function bodies, or unexpected additions to the import or export table, are findings that should block deployment. The specific supply chain attack to guard against is an added backdoor function — a new export that the original source did not contain — which shows up clearly as an addition in the WAT diff.

Incorporate binary diffing into the module ingestion pipeline:

```bash
#!/bin/bash
# verify-wasm-canonical.sh
# Usage: verify-wasm-canonical.sh <received.wasm> <canonical.wasm>

RECEIVED="${1:?usage: $0 <received.wasm> <canonical.wasm>}"
CANONICAL="${2:?}"

# Normalise both modules to eliminate non-semantic metadata differences.
wasm-opt -O0 --strip-producers "$RECEIVED"  -o /tmp/received-norm.wasm
wasm-opt -O0 --strip-producers "$CANONICAL" -o /tmp/canonical-norm.wasm

if ! diff -q \
  <(wasm2wat /tmp/canonical-norm.wasm 2>/dev/null) \
  <(wasm2wat /tmp/received-norm.wasm  2>/dev/null) > /dev/null; then

  echo "FAIL: received module differs from canonical build."
  diff \
    <(wasm2wat /tmp/canonical-norm.wasm 2>/dev/null) \
    <(wasm2wat /tmp/received-norm.wasm  2>/dev/null) | head -40
  exit 1
fi

echo "PASS: received module matches canonical."
```

Combining this check with OCI signing (if the module is distributed as a container image layer) provides two independent verification paths: a cryptographic signature on the module hash, and a structural diff confirming the code content matches what was built. Both are required because a compromised signing key would defeat hash verification alone, while a diff against a separately stored canonical binary would not.

## Expected Behaviour Reference

| Action | Tool | What the analyst sees |
|--------|------|-----------------------|
| Read export table | `wasm-objdump -x` | All exported function names (if not stripped) |
| Read import table | `wasm-objdump -x` | All host dependencies, including every WASI call |
| Read type signatures | `wasm-objdump -x` | Parameter and return types for every function |
| Extract string literals | `strings` on data section | All strings: error messages, paths, URLs, keys |
| Decompile to pseudocode | `wasm-decompile` / Ghidra | Readable control flow; degrades with stripping and `--flatten` |
| Recover full control flow graph | Ghidra WASM / Binary Ninja | Always succeeds — structured control flow is guaranteed by the format |
| Recover original function names | Not possible after stripping | Analyst receives `$func0`, `$func1`; must re-derive by reading code |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Name stripping | Raises analysis time; removes obvious entry points | Production debugging requires the unstripped build | Store unstripped artifacts in the internal build archive, indexed by git SHA |
| `wasm-opt --flatten --rereloop` | Degrades decompiled readability | 5–15% runtime overhead; longer build time | Profile on representative workloads before enabling |
| Dead code elimination | Reduces attack surface; removes analysis footholds | Must verify all required exports still work | Run functional tests on optimised output in CI |
| Keeping logic server-side | True confidentiality — bytecode is not distributed | Latency; availability dependency; architectural cost | Apply selectively to highest-sensitivity functions only |
| Binary diffing for ingested modules | Detects supply chain tampering at the function level | Requires a canonical reference build | Demand reproducible builds and SBOM attestations from suppliers |
| Rejecting high-entropy data sections | Blocks runtime-unpacking evasion technique | May incorrectly flag legitimately compressed data | Check for compression headers first; treat remainder as suspicious |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| wasm-opt validation break | Module rejected at runtime after optimisation | `wasm-tools validate` returns non-zero | Reduce opt level to `-O2`; file bug against Binaryen |
| Binary diff false positive from non-deterministic metadata | Canonical comparison fails on a legitimate rebuild | Diff shows only custom-section changes | Normalise by stripping custom sections before comparison |
| High-entropy data from legitimate compression | Module rejected by evasion detector | Check for zstd/gzip headers in data section bytes | Allowlist modules with provenance attestation; verify compression is declared in the producers section |
| `--flatten` breaks indirect call tables | Runtime call-through-table failure | Functional test failure in CI | Test indirect call paths explicitly; `--flatten` interacts with `call_indirect` |
| Ghidra plugin crash on unusual section layout | Analysis tooling fails silently | No output, no error surfaced | Run `wasm-tools validate` first; fall back to `wasm2wat` for raw text inspection |

## Related Articles

- [WASM Debugging Security: Stripping Debug Symbols, Source Maps, and Build Hardening](/articles/wasm/wasm-debug-symbol-security/)
- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [Reproducible WASM Builds and SBOM Generation](/articles/wasm/reproducible-wasm-builds/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASM Dynamic Linking Security](/articles/wasm/wasm-dynamic-linking-security/)
- [WASM Supply Chain Scanning Tools](/articles/wasm/wasm-supply-chain-scanning-tools/)
