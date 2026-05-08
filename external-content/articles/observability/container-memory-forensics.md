---
title: "Container Memory Forensics for Incident Response"
description: "Malware lives in memory only, credentials sit decrypted in heap, C2 implants leave no files on disk. This guide covers capturing and analysing container process memory without losing evidence — using /proc, gcore, CRIU checkpoints, and Volatility 3."
slug: container-memory-forensics
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - memory-forensics
  - incident-response
  - container-security
  - forensics
  - volatility
personas:
  - security-engineer
  - incident-responder
article_number: 554
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/container-memory-forensics/
---

# Container Memory Forensics for Incident Response

## Why Memory Matters More Than Disk in Container Incidents

When a container is compromised, the most valuable evidence is rarely on the filesystem. Containers are ephemeral by design: images are immutable, writable layers are thin, and attackers who know the environment will avoid writing to disk precisely because disk artefacts survive restart and are trivially collected. Memory does not get the same respect, which is why it is where the interesting material lives.

The specific categories of evidence that only exist in process memory:

**Fileless malware.** Techniques like process hollowing, reflective DLL injection in Windows workloads, and `memfd_create` + `fexecve` on Linux load executable code directly into a process's virtual address space. Nothing touches the container's writable layer. A `docker diff` or filesystem export shows nothing. The running process, however, has the injected code mapped as an anonymous executable region.

**Decrypted credentials and secrets.** Vault tokens, database passwords, API keys, and TLS private keys are injected into containers as environment variables or fetched at startup. At runtime they sit in cleartext in the process heap or stack. An attacker who has exploited a memory-disclosure vulnerability (or who has obtained `CAP_SYS_PTRACE`) can read them without any file access. When you are the incident responder, you need to do the same thing to understand the blast radius.

**C2 implants and staging artefacts.** A second-stage implant fetched over HTTPS and executed in memory leaves the C2 URL, beaconing configuration, and any collected data in the process's heap. Strings extracted from a memory dump of the target process will expose what was downloaded and where it was sent.

**Network connections and socket state.** `/proc/net/tcp` and `/proc/net/tcp6` inside the container's network namespace show open connections at the moment of capture. These disappear when the container stops. A memory dump combined with network namespace inspection gives you the full picture of what the process was communicating with.

**Ephemeral keys and session material.** TLS session keys, ephemeral Diffie-Hellman parameters, and in-memory encryption keys used by ransomware or data-exfiltration tooling exist only in the process address space during the session. Capturing memory before the container is terminated may be the only way to decrypt traffic or recover files.

The operational challenge is that containers make memory forensics harder than it is on bare-metal Linux:

- The process runs in separate PID, mount, and network namespaces. Host-side tools do not see the same view without namespace entry.
- The root filesystem is a union mount (overlayfs in most environments). Kernel symbols and library versions inside the container may differ from the host.
- Container runtimes may impose seccomp and AppArmor profiles that block `ptrace`, which is required for several capture methods.
- In Kubernetes, the kubelet may restart the container automatically, destroying memory before capture completes.

This article covers the full capture and analysis workflow: identifying the right process, acquiring memory with different privilege profiles, capturing filesystem state, and analysing dumps with Volatility 3 and manual string triage.

---

## Stopping the Clock: Preventing Evidence Destruction

Before capturing anything, prevent the container from restarting or being rescheduled. In Kubernetes:

```bash
# Prevent the pod from being replaced if the container exits
kubectl annotate pod <pod-name> -n <namespace> \
  "cluster-autoscaler.kubernetes.io/safe-to-evict=false"

# Cordon the node so the pod is not rescheduled elsewhere
kubectl cordon <node-name>

# If the pod is managed by a Deployment, scale it to zero only AFTER
# capturing memory — scaling down kills the container immediately
```

For Docker:

```bash
# Pause the container to freeze CPU execution without terminating it
# WARNING: this pauses the process — only do this after understanding
# the trade-off (network connections may time out, watchdogs may trigger)
docker pause <container-id>
```

Pausing (`SIGSTOP` via cgroups freezer) stops execution and prevents the process from overwriting in-memory data structures, but it is detectable and may trigger watchdog logic in some workloads. The safer approach for many scenarios is to capture memory without pausing and accept that some in-memory state will be slightly inconsistent — this is standard live forensics practice and is acceptable when the alternative is evidence destruction.

---

## Locating the Target Process on the Host

Container processes run as normal Linux processes on the host, visible in the host's PID namespace under different PIDs. Find the mapping:

```bash
# List all containers and their main process PIDs as seen by the host
docker inspect --format '{{.State.Pid}} {{.Name}} {{.Id}}' \
  $(docker ps -q)

# For a specific container
CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' <container-id>)
echo "Container init PID on host: $CONTAINER_PID"

# List all processes in the container's PID namespace
# The container may have forked child processes worth capturing
ls /proc/$CONTAINER_PID/root/proc/ | head -20

# Get all PIDs that share the same PID namespace as the container
TARGET_NS=$(readlink /proc/$CONTAINER_PID/ns/pid)
for pid in /proc/[0-9]*/ns/pid; do
  if [ "$(readlink $pid)" = "$TARGET_NS" ]; then
    echo "$pid"
  fi
done
```

For Kubernetes pods, find the container's PID via `crictl`:

```bash
# On the node
CONTAINER_ID=$(crictl ps | grep <pod-name> | awk '{print $1}')
crictl inspect $CONTAINER_ID | jq '.info.pid'
```

---

## Capturing Process Memory via /proc/PID/mem

The Linux kernel exposes every process's virtual address space through `/proc/<PID>/mem`. Reading it requires either being root and having `CAP_SYS_PTRACE`, or being the same user as the process. In incident response contexts you will typically be running as root on the node.

The capture procedure:

1. Read `/proc/<PID>/maps` to get the list of mapped virtual address regions.
2. For each readable region (permissions include `r`), seek to the start address in `/proc/<PID>/mem` and read the mapped length.

A minimal capture script:

```python
#!/usr/bin/env python3
"""
Capture all readable virtual memory regions from a running process.
Requires CAP_SYS_PTRACE or root on the host.
"""
import sys
import os
import re

def capture_process_memory(pid, output_path):
    maps_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"

    regions = []
    with open(maps_file, "r") as f:
        for line in f:
            parts = line.split()
            addr_range, perms = parts[0], parts[1]
            if 'r' not in perms:
                continue  # skip non-readable regions
            start, end = [int(x, 16) for x in addr_range.split('-')]
            regions.append((start, end, perms, line.strip()))

    os.makedirs(output_path, exist_ok=True)
    manifest = []

    with open(mem_file, 'rb', buffering=0) as mem:
        for start, end, perms, raw_map in regions:
            size = end - start
            if size > 512 * 1024 * 1024:  # skip implausibly large regions
                continue
            try:
                mem.seek(start)
                data = mem.read(size)
                fname = f"{start:016x}-{end:016x}.bin"
                with open(os.path.join(output_path, fname), 'wb') as out:
                    out.write(data)
                manifest.append(f"{fname}\t{perms}\t{raw_map}")
            except (OSError, ValueError) as e:
                manifest.append(f"FAILED\t{perms}\t{raw_map}\t{e}")

    with open(os.path.join(output_path, "manifest.txt"), 'w') as m:
        m.write('\n'.join(manifest))

    print(f"Captured {len(regions)} regions to {output_path}")

if __name__ == "__main__":
    capture_process_memory(int(sys.argv[1]), sys.argv[2])
```

Run this on the node with the host PID of the target process:

```bash
python3 capture_mem.py $CONTAINER_PID /forensics/$(date +%s)-pid-$CONTAINER_PID/
```

This approach does not require pausing the process. Each region is read independently; if the process modifies memory between reads, the dump will be slightly inconsistent, but this is acceptable for forensic string extraction and code analysis.

---

## gcore: Core Dump from a Running Process

`gcore` (part of GDB) generates an ELF core file from a running process without killing it. Core files are the standard input format for many memory analysis tools.

```bash
# Install gdb if not present on the node
apt-get install -y gdb  # or equivalent

# Generate a core dump. The process is briefly stopped (SIGSTOP) during capture.
# -o specifies output prefix; gcore appends the PID automatically
gcore -o /forensics/container-core $CONTAINER_PID

# The resulting file will be /forensics/container-core.<PID>
ls -lh /forensics/container-core.$CONTAINER_PID
```

`gcore` attaches with `ptrace`, pauses the process briefly (typically milliseconds to a few seconds depending on the process's heap size), dumps all readable segments, then detaches. For large JVM or Node.js processes with multi-gigabyte heaps, the pause may be long enough to trigger liveness probes in Kubernetes. Annotate the pod to disable liveness probe restarts before running gcore on large workloads if this is a concern, or accept the trade-off.

The core file can be analysed with GDB for structured inspection:

```bash
# Load the core with the container's binary
# The binary inside the container can be accessed via the container root
CONTAINER_ROOT=$(docker inspect --format '{{.GraphDriver.Data.MergedDir}}' \
  <container-id>)

gdb $CONTAINER_ROOT/usr/bin/target-binary \
    /forensics/container-core.$CONTAINER_PID

# Inside gdb: inspect heap, stack, open file descriptors
(gdb) info proc mappings
(gdb) x/100s 0x<heap-address>
```

---

## Docker Checkpoint: Full Container State Capture with CRIU

Docker's checkpoint feature uses [CRIU (Checkpoint/Restore In Userspace)](https://criu.org) to dump the complete state of a running container — all process memory, open file descriptors, network connections, and kernel state — to disk. The container can optionally be resumed from the checkpoint.

CRIU is the highest-fidelity capture method because it dumps all processes in the container (not just the init process), captures socket state, and produces structured output that CRIU itself can parse.

```bash
# Checkpoint the container (this pauses and optionally stops it)
# --leave-running keeps the container running after checkpoint
docker checkpoint create --leave-running \
  <container-id> forensic-checkpoint-$(date +%s)

# Checkpoints are stored in the container's checkpoint directory
ls /var/lib/docker/containers/<container-id>/checkpoints/
```

The checkpoint directory contains:

- `core-<PID>.img` — process registers and credentials for each process
- `mm-<PID>.img` — memory map descriptors
- `pages-<N>.img` — actual memory page contents
- `files.img` — open file descriptor table
- `sk-queues.img` — socket queues (in-flight network data)
- `tcp-stream-<ID>.img` — TCP connection state

CRIU images are binary (Protocol Buffers). Use `crit` (CRIU's image tool) to inspect them:

```bash
pip install crit
crit decode -i /var/lib/docker/containers/<id>/checkpoints/<name>/core-1.img \
  | jq '.entries[0]'
```

Note: Docker checkpoint requires `--experimental` in older Docker releases. In Docker 24+, it is available by default on Linux. CRIU requires the kernel to be compiled with `CONFIG_CHECKPOINT_RESTORE`, which is enabled in most distribution kernels since 2014.

---

## Namespace-Aware Forensics with nsenter

Host-side tools operate in the host's namespaces. Inside the container, the view of `/proc/net/tcp`, `/proc/mounts`, and the PID table is different. For accurate network and process enumeration, enter the container's namespaces before collecting:

```bash
# Enter all namespaces of the container init process
nsenter -t $CONTAINER_PID --mount --uts --ipc --net --pid -- /bin/bash

# Inside the container's namespaces:
# Network connections as the container sees them
cat /proc/net/tcp  # IPv4 TCP connections, hex-encoded addresses
cat /proc/net/tcp6

# Convert a hex address from /proc/net/tcp to dotted decimal
python3 -c "
import socket, struct
hex_addr = '0F02000A'  # example: read from /proc/net/tcp local_address field
addr = socket.inet_ntoa(struct.pack('<I', int(hex_addr, 16)))
print(addr)
"

# All processes visible inside the container
ps auxf

# Open file descriptors for the suspect process (container PID 1)
ls -la /proc/1/fd/

# Environment variables (may contain secrets)
cat /proc/1/environ | tr '\0' '\n'
```

The environment variables of a running process (`/proc/<PID>/environ`) are particularly valuable — they contain the container's initial environment including injected secrets, which may differ from what is currently in Kubernetes Secrets if secrets were rotated after the container started.

---

## Capturing the Container Filesystem and Volumes

Memory analysis is more useful when correlated with the container's filesystem state. Two approaches:

```bash
# docker export: creates a tar of the container's filesystem (union mount view)
# This includes the image layers plus the writable layer
docker export <container-id> > /forensics/container-fs-$(date +%s).tar

# Direct overlay2 copy: capture the writable layer only (what changed from image)
UPPER_DIR=$(docker inspect --format \
  '{{.GraphDriver.Data.UpperDir}}' <container-id>)
tar -czf /forensics/writable-layer-$(date +%s).tar.gz -C "$UPPER_DIR" .

# For named volumes
docker inspect <container-id> | jq '.[0].Mounts'
# Then tar each mount source
```

The writable layer copy is faster and more targeted for forensics — it shows exactly what files the container created or modified at runtime, which is the most relevant artefact for detecting fileless malware staging files or dropped payloads.

---

## Analysing Memory Dumps with Volatility 3

[Volatility 3](https://github.com/volatilityfoundation/volatility3) is the standard open-source memory forensics framework. It supports Linux ELF core files and raw memory images, and can analyse process internals, kernel structures, and network artefacts.

Install and configure:

```bash
pip install volatility3

# Volatility 3 requires a Linux symbol table (ISF file) matching the kernel
# running in the container's host. Download or generate one:
# https://isf-server.techanarchy.net/ (community ISF server)
# or generate locally: https://github.com/volatilityfoundation/dwarf2json

# For a core dump, Volatility 3 needs the raw memory format or a converted image
# Convert gcore output to a raw format Volatility can process:
vol -f /forensics/container-core.$CONTAINER_PID linux.pslist
```

Key Volatility 3 plugins for container forensics:

```bash
# List all processes visible in the dump
vol -f <memory-image> linux.pslist

# Show virtual memory maps for a specific process (look for anonymous rwx regions)
vol -f <memory-image> linux.proc_maps --pid <pid>

# Anonymous executable mappings are a strong indicator of injected code
# Filter for regions that are executable and have no backing file
vol -f <memory-image> linux.proc_maps --pid <pid> | grep "rwx\|r-x" | grep "0x0000000000000000"

# Extract strings from a specific memory region
vol -f <memory-image> linux.malfind --pid <pid>

# Network connections captured in the dump
vol -f <memory-image> linux.netstat

# Dump a specific process's memory segments to files for further analysis
vol -f <memory-image> linux.dumpfiles --pid <pid> --output-dir /forensics/vol-out/

# Check for LD_PRELOAD hooks (common persistence technique in containers)
vol -f <memory-image> linux.elfs --pid <pid>
```

The `linux.malfind` plugin is the primary tool for detecting injected code: it identifies memory regions that are executable, anonymous (no backing file), and contain content that looks like executable code (MZ headers on Windows, ELF headers or shellcode patterns on Linux). Any anonymous `rwx` region in a production container process should be treated as suspicious.

---

## Quick Triage with strings and grep

Before running a full Volatility analysis, a strings pass over the captured memory regions gives rapid triage information. This is especially useful when triaging at scale or when the Volatility symbol table is not yet available.

```bash
# Run strings over all captured memory region files
find /forensics/<capture-dir>/ -name "*.bin" -exec strings -n 8 {} \; \
  > /forensics/all-strings.txt

# Or directly from /proc/PID/mem capture (raw binary):
strings -n 8 /forensics/container-core.$CONTAINER_PID \
  > /forensics/strings-output.txt

# Triage: look for URLs and C2 infrastructure
grep -iE 'https?://[a-zA-Z0-9._/-]+' /forensics/strings-output.txt | sort -u

# IP addresses (basic pattern)
grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /forensics/strings-output.txt \
  | grep -v '^127\.\|^10\.\|^192\.168\.\|^172\.' \
  | sort -u

# Credentials patterns: common formats
grep -iE 'password|passwd|secret|token|api.?key|bearer|authorization' \
  /forensics/strings-output.txt | sort -u

# Base64-encoded payloads (look for long base64 strings, possible second-stage)
grep -E '[A-Za-z0-9+/]{64,}={0,2}' /forensics/strings-output.txt \
  | sort -u | head -50

# AWS credential patterns
grep -E 'AKIA[0-9A-Z]{16}' /forensics/strings-output.txt

# Shell commands that may indicate post-exploitation activity
grep -iE 'curl|wget|chmod\s+[47]|base64\s+-d|/bin/sh|/bin/bash' \
  /forensics/strings-output.txt | sort -u
```

Correlate IP addresses found in memory against threat intelligence feeds (AbuseIPDB, VirusTotal, Shodan) during the investigation. URLs found in anonymous executable regions are high-confidence indicators of C2 or second-stage download infrastructure.

---

## Cryptographic Integrity and Chain of Custody

Memory dumps contain credentials, PII, and operational data. Handling them requires the same care as any sensitive evidence artefact.

**Integrity hashing.** Hash every artefact immediately after capture, before analysis. Use SHA-256 minimum:

```bash
sha256sum /forensics/container-core.$CONTAINER_PID \
  > /forensics/container-core.$CONTAINER_PID.sha256

# For a directory of region files
find /forensics/<capture-dir>/ -type f -exec sha256sum {} \; \
  | sort > /forensics/<capture-dir>/SHA256SUMS
```

Store the hash file separately from the dump — ideally in an append-only log or signed by a trusted key. If the dump is ever questioned in a legal or disciplinary context, you must be able to prove the file has not been modified since capture.

**Capture metadata.** Record the following at capture time in a separate metadata file:

- Timestamp (UTC, from an NTP-synchronized source)
- Operator identity (who performed the capture)
- Container ID, image SHA, and image tag at time of capture
- Host kernel version and hostname
- Capture method and tool version
- Reason for capture and authorizing incident ticket

```bash
cat > /forensics/capture-metadata.txt <<EOF
timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
operator: $(whoami)@$(hostname)
container_id: <container-id>
image_sha: $(docker inspect --format '{{.Image}}' <container-id>)
image_tag: $(docker inspect --format '{{index .Config.Image}}' <container-id>)
host_kernel: $(uname -r)
host_hostname: $(hostname)
capture_method: gcore + /proc/PID/mem
tool_versions:
  gdb: $(gdb --version | head -1)
  python: $(python3 --version)
incident_ticket: <ticket-reference>
authorizing_manager: <name>
EOF
```

**Encrypted storage.** Memory dumps should be encrypted at rest before being transferred off the node. Use `age` or GPG:

```bash
# Encrypt with age using a recipient's public key
age -r <recipient-public-key> \
  -o /forensics/container-core.$CONTAINER_PID.age \
  /forensics/container-core.$CONTAINER_PID
```

**Access control.** Restrict read access to the forensics directory. Memory dumps from a production container may contain secrets from other services, customer data, and personal information. Even within the security team, apply need-to-know.

---

## Legal and Regulatory Considerations

Container memory forensics intersects with employment law, data protection regulations, and computer misuse statutes. The legal landscape depends heavily on jurisdiction, but some considerations are universal:

**Authorization.** Memory capture must be authorized before execution. In enterprise environments this typically means a documented incident response procedure that pre-authorizes memory capture for systems in scope, signed off by legal and HR. Capturing memory without authorization — even of a container you operate — may violate computer misuse laws in some jurisdictions if the system processes personal data belonging to individuals with rights under GDPR or CCPA.

**Personal data in memory.** A container processing financial transactions or user sessions will have personal data in memory. Capturing and retaining this data must comply with your data protection obligations. Minimize retention: delete memory dumps once analysis is complete and the incident is closed, and log the deletion.

**Cross-border data.** If the container is running in a cloud region subject to data residency requirements, transferring the memory dump to a forensics workstation in a different region may violate those requirements. Work within the same region where possible, or confirm with legal before transfer.

**Admissibility.** If the incident may result in criminal prosecution or employment termination proceedings, memory dumps may need to meet evidentiary standards. This means documented chain of custody, integrity hashing, use of forensically sound capture tools, and in some jurisdictions, involvement of a qualified digital forensic examiner. Do not contaminate the dump by running analysis tools in the same directory without copying first.

---

## Forensic Readiness: Pre-Authorizing Memory Capture

The worst time to discover that `ptrace` is blocked by your seccomp profile, or that the forensics team does not have node-level access, is during an active incident. Forensic readiness for container memory means:

**Pre-authorized capture procedures.** Document exactly which role or individual is authorized to perform memory capture on production systems, under what circumstances, and through which escalation path. Include this in the incident response runbook.

**Seccomp and AppArmor audit.** Verify that your container security profiles do not block `ptrace` for containers that may need to be forensically captured. If you use `seccomp: RuntimeDefault`, check whether `ptrace` is in the default allow list for your runtime version. If it is blocked, document the alternative capture method (CRIU checkpoint, which does not require `ptrace` from outside the container).

**Node-level access provisioning.** Ensure that incident responders can obtain node-level access (not just `kubectl exec`) in a timely manner. In cloud environments this means having a break-glass IAM role for SSH/SSM access to nodes, with audit logging of use.

**Tested toolchain.** Run a memory capture exercise on a non-production container at least quarterly. Verify that Volatility's ISF symbol tables are current for the kernel versions your node images use. Stale symbol tables mean Volatility cannot parse kernel structures accurately.

**Evidence storage.** Pre-configure an evidence bucket (S3 with Object Lock, or equivalent) with appropriate access controls and retention policies. Having to provision storage during an incident introduces delays and risks unsecured interim storage on the node's local disk.

The goal is that when a suspicious container is flagged at 2 AM, the on-call engineer can execute a documented, tested procedure without needing to improvise capture methods, locate tools, or seek real-time authorization.

---

## Summary

Container memory forensics requires combining Linux internals knowledge (`/proc`, namespaces, `ptrace`) with container runtime mechanics (overlay2, CRIU, seccomp) and memory analysis tooling (Volatility 3, strings). The capture method depends on the available privileges and the acceptable operational impact:

| Method | Pauses container | Requires ptrace | Fidelity |
|---|---|---|---|
| `/proc/PID/mem` script | No | Yes (root) | Per-region files |
| `gcore` | Briefly | Yes | ELF core |
| Docker checkpoint (CRIU) | Yes (optionally) | No (kernel-level) | Full state |
| `nsenter` + manual | No | No | Selective |

Start with the least invasive method that gives sufficient coverage. For full forensic capture with chain-of-custody requirements, CRIU checkpoint with integrity hashing and encrypted off-node storage is the most defensible approach. For rapid triage, a `/proc/PID/mem` script plus a strings pass gives fast answers without pausing the workload.

Memory forensics is not a reactive afterthought. The environments that recover from container compromises quickly are the ones where capture procedures are documented, tested, authorized, and integrated into the incident response workflow before the alert fires.
