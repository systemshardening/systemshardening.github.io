---
title: "Hardening Kubernetes Against LLM-Automated Container Escapes"
description: "The UK AI Security Institute found LLMs escape containers ~50% of the time, 100% with exposed Docker sockets or privileged pods. Eliminate the specific misconfigurations that make automated escape trivial and harden the remaining attack surface against systematic AI exploitation."
slug: kubernetes-llm-escape-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: kubernetes
tags:
  - container-escape
  - ai-security
  - pod-security
  - privileged-containers
  - kubernetes
personas:
  - platform-engineer
  - security-engineer
article_number: 456
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-llm-escape-hardening/
---

# Hardening Kubernetes Against LLM-Automated Container Escapes

## The Problem

The UK AI Security Institute's SandboxEscapeBench evaluated Claude Opus 4.5 and GPT-5 against container escape scenarios in 2026. The headline finding: LLMs escape containers approximately 50% of the time across all scenarios tested, with 100% success rates on two specific configurations — exposed Docker sockets (mounting `/var/run/docker.sock` into a container) and privileged containers (`securityContext.privileged: true`). These are not novel attack vectors. Security teams have known about them for years. What has changed is the attacker.

LLMs do not get tired, do not make assumptions based on incomplete information, enumerate capabilities methodically, and can chain exploit attempts faster than human attackers. A misconfigured Kubernetes cluster that a human attacker might take hours to escape is escaped by an LLM within minutes. SandboxEscapeBench documented three behavioural patterns that distinguish LLM attackers from human ones: systematic capability enumeration (checking every available interface before attempting any exploit), methodical attempt chaining (sequencing known escape vectors in order of likelihood without skipping steps), and rapid iteration (cycling through failed attempts without the hesitation or fatigue that causes human attackers to abandon a vector prematurely).

The implication is not that new defences are needed. It is that previously tolerable misconfiguration debt now has near-certain exploitation probability. A Docker socket mount that your team flagged as "technical debt to address next quarter" is now a guaranteed full-node compromise the moment any workload in that pod is compromised. The calculus has changed.

## Threat Model

The threat model for LLM-automated escape starts with initial access to a container — via a compromised application dependency, a supply chain attack introducing malicious code into a container image, or prompt injection causing an LLM-powered application to execute attacker-controlled instructions. From that foothold, an LLM agent systematically enumerates escape vectors and executes them without hesitation.

**100% escape scenarios (eliminate immediately):**

- **Exposed Docker socket:** A container that mounts `/var/run/docker.sock` gives the LLM agent direct access to the Docker daemon running on the host. The escape is a single command: `docker run --privileged -v /:/host alpine chroot /host`. No kernel exploit required. No capability abuse. Full host filesystem read/write in seconds.
- **Privileged container:** `securityContext.privileged: true` grants the container essentially all Linux capabilities and removes seccomp and AppArmor constraints. The LLM agent uses `nsenter --target 1 --mount --uts --ipc --net --pid` to enter the host's namespaces, or writes directly to `/proc/sysrq-trigger`. Again, no kernel exploit required.

**~50% escape scenarios (harden aggressively):**

- Containers with excess capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`)
- Host path mounts that expose sensitive host directories
- Host PID namespace sharing (`hostPID: true`)
- Host network namespace sharing (`hostNetwork: true`)

**Near-zero escape scenarios (the target state):**

Containers running with a restricted seccomp profile, AppArmor or SELinux enforcing, no host mounts, no excess capabilities, non-root user, read-only root filesystem, and `allowPrivilegeEscalation: false`. The LLM agent's systematic enumeration finds nothing to exploit.

## Hardening Configuration

### Step 1: Eliminate the 100% Escape Vectors

Audit your cluster immediately for Docker socket mounts and privileged containers. These must be treated as P0 issues — not backlog items.

```bash
kubectl get pods -A -o json | jq '
  .items[] |
  select(.spec.volumes[]?.hostPath.path == "/var/run/docker.sock") |
  {namespace: .metadata.namespace, name: .metadata.name}
'
```

```bash
kubectl get pods -A -o json | jq '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  {namespace: .metadata.namespace, name: .metadata.name}
'
```

Enforce the prohibition via Kyverno so no future workload can introduce either configuration:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-privileged-and-docker-socket
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-privileged-containers
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Privileged containers are not permitted."
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: "false | nil"
    - name: block-docker-socket-mount
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Mounting the Docker socket is not permitted."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath.path | contains(@, '/var/run/docker.sock') }}"
                operator: Equals
                value: true
```

For CI/CD pipelines that currently rely on Docker socket access for image builds, migrate to daemonless build tools. Kaniko runs as a container with no daemon dependency:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-build
spec:
  containers:
    - name: kaniko
      image: gcr.io/kaniko-project/executor:latest
      args:
        - "--context=git://github.com/example/repo"
        - "--destination=registry.example.com/image:tag"
        - "--no-push=false"
      volumeMounts:
        - name: registry-credentials
          mountPath: /kaniko/.docker
  volumes:
    - name: registry-credentials
      secret:
        secretName: registry-credentials
```

BuildKit with rootless mode (`BUILDKITD_FLAGS=--oci-worker-no-process-sandbox`) and Podman in rootless mode are equivalent alternatives.

### Step 2: Enforce Pod Security Standards at Restricted Level

Apply the `restricted` Pod Security Standard to all non-system namespaces. This blocks `privileged: true`, all host namespace sharing (`hostPID`, `hostIPC`, `hostNetwork`), and requires `runAsNonRoot`, `allowPrivilegeEscalation: false`, and a restricted seccomp profile at the admission level — before any workload reaches a node.

```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Apply this to every application namespace. Exceptions should require explicit approval and compensating controls, not just silence from the policy engine.

For `kube-system`, use `baseline` as a minimum — not `privileged`. Some system components require elevated access, but the namespace should still block the most obviously dangerous configurations:

```bash
kubectl label namespace kube-system \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

### Step 3: Strip All Non-Essential Capabilities

Default Linux capabilities available to containers include `CAP_NET_RAW`, `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, and others that an LLM agent will systematically attempt to exploit. Drop everything and add back only what a specific workload explicitly requires:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
spec:
  containers:
    - name: app
      image: registry.example.com/app:v1.2.3
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        capabilities:
          drop:
            - ALL
          add: []
        seccompProfile:
          type: RuntimeDefault
```

If a workload genuinely needs a capability — `CAP_NET_BIND_SERVICE` to bind a port below 1024, for example — add it explicitly and document why. The LLM agent's systematic capability enumeration finds nothing usable when the `add` list is empty.

For workloads that need an AppArmor profile in addition to seccomp:

```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
```

### Step 4: Read-Only Root Filesystem and No Privilege Escalation

`readOnlyRootFilesystem: true` and `allowPrivilegeEscalation: false` prevent a specific class of LLM escape attempts: writing an exploit binary to the container filesystem and executing it with elevated privileges. An LLM agent that cannot write to the filesystem cannot stage binaries, cannot modify `/etc/passwd` or `/etc/sudoers` equivalents within the container, and cannot use setuid escalation paths.

Applications that write temporary files at runtime need explicit `emptyDir` volumes for those paths:

```yaml
volumeMounts:
  - name: tmp-dir
    mountPath: /tmp
  - name: app-cache
    mountPath: /var/cache/app
volumes:
  - name: tmp-dir
    emptyDir: {}
  - name: app-cache
    emptyDir: {}
```

This is not optional hardening — it is a direct mitigation against one of the attack patterns SandboxEscapeBench documented.

### Step 5: Use gVisor or Kata Containers for Highest-Risk Workloads

For workloads running untrusted code — AI inference endpoints, user-submitted code execution, third-party plugins, or any workload that processes attacker-controlled input — add a hardware or software sandbox layer. The container runtime is the last line of defence when all other controls are in place, and gVisor and Kata Containers dramatically reduce the kernel attack surface available to an LLM agent attempting kernel exploits.

Install the gVisor runtime and configure a RuntimeClass:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

Apply it to high-risk workloads:

```yaml
spec:
  runtimeClassName: gvisor
  containers:
    - name: untrusted-workload
      image: registry.example.com/inference:v2.1.0
```

Kata Containers provides VM-level isolation with a lightweight kernel per pod:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata-qemu
```

An LLM agent attempting kernel exploits against gVisor's user-space kernel finds a dramatically smaller attack surface than the host Linux kernel — and most kernel exploit techniques documented in SandboxEscapeBench's test corpus fail entirely in gVisor because the syscalls they depend on are either not implemented or are intercepted and validated before reaching real kernel code.

## Expected Behaviour After Hardening

After eliminating 100% escape vectors: querying for Docker socket mounts and privileged containers returns empty results. The Kyverno policy rejects any admission request attempting to introduce either. CI/CD pipelines build images without socket access.

After Pod Security Standards restricted: a pod spec with `privileged: true` is rejected at admission with a clear policy violation message before it reaches any node. The same applies to `hostPID: true`, `hostNetwork: true`, and `hostIPC: true`.

After capability stripping: an LLM agent that gains code execution inside a container and methodically enumerates capabilities finds none beyond the minimal required set — or none at all. The systematic enumeration that SandboxEscapeBench identified as a distinguishing LLM behaviour produces no usable leverage. The agent cycles through its known escape vectors, finds each one blocked, and exhausts its repertoire without achieving escape.

After adding gVisor for untrusted workloads: kernel exploit attempts fail because the syscall interface the agent probes is not the host kernel. The agent's rapid iteration across known kernel CVEs produces consistent failures because those CVEs do not apply to gVisor's user-space implementation.

The combination of these controls does not merely reduce escape probability — it eliminates the specific vectors that SandboxEscapeBench found produced 100% escape rates, and it reduces the remaining attack surface to the point where even systematic, tireless LLM enumeration finds no viable path to host access.

## Trade-offs and Operational Considerations

Removing Docker socket access from CI/CD requires migrating to daemonless build tools. Kaniko, BuildKit, and rootless Podman are all viable, but complex pipelines with multi-stage builds, build caching, and registry authentication need careful migration planning. Allow four to six weeks for a large pipeline estate, with parallel runs of old and new systems during transition to catch edge cases.

gVisor and Kata Containers add latency and memory overhead. gVisor intercepts every syscall, adding measurable latency to syscall-heavy workloads. Kata Containers adds VM boot time and per-pod memory overhead for the guest kernel. Profile your workloads before requiring these runtimes cluster-wide. A practical approach: require `gvisor` RuntimeClass for any namespace labelled as handling untrusted input, and leave standard workloads on the default runtime. Enforce the RuntimeClass requirement with a Kyverno policy that checks namespace labels.

`readOnlyRootFilesystem: true` breaks applications that write to their own filesystem at runtime — log files written to the container filesystem, pid files, temporary compilation artifacts in interpreted language runtimes. Audit your workloads with `strace` or Falco before enabling this flag, identify the write paths, and add `emptyDir` volumes for each. The audit is worth doing once rather than discovering failures in production.

Pod Security Standards at `restricted` will reject workloads that were previously running without issue. Run namespaces in `warn` mode before `enforce` mode to surface violations without breaking existing deployments. Treat the warning output as a remediation backlog and work through it systematically before switching to enforcement.

## Failure Modes

**Kyverno blocks `privileged: true` but allows `hostPID: true`:** An LLM agent that has access to the host PID namespace can use `nsenter` to enter the host's namespaces via any process running on the host. This achieves equivalent escape to a privileged container. The Kyverno policy must block both, and Pod Security Standards at `restricted` covers this — but if your policy implementation is custom-built rather than using PSS, verify it explicitly blocks all host namespace sharing, not only the privileged flag.

**Pod Security Standards set to `restricted` on application namespaces but `kube-system` left at `privileged`:** A compromised system pod — a DaemonSet running on every node, for example — can still be exploited for host access. The policy must cover `kube-system` at minimum with `baseline`, and any system pod that does not genuinely require elevated permissions should run under `restricted`. Audit `kube-system` workloads individually.

**gVisor deployed but some pods default to runc:** If the `runtimeClassName` field is omitted from a pod spec, Kubernetes uses the cluster-default runtime, which is typically `runc`. Unless an admission policy requires `runtimeClassName: gvisor` for high-risk namespaces, workloads will silently run under the unprotected runtime. Enforce this with a Kyverno policy that checks the `runtimeClassName` field against the namespace's risk label.

**Kyverno policy applies to `Pods` but not to pod controllers:** Kyverno policies that match on `Pod` resources catch pods submitted directly, but in most clusters, pods are created by Deployments, StatefulSets, and DaemonSets. Ensure policies also match on `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and `CronJob` resources, or rely on PSS admission which operates at the pod creation level regardless of the controller that initiated it.

## Related Articles

- [Pod Security Context](/articles/kubernetes/pod-security-context/)
- [RuntimeClass gVisor Kata](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [Falco Runtime Security](/articles/kubernetes/falco-runtime-security/)
- [Linux Unprivileged Namespace Restriction](/articles/linux/linux-unprivileged-namespace-restriction/)
- [AI Red Team Container Security](/articles/ai-landscape/ai-red-team-container-security/)
