---
title: "Pod Security Context Deep Dive: runAsNonRoot, readOnlyRootFilesystem, and Capabilities"
description: "Kubernetes SecurityContext has over 15 configurable fields, but most teams only set runAsNonRoot: true and consider the job done."
slug: "pod-security-context"
date: 2026-02-23
lastmod: 2026-02-23
category: "kubernetes"
tags: ["kubernetes", "security-context", "containers", "pod-security", "capabilities"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 26
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "iac-scanning"
published: true
layout: article.njk
permalink: "/articles/kubernetes/pod-security-context/index.html"
---

# Pod Security Context Deep Dive: runAsNonRoot, readOnlyRootFilesystem, and Capabilities

## Problem

[Kubernetes](https://kubernetes.io) SecurityContext has over 15 configurable fields, but most teams only set `runAsNonRoot: true` and consider the job done. The remaining fields control critical security boundaries: whether the container can write to its filesystem, which Linux capabilities it holds, whether child processes can gain more privileges than the parent, and which seccomp profile restricts syscall access.

The specific challenges:

- **Missing fields leave default-open gaps.** A container with `runAsNonRoot: true` but without `readOnlyRootFilesystem: true` can still write malicious binaries to the container filesystem. Without `allowPrivilegeEscalation: false`, a process can use setuid binaries to gain root. Without dropping capabilities, the container retains `NET_RAW` (enabling ARP spoofing) and other capabilities it does not need.
- **Pod-level vs. container-level settings cause confusion.** SecurityContext exists at both `spec.securityContext` (pod level) and `spec.containers[].securityContext` (container level). Container-level settings override pod-level settings, but only for the fields that are set. Missing fields fall through to defaults, not to the pod-level value for all fields.
- **Common mistakes break workloads silently.** Setting `runAsUser: 0` alongside `runAsNonRoot: true` causes an admission error. Setting `readOnlyRootFilesystem: true` without providing writable volumes for `/tmp` or application caches causes crashes. Dropping `ALL` capabilities without adding back `NET_BIND_SERVICE` prevents web servers from binding to ports below 1024.
- **No built-in decision framework.** Different workload types (web servers, databases, workers, init containers) need different SecurityContext configurations, but Kubernetes provides no guidance on which settings to apply to which workload type.

This article covers every SecurityContext field with practical examples, a decision matrix by workload type, common mistakes and how to avoid them, and enforcement using admission policies.

**Target systems:** Kubernetes 1.29+ with Pod Security Standards or a policy engine ([Kyverno](https://kyverno.io), [OPA](https://www.openpolicyagent.org) [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)) for enforcement.

## Threat Model

- **Adversary:** Attacker with code execution inside a container (via application vulnerability, compromised dependency, or malicious image).
- **Access level:** Unprivileged process running inside a container with default SecurityContext settings.
- **Objective:** Escalate from unprivileged container user to root (via setuid binaries or capability abuse), write persistent backdoors to the container filesystem, perform network attacks (ARP spoofing via NET_RAW), access host resources (via privileged mode or hostPID/hostNetwork), or escape the container entirely.
- **Blast radius:** Without SecurityContext hardening, a compromised container can gain root inside the container, write and execute malicious binaries, spoof network traffic, and potentially escape to the host. With proper SecurityContext, the attacker is confined to a non-root, read-only, capability-dropped environment where privilege escalation paths are eliminated.

## Configuration

### Step 1: The Hardened Baseline SecurityContext

This is the recommended starting configuration for most workloads. Every field is explicitly set rather than relying on defaults:

```yaml
# hardened-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: registry.example.com/web-app:2.1.0
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache/app
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: cache
          emptyDir:
            sizeLimit: 500Mi
```

### Step 2: SecurityContext Field Reference

**Pod-level fields** (under `spec.securityContext`):

| Field | Purpose | Recommended Value |
|-------|---------|-------------------|
| `runAsNonRoot` | Prevents containers from running as UID 0 | `true` |
| `runAsUser` | Sets the UID for all containers | Application-specific (1000+) |
| `runAsGroup` | Sets the primary GID for all containers | Match `runAsUser` |
| `fsGroup` | Sets the GID for volume mounts; files created on volumes get this GID | Match `runAsGroup` |
| `fsGroupChangePolicy` | Controls when fsGroup ownership is applied to volumes | `OnRootMismatch` (faster than default `Always`) |
| `supplementalGroups` | Additional GIDs for the container process | Only add groups needed for file access |
| `seccompProfile` | Restricts which syscalls the container can make | `RuntimeDefault` minimum |
| `sysctls` | Kernel parameter tuning for the pod's network namespace | Only set when required (e.g., `net.core.somaxconn`) |

**Container-level fields** (under `spec.containers[].securityContext`):

| Field | Purpose | Recommended Value |
|-------|---------|-------------------|
| `allowPrivilegeEscalation` | Controls whether a process can gain more privileges than its parent | `false` |
| `readOnlyRootFilesystem` | Mounts the container's root filesystem as read-only | `true` |
| `capabilities.drop` | Linux capabilities to remove | `ALL` |
| `capabilities.add` | Linux capabilities to add back after dropping | Only what is needed |
| `privileged` | Gives the container full host access | `false` (never set to true) |
| `procMount` | Controls what /proc exposes | `Default` (masked proc) |
| `seccompProfile` | Per-container seccomp override | Set if container needs a different profile than pod default |

### Step 3: Workload-Specific Configurations

**Web server (nginx, reverse proxy) that needs to bind to port 80/443:**

```yaml
# nginx-security-context.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        runAsGroup: 101
        fsGroup: 101
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: nginx
          image: registry.example.com/nginx:1.27.0
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache/nginx
            - name: run
              mountPath: /var/run
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
        - name: run
          emptyDir: {}
```

**Note:** Modern nginx images support running as non-root on ports above 1024. Configure nginx to listen on 8080 instead of 80, and use a Service to map port 80 to 8080. This avoids needing the `NET_BIND_SERVICE` capability entirely.

**Database ([PostgreSQL](https://www.postgresql.org)) with persistent storage:**

```yaml
# postgres-security-context.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: production
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        runAsGroup: 999
        fsGroup: 999
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: postgres
          image: registry.example.com/postgres:16.2
          ports:
            - containerPort: 5432
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
            - name: run
              mountPath: /var/run/postgresql
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: run
          emptyDir: {}
        - name: tmp
          emptyDir: {}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 50Gi
```

**Init container that needs temporary elevated access:**

```yaml
# init-container-example.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-init
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-with-init
  template:
    metadata:
      labels:
        app: app-with-init
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: fix-permissions
          image: registry.example.com/busybox:1.36
          command: ["sh", "-c", "chown -R 1000:1000 /data"]
          securityContext:
            runAsNonRoot: false
            runAsUser: 0
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
              add:
                - CHOWN
                - FOWNER
          volumeMounts:
            - name: data
              mountPath: /data
      containers:
        - name: app
          image: registry.example.com/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: app-data
```

**Note:** The init container runs as root with only `CHOWN` and `FOWNER` capabilities, then exits. The main container runs as non-root with all capabilities dropped.

### Step 4: Decision Matrix by Workload Type

| Workload Type | runAsNonRoot | readOnlyRootFilesystem | Capabilities | allowPrivilegeEscalation | Notes |
|---------------|-------------|----------------------|--------------|------------------------|-------|
| Stateless web app | true | true | Drop ALL | false | Add emptyDir for /tmp |
| API server (Go, Java) | true | true | Drop ALL | false | Add emptyDir for temp files and caches |
| nginx/reverse proxy | true | true | Drop ALL | false | Listen on 8080+; Service maps to 80 |
| PostgreSQL/MySQL | true | true | Drop ALL | false | fsGroup must match image UID; emptyDir for /run |
| [Redis](https://redis.io) | true | true | Drop ALL | false | emptyDir for /data if not using persistence |
| Worker/queue consumer | true | true | Drop ALL | false | Simplest case; no special requirements |
| Init container (chown) | false (root) | false | Drop ALL, add CHOWN + FOWNER | false | Runs briefly, then exits |
| CronJob/batch | true | true | Drop ALL | false | Same as worker |
| Monitoring agent | true | true | Drop ALL | false | May need hostPath mounts for node metrics |

### Step 5: Enforce with Admission Policy

Use Kyverno to enforce SecurityContext requirements across the cluster:

```yaml
# kyverno-require-security-context.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-security-context
  annotations:
    policies.kyverno.io/title: Require Security Context
    policies.kyverno.io/description: >-
      Requires all containers to set readOnlyRootFilesystem,
      drop ALL capabilities, and disable privilege escalation.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-read-only-root
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "All containers must set readOnlyRootFilesystem: true"
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true
    - name: require-drop-all-capabilities
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "All containers must drop ALL capabilities"
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    drop:
                      - ALL
    - name: require-no-privilege-escalation
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "All containers must set allowPrivilegeEscalation: false"
        pattern:
          spec:
            containers:
              - securityContext:
                  allowPrivilegeEscalation: false
```

### Step 6: Test SecurityContext Configurations

Verify that the settings are applied correctly inside the running container:

```bash
# Check the running user
kubectl exec -n production deploy/web-app -- id
# Expected: uid=1000 gid=1000 groups=1000

# Check filesystem is read-only
kubectl exec -n production deploy/web-app -- touch /test-file 2>&1
# Expected: touch: /test-file: Read-only file system

# Check writable emptyDir volumes
kubectl exec -n production deploy/web-app -- touch /tmp/test-file
# Expected: no error

# Check capabilities
kubectl exec -n production deploy/web-app -- cat /proc/1/status | grep Cap
# Expected: CapBnd and CapEff should show 0000000000000000 (no capabilities)

# Verify no privilege escalation
kubectl exec -n production deploy/web-app -- cat /proc/1/status | grep NoNewPrivs
# Expected: NoNewPrivs: 1

# Test that a privileged pod is rejected by admission policy
kubectl run test-privileged --image=busybox --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"test","image":"busybox","securityContext":{"privileged":true}}]}}'
# Expected: Error from server: admission webhook denied the request
```

## Expected Behaviour

After applying SecurityContext configurations:

- All containers run as non-root (UID 1000+), verified by `id` command output
- Container root filesystems are read-only; writes to non-volume paths fail with "Read-only file system"
- Application writes to emptyDir volumes at `/tmp` and application-specific cache directories succeed normally
- Linux capabilities are fully dropped; `cat /proc/1/status` shows zeroed capability bitmasks
- Privilege escalation is disabled; setuid binaries inside the container have no effect
- Admission policies block pods that do not meet SecurityContext requirements
- Init containers that require temporary elevated access run successfully with minimal capabilities, then exit before the main container starts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| readOnlyRootFilesystem | Prevents writing backdoors or modifying binaries in the container | Applications that write to the local filesystem (log files, temp files, caches, PID files) crash | Add emptyDir volumes for every writable path. Check application documentation for writable directories |
| Drop ALL capabilities | Eliminates capability-based privilege escalation and network attacks | Containers that need specific capabilities (NET_BIND_SERVICE for port 80, SYS_PTRACE for debugging) fail | Drop ALL, then add back only the specific capabilities needed. Never add SYS_ADMIN |
| runAsNonRoot + specific UID | Prevents root-level access inside the container | Images built to run as root (many [Docker](https://www.docker.com) Hub images) fail to start | Use `-nonroot` image variants or rebuild images with a non-root USER instruction |
| allowPrivilegeEscalation: false | Blocks setuid binaries and capability inheritance | Some legacy applications depend on setuid for operation (older versions of ping, su, sudo) | Replace setuid-dependent functionality with capability-based or redesigned alternatives |
| Admission policy enforcement | Prevents non-compliant pods cluster-wide | Blocks legitimate workloads that have not been updated to meet requirements | Roll out in audit mode first. Exclude system namespaces (kube-system). Give teams time to update manifests |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| readOnlyRootFilesystem without writable volumes | Application crashes on startup with "read-only file system" errors | Application logs; pod enters CrashLoopBackOff | Identify which paths the application writes to (strace or error messages), add emptyDir volumes for those paths |
| runAsUser conflicts with image | Container process cannot read its own binary or config files because they are owned by a different UID | Permission denied errors in application logs | Set fsGroup to match the expected GID, or rebuild the image with correct file ownership |
| runAsNonRoot: true with image that defaults to root | Pod fails admission with "container has runAsNonRoot and image will run as root" | `kubectl describe pod` shows the error; pod stays in Pending | Set an explicit `runAsUser` to a non-root UID, or use an image built with a non-root USER |
| Capabilities dropped that application needs | Application-specific functionality fails (e.g., cannot bind to port 443, cannot send raw packets) | Feature-specific errors in application logs | Identify the required capability and add it back minimally. Never re-add ALL |
| Kyverno policy blocks system pods | kube-system pods fail to deploy after cluster upgrade | System pods in Pending state; Kyverno audit logs show denials | Exclude kube-system and other system namespaces from the policy using `exclude` rules |

## When to Consider a Managed Alternative

**Transition point:** Writing SecurityContext for a handful of workloads is straightforward. When your cluster runs 50+ deployments across multiple teams, ensuring every workload has a correct SecurityContext becomes a governance challenge. If teams regularly deploy pods that fail admission policies or run with incomplete security settings, automated scanning and remediation tools reduce friction.

**Recommended providers:**

- **[Snyk](https://snyk.io):** Scans Kubernetes manifests, [Helm](https://helm.sh) charts, and Kustomize overlays for missing or misconfigured SecurityContext fields during CI/CD. Identifies containers running as root, missing readOnlyRootFilesystem, or retaining unnecessary capabilities before deployment.

**What you still control:** The SecurityContext values for each workload, the decision matrix for which settings apply to which workload type, admission policy configuration and exceptions, and the testing process for validating security settings against running containers.


## Related Articles

- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
- [Kubernetes Image Policy Enforcement: Cosign, Notation, and Admission Webhooks](/articles/kubernetes/image-policy-enforcement/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
