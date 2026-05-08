---
title: "Native Sidecar Containers in Kubernetes 1.29+: Lifecycle, Security, and Mesh Migration"
description: "restartPolicy: Always init containers GA'd in 1.29 fix the long-standing init/main race. Bigger security wins for service-mesh and log-shipper deployments."
slug: "native-sidecar-containers"
date: 2026-04-29
lastmod: 2026-04-29
category: "kubernetes"
tags: ["kubernetes", "sidecar", "service-mesh", "init-containers", "lifecycle"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 208
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/kubernetes/native-sidecar-containers/index.html"
---

# Native Sidecar Containers in Kubernetes 1.29+: Lifecycle, Security, and Mesh Migration

## Problem

The classic sidecar pattern — a container in the same Pod as the application that handles cross-cutting concerns (TLS termination, log forwarding, metrics export, mTLS in service mesh) — has been the default for years. Pre-1.29 Kubernetes had no first-class concept of a sidecar; teams used regular `containers` and dealt with the lifecycle problems:

- **Startup race.** The application container starts before the mesh proxy is ready; the first 100ms of requests bypass the mesh. With Istio's default config, this manifests as missing mTLS on early requests.
- **Shutdown race.** When a Pod is deleted, all containers receive SIGTERM simultaneously. The mesh proxy may exit before the application's drain completes, breaking in-flight requests.
- **Job and CronJob brokenness.** Jobs with sidecars never complete because the sidecar (a long-running process) never exits. Workarounds (preStop hooks that signal the proxy, shared volumes for completion markers) are fragile.
- **Restart semantics.** A crashed sidecar restarts independently of the application. The application remains running with no proxy in front of it during the restart window.

Kubernetes 1.29 GA'd `restartPolicy: Always` on init containers — the "native sidecar" feature. A sidecar declared as `initContainers` with `restartPolicy: Always` runs alongside the main containers but with controlled startup and shutdown:

- Started before main containers; main containers wait for the sidecar's `startupProbe` to pass.
- Outlives main containers during shutdown — receives SIGTERM only after main containers exit.
- For Jobs / CronJobs, the sidecar's status doesn't block the Job's completion.

By 2026 the major service meshes (Istio 1.22+, Linkerd 2.16+, Cilium Service Mesh) recommend native sidecars as the deployment model. Logging and observability sidecars (Fluent Bit, OpenTelemetry Collector) follow the same pattern.

The specific gaps in pre-1.29 sidecar deployments:

- mTLS bypass on application startup window (race).
- mTLS lost on application shutdown window (proxy exits early).
- Job-with-sidecar never finishes; eventually OOM-killed by Pod resource limits.
- Sidecar crash leaves application unprotected.
- Restart of mesh-proxy side container drops connections.

This article covers the native sidecar lifecycle, security implications for service-mesh proxies and log shippers, the migration from regular containers to native sidecars, and the operational changes (Pod-spec ergonomics, observability differences).

**Target systems:** Kubernetes 1.29+ for GA; 1.28 had it as beta. Compatible with Istio 1.20+ (officially supported on 1.22+), Linkerd 2.15+, Cilium 1.14+, Fluent Bit 3.0+, OpenTelemetry Collector 0.96+.

## Threat Model

- **Adversary 1 — Network observer during startup window:** an attacker with network position on the Pod's namespace observes plaintext traffic during the period before the mesh proxy is ready.
- **Adversary 2 — Network observer during shutdown:** same observation during graceful drain when the proxy exits before the application.
- **Adversary 3 — Job spillover:** a misconfigured Job with sidecars never completes; an attacker who can submit Jobs creates a denial-of-service against the cluster scheduler.
- **Adversary 4 — Sidecar-crash window:** an attacker exploits a window when the mesh sidecar is restarting; if the application accepts traffic during this window, requests bypass mTLS.
- **Access level:** Adversary 1-2 has network observation. Adversary 3 has Job-create permission. Adversary 4 has the ability to time exploit attempts.
- **Objective:** Read in-flight traffic that should have been mTLS-protected; cause Pod / Job exhaustion.
- **Blast radius:** Pre-native-sidecar: every Pod has a small mTLS-bypass window. With native sidecars: window eliminated; mTLS holds throughout the Pod's lifecycle.

## Configuration

### Step 1: Native Sidecar Pod Spec

Move the sidecar from `spec.containers` to `spec.initContainers` with `restartPolicy: Always`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payments-api
  namespace: payments
spec:
  initContainers:
    - name: istio-proxy
      image: docker.io/istio/proxyv2:1.24.0
      restartPolicy: Always              # makes this a native sidecar
      args: ["proxy", "sidecar"]
      ports:
        - containerPort: 15090
          name: http-envoy-prom
      startupProbe:
        httpGet:
          path: /healthz/ready
          port: 15021
        periodSeconds: 1
        failureThreshold: 30
      livenessProbe:
        httpGet:
          path: /healthz/ready
          port: 15021
      lifecycle:
        preStop:
          exec:
            command: ["pilot-agent", "request", "POST", "quitquitquit"]
      resources:
        limits:
          cpu: "2"
          memory: 1Gi
        requests:
          cpu: 100m
          memory: 128Mi

  containers:
    - name: payments-api
      image: ghcr.io/myorg/payments-api:1.0
      ports:
        - containerPort: 8080
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
```

The `istio-proxy` is in `initContainers` but uses `restartPolicy: Always`. Kubernetes:

- Starts `istio-proxy` first.
- Waits for `istio-proxy.startupProbe` to pass.
- Starts `payments-api` only after the proxy is ready.
- On Pod deletion: sends SIGTERM to `payments-api` first; waits for it to exit; then SIGTERM to `istio-proxy`.

### Step 2: Service Mesh Migration

For Istio:

```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  values:
    pilot:
      env:
        ENABLE_NATIVE_SIDECARS: "true"
```

Setting this flag makes the istio-injector inject sidecars as native init containers rather than regular containers. New Pods automatically get the new pattern; rolling restart applies it across the fleet.

For Linkerd 2.16+:

```yaml
# In Helm values:
proxy:
  nativeSidecar: true
```

For Cilium Service Mesh: set `nativeSidecar: true` in the Cilium Helm chart.

Verify the migration:

```bash
kubectl get pod payments-api-xyz -o jsonpath='{.spec.initContainers[?(@.name=="istio-proxy")].restartPolicy}'
# Always
```

### Step 3: Logging and Observability Sidecars

The same pattern applies to log shippers and metrics collectors:

```yaml
spec:
  initContainers:
    - name: fluent-bit
      image: fluent/fluent-bit:3.2
      restartPolicy: Always
      volumeMounts:
        - name: app-logs
          mountPath: /var/log/app
          readOnly: true
      startupProbe:
        httpGet:
          path: /api/v1/health
          port: 2020
        failureThreshold: 30
        periodSeconds: 1

  containers:
    - name: app
      # ... main app

  volumes:
    - name: app-logs
      emptyDir: {}
```

Fluent Bit starts before the app, is ready when the app starts emitting logs, and continues running until the app's logs are fully drained on shutdown.

### Step 4: Job Compatibility

The classic Job-with-sidecar problem disappears:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: nightly-export
spec:
  template:
    spec:
      restartPolicy: Never
      initContainers:
        - name: istio-proxy
          image: docker.io/istio/proxyv2:1.24.0
          restartPolicy: Always   # native sidecar
          # ... mesh config
      containers:
        - name: exporter
          image: ghcr.io/myorg/exporter:1.0
          # On exit, Pod completes successfully even though
          # istio-proxy is still running. Kubelet sends istio-proxy SIGTERM
          # after the main containers exit.
```

The Job completes when `exporter` exits. Native sidecars are accounted for in the Job-completion logic.

### Step 5: PreStop Hooks for Graceful Shutdown

The sidecar's `preStop` controls how it handles shutdown. For a mesh proxy, signal a graceful drain:

```yaml
- name: istio-proxy
  restartPolicy: Always
  lifecycle:
    preStop:
      exec:
        command:
          - sh
          - -c
          - |
            # Begin proxy drain (stop accepting new connections, finish in-flight).
            pilot-agent request POST quitquitquit
            # Wait for active connections to drain (max 30 seconds).
            sleep 30
```

Combined with the application's preStop:

```yaml
- name: app
  lifecycle:
    preStop:
      exec:
        command:
          - sh
          - -c
          - |
            # Tell the app to stop accepting new requests.
            kill -TERM 1
            # Wait for in-flight to drain.
            sleep 25
```

Kubernetes' default `terminationGracePeriodSeconds` is 30; ensure both preStop hooks complete within that window. For Pods with longer drain requirements, raise `terminationGracePeriodSeconds`.

### Step 6: Telemetry Differences

Native sidecars register slightly differently in some observability tools. `kubectl get pod` shows them in `INIT` containers list:

```bash
kubectl get pod payments-api-xyz -o jsonpath='{.spec.initContainers[*].name}'
# istio-proxy
kubectl get pod payments-api-xyz -o jsonpath='{.status.initContainerStatuses[*].state}'
# {"running":{...}}
```

Some monitoring tools (older versions of Datadog Agent, Sysdig) treated init containers as ephemeral; they need updates to handle long-running init containers.

For per-Pod resource consumption metrics, native sidecars are still counted in the Pod's resource quota. For reporting and capacity planning, they're equivalent to regular sidecars.

## Expected Behaviour

| Signal | Pre-1.29 sidecar | Native sidecar |
|--------|--------------------|------------------|
| App starts before proxy ready | Possible; race | Impossible; main containers wait for `startupProbe` |
| Proxy exits before app drains | Common at shutdown | Proxy stays alive until main containers exit |
| Job with sidecar completes | Never; sidecar blocks completion | Completes when main containers exit |
| Sidecar crash impact | Application unprotected during restart window | Same window exists, but `livenessProbe` triggers app restart too if needed |
| Pod-spec ergonomics | Sidecar mixed with main containers | Sidecar in `initContainers`, ordered explicitly |
| Resource accounting | Same | Same |

Verify the lifecycle:

```bash
# Confirm the proxy is in initContainers.
kubectl get pod payments-api -o jsonpath='{.spec.initContainers[*].name}'
# istio-proxy

# During Pod deletion, observe the order.
kubectl delete pod payments-api &
kubectl logs -f payments-api -c istio-proxy &
# istio-proxy continues running; main app exits first; then proxy receives SIGTERM.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Native sidecar lifecycle | No race conditions | Requires K8s 1.29+ | Standard for new clusters; older clusters need migration plan. |
| `restartPolicy: Always` | Sidecar restart independent of main | Slight learning curve | Document for platform team; codify in templates. |
| Mesh migration | Eliminates mTLS bypass windows | Requires mesh upgrade + rolling restart | Stage by namespace; canary first. |
| Job compatibility | Sidecars no longer block Job completion | Pre-1.29 workarounds become obsolete | Remove old workarounds (preStop hooks signaling proxy exit); cleaner. |
| `startupProbe` requirement | Forces clean readiness signal | Sidecars without proper readiness need updates | Add `startupProbe` per sidecar; small Helm-chart change. |
| Observability tooling | More accurate Pod status | Some tools need updates | Verify your observability stack supports native sidecars; updates are widely available. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sidecar `startupProbe` fails | Main containers never start | Pod stuck in init | Verify probe configuration; check sidecar logs. The startup probe is the gating mechanism — if misconfigured, the Pod is stuck. |
| Sidecar crashes during startup | Main containers can't start | `kubectl get pod` shows init container in `Error` | Standard probing. Restart the Pod after fixing the sidecar config. |
| `terminationGracePeriodSeconds` too short | Sidecar killed mid-drain | Connection-drop spike during Pod terminations | Raise grace period to allow both preStop hooks to complete. |
| Older version of observability tool | Pod metrics inaccurate | Dashboards show incorrect container counts / resource use | Update the agent. All major monitoring tools support native sidecars by 2026. |
| Mixed regular and native sidecars | Confusion about which is which | Both present in same Pod | Pick one pattern per Pod; native sidecars are the new default. |
| Old preStop hooks that depended on regular-container ordering | Stale workarounds break | `kubectl describe pod` shows hooks running in unexpected order | Remove old workaround hooks; native lifecycle handles ordering correctly. |
| Job + sidecar with TTL | Jobs not cleaned up if mesh outage prevents proxy startup | Many Pods stuck in init | Set `activeDeadlineSeconds` on Jobs to fail and clean up if startup never succeeds. |

## Related Articles

- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [User Namespaces for Pods](/articles/kubernetes/user-namespaces-pods/)
- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
- [Gateway API Security Patterns](/articles/kubernetes/gateway-api-security/)
- [Confidential Containers on Kubernetes](/articles/kubernetes/confidential-containers/)
