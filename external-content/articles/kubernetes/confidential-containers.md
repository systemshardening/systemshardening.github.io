---
title: "Confidential Containers on Kubernetes: AMD SEV-SNP, Intel TDX, and the Attestation Flow"
description: "Confidential Containers move workload isolation from the kernel to the silicon. Encrypted memory, hardware-attested boot, and a different threat model than user namespaces."
slug: "confidential-containers"
date: 2026-04-27
lastmod: 2026-04-27
category: "kubernetes"
tags: ["kubernetes", "confidential-computing", "kata", "sev-snp", "tdx", "attestation"]
personas: ["platform-engineer", "security-engineer", "compliance"]
article_number: 200
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/kubernetes/confidential-containers/index.html"
---

# Confidential Containers on Kubernetes: AMD SEV-SNP, Intel TDX, and the Attestation Flow

## Problem

Standard container isolation depends on the host kernel. seccomp, AppArmor, capabilities, user namespaces, and network policies are all kernel-enforced. The host's kernel — and the cloud provider's hypervisor underneath — sees container memory in cleartext and could, if compromised or maliciously configured, read it.

For most workloads this is fine: the threat model treats the host operator as trusted. For some workloads it is not: regulated data (healthcare, defence, financial), proprietary algorithms (ML model weights), or workloads where the host operator is explicitly a different trust boundary (multi-tenant SaaS where customers don't fully trust the platform).

Confidential Containers (CoCo) — the CNCF-incubating project — runs each Pod inside a hardware-attested confidential VM. Memory is encrypted by the CPU; the host cannot read it. A signed attestation certifies that a specific firmware, kernel, and image are running before the workload starts.

The hardware paths:

- **AMD SEV-SNP** (Secure Encrypted Virtualization-Secure Nested Paging) — third-generation AMD memory encryption with integrity protection. Available on EPYC 7003 series and later (since 2021).
- **Intel TDX** (Trust Domain Extensions) — Intel's equivalent. Available on 4th-generation Xeon Scalable ("Sapphire Rapids", since 2023) and later.
- **ARM CCA** (Confidential Compute Architecture) — ARM's design; emerging on Neoverse-based servers in 2025-2026.

CoCo on Kubernetes uses the Kata Containers project as the runtime — each Pod becomes a microVM, and the microVM is launched with the appropriate confidential-computing flags. By 2026, managed offerings (Azure Confidential Containers, GKE Confidential Nodes, AWS Nitro Enclaves) have stable interfaces; self-hosted Kata-with-CoCo is also production-ready on supported hardware.

The specific gaps in a default Kubernetes cluster on confidential-capable hardware:

- Standard `runc` containers run unprotected even when SEV-SNP / TDX is available.
- Without an attestation gate, a workload could be deployed onto a misconfigured node where confidential mode is silently disabled.
- Image trust is decoupled from runtime trust; an attacker who can replace the image bytes between attestation and execution wins.
- Secret injection at runtime (Kubernetes Secrets, env-var passthrough) defeats confidentiality if the secret comes from outside the trust boundary.

This article covers CoCo deployment via the Kata operator, the attestation flow with a Key Broker Service (KBS), image-decryption-after-attestation, secret injection patterns, and when CoCo's threat model is the right fit (vs. user namespaces, vs. nothing).

**Target systems:** Kubernetes 1.30+, Kata Containers 3.6+ with `confidential` runtime class, AMD EPYC 9004+ or Intel Xeon Scalable 4th gen+; Azure AKS Confidential Containers, GKE Confidential Nodes (some configurations).

## Threat Model

- **Adversary 1 — Compromised host kernel / hypervisor:** an attacker with root on the Kubernetes node or, in cloud environments, the cloud provider's hypervisor administrator. Wants to read workload memory or modify execution.
- **Adversary 2 — Memory-inspection attacks:** physical access (cold-boot, DMA via Thunderbolt) reads memory state from a running machine.
- **Adversary 3 — Image substitution:** attacker replaces the container image bytes between when the operator approved the deployment and when the host runs it.
- **Adversary 4 — Lateral movement from a co-resident workload:** another Pod on the same host attempts to read workload memory through a kernel exploit.
- **Adversary 5 — Misconfigured "confidential" node:** the Pod runs but confidential-mode is silently disabled (firmware misconfig, vCPU mismatch). Operator believes protected, attacker reads as if standard.
- **Access level:** Adversary 1 has host-root; Adversary 2 has physical hardware access; Adversary 3 has registry or in-flight network manipulation; Adversary 4 has a Pod on the same node; Adversary 5 has nothing — this is an operational failure mode.
- **Objective:** Read encrypted-at-rest workload memory; impersonate the workload; pivot through the workload to its credentials and data.
- **Blast radius:** Without CoCo: host root or hypervisor access reveals everything. With CoCo: compromise must defeat the SEV-SNP / TDX cryptographic protection — a much higher bar (no public attacks against SEV-SNP through 2026).

## Configuration

### Step 1: Verify Hardware Support

```bash
# AMD SEV-SNP detection on the node.
ssh worker-1
lscpu | grep -i sev
# (looking for: sev_snp, sev_es)
dmesg | grep -i sev
# [    0.000000] AMD Secure Encrypted Virtualization (SEV-SNP) initialized

# Intel TDX detection.
lscpu | grep -i tdx
ls -la /sys/firmware/tdx
# (TDX module status)

# Or check via Kata's host capability detector.
kata-runtime check --debug
```

For cloud environments:

- Azure: select VM size with "DCadsv5", "ECadsv5" (AMD SEV-SNP), or "DCesv5" (TDX preview).
- GCP: N2D family with `--confidential-compute=SEV_SNP`.
- AWS: M7a / R7a family supports SEV-SNP; instances launched with `--enclave-options Enabled=true` for Nitro Enclaves (AWS-specific stack).

### Step 2: Install Kata + CoCo via Operator

```bash
# Install the Confidential Containers operator.
kubectl apply -k "github.com/confidential-containers/operator/config/release"

# Apply the cloud-API-adapter for your environment (or kata-qemu-snp for self-hosted).
kubectl apply -k "github.com/confidential-containers/operator/config/samples/ccruntime/default"

# Wait for the runtime to install on labeled nodes.
kubectl label node worker-1 worker-2 node-role.kubernetes.io/coco=true
kubectl get pods -n confidential-containers-system -w
```

The operator installs:
- A `RuntimeClass` named `kata-snp` (or `kata-tdx`).
- The Kata containerd shim binary.
- A Key Broker Service client per node.
- An attestation agent.

### Step 3: Deploy a Confidential Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: confidential-app
  namespace: payments
  annotations:
    io.containerd.cri.runtime-handler: kata-snp
spec:
  runtimeClassName: kata-snp
  containers:
    - name: app
      image: ghcr.io/myorg/payments-confidential@sha256:abc123...
      env:
        - name: VAULT_ADDR
          value: "https://vault.internal:8200"
      resources:
        requests:
          cpu: 1
          memory: 2Gi
        limits:
          cpu: 4
          memory: 8Gi
```

The Pod boots inside a SEV-SNP-protected microVM. The host's kernel and other Pods cannot read this Pod's memory.

Verify the Pod is actually running confidentially:

```bash
kubectl exec -n payments confidential-app -- dmesg | grep -i "sev"
# [    0.000000] Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
```

Or, more reliably, query the Kata shim:

```bash
ssh worker-1 'sudo crictl ps --label "io.kubernetes.pod.name=confidential-app" -q | xargs -I{} sudo crictl inspect {} | jq .info.runtimeSpec.linux.resources'
```

### Step 4: Attestation Flow with Key Broker Service

The point of CoCo is not just "encrypted memory" — it's "encrypted memory whose state is cryptographically attested before any secrets reach it." The attestation flow:

```
[Pod boot]
  -> [SEV-SNP firmware measures kernel + initrd + agent]
  -> [Pod boots; agent contacts the Key Broker Service (KBS)]
  -> [KBS challenges: "send me your attestation report"]
  -> [Pod produces SEV-SNP attestation report; signs with platform key]
  -> [KBS verifies: signature OK, measurement matches expected]
  -> [KBS releases per-pod secrets and image-decryption keys]
  -> [Pod decrypts image / pulls secrets and runs]
```

Configure the KBS with expected measurements:

```yaml
# kbs-config.yaml
default_policy:
  required_attestation:
    sev_snp:
      measurement: "abc123..."   # SHA-384 of expected firmware + initrd
      tcb_min:
        bootloader: 0x06
        tee: 0x02
        snp: 0x14
        microcode: 0x73
      family_id: "..."
      image_id: "..."
  released_resources:
    - "default/payments-tls-cert"
    - "default/payments-db-password"
```

Workloads request resources from the KBS at startup:

```python
# Inside the Pod, after attestation succeeds.
import requests
db_password = requests.get(
    "http://kbs.internal/resource/default/payments-db-password",
    headers={"X-Attestation-Token": agent_token},
).text
```

If the attestation does not match the policy, KBS refuses to release the secret. The Pod cannot do its work; the operator is alerted.

### Step 5: Encrypted Container Images

Standard images are pulled in plaintext. With CoCo, encrypt the image so even an attacker with registry access cannot read its contents.

```bash
# Encrypt with skopeo + the image-decryption-key from KBS.
skopeo copy --encryption-key jwe:./pubkey.pem \
  docker://ghcr.io/myorg/payments-confidential:1.2.3 \
  docker://ghcr.io/myorg/payments-confidential:1.2.3-encrypted
```

The decryption key lives in the KBS, released only after attestation. An image stolen from the registry without the KBS-released key is opaque ciphertext.

### Step 6: Networking and Volume Considerations

Networking from inside the confidential VM uses the same Pod-network primitives as Kata. CNI plugins work; NetworkPolicy applies as usual. The boundary is at the VM's vNIC.

Volumes need extra care:

- `emptyDir` is inside the VM — encrypted under the same SEV-SNP protection.
- `configMap` and `secret` mounts — the Kubernetes API delivers these in plaintext to the runtime; the runtime injects them into the VM. *This is a trust boundary the operator must understand.* If the host kernel is in your threat model, do not use Kubernetes Secrets directly; pull secrets from KBS after attestation.
- `persistentVolumeClaim` — the underlying CSI driver writes to the host's storage; data is plaintext at rest unless the application encrypts. For full protection, the application encrypts before writing, with a key released by KBS.

### Step 7: Observability of the Attestation Status

Track per-Pod attestation status:

```
coco_attestation_attempts_total{pod, namespace}
coco_attestation_success_total{pod, namespace, measurement_match}
coco_attestation_failure_total{pod, namespace, reason}
coco_kbs_resource_releases_total{resource}
coco_kbs_resource_denials_total{resource, reason}
```

Alert on:
- `coco_attestation_failure_total{reason="measurement_mismatch"}` — the firmware / initrd has changed unexpectedly. Could be a legitimate upgrade or an attack.
- `coco_kbs_resource_denials_total` — workloads attempting to access resources their attestation does not authorize.

## Expected Behaviour

| Signal | Standard Pod | Confidential Pod |
|--------|--------------|--------------------|
| Host can read Pod memory | Yes (via /proc/<pid>/mem with sufficient privilege) | No (SEV-SNP encrypts; integrity-protected) |
| Cloud hypervisor can read | Yes | No |
| Memory dump on cold-boot | Reveals plaintext | Reveals ciphertext only |
| Pod startup time | seconds | +10-30s (VM boot + attestation flow) |
| Kubernetes Secrets readable from host | Yes | Yes (host injects them) — use KBS instead for confidentiality |
| Attestation gate before secret release | None | Required; Pod cannot start consuming secrets without successful attestation |
| Per-Pod CPU overhead | Baseline | +5-15% (encryption / decryption per memory access) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Hardware-encrypted memory | Host root no longer reveals data | Requires SEV-SNP / TDX hardware | Use cloud-managed offerings if you can't deploy modern hardware. |
| Boot attestation | Cryptographic proof of running state | +10-30s startup latency | Acceptable for stateful workloads; not suitable for sub-second cold starts. |
| KBS-mediated secrets | Secrets released only to attested workloads | KBS becomes a critical dependency | Run KBS in HA; cache resource releases briefly to absorb KBS outages. |
| Encrypted images | Registry compromise yields no plaintext | Image build pipeline complexity | Automate via your CI; treat the encryption key like a code-signing key. |
| Per-Pod attestation overhead | Strong runtime trust | More moving parts | Not all workloads need it. Use confidential mode for the subset that warrants the cost. |
| `runtimeClassName` opt-in | Low blast radius if misused | Each workload must explicitly request | Document which workloads should use which runtime class; codify via VAP. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Hardware doesn't actually support SEV-SNP at runtime | Pod claims confidential, host doesn't enforce | Attestation fails (measurement returned doesn't match expected sig) | Verify firmware, BIOS settings, kernel modules. The attestation gate catches this — without a valid signed report, KBS refuses to release secrets. |
| KBS unavailable | Pods cannot start | KBS health check fails; new Pods stuck | Run KBS in HA across zones; cache recent attestations briefly. The fail-closed behavior is correct: you don't want to start a Pod that should be confidential without verification. |
| Attestation policy too strict | New firmware blocks all Pods | After kernel upgrade, all Pods fail attestation | Update KBS policy to allow the new measurement, ideally before rollout. Stage policy changes ahead of fleet upgrades. |
| Secrets leak via Kubernetes API | Operator mistakenly uses standard Secret | Audit log shows `Secret get` from kube-apiserver | For confidentiality, use KBS instead of Secrets. Educate platform users; codify via VAP that prevents Secret mounts on confidential Pods. |
| Image decryption fails | Pod stuck in image-pull errors | Logs show "no decryption key" | Verify image is encrypted with the right pubkey; verify KBS releases the matching private key after attestation. |
| Performance regression | Workload throughput drops 5-15% | Standard Prometheus latency / CPU metrics | Confirm the workload is sensitive to memory-encryption overhead; some are (memory-bandwidth-bound), most aren't. Profile before and after. |
| Cross-runtime confusion | Mix of `kata-snp` and `runc` Pods on same nodes | Annotation drift; PSA enforcement gaps | Use node taints to schedule confidential workloads only on confidential-capable nodes; standard Pods stay elsewhere. |

## When Confidential Containers Is the Right Fit (vs. Alternatives)

- **Use CoCo when:** the host operator (cloud provider, internal infra team) is in your threat model. Regulated data with explicit attestation requirements. Multi-tenant SaaS where tenants must not trust the platform with cleartext data.
- **Don't use CoCo when:** the host operator is trusted (most internal deployments). User namespaces + Pod Security Admission give you most of the runtime-isolation value at much lower cost.
- **Use both:** confidential workloads + user namespaces stack — orthogonal protections.

## Related Articles

- [User Namespaces for Pods](/articles/kubernetes/user-namespaces-pods/)
- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
- [Post-Quantum Crypto Migration Plan](/articles/cross-cutting/post-quantum-migration/)
