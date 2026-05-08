---
title: "KubeVirt VM Security on Kubernetes"
description: "Harden KubeVirt virtual machine workloads with virt-launcher pod security, VM isolation, live migration hardening, and tracking KubeVirt's open source CVE disclosure patterns."
slug: kubevirt-security
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["kubevirt", "vm-security", "virtualization", "qemu", "libvirt", "live-migration"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 336
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubevirt-security/index.html"
---

# KubeVirt VM Security on Kubernetes

## Problem

KubeVirt extends Kubernetes to manage virtual machines alongside container workloads. Each VM runs as a `virt-launcher` pod: a privileged Kubernetes pod that wraps a QEMU/KVM process and exposes a VirtualMachine custom resource to the API server. From the cluster's perspective a VM is a pod. From a security perspective it is a pod with a hypervisor process inside it, a QEMU device emulation stack, a libvirt management socket, and an additional layer of guest OS attack surface that has nothing to do with the OCI threat model that Kubernetes hardening guides are written for.

The appeal is genuine: running legacy VMs and modern containers on the same substrate, using the same scheduler, the same network fabric, and the same RBAC model, removes a whole class of operational complexity. The security problem is that KubeVirt's architecture requires capabilities and host access that have no equivalent in a well-hardened container workload. A `virt-launcher` pod needs `CAP_NET_ADMIN` to configure guest networking, `CAP_SYS_NICE` for real-time scheduling of VCPU threads, and — on nodes where the KVM device is managed by `virt-handler` rather than via device plugins — a `privileged: true` security context. The `virt-handler` DaemonSet, which runs on every VM-hosting node, requires host PID namespace access and bind mounts into `/proc` and `/sys` to configure VM networking, storage attachment, and KVM device permissions. It is, by construction, a privileged component that touches the node.

Live migration — moving a running VM between nodes without stopping it — is one of KubeVirt's most operationally useful features and one of its most significant security risks in its default configuration. During migration, QEMU on the source node streams the entire VM memory image over a TCP connection to QEMU on the destination node. By default this stream is unencrypted. A network-adjacent attacker who can observe traffic on the migration network — typically a flat cluster internal network — sees the full memory contents of the running VM: TLS private keys cached in memory, session tokens, database connection credentials, in-flight encryption keys, and anything else the guest has in active use. The migration protocol itself does not authenticate endpoints, so a MITM can inject pages into the destination VM's memory.

KubeVirt's open source CVE disclosure record deserves careful attention from operators. The project is large and fast-moving — hundreds of contributors, frequent releases, and a deep dependency on QEMU, libvirt, and the Linux kernel. QEMU is not a passive dependency: it is the hypervisor executing untrusted guest code, and QEMU has a long history of guest-to-host escape vulnerabilities in its device emulation code. CVE-2021-3682 (QEMU USB redirection heap buffer overflow enabling arbitrary code execution) and CVE-2023-3354 (QEMU VNC server improper I/O watch removal) are examples of vulnerabilities that affected KubeVirt deployments. Neither was explicitly referenced in KubeVirt release notes. The pattern is consistent: QEMU ships a fix in a point release; KubeVirt opens a dependency bump PR with a commit message reading "bump qemu to 8.2.1" or similar, with no security annotation and no CVE filed against KubeVirt itself. The PR merges into a routine release. Operators monitoring only KubeVirt's GitHub releases page see a minor version bump and miss the embedded QEMU CVE entirely.

The same disclosure gap has occurred for `virt-handler` privilege escalation paths. Multiple PRs fixing host-escape vectors in `virt-handler` have been merged without a corresponding CVE or security advisory. The fix is visible in the public PR diff for weeks — the diff shows the removed syscall or the fixed path traversal — before any advisory reaches the oss-security mailing list. An attacker reading the KubeVirt changelog attentively may have the exploit pattern before most operators have upgraded. This is not unique to KubeVirt: it is a structural property of projects that move fast, vendor large C dependencies, and do not have a dedicated security response team with strict embargo procedures. It requires operators to maintain active upstream monitoring rather than relying on advisory aggregators alone.

Effective tracking requires four channels running in parallel: watching KubeVirt's GitHub releases for any QEMU version bump and manually cross-referencing QEMU's security advisory page at `https://www.qemu.org/docs/master/about/security.html`; subscribing to the `oss-security` mailing list at `https://www.openwall.com/lists/oss-security/` which receives disclosures from QEMU maintainers; querying `osv.dev` for both the `kubevirt/kubevirt` and `qemu/qemu` ecosystems against deployed versions; and maintaining a known-good digest of the `virt-launcher` container image to detect unexpected changes between your last pin and a new release.

Target systems: KubeVirt v1.2+, Kubernetes 1.28+, KVM-capable nodes (bare metal or nested virtualization with `kvm_intel.nested=1` enabled on the hypervisor host).

## Threat Model

1. **Guest VM escape via QEMU CVE.** An attacker running a workload inside a KubeVirt VM exploits a QEMU device emulation bug — USB passthrough, VirtIO, VNC, or network backend — to gain code execution inside the `virt-launcher` pod. From there they access the pod's service account token, the Kubernetes API, and potentially the node via `virt-handler`'s host mounts. QEMU's device emulation surface is wide and has produced exploitable CVEs consistently across its 20-year history.

2. **Live migration MITM.** A network-adjacent attacker on the migration VLAN or subnet captures unencrypted QEMU migration streams using passive packet capture. The captured memory dump contains TLS private keys, session tokens, and encryption keys that are valid and immediately usable. An active MITM can inject arbitrary memory pages into the destination VM, achieving guest OS code execution without interacting with any Kubernetes API.

3. **Patch-gap attacker.** This attacker monitors KubeVirt's public GitHub repository for pull requests that include "bump qemu" or "update qemu" in the title or commit message. On detection, they retrieve the new QEMU version from the PR diff, cross-reference QEMU's changelog and `https://www.qemu.org/docs/master/about/security.html` to identify which CVEs are fixed in that version, and begin weaponizing the vulnerability. The window between PR merge (public) and operator deployment (often days to weeks for production clusters) is the exploitation window. This threat actor exploits the structural disclosure gap described in the Problem section.

4. **`virt-handler` privilege escalation.** An attacker with `kubectl exec` access to a `virt-handler` pod — whether via compromised credentials, a vulnerable admission webhook, or a namespace misconfiguration — leverages the DaemonSet's host PID namespace access, host path mounts, and elevated capabilities to escape to the underlying node. From the node they can access every other pod's secrets, the container runtime socket, and cluster-level credentials.

Any of these paths leads to node-level compromise. From a single node a determined attacker can reach cluster-admin credentials through the kubelet credential chain, pivot to other nodes via the internal network, and exfiltrate data from every namespace on the cluster. Containing VM workloads in dedicated node pools with tainted scheduling is the primary blast-radius reduction: a successful node escape from a VM pool node does not automatically reach production container workloads if the node pool has no route to the API server's internal endpoints beyond what the kubelet requires.

## Configuration / Implementation

### virt-launcher pod security hardening

KubeVirt 1.2+ supports fine-grained security context overrides on the VirtualMachine spec. The goal is to drop all capabilities except those QEMU requires for guest networking and VCPU scheduling, and to avoid `privileged: true` by using KVM device plugins instead of host device passthrough.

```yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: hardened-vm
  namespace: vm-workloads
spec:
  running: true
  template:
    metadata:
      labels:
        kubevirt.io/vm: hardened-vm
    spec:
      domain:
        cpu:
          cores: 2
          model: host-passthrough
        devices:
          disks:
            - name: rootdisk
              disk:
                bus: virtio
          interfaces:
            - name: default
              masquerade: {}
        machine:
          type: q35
        resources:
          requests:
            memory: 2Gi
            cpu: "2"
      # Restrict network interface to masquerade (NAT) — no bridge access to node
      networks:
        - name: default
          pod: {}
      volumes:
        - name: rootdisk
          containerDisk:
            image: quay.io/containerdisks/fedora:39
      # useEmulation: false enforces KVM hardware acceleration; VMs will fail
      # to schedule on nodes without /dev/kvm rather than silently falling back
      # to software emulation (which removes memory isolation guarantees).
      # Set in the KubeVirt CR, not per-VM.
```

The `isolationMode` setting in the KubeVirt CR controls whether `virt-launcher` runs as a fully privileged pod (`none`) or uses a secondary user namespace launcher process (`launcher`). Use `launcher` mode:

```yaml
apiVersion: kubevirt.io/v1
kind: KubeVirt
metadata:
  name: kubevirt
  namespace: kubevirt
spec:
  configuration:
    developerConfiguration:
      useEmulation: false
    # Require hardware KVM — no silent software fallback
    vmRolloutStrategy: Stage
  workloadUpdateStrategy:
    workloadUpdateMethods:
      - LiveMigrate
```

Apply a PSA label to the VM namespace to enforce baseline pod security:

```bash
kubectl label namespace vm-workloads \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

Note: `virt-launcher` pods require the `baseline` profile at minimum due to their capability requirements. `restricted` will block VM scheduling. Apply `restricted` to non-VM namespaces and accept `baseline` for VM namespaces as a documented exception.

### Live migration encryption

Inspect the current migration configuration:

```bash
kubectl get kubevirt kubevirt -n kubevirt -o yaml | grep -A 20 migrationConfiguration
```

Enable TLS for migration traffic. KubeVirt uses cert-manager to issue certificates for migration endpoints. Install cert-manager first, then configure:

```yaml
apiVersion: kubevirt.io/v1
kind: KubeVirt
metadata:
  name: kubevirt
  namespace: kubevirt
spec:
  configuration:
    migrations:
      allowAutoConverge: true
      allowPostCopy: false       # Post-copy migration is higher risk: dirty pages
                                 # are pulled on-demand from source, extending the
                                 # window during which the source holds live memory.
      completionTimeoutPerGiB: 800
      parallelMigrationsPerCluster: 5
      parallelOutboundMigrationsPerNode: 2
      bandwidthPerMigration: "64Mi"
      # TLS is enabled by default in KubeVirt 1.2+ when cert-manager is present.
      # Explicitly verify with:
      #   kubectl get secret kubevirt-virt-handler-server-secret -n kubevirt
      network:
        bindAddress: "0.0.0.0"
```

Create a MigrationPolicy that locks down per-namespace migration parameters:

```yaml
apiVersion: migrations.kubevirt.io/v1alpha1
kind: MigrationPolicy
metadata:
  name: secure-migration
spec:
  selectors:
    namespaceSelector:
      matchLabels:
        kubevirt.io/migration-policy: secure
  allowAutoConverge: true
  allowPostCopy: false
  completionTimeoutPerGiB: 800
  bandwidthPerMigration: "64Mi"
```

```bash
kubectl label namespace vm-workloads kubevirt.io/migration-policy=secure
```

Verify that KubeVirt has issued TLS certificates for migration:

```bash
kubectl get secret -n kubevirt | grep virt-handler
# Expected: kubevirt-virt-handler-server-secret and kubevirt-virt-handler-certs
```

### VM isolation with network policies

Isolate VM namespaces from container workload namespaces with NetworkPolicy. VMs appear as pods with a `kubevirt.io/vm` label; standard NetworkPolicy selectors apply.

```yaml
# Default deny all ingress and egress for the VM namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: vm-workloads
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# Allow DNS resolution for VMs
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: vm-workloads
spec:
  podSelector:
    matchLabels:
      kubevirt.io: virt-launcher
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
# Allow VMs to reach a specific backend namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-vm-to-backend
  namespace: vm-workloads
spec:
  podSelector:
    matchLabels:
      kubevirt.io/vm: hardened-vm
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: backend-services
      ports:
        - protocol: TCP
          port: 8080
```

Use `VirtualMachineInstancePreset` to enforce consistent security profiles across VMs in a namespace:

```yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstancePreset
metadata:
  name: secure-vm-preset
  namespace: vm-workloads
spec:
  selector:
    matchLabels:
      security-profile: hardened
  domain:
    resources:
      limits:
        memory: 8Gi
        cpu: "4"
    devices:
      # Disable USB — large QEMU attack surface, rarely needed in server VMs
      # Disable serial console in production if not needed
      autoattachSerialConsole: false
      autoattachGraphicsDevice: false
```

Apply the label to VMs that must use this preset:

```bash
kubectl label vm hardened-vm security-profile=hardened -n vm-workloads
```

### Node-level KVM hardening

Dedicated node pools for VM workloads limit blast radius. Taint VM nodes so that container-only workloads do not schedule there:

```bash
kubectl taint nodes vm-node-1 vm-node-2 vm-node-3 \
  dedicated=vm-workloads:NoSchedule

kubectl label nodes vm-node-1 vm-node-2 vm-node-3 \
  node-role.kubernetes.io/vm-worker=true
```

Add a toleration and nodeSelector to VM specs:

```yaml
spec:
  template:
    spec:
      tolerations:
        - key: dedicated
          operator: Equal
          value: vm-workloads
          effect: NoSchedule
      nodeSelector:
        node-role.kubernetes.io/vm-worker: "true"
```

Harden KVM module parameters on VM nodes via a MachineConfig (if using OpenShift) or via a privileged DaemonSet that applies sysctl and modprobe options at boot:

```bash
# Disable nested virtualization unless explicitly required.
# Nested virt increases the attack surface and is rarely needed for VM workloads.
echo "options kvm_intel nested=0" > /etc/modprobe.d/kvm-hardening.conf
echo "options kvm_amd nested=0" >> /etc/modprobe.d/kvm-hardening.conf

# Disable unprivileged userfaultfd — used in some QEMU CVE exploit chains
sysctl -w vm.unprivileged_userfaultfd=0
echo "vm.unprivileged_userfaultfd=0" >> /etc/sysctl.d/99-kvm-hardening.conf
```

### Tracking upstream security issues

Identify the QEMU version in your deployed `virt-launcher` image:

```bash
LAUNCHER_IMAGE=$(kubectl get pods -n kubevirt \
  -l kubevirt.io=virt-launcher \
  -o jsonpath='{.items[0].spec.containers[0].image}')
echo "Deployed virt-launcher image: $LAUNCHER_IMAGE"

# Extract QEMU version from a running launcher pod
LAUNCHER_POD=$(kubectl get pods -n vm-workloads \
  -l kubevirt.io=virt-launcher \
  -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n vm-workloads "$LAUNCHER_POD" -- qemu-system-x86_64 --version
```

Query osv.dev for known vulnerabilities in the deployed KubeVirt version:

```bash
KUBEVIRT_VERSION=$(kubectl get kubevirt kubevirt -n kubevirt \
  -o jsonpath='{.status.observedKubeVirtVersion}')

# Query OSV for KubeVirt advisories
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"package\": {
      \"name\": \"kubevirt\",
      \"ecosystem\": \"Go\"
    },
    \"version\": \"${KUBEVIRT_VERSION}\"
  }" | jq '.vulns[].id'

# Query OSV for QEMU advisories (substitute actual QEMU version)
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{
    "package": {
      "name": "qemu",
      "ecosystem": "OSS-Fuzz"
    }
  }' | jq '.vulns[] | {id: .id, summary: .summary}'
```

A GitHub Actions workflow to alert on QEMU bumps in KubeVirt releases:

```yaml
name: KubeVirt QEMU bump monitor
on:
  schedule:
    - cron: "0 8 * * *"    # daily at 08:00 UTC
  workflow_dispatch:

jobs:
  check-releases:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch latest KubeVirt release notes
        id: release
        run: |
          LATEST=$(curl -s \
            https://api.github.com/repos/kubevirt/kubevirt/releases/latest \
            | jq -r '.tag_name')
          BODY=$(curl -s \
            https://api.github.com/repos/kubevirt/kubevirt/releases/latest \
            | jq -r '.body')
          echo "version=$LATEST" >> $GITHUB_OUTPUT
          echo "body<<EOF" >> $GITHUB_OUTPUT
          echo "$BODY" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Check for QEMU version bump
        run: |
          VERSION="${{ steps.release.outputs.version }}"
          BODY="${{ steps.release.outputs.body }}"
          if echo "$BODY" | grep -qi "qemu"; then
            echo "::warning::KubeVirt $VERSION mentions QEMU in release notes."
            echo "Check https://www.qemu.org/docs/master/about/security.html"
            echo "for CVEs fixed in the new QEMU version."
          fi

      - name: Notify on Slack
        if: contains(steps.release.outputs.body, 'qemu') || contains(steps.release.outputs.body, 'QEMU')
        uses: slackapi/slack-github-action@v1.24.0
        with:
          payload: |
            {
              "text": "KubeVirt ${{ steps.release.outputs.version }} released with QEMU changes. Review QEMU security advisories before upgrading."
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### RBAC for KubeVirt CRDs

Restrict who can create and delete VirtualMachine resources. Platform engineers manage VM lifecycle; developers get read access and preset selection only.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vm-platform-admin
rules:
  - apiGroups: ["kubevirt.io"]
    resources:
      - virtualmachines
      - virtualmachineinstances
      - virtualmachineinstancemigrations
      - virtualmachineinstancepresets
    verbs: ["*"]
  - apiGroups: ["kubevirt.io"]
    resources: ["virtualmachineinstancereplicasets"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vm-developer
rules:
  # Developers can read VMs and apply presets, but cannot create raw VMs
  - apiGroups: ["kubevirt.io"]
    resources: ["virtualmachines", "virtualmachineinstances"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["kubevirt.io"]
    resources: ["virtualmachineinstancepresets"]
    verbs: ["get", "list", "watch"]
  # Allow starting/stopping a VM (subresource), not creating new specs
  - apiGroups: ["subresources.kubevirt.io"]
    resources: ["virtualmachines/start", "virtualmachines/stop", "virtualmachines/restart"]
    verbs: ["update"]
```

Bind these roles per-namespace:

```bash
kubectl create rolebinding vm-platform-admin-binding \
  --clusterrole=vm-platform-admin \
  --group=platform-engineers \
  --namespace=vm-workloads

kubectl create rolebinding vm-developer-binding \
  --clusterrole=vm-developer \
  --group=developers \
  --namespace=vm-workloads
```

### Audit logging for VM lifecycle events

Extend your API server audit policy to capture VM events. Add to the audit policy ConfigMap:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all VM lifecycle events at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "kubevirt.io"
        resources:
          - virtualmachines
          - virtualmachineinstances
          - virtualmachineinstancemigrations
    verbs:
      - create
      - delete
      - patch
      - update
  # Log VM subresource actions (start/stop/migrate)
  - level: RequestResponse
    resources:
      - group: "subresources.kubevirt.io"
        resources: ["*"]
    verbs: ["update", "create"]
  # Catch-all: log metadata for everything else in kubevirt.io
  - level: Metadata
    resources:
      - group: "kubevirt.io"
        resources: ["*"]
```

This captures every VM creation, deletion, and migration initiation with the requesting user identity, timestamp, and source IP — sufficient to reconstruct the chain of events in a post-incident investigation.

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| QEMU patch-gap exploitation window | Operators unaware of embedded QEMU CVE; upgrade lag of weeks to months; no alerting on "bump qemu" releases | GitHub Actions workflow alerts within 24 hours of release; osv.dev queries identify vulnerable versions; upgrade SLA triggered immediately |
| Unencrypted live migration capture | Full VM memory readable by any host on migration subnet; TLS keys and tokens exposed in packet capture | Migration traffic encrypted with cert-manager-issued certificates; MITM injection blocked by endpoint authentication |
| `virt-handler` privilege escalation | Any pod with exec access to `virt-handler` can escape to node via host PID namespace or host path mounts | Dedicated VM node pool with taint/toleration isolation; RBAC restricts exec to `kubevirt` namespace service accounts; PSP/PSA prevents non-platform pods from reaching VM nodes |
| VM namespace cross-contamination | VMs can reach container workload namespaces via flat cluster network; compromised VM can exfiltrate secrets from adjacent namespaces | NetworkPolicy enforces default-deny in `vm-workloads`; explicit allow rules required for each egress target; namespace labels enforce policy boundaries |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Live migration TLS overhead | Eliminates memory exposure during migration; prevents MITM injection | CPU overhead for encryption; increased migration duration (typically 5–15% slower) | Set `bandwidthPerMigration` to avoid saturating node NICs; schedule migrations during low-traffic windows; monitor migration duration with `kubectl get vmim` |
| Dropping capabilities in `virt-launcher` | Reduces post-escape pivot surface; container-level blast radius contained | Some guest OS features break: SCSI passthrough, USB passthrough, and SR-IOV require capabilities not available at `baseline` PSA | Document required capabilities per VM class; use `VirtualMachineInstancePreset` to enforce approved capability sets; treat capability additions as change-controlled exceptions |
| Dedicated VM node pool | Limits blast radius of node escape to VM pool; prevents VM workloads from reaching container runtime sockets on shared nodes | Dedicated nodes increase infrastructure cost; bin-packing efficiency decreases when VM and container pools are separate | Use larger instance types for VM nodes to amortize per-node overhead; auto-scale VM node pool separately from container node pool |
| Upstream monitoring automation (osv.dev + GitHub Actions) | Reduces patch-gap from weeks to hours; provides structured CVE data per deployed version | Engineering time to build and maintain the pipeline; false-positive alerts on non-security QEMU bumps | Tune the GitHub Actions filter to check QEMU security advisory page rather than just release body text; integrate with existing vulnerability management tooling |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Migration TLS cert mismatch halts live migration | `VirtualMachineInstanceMigration` stuck in `Scheduling` or `Running` phase; `virt-handler` logs show `certificate signed by unknown authority` or `x509: certificate has expired` | `kubectl get vmim -A`; `kubectl describe vmim <name>`; `kubectl logs -n kubevirt -l kubevirt.io=virt-handler \| grep -i cert` | Renew cert-manager certificates: `kubectl delete secret kubevirt-virt-handler-server-secret -n kubevirt` (cert-manager re-issues); verify `MigrationPolicy` TLS settings; restart `virt-handler` pods after cert renewal |
| KVM device not available on node — VM scheduling fails | VirtualMachineInstance stuck in `Pending`; `virt-handler` logs show `KVM not available`; VM never reaches `Running` phase | `kubectl describe vmi <name>` shows scheduling failure event; check `kubectl get node <node> -o yaml \| grep kvm`; run `ls -la /dev/kvm` on node | Verify KVM kernel module loaded: `lsmod \| grep kvm`; check BIOS/UEFI virtualization enabled; if nested virt required, set `kvm_intel.nested=1`; if `useEmulation: false` is set, the VM correctly fails rather than silently degrading — fix the node, do not disable the check |
| `virt-handler` loses node access after RBAC tightening | VMs fail to start or lose network after RBAC changes; `virt-handler` logs show `forbidden` errors accessing host resources | `kubectl logs -n kubevirt -l kubevirt.io=virt-handler --since=5m`; `kubectl auth can-i <verb> <resource> --as=system:serviceaccount:kubevirt:kubevirt-handler` | Restore the previous ClusterRole binding with `kubectl apply -f`; identify which specific permissions were removed; restore incrementally to find minimum required set; test in non-production VM node pool before applying cluster-wide |
| QEMU version mismatch between source and destination nodes breaks live migration | Migration fails with `Unsupported migration cookie` or `Invalid migration message` in `virt-handler` logs; VM stuck mid-migration and reverts to source | Monitor `kubectl get vmim -A -o wide`; check QEMU version on both nodes: `kubectl exec -n vm-workloads <launcher-pod> -- qemu-system-x86_64 --version`; compare source and destination nodes | Ensure all VM nodes run the same `virt-launcher` image digest: `kubectl get nodes -l node-role.kubernetes.io/vm-worker=true -o yaml \| grep virt-launcher`; update lagging nodes before enabling live migration; pin `virt-launcher` image to a specific digest in the KubeVirt CR |

## Related Articles

- [RuntimeClass with gVisor and Kata Containers](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [Kubernetes Node Hardening](/articles/kubernetes/node-hardening/)
- [Confidential Containers on Kubernetes](/articles/kubernetes/confidential-containers/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
