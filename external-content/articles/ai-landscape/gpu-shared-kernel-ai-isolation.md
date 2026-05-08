---
title: "GPU Shared-Kernel Attacks: Isolation Failures in Multi-Tenant AI Inference Clusters"
description: "NVIDIA GPU drivers run in the host kernel. CVE-2023-0184 (NVKM heap overflow), CUDA context isolation failures, and GPU memory remanence between tenants mean multi-tenant AI inference clusters leak model weights and prompt data across tenant boundaries — through the same shared-kernel surface that affects CPU workloads."
slug: gpu-shared-kernel-ai-isolation
date: 2026-05-08
lastmod: 2026-05-08
category: ai-landscape
tags:
  - gpu
  - cve
  - kernel
  - multi-tenant
  - ai-security
personas:
  - security-engineer
  - platform-engineer
article_number: 694
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/ai-landscape/gpu-shared-kernel-ai-isolation/
---

# GPU Shared-Kernel Attacks: Isolation Failures in Multi-Tenant AI Inference Clusters

## The Problem

The current generation of multi-tenant AI inference platforms — shared GPU clusters, model-hosting APIs, LLM serving infrastructure — rests on an isolation assumption that is architecturally unsound: that a container boundary, combined with Kubernetes RBAC and namespace separation, is sufficient to protect one tenant's GPU workload from another tenant's code running on the same node. It is not, and the failure mode is not theoretical. The GPU driver stack runs in the host Linux kernel as a set of kernel modules — `nvidia` (the core device driver, also called NVKM), `nvidia-uvm` (the unified virtual memory subsystem), `nvidia-modeset` (display and mode-setting, present even on compute-only nodes), and `nvidia-peermem` (GPUDirect RDMA). These modules run in ring 0. Every container that the `nvidia-device-plugin` provisions with GPU access receives character device file paths — `/dev/nvidia0`, `/dev/nvidiactl`, `/dev/nvidia-uvm` — mounted directly into the container filesystem. There is no virtualization layer. The container process calls `ioctl()` on those device files and the calls land in NVKM, in the host kernel, processed by the same code path and in the same address space as every other tenant on that node.

This is the shared-kernel problem, applied to an attack surface with hundreds of undocumented ioctl codes, a driver codebase of several million lines that ships as a closed-source binary blob, and a track record of heap overflows, use-after-free bugs, and privilege escalation vulnerabilities that are patched on a six-to-eight-week cycle.

**CVE-2023-0184** is the clearest recent example of what this surface looks like when it fails. NVIDIA NVKM contained a heap overflow in the GPU channel memory allocation path. The `NV_ESC_RM_ALLOC` ioctl, used to allocate a new GPU channel object, passed an attacker-controlled size parameter to a kernel heap allocator without sufficient validation. A container process with access to `/dev/nvidia0` could send a specific sequence of `NV_ESC_RM_ALLOC` calls with a crafted `paramsSize` field that caused the NVKM allocator to write past the end of the allocated buffer into adjacent kernel heap memory. On a kernel with SLUB allocator and predictable object layout, this is a heap spray primitive: allocate objects of a known size, trigger the overflow into the adjacent object, overwrite a function pointer (a `struct file_operations` pointer is a classic target), and redirect execution to shellcode or a ROP chain in kernel space. The result is kernel code execution as root. Affected: all NVIDIA GPU driver versions prior to 525.85.12, released February 2023. Every Kubernetes GPU node running an unpatched driver was exploitable from any container with access to `/dev/nvidia0` — which is every GPU-provisioned pod.

CVE-2023-0184 is not an isolated incident. CVE-2021-1076 (NVKM use-after-free via `NV_ESC_REGISTER_FD`), CVE-2022-28181 (out-of-bounds write in `nvidia-vgpu-mgr` affecting both host and guest), CVE-2022-34670 (untrusted pointer dereference in the guest kernel driver), and CVE-2024-0074 (null pointer dereference in `nvidia-uvm` causing kernel panic from user space) form a consistent pattern: the ioctl interface between userspace CUDA and the host kernel is an adversarial boundary that NVIDIA's driver code was not originally designed to treat as one.

**GPU memory remanence** is a distinct and more insidious problem, because it requires no CVE and no exploit code. When a CUDA context is destroyed — because an inference pod finishes a request and returns memory to the pool, or because the pod itself terminates — the GPU DRAM pages backing that context's allocations are not zeroed before being returned to the allocator. This is a performance decision: zeroing GPU DRAM is expensive (GPU DRAM bandwidth is high, but zeroing adds latency to every context destruction and pool return operation). The consequence is that the next CUDA context that receives those pages can read the previous context's data. On a shared inference cluster, "the previous context's data" means model weights, intermediate activation tensors, KV-cache entries, and raw input prompt tokens — the exact data that tenant isolation is supposed to protect.

Morshed et al. (2023) in the context of GPU memory side-channel research demonstrated that CUDA context isolation between processes on the same GPU does not prevent cross-context memory reads from deallocated pages. The research showed that `cudaMalloc()` does not guarantee zeroed memory — the CUDA programming model explicitly documents this, noting that `cudaMallocManaged()` also does not zero-initialize. An inference tenant calling `torch.cuda.empty_cache()` and then `torch.cuda.reset_peak_memory_stats()` does not zero the underlying GPU DRAM; it releases the CUDA memory back to PyTorch's caching allocator, which itself returns pages to the NVIDIA driver pool only when the CUDA context is destroyed. A subsequent tenant receiving those physical pages can scan them for transformer weight tensors (which have recognizable structure: floating-point values in characteristic ranges, often followed by LayerNorm parameter patterns) or extract prompt tokens from the KV-cache region.

**CUDA MPS (Multi-Process Service)** is NVIDIA's mechanism for multiplexing GPU access between multiple processes at higher utilization than exclusive-compute mode allows. MPS was designed for tightly coupled HPC workloads — MPI jobs that trust each other, running in a controlled HPC cluster environment. The inference platform community adopted it to improve GPU utilization for small-batch inference workloads: instead of one process holding the GPU context exclusively, MPS allows multiple client processes to share SM (streaming multiprocessor) resources concurrently. The MPS architecture has a central daemon — `nvidia-cuda-mps-server` — that runs in the host context as root and manages a shared CUDA context on behalf of all clients. MPS client processes communicate with the daemon through a Unix socket. The critical isolation property: all MPS clients share a single address space on the GPU. A CUDA error (illegal memory access, stack overflow, assertion failure) in one MPS client kills the MPS context entirely, terminating all co-located MPS clients. In a multi-tenant inference cluster, this means a single malformed model input that triggers a CUDA assertion in Tenant A's inference process can take down Tenant B's and Tenant C's inference processes simultaneously — without any bug in those tenants' code. This is not a theoretical failure mode: GPU kernel panics due to out-of-bounds tensor operations are a routine occurrence in production ML workloads, and MPS propagates them cluster-wide. Beyond denial of service: the `nvidia-cuda-mps-server` process is a root process with a large, largely undocumented IPC interface. Malformed control commands sent to the MPS socket are another unexplored ioctl-like attack surface.

The Kubernetes deployment reality is that none of this is abstracted away. The `nvidia-device-plugin` DaemonSet — the standard mechanism for GPU resource exposure in Kubernetes — directly mounts `/dev/nvidia0` through `/dev/nvidiaX` (one per GPU), `/dev/nvidiactl`, and `/dev/nvidia-uvm` into provisioned pods. No IOMMU isolation. No separate kernel context per pod. The container runtime (containerd or CRI-O) does not interpose on `ioctl()` calls to GPU device nodes — they pass through directly to NVKM in the host kernel. The seccomp profiles that ship with most Kubernetes node configurations do not restrict `ioctl()` on `/dev/nvidia*` to specific ioctl codes, because the set of valid ioctl codes is enormous, undocumented in any public specification, and changes between driver versions. The result is that the container boundary provides filesystem and PID namespace isolation while providing zero protection against any vulnerability in the GPU driver ioctl interface.

## Threat Model

**Kernel code execution via NVKM ioctl vulnerability:** A container process with GPU access (any pod provisioned by `nvidia-device-plugin`) exploits a heap overflow or use-after-free in NVKM via a sequence of crafted `ioctl()` calls to `/dev/nvidia0`. CVE-2023-0184 is the demonstrated example; the driver has historically shipped one to three exploitable kernel-mode bugs per year. Successful exploitation gives the attacker host root with full kernel execution context. From host root: read all pod secrets mounted in the container filesystem, read cloud credential files from host paths, read `/proc/*/mem` for any process on the node including the kubelet and cloud credentials processes, and pivot to the cloud control plane via IMDS access that is unrestricted at the host level. All GPU DRAM across all tenants on the node is readable.

**GPU memory remanence — cross-tenant data extraction without exploit code:** Tenant B, running a legitimate inference workload, allocates GPU memory that was previously released by Tenant A's pod. The allocation is not zeroed. Tenant B's code reads the raw memory buffer contents before writing its own data. In PyTorch, this is `torch.empty()` rather than `torch.zeros()` — the default for most tensor allocations in production inference code because zeroing is expensive and unnecessary when you're about to overwrite the buffer anyway. The data read from unzeroed pages may include: model weight tensors from Tenant A's model (particularly valuable for proprietary fine-tuned models), KV-cache entries containing tokenized input prompts, intermediate attention activations that encode semantic information about the input. This attack requires no CVE, no kernel exploit, and no elevated privileges — only GPU access and knowledge of the memory layout, which for common model architectures is publicly documented.

**MPS daemon exploitation and cross-tenant denial of service:** A malicious or buggy tenant process sends a sequence of crafted commands to the `nvidia-cuda-mps-server` Unix socket, exploiting a parsing bug in the daemon's control interface. The daemon runs as root with access to the shared GPU context. Alternatively, a tenant's inference workload deliberately triggers a CUDA error (illegal memory access via an out-of-bounds tensor operation) that crashes the shared MPS context, terminating all co-located tenants' inference processes simultaneously. The latter requires no exploit — it is a reliable denial-of-service primitive available to any tenant sharing an MPS context.

**Driver ioctl enumeration and zero-day exploitation:** The NVIDIA driver ioctl interface for `/dev/nvidiactl` and `/dev/nvidia-uvm` exposes a large set of undocumented control operations. NVIDIA does not publish the full ioctl specification. Reverse-engineered documentation (the Envytools/nouveau project, the open-driver work) covers a subset. An attacker with GPU access in a container can enumerate ioctl codes systematically, fuzzing for unexpected return values, kernel errors, or crashes. This is the same attack surface that produced CVE-2023-0184 and its predecessors, and the same surface that will produce future CVEs. Running an unpatched driver on a multi-tenant node means accepting that this surface has known-exploitable vulnerabilities; running a current driver means accepting that it has unknown-exploitable vulnerabilities.

**Cloud AI platform shared-kernel exposure:** AWS SageMaker multi-model endpoints, Azure Machine Learning managed inference, and GKE GPU node pools all implement tenant separation at the Kubernetes layer while sharing GPU kernel drivers at the node layer. A SageMaker multi-model endpoint running multiple customer models on a shared `ml.p4d.24xlarge` instance (8 x NVIDIA A100) has a single NVKM instance servicing all models. An attacker who controls one model's inference code (through a supply chain compromise of a model weight file, for example) can attempt NVKM exploitation against the shared kernel. The cloud provider's tenant isolation depends entirely on the correctness of the NVIDIA driver.

## Hardening Configuration

### 1. NVIDIA Driver Version Pinning and Systematic Patch Tracking

The NVIDIA GPU driver is not part of the Linux kernel and is not distributed through Linux distribution update channels by default on most Kubernetes node configurations. It is installed separately — often via the `gpu-operator` or via a node image that includes a pinned driver version — and it must be tracked and updated independently of the OS kernel. The NVIDIA Security Bulletin page publishes CVEs quarterly in a coordinated disclosure cycle, but out-of-cycle fixes for critical vulnerabilities (CVSS >= 7.0 affecting the kernel module) are published ad hoc.

Check the currently running driver version on all GPU nodes:

```bash
kubectl get nodes -l nvidia.com/gpu.present=true -o name \
  | while read node; do
      echo "=== $node ===";
      kubectl debug -it "$node" \
        --image=nvcr.io/nvidia/cuda:12.3.2-base-ubuntu22.04 \
        --target=host \
        -- nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null;
    done
```

Or directly on the node (if you have SSH access for break-glass):

```bash
nvidia-smi --query-gpu=driver_version,gpu_name --format=csv,noheader
# Expected output on a patched node (post-CVE-2023-0184 fix):
# 535.154.05, NVIDIA A100-SXM4-80GB

# CVE-2023-0184 patched in: 525.85.12 (February 2023)
# CVE-2022-28181 patched in: 515.43.04 (May 2022)
# CVE-2021-1076 patched in: 465.19.01 (April 2021)
```

Pin the driver version in the `gpu-operator` ClusterPolicy. This prevents the operator from silently upgrading or downgrading the driver outside your change-control process:

```yaml
apiVersion: nvidia.com/v1
kind: ClusterPolicy
metadata:
  name: gpu-cluster-policy
spec:
  driver:
    enabled: true
    repository: nvcr.io/nvidia
    image: driver
    version: "535.154.05"  # Pin to a specific patched version
    manager:
      image: k8s-driver-manager
      repository: nvcr.io/nvidia
      version: v0.6.4
  operator:
    upgradeCRD: true
  daemonsets:
    updateStrategy: RollingUpdate
    rollingUpdate:
      maxUnavailable: "1"
```

Subscribe to the NVIDIA PSIRT RSS feed and the NVD CPE feed for `cpe:2.3:a:nvidia:gpu_driver` to receive notification of new CVEs as they are published. Treat any CVSS >= 7.0 vulnerability in the kernel module as a P1: patch within 72 hours, cordon and drain affected nodes immediately if exploitation is in the wild.

### 2. Disable CUDA MPS in Multi-Tenant Deployments

CUDA MPS provides GPU utilization improvements for batch inference workloads but eliminates fault isolation between tenants. In any deployment where tenants are not mutually trusted — different teams, different customers, any adversarial tenant model — MPS must be disabled.

In the `nvidia-device-plugin` ConfigMap, disable MPS resource sharing:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nvidia-plugin-config
  namespace: nvidia-device-plugin
data:
  config.yaml: |
    version: v1
    flags:
      migStrategy: "none"
    sharing:
      mps:
        resources: []     # Disable MPS; empty list = no MPS sharing
      timeSlicing:
        resources: []     # Also disable time-slicing if strict isolation required
```

Apply via the device plugin Helm chart:

```bash
helm upgrade nvidia-device-plugin nvdp/nvidia-device-plugin \
  --namespace nvidia-device-plugin \
  --set config.name=nvidia-plugin-config \
  --reuse-values
```

With MPS disabled, each pod receives exclusive access to one or more complete GPU devices. A CUDA error in Pod A cannot terminate Pod B. The tradeoff is reduced GPU utilization for small-batch workloads. Accept the utilization cost; the isolation property is not negotiable in adversarial multi-tenancy.

### 3. NVIDIA MIG for Hardware-Enforced Tenant Isolation

Multi-Instance GPU (MIG) is available on NVIDIA A100, H100, and H200 GPUs. MIG partitions the physical GPU into isolated instances at the hardware level: each MIG instance has its own dedicated DRAM partition, its own L2 cache slice, its own set of streaming multiprocessors, and its own memory controller bandwidth allocation. Critically, the isolation is enforced in hardware — one MIG instance cannot read another instance's DRAM regardless of driver bugs, CUDA API calls, or kernel vulnerabilities. This is the strongest isolation available without separate physical GPUs.

Configure MIG mode and create instances on an A100 node:

```bash
# Enable MIG mode (requires node reboot or driver reload)
sudo nvidia-smi -mig 1

# Verify MIG mode is enabled
nvidia-smi --query-gpu=mig.mode.current --format=csv,noheader
# Output: Enabled

# List available MIG profiles for A100-80GB
nvidia-smi mig -lgip
# Available profiles include:
# 1g.10gb  - 1/7 compute, 10 GB DRAM
# 2g.20gb  - 2/7 compute, 20 GB DRAM
# 3g.40gb  - 3/7 compute, 40 GB DRAM
# 4g.40gb  - 4/7 compute, 40 GB DRAM
# 7g.80gb  - full GPU

# Create 7 x 1g.10gb instances (maximum tenant count for A100-80GB)
sudo nvidia-smi mig -cgi 1g.10gb,1g.10gb,1g.10gb,1g.10gb,1g.10gb,1g.10gb,1g.10gb -C

# Verify instances created
nvidia-smi mig -lgi
# +-------------------------------------------------------+
# | GPU instances:                                          |
# | GPU   Name          Profile  Instance   Placement      |
# |       Name          ID       ID         Start:Size     |
# |=======================================================|
# |   0  MIG 1g.10gb    19        1          0:1           |
# |   0  MIG 1g.10gb    19        2          1:1           |
# ...
```

Configure the Kubernetes MIG device plugin to expose MIG instances as schedulable resources:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mig-parted-config
  namespace: gpu-operator
data:
  config.yaml: |
    version: v1
    mig-configs:
      all-1g.10gb:
        - devices: all
          mig-enabled: true
          mig-devices:
            "1g.10gb": 7     # 7 tenants per A100-80GB
```

Apply the MIG partition configuration via gpu-operator:

```bash
kubectl label nodes <gpu-node> nvidia.com/mig.config=all-1g.10gb --overwrite
```

After partitioning, pods request MIG resources explicitly:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: inference-tenant-a
spec:
  containers:
  - name: inference
    image: your-inference-image:tag
    resources:
      limits:
        nvidia.com/mig-1g.10gb: "1"   # One MIG instance, hardware-isolated
```

Each pod with `nvidia.com/mig-1g.10gb: "1"` gets exactly one MIG instance. The device plugin mounts `/dev/nvidia0` scoped to that MIG instance — Tenant A's pod cannot address Tenant B's DRAM regardless of any CUDA API call or driver bug. GPU memory remanence between MIG tenants is not possible: DRAM partitions are statically assigned and protected by the memory controller hardware.

### 4. Seccomp Profile Restricting GPU ioctl Access

A full enumeration of valid NVIDIA ioctl codes is not publicly available, making a precise allowlist impractical. However, a seccomp profile can restrict `ioctl()` to known-safe file descriptor types and block it entirely on `/dev/nvidia*` for pods that do not require GPU access but are co-located on GPU nodes. This limits blast radius: a compromised CPU-only workload cannot reach the GPU ioctl surface even if it is scheduled on a GPU node.

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["ioctl"],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 1,
          "op": "SCMP_CMP_GT"
        }
      ],
      "comment": "Allow ioctl on fd > 1 (not stdin/stdout/stderr), but restrict further at policy layer"
    }
  ]
}
```

A more targeted approach for GPU workloads is to create a seccomp profile that allows ioctl unconditionally for ML workloads (since you cannot enumerate valid CUDA ioctl codes) but applies `SCMP_ACT_LOG` to record all ioctl calls to `/dev/nvidia*` — this provides audit telemetry without blocking legitimate operations:

```yaml
# Pod seccomp annotation for GPU workloads — audit mode
apiVersion: v1
kind: Pod
metadata:
  name: inference-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "localhost/nvidia-audit.json"
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: nvidia-audit.json
  containers:
  - name: inference
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop: ["ALL"]
```

For non-GPU pods co-located on GPU nodes, apply a seccomp profile that blocks `ioctl()` entirely or allows it only on fd types that are not character devices:

```bash
# Generate a baseline seccomp profile by observing a known-good GPU workload
# using strace, then use that profile to restrict unknown workloads
strace -f -e trace=ioctl -o /tmp/gpu-ioctl-trace.log python3 inference.py
grep 'ioctl(.*nvidia' /tmp/gpu-ioctl-trace.log | awk '{print $2}' | sort -u
```

The trade-off is real: it is not feasible to produce a precise allowlist of NVIDIA ioctl codes that covers all CUDA operations without extensive per-driver-version profiling work. The practical value of seccomp for GPU nodes is (a) blocking GPU device access for workloads that should not have it and (b) generating audit logs for anomalous ioctl patterns.

### 5. GPU Memory Zeroing Between Workloads

NVIDIA driver 525 and later supports explicit GPU memory zeroing on context destruction via the `CUDA_FORCE_PTX_JIT` environment variable and driver-level initialization flags. However, the most reliable approach is application-level zeroing before returning allocations to the memory pool.

For PyTorch-based inference workloads, explicitly zero GPU tensors before releasing them:

```python
import torch
import gc

def secure_teardown(model_tensors: list[torch.Tensor]) -> None:
    """Zero GPU memory before releasing to prevent cross-tenant remanence."""
    for tensor in model_tensors:
        if tensor.is_cuda:
            tensor.zero_()          # In-place zero fill on GPU
            del tensor
    torch.cuda.synchronize()        # Ensure all zero operations complete
    torch.cuda.empty_cache()        # Release cached allocations to driver pool
    gc.collect()

# At inference pod shutdown or model swap:
secure_teardown(list(model.parameters()))
secure_teardown(kv_cache_tensors)
```

At the driver level, NVIDIA's `nvidia-smi` does not provide a direct command to zero DRAM, but you can verify the memory reservation state:

```bash
nvidia-smi --query-gpu=memory.used,memory.free,memory.reserved \
  --format=csv,noheader,nounits
# memory.reserved shows driver-reserved memory not available to applications;
# after pod termination, memory.used should return to baseline before
# scheduling the next tenant on this GPU instance
```

For MIG configurations, GPU memory is hardware-partitioned and the partition boundary prevents cross-instance reads. Application-level zeroing remains a defense-in-depth measure within a single MIG instance between successive requests from different tenants handled by the same inference server process.

### 6. Kata Containers with VFIO GPU Passthrough

For the strongest isolation between a multi-tenant node and per-tenant workloads, Kata Containers with VFIO GPU passthrough gives each pod its own lightweight VM kernel. An NVKM exploit triggered from inside the Kata VM affects only that VM's kernel — it cannot escape to the host kernel because the NVKM instance inside the VM is isolated from the host NVKM by the VFIO IOMMU boundary.

Prerequisites: IOMMU enabled in BIOS/UEFI and kernel (`intel_iommu=on iommu=pt` or `amd_iommu=on` in kernel command line), VFIO drivers loaded (`vfio`, `vfio-pci`, `vfio-iommu-type1`).

Bind the GPU to vfio-pci on the host:

```bash
# Find the PCI address of the GPU
lspci | grep -i nvidia
# 0000:01:00.0 3D controller: NVIDIA Corporation A100-SXM4-80GB [10de:20b2]

# Get vendor:device ID
lspci -n -s 0000:01:00.0
# 0000:01:00.0 0302: 10de:20b2 (rev a1)

# Bind to vfio-pci (prevents host NVIDIA driver from claiming the device)
echo "10de 20b2" > /sys/bus/pci/drivers/vfio-pci/new_id

# Verify binding
ls -la /sys/bus/pci/devices/0000:01:00.0/driver
# -> ../../../../bus/pci/drivers/vfio-pci
```

Configure the Kata runtime class:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-vfio-gpu
handler: kata
scheduling:
  nodeSelector:
    katacontainers.io/kata-runtime: "true"
    kata.vfio/gpu: "true"
```

Configure the Kata agent to pass through the VFIO device:

```toml
# /etc/kata-containers/configuration.toml
[hypervisor.qemu]
  path = "/usr/bin/qemu-system-x86_64"
  kernel = "/usr/share/kata-containers/vmlinuz.container"
  initrd = "/usr/share/kata-containers/kata-containers-initrd.img"
  machine_type = "q35"
  # VFIO GPU passthrough
  extra_args = ["-device", "vfio-pci,host=01:00.0"]
  # IOMMU must be enabled in the VM
  iommu_platform = true
  machine_accelerators = "iommu=on"
```

Pod spec using Kata with VFIO GPU:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: isolated-inference-pod
spec:
  runtimeClassName: kata-vfio-gpu
  containers:
  - name: inference
    image: your-inference-image:tag
    resources:
      limits:
        nvidia.com/gpu: "1"
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
```

With this configuration, the NVKM ioctl surface inside the pod is an NVKM instance running in the VM's kernel, isolated from the host kernel by VFIO/IOMMU. A CVE-2023-0184-class exploit in the VM gains VM root, not host root. The blast radius is bounded to the single tenant's VM.

### 7. Falco Rule for Anomalous GPU Device Access

Falco's kernel instrumentation can detect unexpected access to GPU device files — specifically, processes that are not known ML runtimes accessing `/dev/nvidia*` devices. This catches container escapes that pivot to GPU devices as an intermediate step, and catches non-GPU workloads on GPU nodes that should not have GPU access but do because of misconfigured device plugin policy.

```yaml
- rule: Unexpected GPU device access
  desc: >
    A process that is not a known ML runtime or GPU management tool
    is accessing an NVIDIA GPU device node. This may indicate a
    container escape attempt using a GPU ioctl vulnerability, or a
    misconfigured pod that should not have GPU access.
  condition: >
    (open_read or open_write) and
    fd.name startswith "/dev/nvidia" and
    not proc.name in (python3, python, pytorch, torchserve, tritonserver,
                      vllm, nvidia-smi, nvidia-debugdump, nv-hostengine,
                      dcgmi, dcgm-exporter, nvcc, cuda-gdb) and
    not container.image.repository in (nvcr.io/nvidia, nvcr.io/nvaie) and
    container.id != host
  output: >
    Unexpected GPU device access detected
    (proc=%proc.name pid=%proc.pid uid=%user.uid
     fd=%fd.name container=%container.name
     image=%container.image.repository:%container.image.tag
     node=%k8s.node.name ns=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [gpu, container-escape, mitre_privilege_escalation]

- rule: GPU device access from privileged container
  desc: >
    A privileged container is accessing NVIDIA GPU device nodes.
    Privileged containers combined with GPU ioctl vulnerabilities
    provide a direct path to host kernel code execution.
  condition: >
    (open_read or open_write) and
    fd.name startswith "/dev/nvidia" and
    container.privileged = true
  output: >
    Privileged container accessing GPU device node
    (proc=%proc.name pid=%proc.pid
     fd=%fd.name container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [gpu, privilege-escalation, container-escape]
```

Deploy Falco as a DaemonSet on all GPU nodes:

```bash
helm install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=ebpf \
  --set-file falco.rules_file[0]=/path/to/gpu-rules.yaml \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="<your-slack-webhook>"
```

## Expected Behaviour

On a correctly MIG-partitioned A100-80GB node configured with 7 x `1g.10gb` instances, `nvidia-smi` output shows distinct GPU instances with non-overlapping DRAM ranges:

```
+-----------------------------------------------------------------------------+
| MIG devices:                                                                |
+------------------+----------------------+-----------+-----------------------+
| GPU  GI   CI     Uuid                   MIG         Memory-Usage           |
|       ID   ID    |                       Profile     BAR1-Usage             |
|=============================================================================|
|   0    1   0     MIG-abc123...           1g.10gb     8MiB / 9728MiB        |
|   0    2   0     MIG-def456...           1g.10gb     8MiB / 9728MiB        |
|   0    3   0     MIG-ghi789...           1g.10gb     8MiB / 9728MiB        |
...
+-----------------------------------------------------------------------------+
```

Each pod provisioned with `nvidia.com/mig-1g.10gb: "1"` sees exactly one MIG instance with 9,728 MiB of addressable DRAM. The pod cannot enumerate other MIG instances: `nvidia-smi` inside the pod shows only its own instance. The CUDA device ID (`cuda:0`) maps to the pod's MIG instance. Attempting to allocate more than 9,728 MiB raises `torch.cuda.OutOfMemoryError` for that pod only — other pods are unaffected.

For a Kata Container pod, the NVIDIA driver version reported from inside the VM via `nvidia-smi` is the driver installed in the VM's guest kernel (which will differ from the host driver version if they are managed separately). The VM's kernel ioctl surface is isolated from the host; a `strace` of CUDA calls inside the Kata pod shows `ioctl()` calls to `/dev/nvidia0` landing in the VM kernel's NVKM, not the host kernel's.

Falco alerts on a correctly hardened node should show zero `Unexpected GPU device access` events during normal inference workload operation (assuming the allowlist of known ML runtimes in the Falco rule is accurate for your environment). Any alert outside of scheduled maintenance windows warrants immediate investigation — the most likely cause is a misconfigured pod that requested GPU resources it does not legitimately need, or an active container escape attempt.

## Trade-offs

**MIG partitioning** delivers the hardware-enforced isolation that eliminates the GPU memory remanence problem and eliminates cross-tenant impact from driver bugs within a partition. The costs are real: MIG is only available on A100, H100, H200, and the L40S in limited profiles. A10, A30, T4, and V100 — which constitute a large fraction of deployed ML inference capacity — do not support MIG. Each MIG instance has a fixed DRAM allocation; a model that requires 12 GB cannot fit in a `1g.10gb` instance (9,728 MiB) but a `2g.20gb` profile reduces the tenant count to 3 on an A100-80GB. For large models (LLaMA-3 70B requires approximately 40 GB in FP16), MIG profile granularity may be too coarse for multi-tenancy, forcing use of `4g.40gb` profiles with at most two tenants per GPU. Operational complexity: MIG partition changes require driver-level reconfiguration and cannot be done without terminating all current GPU workloads on the node. Hot-reconfiguration between partition schemes requires a node drain.

**Kata Containers with VFIO passthrough** provides complete kernel isolation and is the correct answer when running untrusted inference code (e.g., user-provided model artifacts). The overhead is meaningful: PCIe device virtualization introduces latency on GPU memory allocation (typically 1–3 ms per CUDA context creation, not per-inference). For short-running batch inference workloads, context creation latency is amortized; for long-running inference servers (vLLM, TGI, Triton) that create the CUDA context once at startup, the latency overhead is negligible in steady state. Kata is not supported on all GPU types with VFIO passthrough: SR-IOV-capable GPUs (NVIDIA A-series with vGPU support) work reliably; older GPU generations may have incomplete VFIO implementation. The cold-start time for Kata pods is longer than for runc pods (VM boot time, typically 500–1,500 ms), which matters for autoscaling workloads that need to start inference pods in response to traffic.

**Disabling CUDA MPS** recovers fault isolation at the cost of reduced GPU utilization. For small-batch inference workloads (batch size 1–4, common in interactive LLM serving), MPS can improve token throughput by 20–40% by allowing multiple request contexts to share SM resources. Disabling MPS and using exclusive-compute mode means each pod holds the GPU exclusively; if the pod is not fully utilizing the GPU (waiting for CPU pre/post-processing, network I/O, tokenizer operations), that capacity is wasted. The capacity cost must be weighed against the isolation requirement. For a single-tenant inference cluster, MPS is acceptable. For any multi-tenant configuration, the capacity cost is the price of fault isolation.

**Application-level GPU memory zeroing** adds measurable overhead to model teardown and warm pool returns. For a 70B-parameter model in FP16, zeroing 140 GB of GPU tensors at GPU DRAM bandwidth (approximately 2 TB/s on A100) takes approximately 70 ms. This is acceptable for inter-tenant model swaps but is too slow for request-level context zeroing in a high-throughput inference server serving hundreds of requests per second. In practice, zeroing should be applied at model load/unload boundaries (between tenant model swaps) rather than at per-request boundaries. The KV cache is the most sensitive structure at the request level: prompt tokens in the KV cache should be zeroed between tenant requests if the inference server reuses KV cache memory across tenants.

## Failure Modes

**Assuming Kubernetes namespace isolation protects GPU memory.** Namespace isolation in Kubernetes is a control plane concept: it controls which pods can communicate with which services, which RBAC roles can read which secrets, and which network policies apply to which pods. It has no mechanism to restrict GPU memory access. `/dev/nvidia0` is a character device on the host filesystem. The `nvidia-device-plugin` mounts it into pods based on resource requests — two pods in different namespaces, on the same node, both requesting `nvidia.com/gpu: "1"`, may both get `/dev/nvidia0` mounted (if using time-slicing or MPS), or they may each get a separate GPU device. In neither case does the namespace boundary protect one pod's GPU DRAM from the other pod's kernel-level access. A security model that says "namespace A's models are protected from namespace B's code" is incorrect for any GPU configuration short of MIG or separate physical GPUs.

**Running CUDA MPS in multi-tenant inference to improve utilization.** This is the most common mistake in GPU cluster configurations built by ML infrastructure teams without a security background. The NVIDIA documentation is explicit that MPS is designed for trusted, cooperating processes in HPC environments. The CUDA Programming Guide (section on MPS) states: "MPS clients share the GPU context. A fault in one client can affect other clients." Treating this as a minor footnote and enabling MPS across tenants from different teams or customers eliminates fault isolation and exposes the root MPS daemon process as a shared attack surface. The GPU utilization gain from MPS is real, but it cannot justify eliminating tenant fault isolation in a genuinely adversarial multi-tenant environment.

**Tracking NVIDIA driver CVEs via the Linux kernel CVE feed.** NVIDIA GPU driver vulnerabilities are published on NVIDIA's security bulletin page (https://www.nvidia.com/en-us/security/) and in NVD under CPE `cpe:2.3:a:nvidia:gpu_driver`. They are not typically tracked through Linux distribution CVE feeds (RHSA, DSA, USN) because the NVIDIA driver is proprietary and not distributed through distro repositories. Teams that rely on their OS vendor's security advisories for patching decisions will miss NVIDIA driver CVEs entirely. The patching cadence is also different: NVIDIA publishes security bulletins quarterly (in addition to ad-hoc critical patches), on a schedule that does not align with Linux kernel stable releases or distribution update cycles. Separate tracking is required.

**Assuming model weights are protected by Kubernetes RBAC and object storage access controls alone.** Model weights stored in S3, GCS, or an OCI registry are protected by IAM policies at rest. Once a model is loaded into GPU DRAM for inference, it is protected only by the GPU driver's memory isolation — which, as detailed above, is not reliable against a co-tenant with GPU access and knowledge of a current NVKM vulnerability, and is not reliable against GPU memory remanence on non-MIG hardware. An adversary who compromises a co-tenant pod's execution context can attempt to extract model weights from GPU DRAM without ever touching the object storage bucket. RBAC on the model artifact does not protect the model once it is materialized in GPU memory. Proprietary fine-tuned models running on shared GPU infrastructure without MIG isolation are exposed to this risk on every node where a co-tenant runs.

## Related Articles

- [Confidential AI Inference](/articles/ai-landscape/confidential-ai-inference/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
- [Confidential Containers](/articles/kubernetes/confidential-containers/)
- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
