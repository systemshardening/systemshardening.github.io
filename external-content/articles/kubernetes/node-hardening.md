---
title: "Kubernetes Node Hardening: From OS Configuration to kubelet Lockdown"
description: "A Kubernetes node is a Linux machine running kubelet, a container runtime, and your workloads."
slug: "node-hardening"
date: 2026-04-15
lastmod: 2026-04-15
category: "kubernetes"
tags: ["kubernetes", "node-security", "kubelet", "containerd", "os-hardening", "kernel"]
personas: ["platform-engineer", "systems-engineer"]
article_number: 30
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
  - name: "Vultr"
    id: 12
    category: "managed-kubernetes"
  - name: "Linode"
    id: 13
    category: "managed-kubernetes"
published: true
layout: article.njk
permalink: "/articles/kubernetes/node-hardening/index.html"
---

# [Kubernetes](https://kubernetes.io) Node Hardening: From OS Configuration to kubelet Lockdown

## Problem

A Kubernetes node is a Linux machine running kubelet, a container runtime, and your workloads. If the node is compromised, every pod on that node is compromised. Node hardening spans four layers: the base operating system, kernel parameters, the container runtime ([containerd](https://containerd.io) or [CRI-O](https://cri-o.io)), and the kubelet configuration. Most hardening guides cover one of these layers but miss the others.

The challenges are concrete:

- **Default OS installations include unnecessary packages.** Ubuntu Server ships with `curl`, `wget`, `gcc`, `python3`, and hundreds of other utilities. A compromised container that escapes to the host finds a full toolkit for lateral movement.
- **Default kernel parameters favour compatibility over security.** IP forwarding, source routing, and ICMP redirects are enabled by default. These are useful for routers, not for Kubernetes nodes.
- **kubelet defaults are permissive.** Anonymous authentication is enabled, read-only port 10255 is open, and the kubelet API allows node-level operations without strong authorization.
- **Container runtime defaults trust all images.** containerd and CRI-O ship with permissive configurations that do not enforce image signing, runtime classes, or seccomp defaults.

This article covers all four layers with production-ready configuration for each. The estimated effort is 4-8 hours per node image, which is why managed Kubernetes providers are the right answer for many teams.

**Target systems:** Kubernetes 1.29+ on Ubuntu 24.04 LTS, Flatcar Container Linux, or Talos Linux. containerd 1.7+ or CRI-O 1.29+.

## Threat Model

- **Adversary:** Attacker who has achieved container escape (via kernel exploit, runtime vulnerability, or misconfigured privileged container) and now has access to the node.
- **Access level:** Unprivileged or root shell on the host operating system, depending on the escape vector.
- **Objective:** Persist on the node, access secrets from other pods, pivot to the control plane or other nodes, exfiltrate data, or deploy cryptominers.
- **Blast radius:** Without node hardening, a compromised node exposes all pods on that node, the kubelet credentials (which can list cluster resources), and potentially the container runtime socket (which allows spawning new containers). With hardening, the attacker faces a minimal OS with no tools, restricted kernel interfaces, a locked-down kubelet that rejects unauthorized requests, and a runtime that limits container capabilities.

## Configuration

### Step 1: Minimal Operating System

Choose a container-optimized OS that ships with only the components needed to run kubelet and containers.

**Option A: Ubuntu 24.04 Minimal**

```bash
# Start with ubuntu-24.04-live-server-amd64.iso (minimal installation)
# After installation, remove unnecessary packages:
apt purge -y \
  snapd \
  unattended-upgrades \
  apport \
  popularity-contest \
  ubuntu-advantage-tools \
  gcc \
  g++ \
  make \
  python3-pip

# Remove package managers that aid post-exploitation:
apt purge -y python3-pip
rm -f /usr/bin/wget  # Keep curl for health checks if needed

# Lock down the package list
apt autoremove -y
apt clean
```

**Option B: Talos Linux (immutable, API-managed)**

Talos has no SSH, no shell, no package manager. All configuration is done via its API:

```yaml
# talos-machine-config.yaml (relevant security sections)
machine:
  install:
    disk: /dev/sda
    image: ghcr.io/siderolabs/installer:v1.9.0
  kubelet:
    extraArgs:
      rotate-server-certificates: "true"
      protect-kernel-defaults: "true"
    extraConfig:
      serverTLSBootstrap: true
  kernel:
    modules:
      - name: br_netfilter
  sysctls:
    net.ipv4.ip_forward: "1"
    net.bridge.bridge-nf-call-iptables: "1"
    net.bridge.bridge-nf-call-ip6tables: "1"
    kernel.panic: "10"
    vm.overcommit_memory: "1"
```

**Option C: Flatcar Container Linux**

Flatcar is immutable with automatic updates. Configuration happens via Ignition:

```json
{
  "ignition": { "version": "3.4.0" },
  "storage": {
    "files": [
      {
        "path": "/etc/sysctl.d/99-kubernetes.conf",
        "contents": {
          "source": "data:,net.ipv4.ip_forward%3D1%0Anet.bridge.bridge-nf-call-iptables%3D1%0Anet.ipv4.conf.all.rp_filter%3D1"
        }
      }
    ]
  }
}
```

### Step 2: Kernel Parameters for Container Nodes

Apply sysctl settings that harden network behaviour and restrict kernel features:

```bash
# /etc/sysctl.d/99-kubernetes-hardening.conf

# Required for Kubernetes networking
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

# Disable source routing (prevents IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirects (prevent MITM via routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable reverse path filtering (drop packets with spoofed source IPs)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests (prevent Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Restrict kernel pointer leaks (prevent KASLR bypass)
kernel.kptr_restrict = 2

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Restrict eBPF to privileged users
kernel.unprivileged_bpf_disabled = 1

# Restrict user namespaces (reduce kernel attack surface)
# Note: set to 0 only if your runtime does not need unprivileged user namespaces
# user.max_user_namespaces = 0

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 1

# Disable SysRq key (prevent console-based attacks on physical/VM nodes)
kernel.sysrq = 0
```

```bash
# Apply without reboot
sysctl --system

# Verify critical settings
sysctl net.ipv4.conf.all.accept_redirects  # Should be 0
sysctl kernel.kptr_restrict                  # Should be 2
```

### Step 3: Kernel Boot Parameters

Add security-relevant boot parameters to the kernel command line:

```bash
# /etc/default/grub (Ubuntu)
GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor \
  vsyscall=none \
  page_poison=1 \
  slab_nomerge \
  init_on_alloc=1 \
  init_on_free=1 \
  randomize_kstack_offset=on"
```

```bash
# Apply the changes
update-grub
# Reboot required for boot parameters
```

| Parameter | Purpose |
|-----------|---------|
| `vsyscall=none` | Disables vsyscall page, removing a known ROP gadget target |
| `page_poison=1` | Fills freed pages with a pattern to detect use-after-free |
| `slab_nomerge` | Prevents slab cache merging, making heap exploitation harder |
| `init_on_alloc=1` | Zero-fills allocated memory pages |
| `init_on_free=1` | Zero-fills freed memory pages |

### Step 4: kubelet Configuration

Lock down the kubelet with a configuration file instead of command-line flags:

```yaml
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# Authentication: disable anonymous access, require webhook auth
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
    cacheTTL: 2m0s
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt

# Authorization: use webhook (API server decides)
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s

# Disable read-only port (10255 exposes node info without auth)
readOnlyPort: 0

# Enable certificate rotation
rotateCertificates: true
serverTLSBootstrap: true

# Protect kernel defaults (kubelet refuses to start if sysctl values
# do not match expected values)
protectKernelDefaults: true

# Event recording rate limits
eventRecordQPS: 5
eventBurst: 10

# Enable seccomp default
seccompDefault: true

# Streaming connection timeouts
streamingConnectionIdleTimeout: 5m0s

# Make sure the kubelet only allows pods scheduled to this node
# (prevents unauthorized pod execution)
enableServer: true
```

```bash
# Verify kubelet is using the config file
systemctl status kubelet
# Check for: --config=/var/lib/kubelet/config.yaml

# Verify anonymous auth is disabled
curl -sk https://localhost:10250/pods
# Expected: 401 Unauthorized (not a list of pods)

# Verify read-only port is closed
curl -s http://localhost:10255/healthz
# Expected: connection refused
```

### Step 5: containerd Hardening

```toml
# /etc/containerd/config.toml
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  # Disable deprecated image pull progress logging
  disable_tcp_service = true

  [plugins."io.containerd.grpc.v1.cri".containerd]
    # Set default runtime to runc with seccomp
    default_runtime_name = "runc"

    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      runtime_type = "io.containerd.runc.v2"

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
        # Enable systemd cgroup driver (matches kubelet)
        SystemdCgroup = true

  [plugins."io.containerd.grpc.v1.cri".registry]
    # Restrict to approved registries only
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
        endpoint = ["https://registry-1.docker.io"]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.example.com"]
        endpoint = ["https://registry.example.com"]
```

```bash
# Restrict the containerd socket permissions
chmod 0660 /run/containerd/containerd.sock
chown root:containerd /run/containerd/containerd.sock

# Restart containerd
systemctl restart containerd

# Verify the configuration
containerd config dump | grep SystemdCgroup
# Expected: SystemdCgroup = true
```

### Step 6: CRI-O Hardening (Alternative Runtime)

```toml
# /etc/crio/crio.conf.d/99-hardening.conf
[crio.runtime]
# Default seccomp profile for all containers
seccomp_profile = "/usr/share/containers/seccomp.json"

# Set default capabilities (drop all, add only what is needed)
default_capabilities = [
  "CHOWN",
  "DAC_OVERRIDE",
  "FSETID",
  "FOWNER",
  "SETGID",
  "SETUID",
  "NET_BIND_SERVICE"
]

# Set allowed registries (block all others)
[crio.image]
allowed_registries = [
  "registry.example.com",
  "docker.io",
  "quay.io",
  "registry.k8s.io"
]
```

### Step 7: Node-Level Network Restrictions

Use iptables rules on the node to restrict access to the kubelet API and metadata endpoints:

```bash
# /etc/iptables/rules.v4 (or use nftables equivalent)

# Block access to kubelet API from pods (only API server should reach it)
iptables -A INPUT -p tcp --dport 10250 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -p tcp --dport 10250 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -p tcp --dport 10250 -s 192.168.0.0/16 -j DROP
# Allow from control plane CIDR
iptables -A INPUT -p tcp --dport 10250 -s <control-plane-cidr> -j ACCEPT

# Block access to cloud metadata endpoint from pods
# (prevents SSRF-based credential theft)
iptables -t nat -A PREROUTING -p tcp -d 169.254.169.254 --dport 80 \
  -s 10.244.0.0/16 -j DNAT --to-destination 127.0.0.1:1
```

## Expected Behaviour

After completing all hardening steps:

- The node runs a minimal OS with no compilers, scripting languages, or unnecessary network tools
- Kernel parameters block source routing, ICMP redirects, and kernel pointer leaks
- kubelet rejects anonymous requests and does not expose a read-only port
- The container runtime enforces a default seccomp profile and restricts image registries
- Pod network traffic cannot reach the kubelet API directly
- `protectKernelDefaults: true` causes kubelet to refuse to start if kernel parameters are reverted, acting as a drift detection mechanism
- Certificate rotation keeps kubelet TLS credentials fresh without manual intervention

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Minimal OS (no debug tools) | Debugging production issues is harder without `tcpdump`, `strace`, `curl` | Increased mean time to resolution during incidents | Use ephemeral debug containers (`kubectl debug node/...`) or maintain a separate debug toolkit image |
| `protectKernelDefaults: true` | kubelet refuses to start if sysctl values do not match | Node fails to join cluster if sysctl configuration is wrong | Test sysctl settings in staging. Include sysctl configuration in node image build pipeline |
| Disabling read-only kubelet port | Monitoring tools that scrape metrics from port 10255 break | Loss of node-level metrics until monitoring is reconfigured | Reconfigure [Prometheus](https://prometheus.io) to scrape the authenticated port 10250 with appropriate ServiceAccount tokens |
| Registry restrictions in containerd/CRI-O | Legitimate images from unapproved registries fail to pull | Deployment failures when teams use new image sources | Maintain an internal registry mirror. Establish a process for adding approved registries |
| Kernel boot parameters | Slight performance overhead from memory zeroing (init_on_alloc/free) | 1-3% memory allocation overhead | Benchmark with your workloads. Disable init_on_free if overhead is unacceptable (keep init_on_alloc) |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| sysctl settings missing after OS update | kubelet refuses to start due to `protectKernelDefaults` check | Node shows NotReady; kubelet logs show "kernel defaults not matching" | Re-apply sysctl settings from `/etc/sysctl.d/99-kubernetes-hardening.conf` and restart kubelet |
| containerd socket permissions too restrictive | kubelet cannot communicate with the container runtime | kubelet logs show "connection refused" for containerd socket; pods stuck in ContainerCreating | Fix socket permissions: `chmod 0660 /run/containerd/containerd.sock` and verify kubelet user is in the containerd group |
| Registry restriction blocks system images | kube-proxy, [CoreDNS](https://coredns.io), or other system components fail to pull updated images | System pods in ImagePullBackOff; `kubectl describe pod` shows registry access denied | Add `registry.k8s.io` and `docker.io` to the allowed registries list. Restart the container runtime |
| kubelet certificate rotation fails | kubelet TLS certificate expires; API server rejects kubelet communication | Node shows NotReady; kubelet logs show TLS handshake errors | Check that the cluster-signing CA is available. Manually approve pending CSRs with `kubectl certificate approve` |
| Firewall rules block legitimate kubelet traffic | API server cannot reach kubelet for logs, exec, port-forward | `kubectl logs` and `kubectl exec` return errors; node shows Ready but pod operations fail | Review iptables rules. Ensure the control plane CIDR is in the ACCEPT rule for port 10250 |

## When to Consider a Managed Alternative

**Transition point:** Node hardening requires 4-8 hours per node image to implement correctly, plus ongoing maintenance for OS updates, kernel upgrades, and runtime patches. Every time you update the base image, you must verify that all hardening controls survive the update. For teams running 3+ nodes, this is 12-24 hours of initial effort plus a recurring maintenance burden on every OS update cycle.

**Recommended providers:**

- **[Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), and [Linode](https://www.linode.com):** Managed Kubernetes services handle node OS selection, kernel configuration, kubelet hardening, and runtime configuration. You deploy workloads; they maintain the node image. This eliminates the entire surface area covered in this article.

**What you still control:** Pod Security Standards, network policy, seccomp profiles, and application-level security remain your responsibility regardless of whether nodes are managed. The managed provider handles the infrastructure layer; you handle the workload layer.

**Premium content pack:** Packer templates for building hardened node images (Ubuntu 24.04 and Flatcar) with all sysctl, kubelet, and runtime configurations from this article pre-applied. Includes a CI pipeline for rebuilding images monthly with the latest security patches.


## Related Articles

- [Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port](/articles/kubernetes/kubelet-security/)
- [etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact](/articles/kubernetes/etcd-encryption/)
- [Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries](/articles/kubernetes/multi-tenancy-hardening/)
- [Hardening the Kubernetes Scheduler: Topology Constraints and Security-Aware Placement](/articles/kubernetes/scheduler-hardening/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
