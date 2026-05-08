---
title: "Linux Network Namespace Security: Service Isolation Without a Firewall Per Rule"
description: "Network namespaces give each service its own TCP/IP stack, routing table, and firewall rules. Lateral movement between services requires an explicit veth bridge — it cannot happen by accident."
slug: linux-network-namespace-isolation
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - network-namespaces
  - service-isolation
  - veth
  - systemd
  - zero-trust
personas:
  - security-engineer
  - platform-engineer
article_number: 478
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-network-namespace-isolation/
---

# Linux Network Namespace Security: Service Isolation Without a Firewall Per Rule

## The Problem

On a default Linux host, every process shares the same network stack. A web server, a database, a background job processor, and a metrics exporter all live in the same TCP/IP namespace. The host has one routing table, one set of iptables/nftables rules, and one view of every bound socket. If the web server is compromised, the attacker inherits that view. They can connect to `127.0.0.1:5432` (PostgreSQL), `127.0.0.1:6379` (Redis), or any other locally-bound port without crossing a firewall rule, because there is no firewall boundary between localhost listeners.

This is the fundamental assumption that lateral movement exploits: once you own one process, the local network is flat. Services that bind to `127.0.0.1` assume that only trusted processes reach localhost. That assumption does not hold when an attacker has code execution on the host.

Network namespaces break this assumption at the kernel level. Each namespace has its own:

- Network interfaces (including loopback — `lo` in namespace A is not `lo` in namespace B)
- Routing table
- iptables/nftables rule sets
- Socket table — `ss -tlnp` inside one namespace shows only sockets created in that namespace
- ARP and NDP caches

A process inside namespace B cannot connect to a socket bound inside namespace A unless a deliberate veth pair or bridge connects them. There is no `127.0.0.1` in common. The kernel enforces this, not a rule that an admin might forget to write.

**Target systems:** Ubuntu 22.04+, Debian 12+, RHEL 9+, any system running kernel 3.8+ and systemd 235+.

## Threat Model

- **Adversary:** An attacker with code execution inside a compromised service process (RCE via a web application vulnerability, supply-chain compromise, or deserialization bug).
- **Access level:** Process-level — the attacker can run arbitrary code as the service user.
- **Objective:** Lateral movement to other services on the same host (database, cache, internal APIs), data exfiltration via unauthorized outbound connections, or pivoting to the internal network via the host's network interfaces.
- **Blast radius without namespace isolation:** All services listening on any interface on the host, including loopback-only listeners that developers assume are "not network-accessible."
- **Blast radius with namespace isolation:** Only services that have been explicitly connected to the compromised service's namespace via a veth pair. A PostgreSQL instance in its own namespace with no veth to the web namespace is completely unreachable from a compromised web process.

## Network Namespace Primitives

### Creating and Inspecting Namespaces

The `ip netns` subcommand manages named network namespaces. Named namespaces are represented as bind-mount files under `/run/netns/`.

```bash
# Create a named namespace
ip netns add webapp

# List all named namespaces
ip netns list

# Execute a command inside the namespace
ip netns exec webapp ip addr show
# Output: only lo (down), nothing else

# Run a shell inside the namespace
ip netns exec webapp bash

# Delete the namespace (processes inside must be stopped first)
ip netns del webapp
```

Named namespaces persist in `/run/netns/` as long as the bind-mount file exists or a process is attached. To make a namespace persist across reboots, bind-mount the file elsewhere:

```bash
# Create a persistent namespace backed by a bind mount
mkdir -p /etc/netns/webapp
touch /etc/netns/webapp/resolv.conf          # per-namespace resolver config
mount --bind /run/netns/webapp /run/netns/webapp
mount --make-shared /run/netns/webapp
```

In practice, systemd manages namespace lifecycle through service units, so manual bind mounts are rarely needed for service workloads.

### Verifying Namespace Boundaries

The kernel represents namespaces as inodes under `/proc/<pid>/ns/`. Two processes share a network namespace if and only if their `net` namespace symlinks point to the same inode:

```bash
# Check which network namespace a process is in
ls -la /proc/$(pgrep postgres)/ns/net
# lrwxrwxrwx ... net -> net:[4026532001]

ls -la /proc/$(pgrep nginx)/ns/net
# lrwxrwxrwx ... net -> net:[4026531992]
# Different inode = different namespace = no shared network stack
```

## Connecting Namespaces: veth, macvlan, ipvlan

Namespaces are useful only if services can communicate when they are supposed to. Three mechanisms connect namespaces to each other or to the host:

### veth Pairs

A veth pair is a virtual Ethernet cable. Packets written to one end appear on the other. One end lives in the host namespace, the other in the service namespace.

```bash
# Create a veth pair
ip link add veth-host type veth peer name veth-webapp

# Move one end into the webapp namespace
ip link set veth-webapp netns webapp

# Assign addresses
ip addr add 10.10.1.1/30 dev veth-host
ip netns exec webapp ip addr add 10.10.1.2/30 dev veth-webapp

# Bring both ends up
ip link set veth-host up
ip netns exec webapp ip link set veth-webapp up
ip netns exec webapp ip link set lo up

# Add a default route inside the namespace (traffic goes through the host)
ip netns exec webapp ip route add default via 10.10.1.1
```

Use veth pairs when you want point-to-point connectivity between two namespaces, or between a namespace and a Linux bridge that connects multiple namespaces.

### macvlan

macvlan creates a virtual interface that shares the MAC layer of a parent physical interface but has its own MAC address and IP. Each macvlan interface appears to the network as a separate host.

```bash
ip link add macvlan0 link eth0 type macvlan mode bridge
ip link set macvlan0 netns webapp
ip netns exec webapp ip addr add 192.168.1.50/24 dev macvlan0
ip netns exec webapp ip link set macvlan0 up
```

Use macvlan when the service needs to be directly reachable from the LAN with its own IP address, without routing through the host. Note: a macvlan interface cannot communicate with the parent interface (`eth0`) directly; for host-to-namespace communication you need a separate macvlan in the host namespace.

### ipvlan

ipvlan is similar to macvlan but all virtual interfaces share the parent's MAC address, using different IPs. It operates in L2 or L3 mode. L3 mode is useful for namespaces that should participate in routing rather than bridging:

```bash
ip link add ipvlan0 link eth0 type ipvlan mode l3
ip link set ipvlan0 netns webapp
ip netns exec webapp ip addr add 192.168.1.51/32 dev ipvlan0
```

Use ipvlan L3 when you have many namespaces and want to avoid ARP at scale, or when the parent NIC does not support promiscuous mode (which macvlan requires in some modes).

**Summary of when to use each:**

| Mechanism | Use case |
|-----------|----------|
| veth pair | Service-to-service and service-to-host connectivity; most common |
| macvlan | Service needs its own LAN IP; no host-to-namespace requirement |
| ipvlan L3 | High-density deployments, no promiscuous mode, routed topology |

## Running Services in a Network Namespace with systemd

systemd 235 (shipped in Ubuntu 20.04, RHEL 8) added `NetworkNamespacePath=` for service units, allowing you to attach a service to a pre-existing named namespace. systemd 247+ also supports creating a private namespace inline.

### Full Network Isolation with PrivateNetwork=

The simplest option: the service gets its own namespace with only a loopback interface. No host network access whatsoever.

```ini
# /etc/systemd/system/myworker.service
[Unit]
Description=Background worker with no network access
After=network.target

[Service]
ExecStart=/usr/bin/myworker
User=myworker
PrivateNetwork=yes

[Install]
WantedBy=multi-user.target
```

`PrivateNetwork=yes` creates a new network namespace for the service. The namespace contains only a loopback interface. The service cannot make outbound connections and is unreachable from any network. Use this for compute-only workers that read from a Unix socket or file and write results to disk.

### Attaching a Service to a Named Namespace

For services that need controlled connectivity, create a named namespace and attach the service to it:

```bash
# Create the namespace (do this in a oneshot service or at boot)
ip netns add postgres-ns
ip link add veth-pg-host type veth peer name veth-pg
ip link set veth-pg netns postgres-ns
ip addr add 10.20.1.1/30 dev veth-pg-host
ip netns exec postgres-ns ip addr add 10.20.1.2/30 dev veth-pg
ip link set veth-pg-host up
ip netns exec postgres-ns ip link set veth-pg up
ip netns exec postgres-ns ip link set lo up
```

```ini
# /etc/systemd/system/postgresql.service (override snippet)
# /etc/systemd/system/postgresql.service.d/namespace.conf
[Service]
NetworkNamespacePath=/run/netns/postgres-ns
```

When systemd starts `postgresql.service`, it calls `setns(2)` on `/run/netns/postgres-ns` before executing the service binary. PostgreSQL binds to `10.20.1.2` (or `127.0.0.1` inside the namespace's own loopback, which is unreachable from outside). Only processes that also join `postgres-ns`, or that have a veth connected to it, can reach the database.

### BindToDevice=: Socket-Level Interface Restriction

For a lighter alternative that does not require a separate namespace, systemd's `BindToDevice=` ties a socket-activated service to a specific network interface at the socket level:

```ini
# /etc/systemd/system/myapi.socket
[Socket]
ListenStream=8080
BindToDevice=veth-api
```

The kernel will only deliver packets arriving on `veth-api` to this socket, even if the service process itself is in the host namespace. This is a useful defense-in-depth layer even when full namespace isolation is not feasible, because it prevents the service from accidentally accepting connections on the wrong interface.

## Practical Example: Isolating PostgreSQL

The goal: PostgreSQL should be unreachable from the host network and from all other service namespaces. Application services connect via a Unix domain socket. If a Unix socket is not practical (e.g., the application runs in a container), a dedicated veth pair is used with a /30 subnet.

### Step 1: Namespace Setup Service

```ini
# /etc/systemd/system/postgres-netns-setup.service
[Unit]
Description=Create postgres network namespace
Before=postgresql.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
  ip netns add postgres-ns 2>/dev/null || true; \
  ip link show veth-pg-host 2>/dev/null || ( \
    ip link add veth-pg-host type veth peer name veth-pg && \
    ip link set veth-pg netns postgres-ns && \
    ip addr add 10.20.1.1/30 dev veth-pg-host && \
    ip netns exec postgres-ns ip addr add 10.20.1.2/30 dev veth-pg && \
    ip link set veth-pg-host up && \
    ip netns exec postgres-ns ip link set veth-pg up && \
    ip netns exec postgres-ns ip link set lo up \
  )'
ExecStop=/bin/bash -c '\
  ip link del veth-pg-host 2>/dev/null || true; \
  ip netns del postgres-ns 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
```

### Step 2: PostgreSQL Service Override

```ini
# /etc/systemd/system/postgresql@14-main.service.d/netns.conf
[Unit]
Requires=postgres-netns-setup.service
After=postgres-netns-setup.service

[Service]
NetworkNamespacePath=/run/netns/postgres-ns
# Bind only to the veth endpoint and loopback inside the namespace
Environment=PGHOST=10.20.1.2
```

### Step 3: PostgreSQL Configuration

```ini
# /etc/postgresql/14/main/postgresql.conf
listen_addresses = '127.0.0.1,10.20.1.2'
# 127.0.0.1 here is the namespace's own loopback, not the host's
```

```ini
# /etc/postgresql/14/main/pg_hba.conf
# Only allow connections from the veth subnet and local Unix socket
local   all   all                   peer
host    all   all   10.20.1.0/30    scram-sha-256
# No entry for host network ranges
```

After reloading, verify from the host:

```bash
# This should FAIL — host and postgres-ns have different lo
psql -h 127.0.0.1 -U postgres
# psql: error: connection to server at "127.0.0.1", port 5432 failed

# This should SUCCEED — veth-pg-host is in the host namespace, veth-pg is in postgres-ns
psql -h 10.20.1.2 -U postgres
```

Any service that should NOT reach PostgreSQL simply has no veth peered into `postgres-ns`. The kernel enforces this — there is no rule to forget or misconfigure.

## Combining with nftables

Each network namespace has its own nftables rule set. Rules added in the host namespace do not exist inside a service namespace, and vice versa. This means you can apply tight, service-specific rules inside a namespace without affecting other services:

```bash
# Apply nftables rules inside the postgres namespace
ip netns exec postgres-ns nft -f /etc/nftables-postgres.conf
```

```nft
# /etc/nftables-postgres.conf
# Applied inside postgres-ns only
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Allow established connections
    ct state established,related accept

    # Allow connections from the veth subnet only
    ip saddr 10.20.1.0/30 tcp dport 5432 accept

    # Allow loopback
    iif lo accept

    # Drop everything else (including any future veth pairs
    # that might accidentally be added to this namespace)
    drop
  }

  chain output {
    type filter hook output priority 0; policy drop;

    # Allow established outbound
    ct state established,related accept

    # Allow responses to the veth subnet
    ip daddr 10.20.1.0/30 accept

    # Allow loopback
    oif lo accept

    drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
```

Because nftables rules are namespace-local, an operator adding a rule to the host namespace cannot accidentally open a port in the postgres namespace. The failure mode is isolation rather than exposure.

To apply nftables rules at namespace creation time, add the rule load to the setup service:

```ini
# In postgres-netns-setup.service ExecStart
ExecStart=/bin/bash -c '... && ip netns exec postgres-ns nft -f /etc/nftables-postgres.conf'
```

## Monitoring and Visibility

Network namespaces create a visibility gap: tools run from the host see only host-namespace sockets by default.

### Inspecting Sockets Inside a Namespace

```bash
# List listening sockets inside postgres-ns
ip netns exec postgres-ns ss -tlnp

# List all established connections inside a namespace
ip netns exec postgres-ns ss -tnp state established

# Inspect from the outside using nsenter (useful when the namespace
# has no shell or when you don't want to exec into an untrusted namespace)
nsenter --net=/run/netns/postgres-ns -- ss -tlnp
```

### nsenter for Debugging Without a Shell in the Namespace

`nsenter` is the production-safe way to run diagnostic commands inside a namespace without modifying the service process or adding a shell to the namespace:

```bash
# Enter only the network namespace of a running postgres process
nsenter -t $(pgrep -o postgres) --net -- ss -tlnp

# Run tcpdump inside the namespace (requires CAP_NET_RAW in the namespace)
nsenter --net=/run/netns/postgres-ns -- tcpdump -i veth-pg -n tcp port 5432
```

### Monitoring Namespace Membership

To verify that a service is actually running in the expected namespace:

```bash
# Check the network namespace inode of the postgres process
readlink /proc/$(pgrep -o postgres)/ns/net
# net:[4026532345]

# Compare with the named namespace inode
stat -L --format='%i' /run/netns/postgres-ns
# 4026532345  <- must match
```

A mismatch between these two inodes means the service is not running in the expected namespace — either the setup service failed, or a restart occurred before the namespace was recreated.

### Integration with Prometheus and Node Exporter

Node Exporter does not cross namespace boundaries for network metrics. To collect per-namespace metrics, run a namespace-aware exporter or use `ip netns exec` in a wrapper:

```bash
# Collect socket stats from postgres-ns for a monitoring script
ip netns exec postgres-ns ss -s | grep -E 'TCP|UDP'
```

For production observability, consider running a lightweight `ss`-based collector as a systemd service with `NetworkNamespacePath=/run/netns/postgres-ns` so it sees exactly what PostgreSQL sees.

## Limitations and Edge Cases

### The Kernel Shares More Than Routes

Network namespaces isolate the network stack, but they do not isolate everything. Be aware:

- **Unix domain sockets** are filesystem objects, not network objects. A process in namespace B can connect to a Unix socket created by a process in namespace A if the filesystem path is accessible. Unix sockets bypass network namespace boundaries entirely. Use filesystem permissions and mount namespaces to control access to Unix sockets.
- **eBPF programs** attached to a network interface in one namespace are not visible from another namespace, but eBPF programs attached to cgroup hooks or tracepoints may observe traffic from all namespaces depending on attachment scope. Audit your eBPF programs for cross-namespace visibility.
- **`/proc/net/` files** inside a namespace reflect only that namespace's sockets. However, from the host, `/proc/<pid>/net/` for a pid inside a namespace reveals that namespace's full socket table. This is expected and used by monitoring tools, but it means a root process on the host can always inspect any namespace.
- **Raw sockets and `CAP_NET_RAW`** inside a namespace are isolated to that namespace's interfaces. A process with `CAP_NET_RAW` inside `postgres-ns` cannot sniff traffic on `eth0` in the host namespace.

### Namespace Creation Races

If `postgres-netns-setup.service` fails or takes longer than expected, PostgreSQL may start in the host namespace. Always verify namespace membership after startup as part of your readiness checks:

```bash
# In a post-start check or monitoring probe
expected=$(stat -L --format='%i' /run/netns/postgres-ns)
actual=$(readlink /proc/$(pgrep -o postgres)/ns/net | tr -d 'net:[]')
[ "$expected" = "$actual" ] || echo "ALERT: postgres not in expected namespace"
```

### Container Runtimes and Nested Namespaces

If services run in containers (Docker, Podman), each container already has its own network namespace created by the runtime. You can still add additional isolation layers — for example, attaching a container's network namespace to a restricted nftables rule set — but the runtime must cooperate. Use `--network=none` (Docker/Podman) to create containers with only a loopback interface, equivalent to `PrivateNetwork=yes` for bare-metal services.

### eBPF and netns Boundaries

eBPF TC (traffic control) programs attached to a veth interface see traffic in the namespace where the interface lives. An eBPF program on `veth-pg-host` (in the host namespace) sees packets entering from `postgres-ns` before they are processed by the host routing stack. This is the correct attachment point for host-side packet inspection. An eBPF program on `veth-pg` (inside `postgres-ns`) sees only traffic within the namespace.

Cilium and other eBPF-based CNI plugins use this architecture to enforce per-pod policy without iptables. The same model applies to bare-metal service isolation.

## Verification Checklist

```bash
# 1. Namespace exists and is a named namespace
ip netns list | grep postgres-ns

# 2. Service is running in the correct namespace
diff \
  <(readlink /proc/$(pgrep -o postgres)/ns/net) \
  <(echo "net:[$(stat -L --format='%i' /run/netns/postgres-ns)]")

# 3. PostgreSQL is not listening on any host-namespace interface
ss -tlnp | grep 5432
# Should return nothing (or only sockets in other namespaces, which won't show here)

# 4. PostgreSQL is listening on the correct address inside its namespace
ip netns exec postgres-ns ss -tlnp | grep 5432
# Should show 10.20.1.2:5432 and/or 127.0.0.1:5432 (namespace loopback)

# 5. Connection from host via veth succeeds
psql -h 10.20.1.2 -U postgres -c 'SELECT 1'

# 6. Connection from host via host loopback fails
timeout 3 psql -h 127.0.0.1 -U postgres -c 'SELECT 1' 2>&1 | grep -q 'failed'
echo "Host loopback correctly rejected: $?"

# 7. nftables rules are loaded inside the namespace
ip netns exec postgres-ns nft list ruleset | grep -q 'policy drop'
```

## Summary

Network namespaces are the most direct mechanism Linux provides for enforcing that services cannot reach each other by default. Unlike firewall rules — which require every future service to be explicitly blocked — namespaces invert the model: connectivity requires explicit construction of a veth pair or bridge. A service that was never given a veth into the database namespace cannot reach the database regardless of what port it is listening on or what rules are configured.

The systemd integration (`NetworkNamespacePath=`, `PrivateNetwork=yes`) makes namespace-per-service practical without manual `ip netns exec` wrappers. Combined with per-namespace nftables rules, this gives each service its own isolated network stack with its own firewall policy, verified at the kernel level.

The primary operational cost is visibility: monitoring, debugging, and log collection must account for namespace boundaries. `nsenter` and `ip netns exec` are the standard tools for this. Build namespace membership verification into your service startup checks and monitoring probes so that configuration drift — a service starting outside its expected namespace — is caught immediately rather than discovered during an incident.
