---
title: "Kubernetes Defence Against Compromised npm Packages: Lessons from Axios"
description: "The Axios supply chain attack hit every CI pipeline running npm install during a 3-hour window. Enforce npm ci --ignore-scripts in Dockerfiles via Kyverno, block build-pod egress, and prevent runtime node_modules mutation in Kubernetes."
slug: kubernetes-npm-supply-chain-defence
date: 2026-05-03
lastmod: 2026-05-03
category: kubernetes
tags:
  - supply-chain
  - npm
  - kyverno
  - network-policy
  - container-security
personas:
  - platform-engineer
  - security-engineer
article_number: 416
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-npm-supply-chain-defence/
---

# Kubernetes Defence Against Compromised npm Packages: Lessons from Axios

## The Problem

The Axios compromise on March 31 2026 was not a slow, stealthy intrusion — it was a 3-hour blast radius. A North Korean threat actor tracked as Sapphire Sleet obtained a stolen npm publish token for the `axios` package, published malicious versions `1.14.1` and `0.30.0`, and every CI pipeline in the world that ran `npm install axios` (or resolved it as a transitive dependency) during that window installed a remote-access trojan. With Axios downloaded roughly 100 million times per week, the number of affected builds in that window numbered in the tens of thousands.

The attack is notable not because of any novel technique but because of where it executed. The RAT was delivered via a `postinstall` script in `package.json`. This means it ran not inside a deployed application container but during the `npm install` step of the Docker build itself — inside the build pod, with whatever network access that pod had at build time. In a typical Kubernetes CI setup using kaniko, BuildKit, or Docker-in-Docker, build pods are granted broad internet egress to pull npm packages from the registry. That same egress allowed the RAT to reach its command-and-control server during the build.

This creates two distinct attack surfaces that require separate mitigations.

**Build-time surface.** The `RUN npm install` instruction in a Dockerfile executes inside the build pod's filesystem and network namespace. A malicious `postinstall` script runs here with full access to the build environment: any environment variables set for the build (which commonly include registry credentials, signing keys, or cloud provider tokens), and full outbound network connectivity. If the build pod runs with Kubernetes RBAC permissions that allow API server access — common in CI systems that inject kubeconfig for deployment steps — the RAT can also enumerate or modify cluster resources.

**Runtime surface.** If the build completed before the malicious package was pulled from the registry (i.e., the build ran before the attack window), the image is clean. But if the build ran during the window, the resulting image contains a compromised `node_modules` directory that will be baked into every container deployed from that image. If the `postinstall` script writes a persistent backdoor (a cron entry, a modified binary, a background process spawned at container start via `CMD` or `ENTRYPOINT` manipulation of the dependency), that backdoor runs again in every container deployed from the image. Additionally, clusters that mount `node_modules` as a writable volume or run `npm install` at container startup (a practice seen in development-in-cluster setups) re-execute `postinstall` at runtime, re-activating the RAT every time a pod starts.

The Axios attack also highlighted the transitive dependency problem. Packages that depend on Axios — there are thousands — pulled the malicious version automatically when resolving their own `package-lock.json` unless their lock file pinned the exact previous version. A project that had not run `npm install` in weeks had a stale lock file, and a fresh CI run resolved the newest-satisfying version, which was the malicious one.

Kubernetes-specific hardening for this threat class requires controls at three layers: the build pod's network access, the Dockerfile's npm invocation semantics, and the runtime container's filesystem permissions. Image signing with provenance attestation adds a verification layer that can catch images built without these controls before they reach production. Falco provides a last line of defence at runtime.

## Threat Model

- **Build pod with internet egress running `npm install`.** A malicious `postinstall` script executes during the build inside the build pod. The pod has internet egress to pull npm packages. The RAT uses this same egress to connect to a C2 server, exfiltrate environment variables (which may contain registry credentials, cloud tokens, or signing keys), and download a second-stage payload.

- **Container image built from a compromised npm install pushed to the registry.** The build completes and the image — now containing a trojaned `node_modules` — is pushed to the internal container registry. Every deployment of that image runs the compromised code. If the `postinstall` script modified a deeply nested dependency binary (rather than writing an obvious file), the compromise may not be visible in a simple `docker inspect`.

- **Runtime `node_modules` mutation.** In clusters where `node_modules` is mounted from a writable `PersistentVolume` or where the container start command runs `npm install` to pick up runtime dependency updates, the malicious `postinstall` runs at container start. This re-executes in every new pod, including pods started by autoscaling events.

- **Transitive dependency compromise.** The direct dependency `axios` is obvious to audit. Transitive dependencies — packages like `plain-crypto-js` that Axios itself depends on — are invisible to most teams. Sapphire Sleet's earlier campaigns compromised shallow transitive dependencies precisely because they receive less scrutiny. A `package-lock.json` with a known-good SHA is the only reliable check; `npm install` without a lockfile will re-resolve and can pull malicious transitive versions.

- **CI runner RBAC pivot.** Build pods in many clusters are created by a CI system (Tekton, Argo Workflows, GitHub Actions Runner Controller) that grants the build pod a Kubernetes ServiceAccount. If that ServiceAccount has `pods/exec` or `secrets/get` permissions — common in CI systems that inject kubeconfig for deployment steps — a RAT executing in the build pod can use the in-pod service account token to enumerate secrets, create new pods, or modify running deployments across the cluster.

- **Base image npm dependency compromise.** A node base image (`node:22-alpine`) itself includes npm and a bundled set of npm packages in its global `node_modules`. A supply chain compromise of a base image's bundled dependencies affects every Dockerfile that extends it, regardless of whether the application's own `npm install` ran clean.

## Hardening Configuration

### 1. Kyverno Policy: Enforce `--ignore-scripts` in Dockerfiles

The `--ignore-scripts` flag passed to `npm ci` or `npm install` prevents execution of `preinstall`, `install`, `postinstall`, and related lifecycle scripts. This is the single highest-value control for build-time supply chain attacks: it prevents a malicious `postinstall` from executing during the build regardless of which version of a package was resolved.

Kyverno cannot inspect Dockerfile contents after the fact by examining image layers — layer contents are not exposed through Kubernetes admission. The enforcement point is the build system. Kyverno's `verifyImages` rule can verify a cosign attestation that records whether `--ignore-scripts` was used during the build. The build system writes this as a custom attestation predicate, and Kyverno rejects images lacking that attestation.

The build system (kaniko job, Tekton Task, or Argo Workflows step) must be configured to:
1. Pass `--ignore-scripts` to all npm invocations in the Dockerfile.
2. Sign the resulting image with a cosign attestation that includes a `npmIgnoreScripts: true` field in the predicate.

The Kyverno policy then enforces the presence of that attestation:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-npm-ignore-scripts-attestation
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-npm-ignore-scripts
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "*"
          attestations:
            - predicateType: https://systemshardening.com/attestations/npm-build/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/your-org/*"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ npmIgnoreScripts }}"
                      operator: Equals
                      value: "true"
                    - key: "{{ packageLockSha }}"
                      operator: NotEquals
                      value: ""
```

The limitation of this approach is that it relies on the build system writing an honest attestation. The policy does not independently verify that the Dockerfile actually used `--ignore-scripts` — it verifies only that the build system claimed it did. This is acceptable in a trusted build environment but is not a substitute for a verified build provenance system (SLSA level 2+). At minimum, the Kyverno policy blocks images built outside the approved build system entirely, since those images will lack the attestation.

### 2. BuildKit Build Pod NetworkPolicy

Restricting build pod egress is the most direct mitigation for the RAT-phones-home attack. A `postinstall` RAT that cannot reach its C2 server during the build cannot exfiltrate credentials or download a second-stage payload, even if it executes.

The policy allows egress only to the npm registry IP ranges and the internal container registry. All other egress — including the attacker's C2 server — is dropped at the network layer.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: build-pod-restricted-egress
  namespace: ci-builds
spec:
  podSelector:
    matchLabels:
      app: buildkit
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 104.16.0.0/12
      ports:
        - port: 443
          protocol: TCP

    - to:
        - ipBlock:
            cidr: 172.64.0.0/13
      ports:
        - port: 443
          protocol: TCP

    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: registry
          podSelector:
            matchLabels:
              app: registry
      ports:
        - port: 5000
          protocol: TCP
        - port: 443
          protocol: TCP

    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

Apply the same policy with `app: kaniko` for kaniko build pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kaniko-pod-restricted-egress
  namespace: ci-builds
spec:
  podSelector:
    matchLabels:
      app: kaniko
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 104.16.0.0/12
      ports:
        - port: 443
          protocol: TCP
    - to:
        - ipBlock:
            cidr: 172.64.0.0/13
      ports:
        - port: 443
          protocol: TCP
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: registry
      ports:
        - port: 5000
          protocol: TCP
        - port: 443
          protocol: TCP
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### 3. Immutable `node_modules` in Runtime Containers

A read-only root filesystem prevents any runtime mutation of `node_modules`. Even if a container is deployed from an image that was built during the attack window (and thus contains a trojaned `node_modules`), a `postinstall` script cannot write new files, modify binaries, or install persistence mechanisms at runtime because the filesystem is immutable.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-app
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: your-registry.internal/node-app:1.2.3
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: app-logs
          mountPath: /app/logs
        - name: app-cache
          mountPath: /app/.cache
  volumes:
    - name: tmp
      emptyDir: {}
    - name: app-logs
      emptyDir: {}
    - name: app-cache
      emptyDir: {}
```

Critically, `node_modules` is not in the list of writable mounts. Any attempt to write to `/app/node_modules` at runtime will fail with `Read-only file system`. This also prevents a compromised container from using `node_modules` as a staging area to write a second-stage payload.

Enforce this via a Kyverno policy that rejects pods without `readOnlyRootFilesystem: true`:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-root-filesystem
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-readonly-rootfs
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - production
                - staging
      validate:
        message: "readOnlyRootFilesystem must be true for all containers"
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true
```

### 4. Image Signing and Provenance Verification

Sign every image at build time with a cosign attestation that records the `package-lock.json` SHA256 used during the build. This creates a verifiable chain: you can prove which exact dependency tree was installed, and you can detect if an image was built without a lockfile (which means npm was free to resolve newer — potentially malicious — versions).

At build time, record the lockfile hash and attach it as an attestation:

```bash
LOCK_SHA=$(sha256sum package-lock.json | awk '{print $1}')

cosign attest \
  --predicate - \
  --type https://systemshardening.com/attestations/npm-build/v1 \
  --key cosign.key \
  your-registry.internal/node-app:1.2.3 <<EOF
{
  "npmIgnoreScripts": "true",
  "packageLockSha": "${LOCK_SHA}",
  "buildTimestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "nodeVersion": "$(node --version)",
  "npmVersion": "$(npm --version)"
}
EOF
```

The Kyverno `verifyImages` policy (shown in section 1) then enforces that this attestation is present and signed with a trusted key before admitting the pod to the cluster. Any image built without a `package-lock.json` (where `packageLockSha` would be empty) is rejected at admission.

For keyless signing using Sigstore Fulcio in a GitHub Actions workflow:

```bash
cosign attest \
  --predicate npm-build-predicate.json \
  --type https://systemshardening.com/attestations/npm-build/v1 \
  --yes \
  your-registry.internal/node-app:${IMAGE_TAG}
```

The corresponding Kyverno policy for keyless verification:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-npm-provenance-attestation
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-npm-build-provenance
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - production
                - staging
      verifyImages:
        - imageReferences:
            - "your-registry.internal/*"
          attestations:
            - predicateType: https://systemshardening.com/attestations/npm-build/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/your-org/your-repo/.github/workflows/build.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ npmIgnoreScripts }}"
                      operator: Equals
                      value: "true"
                    - key: "{{ packageLockSha }}"
                      operator: NotEquals
                      value: ""
```

### 5. Falco Runtime Rule for Node Process Anomalies

Falco running as a DaemonSet provides runtime detection for unexpected network connections from Node.js processes. A compromised `postinstall` that evades the build-time controls and executes at runtime will typically make an outbound connection to a C2 server on a non-standard port or to an IP outside the application's expected egress range. The following Falco rule detects this:

```yaml
- rule: nodejs_unexpected_outbound_connection
  desc: >
    A node process inside a container opened a network connection to an
    address outside the approved CIDR list. This may indicate a compromised
    npm postinstall script making a C2 connection.
  condition: >
    spawned_process and
    container and
    proc.name in (node, nodejs) and
    fd.typechar = 4 and
    fd.ip != "0.0.0.0" and
    not fd.net in (
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "169.254.0.0/16"
    ) and
    not proc.pname in (node, nodejs, npm, sh)
  output: >
    Unexpected outbound connection from node process
    (user=%user.name container=%container.name image=%container.image.repository
    connection=%fd.name pid=%proc.pid cmdline=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
  tags:
    - supply-chain
    - nodejs
    - network
```

Deploy Falco as a DaemonSet using the official Helm chart, enabling the eBPF probe for kernel-level syscall visibility without requiring a kernel module:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/your-webhook" \
  --set-file customRules."nodejs-supply-chain\.yaml"=falco-nodejs-rules.yaml
```

The Falco rule above focuses on connections from `node` processes. A more sophisticated RAT that spawns `sh` to invoke `curl` will be caught by parent process ancestry rules (see Failure Modes below).

Add a complementary rule for filesystem writes to sensitive paths that no runtime container should write to:

```yaml
- rule: nodejs_write_to_node_modules
  desc: >
    A process wrote a file into node_modules at runtime. This is unexpected
    with a read-only root filesystem and may indicate a policy bypass or
    a compromised container attempting to install persistence.
  condition: >
    open_write and
    container and
    fd.name startswith "/app/node_modules/" and
    not proc.name in (npm, node)
  output: >
    Write to node_modules at runtime
    (user=%user.name file=%fd.name container=%container.name image=%container.image.repository)
  priority: WARNING
  tags:
    - supply-chain
    - nodejs
    - filesystem
```

## Expected Behaviour After Hardening

After the NetworkPolicy is applied to the build namespace, a `postinstall` RAT that executes during an `npm install` step inside the build pod attempts to open a TCP connection to its C2 server. The connection is dropped at the CNI layer — the pod's egress is restricted to npm registry CIDRs and the internal container registry. The RAT may still write files to the build filesystem and embed itself in the resulting image, but it cannot phone home to exfiltrate credentials or download a second-stage payload during the build.

After the read-only root filesystem is enforced on runtime pods, a container deployed from a compromised image attempts to execute a `postinstall` persistence mechanism. Any attempt to write to `/app/node_modules` or any path on the container root filesystem fails immediately with `Read-only file system`. The container process receives `EROFS` and cannot install a cron job, modify a binary, or write a new file. The RAT's execution ends here without persistence.

After the Falco rule is deployed, an unexpected outbound connection from a `node` process inside a container generates a `CRITICAL` alert within milliseconds of the connection attempt. The alert is forwarded to Slack (or PagerDuty, or the SIEM) via Falcosidekick. If Falco is configured with the `k8saudit` plugin and the `response_engine` integration, the pod can be automatically evicted on alert trigger.

After the Kyverno image signing policy is applied, a pod spec referencing an image built without a valid npm build provenance attestation is rejected at admission with a descriptive error. Images built outside the approved CI pipeline — or built during the attack window without `--ignore-scripts` — lack the attestation and cannot be deployed to `production` or `staging` namespaces.

## Trade-offs and Operational Considerations

**npm registry IP ranges change.** The build pod NetworkPolicy uses raw IP CIDRs for the npm registry. Cloudflare's IP ranges (used by registry.npmjs.org) are published but can change. Hard-coded CIDRs will break builds if Cloudflare reassigns IPs. The more maintainable approach is to route build pod egress through a DNS-resolving egress proxy (Squid or a purpose-built egress gateway) with an allowlist of hostnames (`registry.npmjs.org`, `registry.yarnpkg.com`, your internal registry hostname). The NetworkPolicy then needs only to permit egress to the proxy pod IP, and the proxy enforces hostname allowlisting in software. This eliminates the IP range maintenance problem entirely.

**Read-only root filesystem breaks many applications.** Node.js applications commonly write to paths under the container root: `/tmp` for scratch files, `~/.npm` for the npm cache, log files in `/app/logs` or the current directory, and session files. Each of these must be explicitly mapped to an `emptyDir` or `PersistentVolume` mount before enabling `readOnlyRootFilesystem: true`. The discovery phase — running the container, identifying all write paths via `strace` or `inotifywait`, then mapping each to a volume — takes time per application but is a one-time cost. Running without this in production means any runtime compromise can freely modify the container filesystem.

**Falco DaemonSet resource overhead.** A Falco DaemonSet with the eBPF driver adds approximately 100–200 MB of memory and 2–5% CPU overhead per node at moderate workload. On nodes running high-throughput Node.js applications that make many outbound connections (HTTP clients, database drivers), the `nodejs_unexpected_outbound_connection` rule requires careful tuning of the approved CIDR list to avoid alert fatigue. Start by running the rule in `output` mode (not enforcement mode) and reviewing alerts for a week before switching to a response action.

**`--ignore-scripts` breaks some legitimate packages.** A small number of npm packages use `postinstall` scripts for legitimate purposes: native module compilation (`node-gyp`), binary download (`esbuild`, `puppeteer`), or platform-specific setup. Running `npm ci --ignore-scripts` will break these. The correct response is not to remove `--ignore-scripts` globally but to explicitly re-run the required scripts for approved packages: `npm rebuild esbuild` after the install. Maintain a documented allowlist of packages whose post-install scripts are approved, and run only those scripts explicitly.

## Failure Modes

**Build pods using `hostNetwork: true` bypass NetworkPolicy.** Kubernetes NetworkPolicy applies to pods using the cluster network overlay. A build pod configured with `hostNetwork: true` — which gives it the host node's network namespace — is not subject to NetworkPolicy rules. A RAT running in such a pod has unrestricted access to all interfaces on the host node, including its default route to the internet. Audit build pod specs for `hostNetwork: true` and prohibit it via a Kyverno policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-network-in-build-pods
spec:
  validationFailureAction: Enforce
  rules:
    - name: no-host-network
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - ci-builds
      validate:
        message: "Build pods must not use hostNetwork"
        pattern:
          spec:
            hostNetwork: "false | null"
```

**Attestation verifies signing but not lockfile integrity.** The Kyverno `verifyImages` policy checks that a `packageLockSha` field is non-empty in the attestation predicate. It does not independently verify that the recorded SHA actually matches the `package-lock.json` in the repository at build time. A build system that is itself compromised could write an attestation with any SHA value and pass the check. This failure mode is addressed by SLSA provenance at level 3, where the provenance is generated by a hosted build platform that the developer cannot influence (e.g., GitHub-hosted Actions with OIDC token binding). Short of SLSA L3, treat the attestation as a signal that the build ran through the approved pipeline, not as a cryptographic proof of lockfile contents.

**Falco detects `node` process but RAT spawns `sh` then `curl`.** A `postinstall` script that spawns a shell subprocess defeats a Falco rule that matches on `proc.name in (node, nodejs)`. The network connection is opened by `sh` or `curl`, not by `node`. The fix is to match on the process ancestry chain: detect any container process making an outbound connection whose ancestor chain includes `node` or `npm`:

```yaml
- rule: nodejs_descendant_unexpected_outbound
  desc: >
    A process descended from node or npm opened an outbound connection to
    a non-cluster IP. Catches sh/curl spawned by postinstall scripts.
  condition: >
    spawned_process and
    container and
    fd.typechar = 4 and
    fd.ip != "0.0.0.0" and
    not fd.net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") and
    (proc.aname[2] in (node, npm) or proc.aname[3] in (node, npm))
  output: >
    Outbound connection from node/npm descendant process
    (proc=%proc.name parent=%proc.pname ancestor2=%proc.aname[2]
    connection=%fd.name container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags:
    - supply-chain
    - nodejs
```

**Image signing enforced but images in exempt namespaces are not covered.** Kyverno policies that scope to `production` and `staging` namespaces leave `development` and `qa` namespaces uncovered. A compromised image that enters through a development namespace can be promoted to production by a developer manually updating a production manifest. Extend the Kyverno policy to cover all namespaces, using `exclude` to omit only the `kube-system` namespace where cluster infrastructure images (which may be signed differently) run.

## Related Articles

- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Kyverno Policy Development](/articles/kubernetes/kyverno-policy-development/)
- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [Falco Runtime Security](/articles/kubernetes/falco-runtime-security/)
