---
title: "Kubernetes Incident Response for npm Supply Chain Compromises"
description: "If your K8s cluster built or ran containers during the Axios attack window, you need a playbook. Scope affected pods via image provenance, identify exposed credentials, rotate secrets cluster-wide, and use network logs to determine if the RAT reached C2."
slug: kubernetes-supply-chain-incident-response
date: 2026-05-04
lastmod: 2026-05-04
category: kubernetes
tags:
  - supply-chain
  - npm
  - incident-response
  - secrets-rotation
  - forensics
personas:
  - security-engineer
  - platform-engineer
article_number: 424
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-supply-chain-incident-response/
---

# Kubernetes Incident Response for npm Supply Chain Compromises

## The Problem

When the Axios compromise was announced on March 31 2026, every organisation running Node.js in Kubernetes faced the same question: were any of our builds or deployments affected? Answering it required correlating build timestamps against the ~3-hour attack window (2026-03-31 00:00–03:00 UTC), inspecting deployed image manifests for the compromised package version, and determining what credentials the RAT could have accessed — environment variables injected into pods (database passwords, API keys, cloud credentials mounted as Kubernetes Secrets). The challenge in Kubernetes is scale: a large cluster may have hundreds of Deployments, many built by different teams at different times, with no centralised record of which npm packages were installed during which build. The IR playbook must be systematic: start from the known attack window, work backwards through image build history, identify affected images, then scope credential exposure.

The Axios RAT, attributed to North Korean threat actor Sapphire Sleet, ran during the `postinstall` hook of the npm install lifecycle. In a Kubernetes CI context this means the malicious code executed inside the build pod — not the runtime container — but if the build completed without detection and the image was pushed to the registry, every pod deployed from that image carries a trojaned `node_modules`. The RAT established outbound connections to command-and-control infrastructure on TCP/443, attempted to read environment variables, and wrote a persistence stub. For pods that were running during the attack window and whose images were pulled directly from npm during a layer cache miss, there is a further question: did the running container re-execute `npm install` at startup (a pattern common in development-facing services)?

The IR task has four phases: scope (which images are affected), credential exposure (what did those pods have access to), rotation (invalidate and replace all exposed credentials), and forensics (determine whether any C2 contact occurred and what commands were issued). Kubernetes provides the APIs to answer all four questions systematically; the challenge is that most teams have not wired them together before an incident. This playbook does that wiring.

## Threat Model

- Container images built during 2026-03-31 00:00–03:00 UTC containing `axios@1.14.1` or `axios@0.30.0`, where the `postinstall` hook executed during the `npm install` step inside the build pod and embedded the RAT in the image's `node_modules` layer
- Running pods from those images with environment variables containing Kubernetes Secret values that the RAT could have exfiltrated — database passwords, API keys, OIDC client secrets, cloud provider credentials injected via `envFrom` or `env` secret references
- CI service account tokens mounted in build pods (the default `automountServiceAccountToken: true` behaviour means nearly every build pod receives a token in `/var/run/secrets/kubernetes.io/serviceaccount/token`); a stolen build pod service account token gives the attacker `kubectl`-equivalent access at whatever RBAC scope the CI ServiceAccount holds
- Registry credentials (`imagePullSecrets`) in build pod environments — `DOCKER_USERNAME`, `DOCKER_PASSWORD`, or a `~/.docker/config.json` mounted from a Secret; stolen registry credentials allow the attacker to push malicious images to the internal registry, which is a persistent foothold that survives pod restarts and image rotations
- Lateral movement: the RAT payload attempting to establish persistence in the container by writing to `node_modules` or modifying the entrypoint, surviving pod restarts if the image is not rebuilt and redeployed from a clean source

## Hardening Configuration

### Step 1: Identify the Attack Window and Scope Affected Builds

The attack window is 2026-03-31 00:00–03:00 UTC. Every CI build that ran `npm install` during this window is a candidate for compromise. Start with the CI system's build API before touching the cluster — you need timestamps and image references.

For GitHub Actions, query the workflow runs API for the affected window:

```bash
gh api \
  "/repos/YOUR-ORG/YOUR-REPO/actions/runs?created=2026-03-31T00:00:00Z..2026-03-31T03:00:00Z&status=completed" \
  --jq '.workflow_runs[] | {id: .id, name: .name, conclusion: .conclusion, created_at: .created_at, head_sha: .head_sha}'
```

For Tekton, query PipelineRuns by start time:

```bash
kubectl get pipelineruns -A -o json | jq '
  .items[] |
  select(
    .status.startTime >= "2026-03-31T00:00:00Z" and
    .status.startTime <= "2026-03-31T03:00:00Z"
  ) |
  {
    namespace: .metadata.namespace,
    name: .metadata.name,
    startTime: .status.startTime,
    completionTime: .status.completionTime,
    params: .spec.params
  }
'
```

Cross-reference build output with image registry push timestamps. For a registry exposing a Docker HTTP API:

```bash
crane ls your-registry.internal/node-app | while read tag; do
  digest=$(crane digest your-registry.internal/node-app:"$tag" 2>/dev/null)
  created=$(crane config your-registry.internal/node-app:"$tag" 2>/dev/null | jq -r '.created')
  echo "$tag $digest $created"
done | awk '$3 >= "2026-03-31T00:00:00Z" && $3 <= "2026-03-31T03:00:00Z"'
```

This produces a list of image tags pushed during the attack window. These are your candidates for SBOM inspection.

### Step 2: Inspect Deployed Images for Compromised Package Versions

With the candidate image list from step 1, determine which of those images are currently deployed in the cluster, and which contain `axios@1.14.1` or `axios@0.30.0`.

Extract all image references currently running in the cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  {
    namespace: .metadata.namespace,
    pod: .metadata.name,
    images: [.spec.containers[].image]
  } |
  .namespace + " " + .pod + " " + (.images | join(","))
' > /tmp/running-images.txt
```

Cross-reference with the attack-window image list to find pods running images built during the window:

```bash
while read namespace pod images; do
  for image in $(echo "$images" | tr ',' '\n'); do
    digest=$(crane digest "$image" 2>/dev/null)
    if grep -q "$digest" /tmp/attack-window-digests.txt 2>/dev/null; then
      echo "AFFECTED: $namespace/$pod image=$image digest=$digest"
    fi
  done
done < /tmp/running-images.txt
```

For each candidate image, run `syft` to generate a software bill of materials and check for the malicious package versions:

```bash
syft your-registry.internal/node-app:v1.14.1-build-20260331T0137 \
  -o json | jq '
  .artifacts[] |
  select(.name == "axios" or .name == "plain-crypto-js") |
  {name: .name, version: .version, type: .type}
'
```

If the image is large and you want to avoid a full pull, use `crane` to inspect only the `node_modules` layer manifest and fetch the layer containing `package-lock.json`:

```bash
crane export your-registry.internal/node-app:suspect-tag - | \
  tar -x --to-stdout app/package-lock.json 2>/dev/null | \
  jq '.packages["node_modules/axios"].version'
```

A result of `1.14.1` or `0.30.0` confirms the image is compromised. Record the full list of confirmed-affected image digests.

### Step 3: Determine Credential Exposure Scope

For every pod running a confirmed-affected image, enumerate all Kubernetes Secrets that were projected into the pod's environment at the time the pod started. This is the authoritative list of credentials that must be rotated.

List environment variable secret references for each affected pod:

```bash
kubectl get pod AFFECTED-POD -n NAMESPACE -o json | jq '
  .spec.containers[] |
  {
    container: .name,
    secretEnvVars: [
      .env[]? |
      select(.valueFrom.secretKeyRef != null) |
      {
        envVar: .name,
        secret: .valueFrom.secretKeyRef.name,
        key: .valueFrom.secretKeyRef.key
      }
    ],
    secretEnvFrom: [
      .envFrom[]? |
      select(.secretRef != null) |
      .secretRef.name
    ]
  }
'
```

List volume-mounted secrets:

```bash
kubectl get pod AFFECTED-POD -n NAMESPACE -o json | jq '
  .spec.volumes[]? |
  select(.secret != null) |
  {volumeName: .name, secretName: .secret.secretName}
'
```

Produce a rotation checklist from all affected pods with a script:

```bash
#!/bin/bash
AFFECTED_PODS="$1"

echo "Secret Rotation Checklist — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > /tmp/rotation-checklist.txt
echo "=================================================" >> /tmp/rotation-checklist.txt

while IFS=' ' read -r namespace pod; do
  echo "" >> /tmp/rotation-checklist.txt
  echo "Pod: $namespace/$pod" >> /tmp/rotation-checklist.txt

  kubectl get pod "$pod" -n "$namespace" -o json | jq -r '
    .spec.containers[] |
    (.env[]? | select(.valueFrom.secretKeyRef != null) |
      "  ENV \(.name) <- secret/\(.valueFrom.secretKeyRef.name)[\(.valueFrom.secretKeyRef.key)]"),
    (.envFrom[]? | select(.secretRef != null) |
      "  ENVFROM <- secret/\(.secretRef.name) (all keys)"),
    (.volumeMounts[]? | "  MOUNT \(.mountPath)")
  ' 2>/dev/null >> /tmp/rotation-checklist.txt

  kubectl get pod "$pod" -n "$namespace" -o json | jq -r '
    .spec.volumes[]? |
    select(.secret != null) |
    "  VOLUME secret/\(.secret.secretName)"
  ' 2>/dev/null >> /tmp/rotation-checklist.txt

done < "$AFFECTED_PODS"

echo "" >> /tmp/rotation-checklist.txt
echo "Total secrets requiring rotation: $(grep -c 'secret/' /tmp/rotation-checklist.txt)" >> /tmp/rotation-checklist.txt
cat /tmp/rotation-checklist.txt
```

Also explicitly check for service account tokens — every pod that ran with the default `automountServiceAccountToken: true` had a valid cluster token accessible at `/var/run/secrets/kubernetes.io/serviceaccount/token`. List all ServiceAccounts used by affected pods:

```bash
kubectl get pod AFFECTED-POD -n NAMESPACE \
  -o jsonpath='{.spec.serviceAccountName}'
```

Treat every ServiceAccount used by an affected pod as potentially compromised. The token is a long-lived JWT that must be invalidated by deleting and recreating the ServiceAccount, or by rotating the cluster's signing key (the latter is a larger operation requiring cluster-level coordination).

### Step 4: Rotate Affected Secrets

Rotate in dependency order: most-privileged credentials first. Cloud IAM keys and registry credentials take priority because their compromise enables broader attack surface. Database passwords and API keys follow.

For each secret in the rotation checklist:

1. Rotate the underlying credential in the upstream system (AWS IAM, GitHub, database, etc.)
2. Update the Kubernetes Secret object with the new value:

```bash
kubectl create secret generic my-api-credentials \
  --from-literal=API_KEY="NEW-ROTATED-VALUE" \
  --dry-run=client -o yaml | kubectl apply -f -
```

3. Trigger a rolling restart of every Deployment that references the secret:

```bash
kubectl rollout restart deployment/my-api-service -n production
kubectl rollout status deployment/my-api-service -n production --timeout=300s
```

For secrets referenced by many Deployments, script the rolling restart across namespaces:

```bash
SECRET_NAME="my-api-credentials"

kubectl get deployments -A -o json | jq -r '
  .items[] |
  select(
    (.spec.template.spec.containers[].env[]? |
     .valueFrom.secretKeyRef.name == "'"$SECRET_NAME"'") or
    (.spec.template.spec.containers[].envFrom[]? |
     .secretRef.name == "'"$SECRET_NAME"'")
  ) |
  .metadata.namespace + " " + .metadata.name
' | while IFS=' ' read -r namespace deployment; do
  echo "Restarting $namespace/$deployment"
  kubectl rollout restart deployment/"$deployment" -n "$namespace"
  kubectl rollout status deployment/"$deployment" -n "$namespace" --timeout=600s
done
```

For CI service account tokens: delete the Kubernetes ServiceAccount (which revokes all issued tokens) and recreate it with the same name and RBAC bindings:

```bash
kubectl get serviceaccount ci-build-sa -n ci-builds -o yaml > /tmp/ci-build-sa-backup.yaml
kubectl delete serviceaccount ci-build-sa -n ci-builds
kubectl create serviceaccount ci-build-sa -n ci-builds
```

For `imagePullSecrets` that may have been exposed: rotate the registry credentials in the registry's admin interface, then update the corresponding Kubernetes Secret and the ServiceAccount's `imagePullSecrets` reference. Any node that cached the old credentials will use the cached value until the kubelet refreshes; force a credential cache flush by restarting the kubelet on affected nodes or draining and cycling nodes.

### Step 5: Network Forensics to Determine C2 Contact

The critical question for incident severity classification is whether any affected pod successfully established a connection to the Axios RAT's C2 infrastructure. CISA and Microsoft published IOC lists containing the confirmed C2 IP addresses and domains within hours of the attack announcement. Check these against your network flow logs.

With Cilium Hubble, query outbound flows from affected pod namespaces during the attack window:

```bash
hubble observe \
  --namespace production \
  --since "2026-03-31T00:00:00Z" \
  --until "2026-03-31T06:00:00Z" \
  --verdict FORWARDED \
  --type l3-l4 \
  --output json | jq '
  select(
    .destination.identity == 2 or
    (.IP.destination | test("^(185\\.220\\.|45\\.153\\.|194\\.165\\.)"))
  ) |
  {
    time: .time,
    source_pod: .source.pod_name,
    source_namespace: .source.namespace,
    dest_ip: .IP.destination,
    dest_port: .l4.TCP.destination_port
  }
'
```

Replace the IP prefix patterns with the actual C2 CIDRs from the CISA advisory for the Axios incident.

If Hubble is not available, check VPC flow logs (for cloud-hosted clusters). For EKS with VPC flow logs in CloudWatch Logs:

```bash
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs/your-vpc" \
  --start-time $(date -d "2026-03-31T00:00:00Z" +%s000) \
  --end-time $(date -d "2026-03-31T06:00:00Z" +%s000) \
  --filter-pattern "ACCEPT 185.220" \
  --query 'events[*].message' \
  --output text
```

For CNI-level flow logs from Calico or Cilium's flow exporter, the query pattern is equivalent: filter by destination IP matching the C2 IOC list, source IP matching affected pod CIDR ranges, and the attack window timestamp range.

Interpret results:

- No outbound connections to C2 IPs: the RAT deployed but could not phone home. If NetworkPolicy was in place blocking egress to non-allowlisted destinations, this is the expected result. Severity remains high (a compromised image ran) but active exploitation is not confirmed.
- Outbound connections from affected pods to C2 IPs but no response (REJECT/DROP): the RAT attempted contact but was blocked by an upstream firewall or the C2 was already taken down. Treat as near-miss — still rotate all credentials.
- Confirmed bidirectional flows to C2 IPs: the RAT successfully phoned home. The attacker received at least one beacon and may have issued commands. This escalates to a full compromise response: assume all credentials in affected pods were exfiltrated, assume the attacker has the build pod service account token, and initiate a full cluster credential rotation including the API server's service account signing key.

### Step 6: Replace Affected Images and Verify Clean State

Rebuild all affected images from a clean base, with `axios` pinned to `1.14.0` (the last known-good version) in `package.json` and `package-lock.json`:

```bash
npm install axios@1.14.0 --save-exact
npm ci --ignore-scripts
```

Verify the rebuilt image's SBOM shows no compromised packages before deploying:

```bash
syft your-registry.internal/node-app:clean-rebuild -o json | jq '
  .artifacts[] |
  select(.name == "axios" or .name == "plain-crypto-js")
'
```

The output should show only `axios@1.14.0` with no `plain-crypto-js` entry.

Verify the image was signed with a valid provenance attestation from the clean build:

```bash
cosign verify-attestation \
  --type https://systemshardening.com/attestations/npm-build/v1 \
  --key cosign.pub \
  your-registry.internal/node-app:clean-rebuild | \
  jq '.payload | @base64d | fromjson | .predicate'
```

The predicate should show `npmIgnoreScripts: true` and a `buildTimestamp` outside the attack window. Deploy the verified clean image:

```bash
kubectl set image deployment/my-api-service \
  app=your-registry.internal/node-app:clean-rebuild \
  -n production

kubectl rollout status deployment/my-api-service -n production
```

After the rollout completes, confirm no pods are running the compromised image digest:

```bash
COMPROMISED_DIGEST="sha256:abc123..."

kubectl get pods -A -o json | jq -r '
  .items[] |
  select(
    .status.containerStatuses[]?.imageID |
    contains("'"$COMPROMISED_DIGEST"'")
  ) |
  .metadata.namespace + "/" + .metadata.name
'
```

An empty result confirms no pods remain on the compromised image.

## Expected Behaviour After Hardening

After completing the scoping phase, the playbook produces a list of images built during the attack window. In a representative cluster, 3 images are flagged by the registry timestamp query; SBOM inspection with `syft` confirms 2 contain `axios@1.14.1`. The third image was built in the final minutes of the window before the npm registry reverted the malicious version and pulled a clean resolution. The credential rotation checklist identifies 11 Kubernetes Secrets across 4 namespaces that were referenced by the 2 affected Deployments.

After credential rotation, all 11 secrets have been rotated at the source system and updated as Kubernetes Secret objects. The rolling restart of the 2 affected Deployments completes within 35 minutes of the rotation beginning, well inside the 4-hour SLA. A follow-up check confirms no pods retain the old secret values in their environment by inspecting the `env` output from a `kubectl exec` against one of the new pods.

After network forensics, Hubble flow logs for the production namespace during the attack window show zero outbound connections from the 2 affected Deployments to any IP in the CISA IOC list. The egress NetworkPolicy restricting production pods to cluster-internal destinations and approved API endpoints was in place at the time of deployment. The RAT deployed but could not phone home. Incident severity is downgraded from active compromise to contained supply chain delivery, and the post-incident action items focus on preventive controls rather than breach response.

## Trade-offs and Operational Considerations

SBOM-based image scanning requires SBOMs to exist at the time of the incident. If images were built without SBOM attestations, the fallback is `syft` layer inspection of images pulled from the registry. `syft` can generate an SBOM from an image by pulling and inspecting all layers, but this is significantly slower — 2–5 minutes per image versus milliseconds for a pre-attached SBOM — and requires pulling full image archives. For a cluster with 50 Node.js images, the inspection phase alone takes hours. The operational lesson is to attach SBOMs at build time as part of the CI pipeline; the cost is negligible and the IR value is high.

Rotating secrets for dozens of services requires coordination with service owners. Not all secrets belong to the platform team: an API key for a third-party payment processor may require manual rotation through a vendor portal with a different team's credentials. Establish a 4-hour SLA for rotation from the moment of compromise confirmation, with named DRIs per service. Without pre-established ownership, the rotation phase can stall on a single credential while the clock runs and attacker dwell time increases.

Network flow log retention at 24 hours — common in cost-optimised cloud deployments — means that by the time an incident is detected and the playbook is invoked, the flow logs covering the attack window may already have been deleted. The Axios attack window closed at 03:00 UTC; if your team is first notified 30 hours after the event, a 24-hour retention policy means the forensics window is gone. Increase flow log retention to 30 days at minimum, and ensure the storage cost (typically small relative to the forensic value) is justified to finance leadership before an incident, not during one.

## Failure Modes

Scoping that only looks at currently-running pods misses images that were built during the attack window, pushed to the registry, but never deployed — or deployed and then scaled to zero. These images are dormant threats: a future deployment from the registry would spin up compromised pods. Always scan the registry directly for all images tagged within the attack window, not only the pods that `kubectl get pods -A` returns at the moment of the investigation.

Secrets that are rotated at the source but whose corresponding Kubernetes Secret objects are not updated leave the old credential value in the cluster's etcd. Pods that are then not restarted continue to hold the old (now-invalid) credential in their environment for the lifetime of the pod, and if the pod is restarted it reads the new value from the updated Secret — but a pod that never restarts because it is a long-running StatefulSet may retain the old value for days. The playbook's rolling restart step is mandatory, not optional, even if the application appears to be functioning normally.

C2 contact confirmed in flow logs but classified as low severity because the affected pod was in a development or staging namespace requires correction. Any successful C2 contact — regardless of environment — means the attacker received a beacon containing pod environment variables. Development pods often hold production-equivalent API keys for integration testing. Treat any confirmed C2 contact as a full credential exposure event for all secrets in the affected pod, regardless of which namespace the pod ran in.

The CI service account token exposure path is frequently underestimated. A compromised build pod's ServiceAccount may have been granted RBAC permissions to deploy to production namespaces as part of a GitOps or CD workflow. If that token was exfiltrated, the attacker has a valid Kubernetes API credential that is not a Kubernetes Secret and does not appear in the rotation checklist produced by step 3. Explicitly audit build pod ServiceAccount RBAC bindings as part of every supply chain IR and rotate ServiceAccounts (delete and recreate) for all build pods that ran during the attack window.

## Related Articles

- [Kubernetes npm Supply Chain Defence](/articles/kubernetes/kubernetes-npm-supply-chain-defence/)
- [Secrets Management](/articles/kubernetes/secrets-management/)
- [SBOM Supply Chain Compromise Detection](/articles/observability/sbom-supply-chain-compromise-detection/)
- [Velero Backup Security](/articles/kubernetes/velero-backup-security/)
- [Audit Log Analysis](/articles/kubernetes/audit-log-analysis/)
