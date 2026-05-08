---
title: "LMDeploy SSRF and IMDS Exfiltration: CVE-2026-33626 on GPU Inference Nodes"
description: "CVE-2026-33626 lets attackers send LMDeploy's image loader to fetch AWS IMDS credentials. Exploited within 12 hours of disclosure. Harden LMDeploy with URL validation, IMDSv2 enforcement, network egress restrictions, and GPU node isolation."
slug: lmdeploy-ssrf-imds-exfiltration
date: 2026-05-04
lastmod: 2026-05-04
category: ai-landscape
tags:
  - lmdeploy
  - ssrf
  - imds
  - inference-security
  - cve
personas:
  - platform-engineer
  - security-engineer
article_number: 444
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/lmdeploy-ssrf-imds-exfiltration/
---

# LMDeploy SSRF and IMDS Exfiltration: CVE-2026-33626 on GPU Inference Nodes

## The Problem

CVE-2026-33626 is a server-side request forgery vulnerability in LMDeploy's vision-language inference pipeline. CVSS 7.5 High. Published April 21, 2026. Fixed in LMDeploy 0.12.1. Affected versions are any LMDeploy release prior to 0.12.1 that loads a vision-language model with image URL support. LMDeploy is a high-performance inference framework for large language models developed by OpenMMLab, widely deployed on GPU-backed servers where it handles production multimodal inference at scale.

The vulnerability lives in a single function. LMDeploy's vision-language support accepts image URLs in inference requests and fetches them server-side before passing the image data to the GPU. The `load_image()` function in the multimodal preprocessing pipeline calls Python's `requests.get(url)` with the URL supplied directly by the API caller. There is no scheme validation, no hostname validation, and no check against RFC 1918 private address ranges or link-local ranges. Any URL that Python's `requests` library can resolve is fetched — including `http://169.254.169.254/`, the AWS Instance Metadata Service.

An attacker who can send an inference request to the LMDeploy API constructs the following payload:

```bash
curl -X POST http://lmdeploy-host:23333/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "InternVL2-8B",
    "messages": [{
      "role": "user",
      "content": [
        {
          "type": "image_url",
          "image_url": {
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/inference-node-role"
          }
        },
        {"type": "text", "text": "Describe this image."}
      ]
    }]
  }'
```

LMDeploy fetches the URL. The AWS IMDS returns a JSON document containing `AccessKeyId`, `SecretAccessKey`, and `Token` — the temporary credentials for the EC2 instance role. This response flows into the inference pipeline as image data. The model processes it and returns the credential JSON in its response to the attacker. The attacker reads the credentials from the model output.

Sysdig Threat Research documented real exploitation in the wild within 12 hours and 31 minutes of the CVE being published. Attackers followed a consistent pattern: they enumerated the IMDS metadata tree to discover the role name (at `/latest/meta-data/iam/security-credentials/`), then fetched the credentials for that role, then used those credentials to call S3 and EC2 APIs from attacker-controlled infrastructure. On several compromised nodes, attackers also used the SSRF for internal network enumeration — probing port combinations on RFC 1918 addresses accessible from the GPU subnet to discover Redis instances, internal APIs, and databases. The SSRF is not restricted to HTTP port 80; `requests.get()` follows any URL that resolves, and LMDeploy's error handling surfaces connection failures and partial responses in ways that allow port inference.

GPU inference nodes make high-value SSRF targets precisely because of what their instance roles are allowed to do. A GPU node that loads model weights from S3 needs `s3:GetObject` on a model bucket. A node that pulls container images needs `ecr:GetAuthorizationToken` and related ECR read permissions. A node that logs to CloudWatch needs `logs:PutLogEvents`. The combined scope of a real inference node role is typically broad enough that stolen credentials allow S3 bucket enumeration across the account, ECR image pulls for lateral movement, and EC2 API calls sufficient to spin up new instances.

This vulnerability is a specific instance of a recurring vulnerability class in ML and AI frameworks: any component that fetches arbitrary URLs on behalf of user-supplied input is a potential SSRF vector. The same pattern has appeared in other multimodal inference systems (including the earlier vLLM CVE-2026-22778 chain), in model registries that fetch external dataset URLs, and in training pipeline orchestrators that download data from user-specified endpoints. The SSRF-to-IMDS path is particularly reliable because the IMDS is always reachable from EC2 instances on the link-local address `169.254.169.254` — no special network path is required, and the endpoint requires no authentication in IMDSv1.

## Threat Model

**Attacker with API access.** LMDeploy's HTTP API (default port 23333) is the attack surface. The attacker needs one of two things: no authentication (LMDeploy has no built-in authentication and is frequently deployed without an authenticating proxy in internal environments), or a valid API token in organisations that deploy LMDeploy behind a token-authenticated API gateway. Any authorised API user — including users of applications built on top of LMDeploy — can trigger the SSRF.

**AWS IMDS credential theft.** The primary impact path: SSRF to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` returns temporary IAM credentials. The attacker uses those credentials from off-node infrastructure, out of band from the original SSRF. Derived impacts:

- S3 access to model weight buckets and training data stores
- ECR pull access to private container image registries
- EC2 API access enabling new instance creation (for cryptomining or further pivot) and instance metadata modification
- SageMaker and Bedrock API access if the role has ML service permissions
- CloudTrail, CloudWatch, and Secrets Manager access depending on role scope

**Internal network scanning.** The SSRF can target any IP address accessible from the GPU subnet. Attackers probe internal RFC 1918 ranges on ports for Redis (6379), MySQL (3306), PostgreSQL (5432), etcd (2379), Consul (8500), and internal REST APIs. Response timing differences and error messages from LMDeploy distinguish open from closed ports.

**Data exfiltration via internal endpoints.** Configuration endpoints, secrets management APIs (Vault, AWS Secrets Manager if accessible on a private endpoint), and internal model registries reachable on the VPC network can be targeted directly through the SSRF without going through the IMDS.

**Chain attack via stolen credentials.** Credentials stolen from one GPU inference node can be used to access other ML infrastructure in the same AWS account — SageMaker training jobs, Bedrock model invocations, EMR clusters processing training data, and other EC2 instances if the role includes `ec2:*` permissions. A single compromised inference node with a broad IAM role is a foothold into the entire ML platform.

## Hardening Configuration

### 1. Upgrade LMDeploy to 0.12.1

LMDeploy 0.12.1 adds allowlist validation to `load_image()`. Before issuing a request, the function checks the resolved IP address against RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the link-local range (`169.254.0.0/16`), and loopback (`127.0.0.0/8`). URLs that resolve to any of these ranges are rejected with a validation error before the HTTP request is made. The check occurs after DNS resolution, which prevents DNS rebinding attacks from bypassing a hostname-only check.

Verify the installed version:

```bash
pip show lmdeploy | grep Version
```

Upgrade to the patched release:

```bash
pip install "lmdeploy>=0.12.1"
```

For containerised deployments, pull the patched image and verify the package version inside the container before promoting it to the registry:

```bash
docker pull openmmlab/lmdeploy:v0.12.1-cu12
docker run --rm openmmlab/lmdeploy:v0.12.1-cu12 pip show lmdeploy | grep Version
```

Confirm no older version satisfies the constraint in the active environment — a dependency conflict can leave a vulnerable `lmdeploy` installed even when the upgrade command succeeds against a different Python environment:

```bash
pip install "lmdeploy>=0.12.1" --dry-run 2>&1 | grep -E "Would install|Requirement already"
```

### 2. Enforce IMDSv2 on GPU Instances

IMDSv2 requires a two-step process to obtain credentials: first, a PUT request to acquire a session token, then a GET request carrying that token in an `X-aws-ec2-metadata-token` header. A simple SSRF using a single GET request cannot obtain credentials when IMDSv2 is enforced because the IMDS returns a 401 response to any unauthenticated GET. The attacker's SSRF call to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns nothing useful.

Enforce IMDSv2 on existing GPU instances:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region us-east-1
```

The `--http-put-response-hop-limit 1` setting ensures that only processes running directly on the instance can obtain IMDS session tokens — a token acquired inside a container does not propagate to nested containers or the host network.

To enforce IMDSv2 across all running instances in an account:

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text \
  | tr '\t' '\n' \
  | xargs -I{} aws ec2 modify-instance-metadata-options \
      --instance-id {} \
      --http-tokens required \
      --http-put-response-hop-limit 1
```

Enforce IMDSv2 at instance launch time with Terraform:

```yaml
resource "aws_instance" "gpu_inference" {
  ami           = var.gpu_ami_id
  instance_type = "g5.xlarge"

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  iam_instance_profile = aws_iam_instance_profile.inference_node.name

  tags = {
    Name = "lmdeploy-inference-node"
    Role = "gpu-inference"
  }
}
```

Apply IMDSv2 enforcement as an AWS Service Control Policy at the organisation level to prevent new instances from launching without it:

```yaml
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
```

### 3. Kubernetes NetworkPolicy for GPU Inference Pods

A NetworkPolicy that explicitly denies egress to the link-local range and to internal networks beyond what inference pods require blocks IMDS access and internal network scanning at the kernel network layer, regardless of whether LMDeploy is patched. This is the most reliable defence-in-depth control because it operates outside the application and cannot be bypassed through the LMDeploy process.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lmdeploy-inference-egress
  namespace: inference
spec:
  podSelector:
    matchLabels:
      app: lmdeploy
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: api-gateway
          podSelector:
            matchLabels:
              app: envoy
      ports:
        - port: 23333
          protocol: TCP
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              - 169.254.0.0/16
              - 127.0.0.0/8
      ports:
        - port: 443
          protocol: TCP
        - port: 80
          protocol: TCP
```

This policy allows LMDeploy inference pods to fetch publicly-addressed image URLs (port 80 and 443) while blocking all egress to RFC 1918 ranges, link-local, and loopback. DNS resolution over UDP 53 to cluster DNS is permitted.

Verify the IMDS is unreachable from an inference pod after applying the policy:

```bash
kubectl exec -n inference deploy/lmdeploy -- \
  curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/
```

Expected: the connection times out. If the IMDS responds, the NetworkPolicy did not apply — check that the CNI plugin installed in the cluster enforces NetworkPolicy (Calico, Cilium, and Weave Net do; the default bridge CNI does not).

### 4. Least-Privilege IAM Role for GPU Inference Nodes

Scope the EC2 instance role to the minimum permissions the inference service actually needs. If a credential theft does occur, the attacker's scope is bounded by what the role is permitted to do. Remove `ec2:*`, `iam:*`, `s3:*` wildcards and replace them with resource-specific permissions.

An example IAM policy for an inference node that loads model weights from S3 and pulls container images from ECR:

```yaml
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ModelWeightAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-model-weights",
        "arn:aws:s3:::company-model-weights/*"
      ]
    },
    {
      "Sid": "ECRImagePull",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ECRRepositoryAccess",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:us-east-1:123456789012:repository/lmdeploy-inference"
    },
    {
      "Sid": "DenyDangerousActions",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "ec2:CreateVpc",
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

Audit the current instance role permissions before scoping them down — identify every AWS API call the inference service makes in production by reviewing CloudTrail logs:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=inference-node-role \
  --start-time "$(date -d '30 days ago' --iso-8601=seconds)" \
  --query 'Events[].{EventName: EventName, Time: EventTime}' \
  --output table | sort -u
```

Use only the actions that appear in that output when constructing the least-privilege policy.

### 5. Input URL Validation at the API Gateway

Deploy a reverse proxy in front of LMDeploy that inspects and rejects inference requests containing image URLs targeting private IP ranges before they reach the LMDeploy process. This is a defence-in-depth layer that blocks the exploit on unpatched LMDeploy versions and adds an independent validation point even on patched versions.

Nginx configuration with a Lua filter that validates `image_url` values:

```nginx
location /v1/chat/completions {
    access_by_lua_block {
        local body = ngx.req.get_body_data()
        if not body then
            ngx.req.read_body()
            body = ngx.req.get_body_data()
        end

        if body then
            local url = body:match('"image_url"%s*:%s*{%s*"url"%s*:%s*"([^"]+)"')
            if url then
                local private_patterns = {
                    "^https?://10%.",
                    "^https?://172%.[1-3][0-9]%.",
                    "^https?://192%.168%.",
                    "^https?://169%.254%.",
                    "^https?://127%.",
                    "^https?://localhost",
                    "^https?://0%.0%.0%.0",
                }
                for _, pattern in ipairs(private_patterns) do
                    if url:match(pattern) then
                        ngx.status = 400
                        ngx.header["Content-Type"] = "application/json"
                        ngx.say('{"error":{"message":"image_url targets a disallowed address range","type":"invalid_request_error"}}')
                        return ngx.exit(400)
                    end
                end
            end
        end
    }

    proxy_pass http://lmdeploy-backend:23333;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 300s;
    client_max_body_size 10m;
}
```

For Envoy deployments, an equivalent Lua filter can be attached to the HTTP connection manager. The pattern matching must cover hex-encoded IP addresses and potential bypasses via IPv6 representations — treat gateway-level validation as a best-effort layer, not a complete fix. The authoritative fix is the application-level validation in LMDeploy 0.12.1 combined with the NetworkPolicy egress block.

## Expected Behaviour After Hardening

**After upgrading to LMDeploy 0.12.1:** An inference request with `image_url` set to `http://169.254.169.254/latest/meta-data/iam/security-credentials/inference-node-role` returns a `400 Bad Request` response before any network connection is made. The `load_image()` function resolves the hostname, identifies `169.254.169.254` as falling within the `169.254.0.0/16` link-local block, and raises a validation error. The IMDS is never contacted. The error response contains no credential data and no indication of what exists at the target address.

**After IMDSv2 enforcement:** A SSRF request that reaches the IMDS despite other controls receives a `401 Unauthorized` response to its GET. Obtaining a session token requires a PUT request to `http://169.254.169.254/latest/api/token` with a `X-aws-ec2-metadata-token-ttl-seconds` header — a two-step flow that a simple URL-fetch SSRF cannot complete. The IMDS returns no credentials. The attacker receives an error response or a null body rather than the IAM credential JSON.

**After NetworkPolicy:** The SSRF request is refused at the kernel network layer before leaving the pod. The connection to `169.254.254.254` does not complete — the SYN packet is dropped by the CNI's eBPF or iptables rules enforcing the NetworkPolicy egress deny. This applies to both the IMDS address and all RFC 1918 ranges, blocking internal network scanning as well.

**After IAM role scoping:** If an attacker does exfiltrate credentials through a control gap, the credentials authorise only `s3:GetObject` on the model weight bucket and ECR image pulls. The attacker cannot create new EC2 instances, enumerate other S3 buckets, assume other IAM roles, or access Secrets Manager. The blast radius of a credential compromise is bounded to read access on specific resources.

## Trade-offs and Operational Considerations

IMDSv2 enforcement must be applied to all running GPU instances, not just new launches. Existing long-running inference nodes on IMDSv1 remain vulnerable after the Terraform change is applied — the launch template change only affects new instances. Retroactively applying IMDSv2 to running instances via `modify-instance-metadata-options` is safe and does not require a reboot, but it must be applied as an explicit remediation step across all regions and accounts. After a suspected SSRF event, rotate all credentials associated with the compromised instance role regardless of IMDSv2 status — tokens already issued before enforcement are valid until they expire.

NetworkPolicy egress denials require careful auditing before deployment. An inference pod may need to reach image CDN addresses, external model APIs, or object storage endpoints that happen to use private-range IP addresses on the cluster's network topology. Blocking the entire RFC 1918 range may break access to a local S3-compatible object store, an internal model registry, or a caching proxy. Map all required egress destinations for each inference workload before converting a permissive egress policy to an explicit allow-list. Run the policy in audit mode (using Cilium's policy verdict logging or a `warn` enforcement mode equivalent) for at least 48 hours before enforcing, and review the logs for denied connections that correspond to legitimate traffic.

IAM role scoping proportionally increases the effort required to onboard new models, new S3 buckets, or new ECR repositories, because each addition requires a policy update. Establish a process for IAM policy changes in the inference role — pull request review, CloudTrail-based auditing of policy updates, and automatic detection of policy changes that add `*` wildcards. The operational overhead is lower than the blast radius of a broad IAM role compromise.

## Failure Modes

**LMDeploy upgraded in the development environment but the container image in the production registry still contains 0.12.0.** The next deployment rolls out the old container image and reverts to the vulnerable version. The `pip show lmdeploy` check passes in the local environment but the production container continues serving vulnerable requests. Mitigation: verify the version inside the running container with `kubectl exec -n inference deploy/lmdeploy -- pip show lmdeploy | grep Version` after every deployment, and fail deployments where the version check does not meet the minimum.

**IMDSv2 enforced on new instances but existing GPU instances running for weeks or months not updated.** Nodes launched before the Terraform change applies IMDSv1 and remain so until they are replaced. SSRF against these nodes still retrieves credentials via a simple GET. Mitigation: enumerate instances with IMDSv1 enabled and apply `modify-instance-metadata-options` to each, or schedule a rolling replacement of all GPU nodes during the next maintenance window.

**NetworkPolicy blocks IMDS but allows the VPC CIDR.** The egress deny covers `169.254.0.0/16` but not RFC 1918 ranges. An attacker uses the SSRF to probe and access internal services — Redis, etcd, internal APIs — accessible from the GPU subnet on the VPC CIDR range. Internal services reachable by the inference pod can be enumerated and queried through the SSRF even when the IMDS is blocked. Mitigation: deny egress to all RFC 1918 ranges in the NetworkPolicy, not only the link-local range, and maintain a specific allow-list of required internal egress destinations.

**Gateway URL validation bypassed via DNS rebinding.** An attacker registers a domain that initially resolves to a public IP (passing the gateway check) and then changes the DNS record to `169.254.169.254` after the gateway validates but before LMDeploy resolves. This bypass is addressed by LMDeploy 0.12.1's post-resolution IP check, but not by a gateway-level hostname-only check. Gateway validation is not a substitute for the application-layer fix.

## Related Articles

- [Inference Endpoint Hardening](/articles/kubernetes/inference-endpoint-hardening/)
- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [vLLM Multimodal RCE Security](/articles/ai-landscape/vllm-multimodal-rce-security/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
