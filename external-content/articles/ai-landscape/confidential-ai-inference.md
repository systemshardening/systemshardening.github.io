---
title: "Confidential AI Inference: Protecting Model Weights and User Data with TEEs"
description: "Cloud providers, hypervisors, and privileged insiders can observe model weights and every inference query. Trusted Execution Environments — Intel TDX, AMD SEV-SNP, Nvidia H100 confidential computing — move the trust boundary to hardware attestation."
slug: confidential-ai-inference
date: 2026-05-07
lastmod: 2026-05-07
category: ai-landscape
tags:
  - confidential-computing
  - tee
  - intel-tdx
  - amd-sev
  - model-privacy
personas:
  - security-engineer
  - platform-engineer
article_number: 465
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/ai-landscape/confidential-ai-inference/
---

# Confidential AI Inference: Protecting Model Weights and User Data with TEEs

## The Problem

When you deploy a language model to a cloud provider, you are making a trust decision that most organisations do not examine carefully: you are trusting the provider's entire software stack — hypervisor, host OS, management plane, and every privileged employee with console access — with both your model weights and every query that users send to your inference endpoint.

The model weights represent months of GPU compute and proprietary training data. A 70B-parameter model checkpoint is roughly 140 GB of floating-point values that can be copied to an external bucket in minutes by anyone with appropriate cloud credentials. The inference queries are frequently more sensitive still: healthcare providers run patient-facing triage tools, financial institutions route transaction data through fraud detection models, legal teams submit privileged documents for analysis. In every case the plaintext of every query passes through infrastructure the organisation does not control.

The attack surface is not theoretical. In 2023 and 2024, multiple cloud providers experienced incidents where privileged internal access to customer compute resources was abused. In the AI context the incentives are compounding: stolen model weights are immediately monetisable — a stolen checkpoint can be deployed at near-zero marginal cost. Stolen inference logs contain a continuous stream of the most sensitive queries an organisation's users ask. Neither class of data is visible in conventional SIEM or DLP deployments that monitor network traffic, because the exposure is architectural: the cloud hypervisor can read any guest memory at any time.

Confidential computing addresses this by moving sensitive computation inside a hardware-isolated Trusted Execution Environment whose memory is encrypted with keys that the CPU generates and holds. The cloud provider's hypervisor, host kernel, and management software cannot read the plaintext content of a confidential VM or enclave, even with root access to the physical host. The isolation guarantee is enforced in silicon, not software.

For AI inference the implication is direct: model weights loaded inside a TEE are encrypted at rest and in the enclave's memory pages. User queries arrive over attested TLS channels, are processed inside the isolated environment, and responses leave without the provider stack ever seeing the plaintext.

The gap in most current deployments:

- Models are loaded from object storage into standard VM memory that the hypervisor can read.
- Inference servers accept requests over TLS that terminates at a load balancer controlled by the provider, not the model operator.
- No attestation exists — the client has no way to verify which code is processing their request.
- Model weights are encrypted at rest in object storage but are decrypted into plaintext before loading, in a context the provider controls.
- GPU memory on standard instances is accessible to the hypervisor layer.

**Target systems:** Intel TDX (4th Gen Xeon Scalable and later); AMD SEV-SNP (EPYC 3rd Gen and later); Nvidia H100/H200 with Confidential Computing mode; AWS Nitro Enclaves; Azure Confidential VMs (DCasv5/ECasv5 series); GKE Confidential Nodes; Kata Containers 3.x with confidential VM backing; gramine-ratls for SGX-based enclaves; NVIDIA CCCL for GPU confidential workloads.

## Threat Model

- **Adversary 1 — Privileged cloud insider:** A cloud provider employee with hypervisor or management plane access reads guest VM memory to extract model weights or inference logs. Motivation: IP theft, competitive intelligence, or sale on underground markets.
- **Adversary 2 — Compromised hypervisor:** An attacker exploits a hypervisor vulnerability (VM escape) from a co-tenant VM and gains host-level access. From the host, all guest VM memory is readable without TEE protection.
- **Adversary 3 — Rogue co-tenant:** In a multi-tenant inference deployment, a co-tenant achieves side-channel access to another tenant's model weights via cache timing attacks (Flush+Reload, Prime+Probe) if isolation is insufficient.
- **Adversary 4 — Supply chain attacker in the inference stack:** A malicious dependency or compromised container image in the inference serving pipeline exfiltrates weights or logs before they enter the TEE boundary.
- **Adversary 5 — Management plane credential theft:** Cloud credentials with sufficient IAM permissions allow an attacker to snapshot the inference VM disk or memory, extracting weights and decryption keys from a running instance.
- **Access level:** Adversaries 1 and 5 operate at the cloud control plane. Adversary 2 operates at hypervisor level after an initial exploit. Adversary 3 operates from a co-tenant compute context. Adversary 4 operates inside the software supply chain before deployment.
- **Objective:** Obtain plaintext model weights, capture inference request/response pairs, or forge attestation to route queries to a malicious inference server.
- **Blast radius without TEEs:** Every query ever processed by the inference deployment is observable; weights can be exfiltrated by anyone with hypervisor access; there is no technical control preventing the provider from reading model or query data. With TEEs and attestation: the blast radius is bounded to the hardware TCB and the integrity of the attestation chain; the provider stack cannot read protected memory.

## TEE Technologies for AI Inference

The four platforms relevant to production AI inference differ in their isolation model, memory capacity, and GPU support.

### Intel TDX (Trust Domain Extensions)

TDX is Intel's VM-level confidential computing architecture, available on 4th Gen (Sapphire Rapids) and later Xeon processors. A TDX-protected VM is called a Trust Domain (TD). The TD's memory is encrypted using AES-128-XTS with keys generated by and stored inside the CPU. The hypervisor cannot read TD memory even with root access to the host kernel.

The TDX TCB (Trusted Computing Base) consists only of the CPU firmware and the TD's own software. The hypervisor is explicitly outside the TCB — it can manage the TD (schedule, migrate, resize) but cannot read its memory.

TDX attestation produces a TD Quote: a signed measurement of the TD's initial memory state, signed by Intel's Attestation Service. A client can verify the Quote before sending data to verify that the expected firmware and kernel image is running inside the TD.

Memory capacity is limited only by the physical DRAM on the host — a practical advantage over older SGX, which was limited to 512 MB of EPC (Encrypted Page Cache). A TDX TD can use the full host memory, making it suitable for loading large language model weights (70B+ parameters require 140+ GB).

### AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging)

SEV-SNP is AMD's equivalent on EPYC 3rd Gen (Milan) and later processors. Like TDX, it encrypts VM memory with per-VM keys generated by the AMD Secure Processor. SNP adds integrity protection over SEV-ES: it uses a Reverse Map Table (RMap) to prevent hypervisor remapping attacks and detect memory tampering.

SEV-SNP attestation produces a SNP Report containing the VM's measurement and platform state, signed by the AMD Root Key. The attestation chain goes through AMD's Key Distribution Service (KDS).

In Azure, the DCasv5/ECasv5 series run on AMD EPYC with SEV-SNP. In GCP, N2D Confidential VMs use SEV. Both platforms expose the attestation report to code running inside the confidential VM.

### Nvidia H100/H200 Confidential Computing

Starting with the H100 (Hopper architecture), Nvidia added hardware support for GPU Confidential Computing mode. In this mode, the GPU's HBM memory is encrypted with keys held inside the GPU's security processor. The CPU-side hypervisor cannot read GPU memory. PCIe bus traffic between the CPU and GPU is encrypted.

When a TDX or SEV-SNP VM attaches an H100 in confidential mode, the GPU produces its own attestation report that can be chained with the CPU TEE attestation. The combined attestation covers both the CPU and GPU execution environments, verifying that the full inference pipeline — from weight loading on the GPU to output generation — ran inside a protected environment.

This is critical for LLM inference: transformer models run almost entirely on GPU. A CPU-only TEE that protects the host VM but allows the GPU to operate in standard mode leaves the bulk of model computation visible to the hypervisor through the PCIe bus and GPU memory interfaces.

H100 Confidential Computing is available on Azure NC H100 v5 series and GCP A3 Confidential instances as of early 2026.

### AWS Nitro Enclaves

Nitro Enclaves are a different model: isolated compute environments created from EC2 instance resources (vCPUs and memory), connected to the parent EC2 instance only via a local vsock. The enclave has no network interface, no storage, and no persistent identity — it cannot be accessed via SSH, the AWS console, or any AWS API except through the vsock channel from its parent instance.

The Nitro Hypervisor enforces the isolation: even with root access to the parent EC2 instance, an operator cannot read the enclave's memory. The parent instance controls the enclave lifecycle but cannot inspect its state.

Attestation produces a Signed Attestation Document (SAD) containing a measurement of the enclave image (a hash of its Enclave Image File) and the enclave's ephemeral public key. The client or an AWS KMS policy can verify the SAD before releasing a decryption key or sending sensitive data.

The vsock-only connectivity model is a significant architectural constraint: the inference server inside the enclave cannot make outbound network requests. All model weights must be streamed in from the parent instance (which can access S3 or other services), and all inference requests must be proxied through the parent. This makes Nitro Enclaves better suited for smaller specialised models than large multi-hundred-GB checkpoints.

### ARM CCA (Confidential Compute Architecture)

ARM CCA introduces Realms — a hardware-isolated execution environment on ARMv9-A silicon. The architecture is supported in AWS Graviton4 and select mobile platforms. CCA uses a Realm Management Monitor (RMM) that sits below the hypervisor to enforce isolation. Attestation is via the DICE (Device Identity Composition Engine) chain. CCA is the newest of the four platforms; production cloud availability is limited as of mid-2026 but will be relevant for edge inference deployments on ARM hardware.

## Remote Attestation

Attestation is the mechanism that allows a client to verify it is communicating with a genuine TEE running the expected software before sending sensitive data. Without attestation, a confidential VM deployment is meaningless for the client: they cannot distinguish the real TEE from a standard VM that claims to be one.

The attestation flow for a TDX inference deployment:

```
Client                         Inference Server (TDX TD)          Intel Attestation Service
  |                                     |                                      |
  |---- GET /attestation-nonce -------->|                                      |
  |<--- nonce (random 32 bytes) --------|                                      |
  |                                     |                                      |
  |---- GET /quote?nonce=<nonce> ------>|                                      |
  |                           [TD generates quote]                             |
  |                           [Quote includes nonce,                           |
  |                            MRTD (TD measurement),                         |
  |                            RTMR0-3 (runtime measurements)]                |
  |<--- TD Quote (CBOR/DER) -----------|                                      |
  |                                     |                                      |
  |---- POST /quote ------------------------------------------------->|        |
  |                                                          [IAS verifies]    |
  |<--- Attestation Report (JSON, signed by Intel root) -------------|        |
  |                                     |                                      |
  [Client verifies MRTD matches published measurement]
  [Client verifies report is signed by Intel root cert]
  [Client verifies nonce to prevent replay]
  |                                     |
  |---- TLS session to inference endpoint (key sealed to MRTD) ---->|
```

In practice, clients verify attestation using libraries rather than implementing the flow manually:

```python
# Client-side attestation verification for TDX inference endpoint.
# Using the tdx-attest Python library (Intel reference implementation).

import hashlib
import requests
from tdx_attest import verify_quote, QuoteVerificationResult

def establish_attested_channel(inference_endpoint: str, expected_mrtd: str) -> requests.Session:
    """
    Obtain and verify a TDX attestation quote before creating an
    authenticated session to the inference endpoint.
    """
    # Step 1: Get a nonce from the server to bind the quote to this session.
    nonce_resp = requests.get(f"{inference_endpoint}/v1/attestation/nonce")
    nonce = nonce_resp.json()["nonce"]

    # Step 2: Retrieve the TD Quote for this nonce.
    quote_resp = requests.get(
        f"{inference_endpoint}/v1/attestation/quote",
        params={"nonce": nonce}
    )
    quote_bytes = bytes.fromhex(quote_resp.json()["quote"])

    # Step 3: Verify the quote against Intel's Attestation Service.
    result: QuoteVerificationResult = verify_quote(
        quote=quote_bytes,
        nonce=bytes.fromhex(nonce),
    )

    if not result.is_valid:
        raise RuntimeError(f"Attestation verification failed: {result.error}")

    # Step 4: Verify the TD measurement matches the expected binary.
    actual_mrtd = result.td_report.mrtd.hex()
    if actual_mrtd != expected_mrtd:
        raise RuntimeError(
            f"MRTD mismatch: expected {expected_mrtd}, got {actual_mrtd}. "
            "The inference server is not running the expected code."
        )

    # Attestation passed — create an authenticated session.
    session = requests.Session()
    session.headers["X-Attestation-Nonce"] = nonce
    session.headers["X-Attestation-Quote"] = quote_resp.json()["quote"]
    return session


# Usage:
# Published MRTD is the hash of the known-good inference server image.
EXPECTED_MRTD = "a3f2c1..."   # From release pipeline; stored in policy repo.

session = establish_attested_channel(
    "https://inference.example.com",
    expected_mrtd=EXPECTED_MRTD,
)
response = session.post("/v1/chat/completions", json={
    "model": "llama-3-70b",
    "messages": [{"role": "user", "content": user_query}]
})
```

For AMD SEV-SNP, the same logic applies using the AMD KDS (Key Distribution Service) to verify the SNP Report signature. The Azure Attestation Service and Google Cloud Confidential Computing API both provide managed attestation verification that abstracts the platform-specific report format.

## Model Weight Protection

The goal: model weights must be encrypted outside the TEE, and the decryption key must only be accessible inside an attested TEE running the expected code.

The pattern uses a remote KMS that releases the decryption key only after verifying a valid attestation report.

```python
# Inside the TEE: request decryption key from KMS only after attestation.
# This runs inside the TDX Trust Domain or SEV-SNP VM.

import os
import boto3
from tdx_attest import get_quote

def load_model_weights_sealed_to_tee(
    weights_s3_bucket: str,
    weights_s3_key: str,
    kms_key_id: str,
    output_path: str,
) -> None:
    """
    Download encrypted model weights from S3 and decrypt them inside the TEE.
    The KMS key policy only allows decryption when the request includes a
    valid TDX attestation report with the expected MRTD.
    """
    # Generate a TDX quote that includes the expected weights hash as userData.
    # This binds the attestation to this specific operation.
    weights_hash_placeholder = b"\x00" * 64  # Will be verified post-decrypt.
    quote = get_quote(user_data=weights_hash_placeholder)

    # Request decryption of the data encryption key (DEK) from KMS.
    # The KMS key policy (see below) requires a valid TDX attestation.
    kms = boto3.client("kms", region_name="us-east-1")
    response = kms.decrypt(
        CiphertextBlob=get_encrypted_dek_from_metadata(weights_s3_bucket, weights_s3_key),
        EncryptionContext={
            "purpose": "model-inference",
            "model": weights_s3_key,
        },
        # The attestation document is passed as an additional authenticated header
        # via a custom KMS proxy that validates TEE attestation before forwarding.
        # Standard KMS does not natively verify TDX quotes; a proxy layer is required.
    )
    dek = response["Plaintext"]   # 32-byte AES-256 key; never leaves the TEE.

    # Download the encrypted weights.
    s3 = boto3.client("s3")
    encrypted_weights_path = f"/tmp/weights_encrypted.bin"
    s3.download_file(weights_s3_bucket, weights_s3_key, encrypted_weights_path)

    # Decrypt inside the TEE. The DEK is in memory only; never written to disk.
    decrypt_file_aes_gcm(encrypted_weights_path, dek, output_path)
    os.unlink(encrypted_weights_path)
    os.remove_from_memory(dek)  # Zero the key material.
```

The KMS key policy (using a confidential computing attestation proxy pattern):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowDecryptInAttestedTEEOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/inference-tee-role"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:purpose": "model-inference",
          "aws:RequestedRegion": "us-east-1"
        },
        "StringLike": {
          "kms:ViaService": "tee-attestation-proxy.internal"
        }
      }
    },
    {
      "Sid": "DenyAllOtherDecrypt",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "kms:EncryptionContext:purpose": "model-inference"
        }
      }
    }
  ]
}
```

For AWS Nitro Enclaves, KMS natively supports attestation-conditioned key policies using the `kms:RecipientAttestation:ImageSha384` condition key, which makes the proxy pattern unnecessary:

```json
{
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<sha384-of-enclave-image>"
    }
  }
}
```

This ensures the DEK is only released to an enclave running the exact expected image — no other code path can obtain it.

## Confidential Containers on AKS and GKE

For Kubernetes-native deployments, both Azure (AKS) and Google Cloud (GKE) support confidential node pools backed by SEV-SNP or TDX VMs.

### Azure AKS Confidential Nodes

```bash
# Create an AKS node pool with AMD SEV-SNP confidential VMs.
az aks nodepool add \
  --resource-group rg-ai-inference \
  --cluster-name aks-inference \
  --name confnodepool \
  --node-count 3 \
  --node-vm-size Standard_DC4as_v5 \   # AMD SEV-SNP (DCasv5 series)
  --os-sku AzureLinux \
  --enable-node-public-ip false

# Verify the node pool is using confidential VMs.
az aks nodepool show \
  --resource-group rg-ai-inference \
  --cluster-name aks-inference \
  --name confnodepool \
  --query "securityProfile.enableConfidentialOsDisk"
```

Deploying inference pods onto confidential nodes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-inference
  namespace: ml-serving
spec:
  replicas: 2
  selector:
    matchLabels:
      app: llm-inference
  template:
    metadata:
      labels:
        app: llm-inference
      annotations:
        # Request confidential container attestation via the Azure CC agent.
        microsoft.com/confidential-container: "true"
    spec:
      nodeSelector:
        agentpool: confnodepool
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      containers:
        - name: inference-server
          image: myregistry.azurecr.io/llm-inference:v1.2.3-verified
          env:
            - name: MODEL_WEIGHTS_BUCKET
              value: "az://model-weights/llama-70b-encrypted.bin"
            - name: KMS_ENDPOINT
              value: "https://kms-proxy.internal:8443"
            - name: ATTESTATION_ENDPOINT
              value: "https://shareduks.uks.attest.azure.net"
          resources:
            requests:
              memory: "160Gi"
              cpu: "8"
            limits:
              memory: "180Gi"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: model-weights
              mountPath: /models
              readOnly: false   # Weights written here after TEE-side decryption.
      volumes:
        - name: model-weights
          emptyDir:
            medium: Memory   # tmpfs; weights never written to disk.
            sizeLimit: 160Gi
```

### GKE Confidential Nodes

```bash
# Create a GKE node pool with confidential VMs (AMD SEV or Intel TDX).
gcloud container node-pools create confidential-inference \
  --cluster inference-cluster \
  --region us-central1 \
  --machine-type n2d-highmem-64 \
  --enable-confidential-nodes \
  --confidential-compute-type SEV_SNP \
  --num-nodes 2 \
  --node-taints cloud.google.com/gke-confidential-node=true:NoSchedule

# Verify confidential node attestation is enabled.
gcloud container node-pools describe confidential-inference \
  --cluster inference-cluster \
  --region us-central1 \
  --format="value(config.confidentialNodes.enabled)"
```

## Nvidia H100 Confidential Computing for GPU Inference

Enabling Confidential Computing mode on an H100 attached to a TDX or SEV-SNP VM:

```bash
# Check if the H100 supports CC mode (requires driver 525.60+ and CC-capable GPU).
nvidia-smi conf-compute -s

# Enable Confidential Computing mode (requires GPU reset; done at provisioning time).
nvidia-smi conf-compute -e 1

# Verify CC mode is active.
nvidia-smi conf-compute -s
# Output: CC status: ON

# Generate a combined CPU+GPU attestation report.
# Using the NVIDIA NVML attestation library.
python3 - <<'EOF'
import ctypes

# Load NVML.
nvml = ctypes.CDLL("libnvidia-ml.so.1")
nvml.nvmlInit()

# Get attestation report from the first GPU.
handle = ctypes.c_void_p()
nvml.nvmlDeviceGetHandleByIndex(0, ctypes.byref(handle))

nonce = b"\x01" * 32   # Nonce from client or attestation flow.
report_buf = ctypes.create_string_buffer(4096)
report_len = ctypes.c_uint32(4096)

ret = nvml.nvmlDeviceGetConfComputeMemSizeInfo(handle, nonce, len(nonce),
                                               report_buf, ctypes.byref(report_len))
print(f"GPU attestation report ({report_len.value} bytes): {report_buf.raw[:report_len.value].hex()}")
nvml.nvmlShutdown()
EOF
```

Inference using vLLM with H100 in Confidential Computing mode:

```bash
# Deploy vLLM inside the TEE with CC-mode GPU.
# The inference server runs in the TDX TD; the H100 is in CC mode.

docker run --gpus all \
  --runtime=nvidia \
  -e NVIDIA_VISIBLE_DEVICES=all \
  -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
  -v /models/llama-70b:/models/llama-70b:ro \
  -p 8000:8000 \
  vllm/vllm-openai:v0.4.3 \
    --model /models/llama-70b \
    --gpu-memory-utilization 0.95 \
    --max-model-len 8192 \
    --enforce-eager
```

Inside the TEE, the model weights are loaded onto the H100. Because the GPU is in CC mode, the GPU's HBM memory is encrypted with a key the GPU's security processor holds. The host hypervisor cannot read the HBM content. PCIe traffic between the CPU TEE and the GPU is encrypted using a session key established during the CC attestation handshake.

## Performance Trade-offs

Confidential computing adds overhead from memory encryption, attestation, and the reduced CPU cache efficiency that results from encrypted memory pages. The impact varies significantly by platform and workload.

| Platform | Memory encryption overhead | Attestation latency | LLM inference throughput impact |
|---|---|---|---|
| Intel TDX | 1–5% on memory-bound workloads | 100–300 ms (one-time at startup) | 2–8% tokens/sec reduction |
| AMD SEV-SNP | 1–3% on memory-bound workloads | 50–200 ms (AMD KDS lookup) | 2–5% tokens/sec reduction |
| Nvidia H100 CC mode | < 2% GPU compute overhead | ~50 ms additional startup | < 2% tokens/sec reduction |
| AWS Nitro Enclaves | Minimal (process isolation model) | ~10 ms (local attestation) | vsock proxy adds 1–3 ms per request |
| SGX (legacy) | 10–30% (EPC thrashing on large models) | 200–500 ms | Not practical for LLMs > 7B parameters |

The TDX and SEV-SNP overhead figures are for memory bandwidth-intensive workloads (LLM inference at batch size 1). At higher batch sizes, the compute-to-memory ratio shifts in favour of the GPU; the overhead on throughput decreases proportionally.

The critical practical finding from 2025 deployments: H100 Confidential Computing adds negligible inference overhead. The GPU does the majority of the computation; the memory encryption on the CPU side only affects the relatively small CPU-side processing (tokenisation, KV cache management, request scheduling). The result is that a full confidential inference stack — TDX host VM + H100 CC mode — runs at roughly 95–98% of unprotected throughput for batch sizes above 4.

Latency at batch size 1 is the most affected scenario: an additional 3–8% latency overhead from the encrypted memory path on the first-token generation. For interactive chatbot use cases where p99 first-token latency matters, this is measurable but not disqualifying.

## Practical Deployment: TDX Confidential VM with Attestation Flow

End-to-end deployment on Azure with TDX:

```bash
# 1. Create a TDX confidential VM on Azure (DCesv5 series = Intel TDX).
az vm create \
  --resource-group rg-confidential-inference \
  --name inference-tdx-01 \
  --image "Canonical:ubuntu-24_04-lts:server:latest" \
  --size Standard_DC8es_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --enable-secure-boot true \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub

# 2. Verify TDX is active inside the VM.
ssh azureuser@<vm-ip> "cpuid | grep -i tdx || dmesg | grep -i tdx"
# Expected: "Intel TDX" present in cpuid or dmesg.

# 3. Install the inference server and attestation agent.
ssh azureuser@<vm-ip> << 'ENDSSH'
  # Install NVIDIA drivers with CC support.
  sudo apt-get install -y linux-headers-$(uname -r)
  sudo apt-get install -y cuda-drivers-525

  # Install Azure Attestation agent.
  wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.5_amd64.deb
  sudo dpkg -i azguestattestation1_1.0.5_amd64.deb

  # Install vLLM and attestation libraries.
  pip install vllm==0.4.3 azure-security-attestation==1.0.0

  # Fetch and verify the attestation report.
  python3 - <<'PYEOF'
  from azure.security.attestation import AttestationClient, AttestationData
  from azure.identity import DefaultAzureCredential
  import base64, json

  client = AttestationClient(
      "https://sharedeau.eau.attest.azure.net",
      credential=DefaultAzureCredential()
  )

  # Get the hardware attestation evidence (TPM-based for TDX on Azure).
  with open("/sys/kernel/security/tpm0/binary_bios_measurements", "rb") as f:
      evidence = f.read()

  response = client.attest_tpm(evidence)
  claims = json.loads(base64.b64decode(response.token.split(".")[1] + "=="))
  print("Platform claims:", json.dumps(claims, indent=2))
  PYEOF
ENDSSH

# 4. Encrypt model weights using the enclave's public key before upload.
# On the operator's build machine (outside the TEE):
python3 encrypt_weights_for_tee.py \
  --weights-path ./llama-3-70b/ \
  --kms-key-id "arn:aws:kms:us-east-1:ACCOUNT:key/MODEL-KEY" \
  --output-path ./llama-3-70b-encrypted.bin \
  --output-dek-ciphertext ./dek.enc

# Upload encrypted weights.
aws s3 cp ./llama-3-70b-encrypted.bin s3://model-weights-confidential/llama-70b/
aws s3 cp ./dek.enc s3://model-weights-confidential/llama-70b/dek.enc

# 5. Start the inference server inside the TEE.
ssh azureuser@<vm-ip> << 'ENDSSH'
  # The startup script:
  # a. Obtains an attestation report.
  # b. Presents the report to the KMS proxy.
  # c. KMS proxy verifies attestation and returns the DEK.
  # d. Downloads and decrypts weights using the DEK.
  # e. Loads weights into H100 (CC mode).
  # f. Starts vLLM with the decrypted weights.
  python3 /opt/inference/tee_startup.py \
    --weights-bucket model-weights-confidential \
    --weights-key llama-70b/llama-3-70b-encrypted.bin \
    --dek-key llama-70b/dek.enc \
    --kms-proxy https://kms-proxy.internal:8443
ENDSSH
```

The `tee_startup.py` script handles the full attestation and weight loading sequence:

```python
#!/usr/bin/env python3
"""
Startup script for confidential inference inside a TDX Trust Domain.
Runs inside the TEE; obtains attestation, fetches DEK, decrypts weights.
"""

import os
import sys
import subprocess
import boto3
import requests
import argparse
from pathlib import Path


def get_tdx_attestation_report(nonce: bytes) -> bytes:
    """Request a TDX attestation quote from the CPU."""
    result = subprocess.run(
        ["tdx-attest-tool", "--nonce", nonce.hex(), "--format", "raw"],
        capture_output=True,
        check=True,
    )
    return result.stdout


def fetch_dek_from_kms_proxy(kms_proxy_url: str, attestation_report: bytes) -> bytes:
    """
    Present the attestation report to the KMS proxy.
    The proxy verifies the TDX quote, checks the MRTD against its allowlist,
    then forwards the KMS decrypt request if attestation passes.
    """
    response = requests.post(
        f"{kms_proxy_url}/v1/release-key",
        json={
            "attestation_report": attestation_report.hex(),
            "key_purpose": "model-inference",
        },
        verify="/etc/ssl/certs/kms-proxy-ca.crt",
        timeout=30,
    )
    response.raise_for_status()
    return bytes.fromhex(response.json()["dek"])


def decrypt_weights(encrypted_path: Path, dek: bytes, output_path: Path) -> None:
    """Decrypt weights using AES-256-GCM with the DEK."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with open(encrypted_path, "rb") as f:
        nonce = f.read(12)        # 96-bit GCM nonce.
        tag = f.read(16)          # 128-bit authentication tag.
        ciphertext = f.read()

    aesgcm = AESGCM(dek)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    # Zero the DEK from memory after use.
    dek_array = bytearray(dek)
    for i in range(len(dek_array)):
        dek_array[i] = 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--weights-bucket", required=True)
    parser.add_argument("--weights-key", required=True)
    parser.add_argument("--dek-key", required=True)
    parser.add_argument("--kms-proxy", required=True)
    args = parser.parse_args()

    nonce = os.urandom(32)
    print("Obtaining TDX attestation report...")
    attestation = get_tdx_attestation_report(nonce)

    print("Fetching DEK from KMS proxy (attestation required)...")
    dek = fetch_dek_from_kms_proxy(args.kms_proxy, attestation)

    print("Downloading encrypted weights from S3...")
    s3 = boto3.client("s3")
    encrypted_path = Path("/tmp/weights_encrypted.bin")
    s3.download_file(args.weights_bucket, args.weights_key, str(encrypted_path))

    print("Decrypting weights inside TEE...")
    output_path = Path("/models/llama-70b")
    output_path.mkdir(parents=True, exist_ok=True)
    decrypt_weights(encrypted_path, dek, output_path / "model.safetensors")
    encrypted_path.unlink()

    print("Starting vLLM inference server...")
    os.execv("/usr/bin/python3", [
        "python3", "-m", "vllm.entrypoints.openai.api_server",
        "--model", str(output_path),
        "--host", "0.0.0.0",
        "--port", "8000",
        "--gpu-memory-utilization", "0.95",
    ])


if __name__ == "__main__":
    main()
```

## 2025–2026 Developments

Several developments in the last eighteen months have moved confidential AI inference from research to production viability.

**Nvidia H100/H200 Confidential Computing GA (2024–2025).** The availability of CC-mode GPUs resolved the fundamental gap in earlier TEE deployments: CPU-only confidential VMs left GPU computation — which is where LLM inference actually runs — exposed. H100 CC mode, combined with TDX or SEV-SNP on the CPU, now provides end-to-end memory encryption across the full inference pipeline.

**Azure Confidential Inferencing Preview (2025).** Microsoft launched a managed confidential inferencing service on Azure that combines AKS confidential node pools, the Azure Attestation Service, and Azure Key Vault integration for DEK management. The service provides the attestation proxy and KMS integration out of the box, reducing the engineering burden of building the components described above.

**CNCF Confidential Containers (CoCo) v0.9–1.0 (2025).** The Confidential Containers project reached production readiness with stable support for TDX and SEV-SNP backends. CoCo integrates with containerd and Kubernetes to make confidential VM-backed pods a standard pod scheduling primitive rather than a separate deployment model. The attestation flow is handled by a sidecar agent (the `attestation-agent`) rather than requiring application-level integration.

**Inference frameworks with TEE-awareness.** vLLM 0.5.x added explicit documentation and configuration for TEE deployments. Ollama 0.3.x added support for encrypted model file formats that are compatible with TEE-side decryption. Triton Inference Server added confidential deployment documentation for Nitro Enclaves.

**IETF RATS (Remote Attestation Procedures) standardisation.** The RATS working group finalised RFC 9334 (Remote ATtestation procedureS Architecture) and related EAT (Entity Attestation Token) drafts. Standardised attestation token formats reduce the platform-specific integration work: a client that speaks EAT can verify attestation from TDX, SEV-SNP, and Nitro Enclaves with a single verification library rather than three platform-specific implementations.

## Telemetry

```
confidential_inference_attestation_latency_ms{platform, result}        histogram
confidential_inference_attestation_failures_total{platform, reason}    counter
confidential_inference_dek_fetch_latency_ms{kms_proxy}                 histogram
confidential_inference_weight_decrypt_duration_ms{model}               histogram
confidential_inference_tee_startup_total{result}                       counter
confidential_inference_tokens_per_second{model, batch_size}            gauge
confidential_inference_memory_encryption_overhead_pct                  gauge
```

Alert on:

- `confidential_inference_attestation_failures_total` non-zero — the TEE cannot produce a valid attestation report; possible firmware update, configuration change, or tampering.
- Attestation report MRTD value differs from the expected measurement in the policy — the inference server binary has changed; verify the change was intentional and update the policy allowlist.
- `confidential_inference_dek_fetch_latency_ms` p99 > 5000 ms — KMS proxy availability issue; inference startup will stall.
- GPU CC mode disabled at startup — the H100 is not in confidential mode; weights will load into unencrypted HBM.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| TDX/SEV-SNP memory encryption | Hypervisor cannot read model weights or query data | 2–8% throughput reduction; higher memory latency | Accept overhead for high-sensitivity deployments; benchmark against your SLA before committing. |
| H100 Confidential Computing | Full inference pipeline covered including GPU computation | Requires CC-capable hardware (H100/H200); not available on A100 or older GPUs | Plan hardware procurement around CC requirements. |
| Remote attestation per client | Client can verify the code processing their data | One-time 100–300 ms attestation at session start | Cache the attestation result per client session; re-attest on session renewal (e.g., hourly). |
| DEK sealed to MRTD | Decryption key only released to attested code | Binary updates require new attestation policy; deployment pipeline must update MRTD allowlist | Automate MRTD extraction in CI/CD; publish measurements in a transparency log. |
| Weights in tmpfs only | No plaintext weights on disk | Memory-only storage lost on crash; requires re-decrypt on restart | Accept re-decrypt latency (typically 30–120 seconds for 70B models); build restart tolerance into your serving SLA. |
| Confidential Containers (CoCo) | Kubernetes-native deployment model | Additional container runtime overhead; Kata Containers VM startup adds 2–5 seconds to pod start | Only affects cold start; warm pods have normal scheduling latency. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Attestation MRTD mismatch | Client rejects server attestation; inference requests fail with attestation error | Client-side attestation verification exception; `attestation_failures_total` metric | Verify that the deployed binary hash matches the MRTD in the policy; update the MRTD allowlist after intentional updates. |
| DEK release blocked by KMS policy | Inference server cannot decrypt weights; startup fails | `confidential_inference_tee_startup_total{result="failure"}` | Verify the attestation report is valid and the MRTD is in the KMS policy allowlist; check KMS proxy availability. |
| H100 not in CC mode | GPU HBM unencrypted; attestation does not cover GPU computation | `nvidia-smi conf-compute -s` shows CC OFF at startup | Enable CC mode at provisioning; add CC mode check to startup health verification. |
| TDX firmware update changes MRTD | Existing KMS policies reject the new measurement | Attestation failures after host firmware update | Pre-compute MRTD for the new firmware before update; add to policy before update; remove old measurement after rollout. |
| tmpfs weights lost on crash | Re-decrypt required on every pod restart; startup latency spike | Increased startup time metrics; S3 download and decryption on every restart | Increase pod liveness probe start period; alert on frequent restarts. |
| Side-channel attack via shared CPU cache | Potential information leakage between co-tenant workloads | Not directly observable; mitigated by platform | Use dedicated hosts for highest-sensitivity deployments; TDX and SEV-SNP reduce but do not eliminate cache side-channel risk on shared hardware. |

## Related Articles

- [Privacy-Preserving ML Inference](/articles/ai-landscape/privacy-preserving-ml-inference/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
- [Membership Inference Defence and Model Extraction Prevention](/articles/ai-landscape/membership-inference-defence/)
- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [vLLM Production Security](/articles/ai-landscape/vllm-production-security/)
