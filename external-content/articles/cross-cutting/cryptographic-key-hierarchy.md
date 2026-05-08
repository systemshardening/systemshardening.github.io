---
title: "Cryptographic Key Hierarchy Design: Root Keys, Intermediate Keys, and Data Encryption Keys"
description: "Flat key management — one key for everything — creates catastrophic exposure when compromised. Key hierarchies limit blast radius: a compromised data key affects one dataset; a compromised root key is catastrophic. This guide covers key hierarchy design, envelope encryption, key derivation functions, hardware root of trust, and managing key rotation without service disruption."
slug: cryptographic-key-hierarchy
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - key-management
  - cryptography
  - envelope-encryption
  - kms
  - hsm
personas:
  - security-engineer
  - platform-engineer
article_number: 621
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/cryptographic-key-hierarchy/
---

# Cryptographic Key Hierarchy Design: Root Keys, Intermediate Keys, and Data Encryption Keys

## Problem

Flat key management is when one key — or a handful of manually-managed keys — encrypts everything. A single S3-bucket KMS key for all objects. One database master key. One signing key for every service. The appeal is simplicity: fewer keys means less key management ceremony.

The failure mode is catastrophic. When the key is compromised, every object, every record, every artifact signed with it is in scope. The attacker has everything encrypted since that key was created. There is no containment, because there is nothing to contain — one key, one blast radius.

A cryptographic key hierarchy changes the geometry of this risk. Keys exist in layers. Root key material — protected in hardware, rarely used, rarely touched — wraps intermediate Key Encryption Keys (KEKs). KEKs wrap per-object or per-tenant Data Encryption Keys (DEKs). A compromised DEK exposes one dataset; a compromised KEK exposes the DEKs it wraps, requiring re-keying at that layer; a compromised root key is catastrophic, which is precisely why root key material never leaves hardware and why all access to it is logged, rate-limited, and MFA-protected.

The hierarchy is the separation of concerns for cryptographic material. The specific problems it addresses:

- **No blast radius isolation.** A single KMS key for all customer data means any KMS authentication failure, insider threat, or misconfigured IAM policy exposes every customer's data simultaneously.
- **No per-tenant isolation in multi-tenant SaaS.** Using platform-managed keys for all tenants means tenant A's data is co-protected with tenant B's. A customer-managed key (CMK) model requires the hierarchy to support tenant-scoped intermediate keys.
- **No rotation granularity.** Rotating a flat key requires re-encrypting all data it protects. In a hierarchy, rotating a DEK affects only the objects that DEK encrypts; rotating the KEK requires re-wrapping the DEKs it holds, not re-encrypting the data.
- **No separation between encryption and key management.** Applications that encrypt data should not also hold the material needed to decrypt the key used for encryption. Envelope encryption enforces this separation structurally.
- **Shared key material across environments.** Dev, staging, and production sharing the same key material means a dev environment compromise can yield production-decrypting capability.

**Target systems:** AWS KMS, GCP Cloud KMS, Azure Key Vault / Managed HSM, HashiCorp Vault transit engine, on-premise HSMs (Thales Luna, nCipher nShield), any system storing encrypted data at rest or passing encrypted payloads between services.

## Threat Model

- **Adversary 1 — Compromised application credential:** An attacker gains an application's IAM role or Vault token with KMS decrypt permissions. With a flat key, they can decrypt every object the application can access. With a key hierarchy, they can decrypt only the DEKs for objects that application would ordinarily decrypt — a much smaller scope.
- **Adversary 2 — Compromised DEK in memory:** An application holds a plaintext DEK in memory to encrypt a batch of objects. An attacker with process-level access or a heap dump extracts the DEK. The blast radius is bounded to the objects that specific DEK encrypted. The root key and KEK are never in application memory.
- **Adversary 3 — Insider with KMS access:** A malicious insider with access to a KMS key. With a flat key, this is unconditional access to all data. With a hierarchy, the damage is bounded by the scope of the key they accessed. Root key operations are separately authenticated, separately logged, and MFA-gated.
- **Adversary 4 — Exfiltrated ciphertext without key access:** An attacker obtains the encrypted database backup. Without the DEK, they cannot decrypt it. Without the KEK to unwrap the DEK, they cannot get the DEK. Without root key access to unwrap the KEK, they are blocked at every layer.
- **Adversary 5 — Cross-tenant data access in SaaS:** An attacker exploits an authorization bug in a multi-tenant application. With a flat key, tenant isolation is purely at the application layer — one hole in the access control, and they decrypt another tenant's data. With per-tenant KEKs, they would also need to access that tenant's specific KMS material.
- **Access level:** Adversaries 1 and 3 have valid credentials or IAM access. Adversary 2 has OS-level access to the application process. Adversaries 4 and 5 have data access but not key access.
- **Objective:** Decrypt data at rest, move laterally across tenant boundaries, or maintain persistent access to decryption capability after a remediation event.
- **Blast radius:** Proportional to the scope of the compromised key in the hierarchy. A DEK is the smallest possible blast radius; a root key is the largest. The hierarchy is the mechanism that keeps most compromises in the DEK tier.

## Configuration

### Step 1: Design the Key Hierarchy Layers

Before touching any KMS API, define the hierarchy on paper. Three-layer is standard:

```
Root Key (hardware-protected, rarely used)
  └── Key Encryption Key / KEK (per-service or per-tenant, managed in KMS)
        └── Data Encryption Key / DEK (per-object or per-dataset, stored encrypted alongside data)
```

Four-layer hierarchies are used for large multi-tenant systems:

```
Root Key (HSM, single master per region)
  └── Tenant KEK (one per customer, in KMS as a CMK)
        └── Collection KEK (one per data class or S3 prefix, wrapped by tenant KEK)
              └── DEK (per object, wrapped by collection KEK)
```

The rule: **a key at level N is only ever used to wrap or unwrap keys at level N+1.** Root keys do not directly encrypt data. DEKs do not wrap other keys. This constraint is what makes the blast-radius guarantees meaningful.

For each key in the hierarchy, define:

| Property | Decision |
|----------|---------|
| Purpose | Wrap/unwrap only (KEK/root) or encrypt data (DEK) |
| Scope | What data or tenants does this key protect? |
| Storage | KMS-managed (KEK), encrypted in database (DEK ciphertext), or HSM (root) |
| Rotation schedule | Root: annually or on events; KEK: 90 days or on events; DEK: per-object or on compromise |
| Access control | Who/what IAM principal or Vault policy can use this key and for which operations? |
| Audit requirements | Every root-key operation audited to SIEM; DEK operations sampled |

### Step 2: Implement Envelope Encryption

Envelope encryption is the pattern by which DEKs are used in practice. The application never stores plaintext DEKs. It stores the DEK ciphertext alongside the data. To decrypt the data, it calls the KMS API to decrypt the DEK ciphertext, gets the plaintext DEK, decrypts the data, and then discards the plaintext DEK.

```python
import os
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KMS_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"  # KEK in KMS

kms = boto3.client("kms", region_name="us-east-1")


def encrypt_object(plaintext: bytes, object_id: str) -> dict:
    """
    Envelope encryption:
    1. Generate a fresh DEK (never reuse a DEK across objects).
    2. Encrypt the data with the DEK using AES-256-GCM.
    3. Wrap the DEK using KMS (the KMS key acts as the KEK).
    4. Store the encrypted DEK alongside the ciphertext — never the plaintext DEK.
    """
    # Step 1: generate DEK — 256-bit random key.
    dek_plaintext = os.urandom(32)

    # Step 2: encrypt the data.
    aead = AESGCM(dek_plaintext)
    nonce = os.urandom(12)
    # AAD binds the object identity to this ciphertext — prevents ciphertext transplant.
    aad = f"object-id:{object_id}".encode()
    ciphertext = aead.encrypt(nonce, plaintext, aad)

    # Step 3: wrap the DEK with KMS.
    wrap_response = kms.encrypt(
        KeyId=KMS_KEY_ID,
        Plaintext=dek_plaintext,
        EncryptionContext={"object_id": object_id, "purpose": "data-encryption"},
    )
    encrypted_dek = wrap_response["CiphertextBlob"]

    # Step 4: zero the plaintext DEK from memory before returning.
    dek_plaintext = b"\x00" * len(dek_plaintext)

    return {
        "object_id": object_id,
        "kms_key_id": KMS_KEY_ID,
        "encrypted_dek": encrypted_dek,  # stored with the object; not the plaintext DEK
        "nonce": nonce,
        "ciphertext": ciphertext,
        "aad": aad,
    }


def decrypt_object(envelope: dict) -> bytes:
    """
    Decryption:
    1. Call KMS to decrypt the stored encrypted DEK.
    2. Decrypt the data with the recovered DEK.
    3. Discard the plaintext DEK.
    """
    # Step 1: unwrap DEK via KMS API call.
    unwrap_response = kms.decrypt(
        CiphertextBlob=envelope["encrypted_dek"],
        KeyId=envelope["kms_key_id"],
        EncryptionContext={
            "object_id": envelope["object_id"],
            "purpose": "data-encryption",
        },
    )
    dek_plaintext = unwrap_response["Plaintext"]

    # Step 2: decrypt the data.
    aead = AESGCM(dek_plaintext)
    plaintext = aead.decrypt(envelope["nonce"], envelope["ciphertext"], envelope["aad"])

    # Step 3: zero the DEK.
    dek_plaintext = b"\x00" * len(dek_plaintext)

    return plaintext
```

Key points: the plaintext DEK is never persisted, never logged, and explicitly zeroed after use. The `EncryptionContext` binds the DEK to its specific purpose and object — if you try to use the encrypted DEK for a different object or purpose, KMS will reject the decrypt call.

### Step 3: Key Derivation Functions for Per-Entity Keys

When issuing a unique DEK per object via KMS would create too many KMS API calls (high-frequency writes, per-row encryption in a database), HKDF (HMAC-based Key Derivation Function, RFC 5869) can derive per-entity keys from a single master key without a KMS call per entity.

The KMS call retrieves the master key once. HKDF derives unique per-entity keys deterministically from the master plus a context that uniquely identifies each entity.

```python
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_entity_key(master_key: bytes, entity_id: str, purpose: str) -> bytes:
    """
    Derive a unique 256-bit key for a specific entity and purpose.

    HKDF(master_key, salt=entity_id, info=purpose) -> entity_key

    Properties:
    - Deterministic: the same inputs always yield the same output.
    - Unique per entity: different entity_ids yield independent keys.
    - Purpose-bound: a key derived for "encryption" cannot be used for "mac".
    - Forward-secure from the entity key: knowing entity_key does not help
      the attacker derive master_key or any other entity's key.
    """
    info = f"{purpose}:{entity_id}".encode()
    salt = entity_id.encode()  # entity-specific salt prevents cross-entity correlation

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


# Usage pattern: master key retrieved once from KMS; entity keys derived locally.
def get_master_key_from_kms() -> bytes:
    response = kms.decrypt(
        CiphertextBlob=WRAPPED_MASTER_KEY,  # stored encrypted; unwrapped on demand
        EncryptionContext={"purpose": "master-key"},
    )
    return response["Plaintext"]


def encrypt_user_record(user_id: str, record: bytes) -> dict:
    master_key = get_master_key_from_kms()
    user_enc_key = derive_entity_key(master_key, user_id, "encryption")
    user_mac_key = derive_entity_key(master_key, user_id, "mac")

    aead = AESGCM(user_enc_key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, record, user_id.encode())

    # Zero derived keys immediately after use.
    user_enc_key = b"\x00" * 32
    user_mac_key = b"\x00" * 32
    master_key = b"\x00" * 32

    return {"user_id": user_id, "nonce": nonce, "ciphertext": ciphertext}
```

HKDF derivation is appropriate when:

- The set of entities is large (millions of users, billions of rows).
- The derived keys are short-lived and only held in memory during a request.
- The master key rotation schedule is acceptable for all derived keys simultaneously (rotating the master key invalidates all derived keys — this is the intended blast-radius for a master-key rotation event).

HKDF derivation is **not** appropriate when you need per-entity key rotation without rotating the master, or when you need to re-encrypt individual entities. For those cases, use per-entity DEKs wrapped by a KEK.

### Step 4: Hardware Root of Trust

The root key sits at the top of the hierarchy. If it is extracted, the entire hierarchy collapses. Root key material must be protected by hardware that prevents plaintext export.

**AWS KMS with CloudHSM custom key store:**

```bash
# Create a CloudHSM cluster for root key material.
aws cloudhsmv2 create-cluster \
  --hsm-type hsm2m.medium \
  --subnet-ids subnet-prod-a subnet-prod-b

CLUSTER_ID=$(aws cloudhsmv2 describe-clusters \
  --query 'Clusters[0].ClusterId' --output text)

# Create HSMs in two AZs (minimum for HA).
aws cloudhsmv2 create-hsm \
  --cluster-id "$CLUSTER_ID" --availability-zone us-east-1a
aws cloudhsmv2 create-hsm \
  --cluster-id "$CLUSTER_ID" --availability-zone us-east-1b

# Create a custom key store backed by the CloudHSM cluster.
aws kms create-custom-key-store \
  --custom-key-store-name "prod-root-keystore" \
  --cloud-hsm-cluster-id "$CLUSTER_ID" \
  --key-store-password "$HSM_CO_PASSWORD"

KEY_STORE_ID=$(aws kms describe-custom-key-stores \
  --custom-key-store-name "prod-root-keystore" \
  --query 'CustomKeyStores[0].CustomKeyStoreId' --output text)
aws kms connect-custom-key-store --custom-key-store-id "$KEY_STORE_ID"

# Create the root KEK inside the HSM — this key never leaves hardware.
ROOT_KEK_ID=$(aws kms create-key \
  --origin AWS_CLOUDHSM \
  --custom-key-store-id "$KEY_STORE_ID" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --description "Root KEK — HSM-backed — wraps service KEKs only" \
  --query 'KeyMetadata.KeyId' --output text)

aws kms create-alias \
  --alias-name alias/root-kek-prod \
  --target-key-id "$ROOT_KEK_ID"
```

**Key policy for the root KEK** — restrict usage to administrators only, require MFA, deny all other access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRootKEKAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/key-administrators"
      },
      "Action": [
        "kms:Describe*",
        "kms:List*",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowRootKEKWrapUnwrapWithMFA",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/kek-provisioner"
      },
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*"],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "StringEquals": {
          "kms:EncryptionContextKeys": "purpose",
          "kms:EncryptionContextValues": "kek-wrapping"
        }
      }
    },
    {
      "Sid": "DenyAllOtherAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:*",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/key-administrators",
            "arn:aws:iam::123456789012:role/kek-provisioner"
          ]
        }
      }
    }
  ]
}
```

The root KEK is used only to wrap/unwrap service KEKs during provisioning or rotation. Applications never call the root KEK directly. Applications call their service KEK to wrap/unwrap DEKs.

### Step 5: Separate Key Hierarchies per Environment

Dev, staging, and production must have entirely separate key hierarchies with no shared material. This is not a best practice suggestion — it is a structural requirement.

If staging and production share a KEK, a compromised staging credential can decrypt production data. If dev and production share a root KMS key, development team members who need dev access gain indirect path to production decryption capability.

```bash
# Separate KMS keys per environment via alias convention.
# Production.
aws kms create-key \
  --description "Production payment-service KEK" \
  --origin AWS_CLOUDHSM \
  --custom-key-store-id "$PROD_KEY_STORE_ID"
aws kms create-alias \
  --alias-name alias/payment-service-kek-prod \
  --target-key-id "$PROD_KEY_ID"

# Staging — separate key, different account preferred.
aws kms create-key \
  --description "Staging payment-service KEK" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT   # standard KMS, not HSM-backed — staging doesn't need HSM
aws kms create-alias \
  --alias-name alias/payment-service-kek-staging \
  --target-key-id "$STAGING_KEY_ID"

# Development — lowest-cost setup; no HSM, separate account.
aws kms create-key \
  --description "Dev payment-service KEK" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT
aws kms create-alias \
  --alias-name alias/payment-service-kek-dev \
  --target-key-id "$DEV_KEY_ID"
```

Enforce environment separation at the IAM level: the production role cannot access any staging or dev keys; the staging role cannot access any production keys. Cross-environment access should produce an IAM explicit deny, not merely an absent allow.

Use separate AWS accounts per environment (the AWS Organizations multi-account model) to make cross-environment key access physically impossible through IAM misconfiguration alone.

### Step 6: Key Rotation Without Service Disruption

Rotating a key in a hierarchy requires care to avoid decryption failures during the transition. The pattern: introduce the new key while keeping the old key available for decryption; re-encrypt gradually; retire the old key once all data has been re-encrypted.

**DEK rotation** (the most common rotation):

```python
import concurrent.futures
import logging

log = logging.getLogger(__name__)


def rotate_dek_for_object(object_id: str, old_kms_key_id: str, new_kms_key_id: str) -> bool:
    """
    Re-wrap the DEK for a single object under the new KEK.
    The actual data (ciphertext) is not re-encrypted — only the DEK wrapper changes.
    """
    try:
        # Load the current envelope from storage.
        envelope = storage.get_envelope(object_id)

        # Decrypt the DEK with the old KEK.
        old_unwrap = kms.decrypt(
            CiphertextBlob=envelope["encrypted_dek"],
            KeyId=old_kms_key_id,
            EncryptionContext={"object_id": object_id, "purpose": "data-encryption"},
        )
        dek_plaintext = old_unwrap["Plaintext"]

        # Re-wrap the same DEK with the new KEK.
        new_wrap = kms.encrypt(
            KeyId=new_kms_key_id,
            Plaintext=dek_plaintext,
            EncryptionContext={"object_id": object_id, "purpose": "data-encryption"},
        )

        # Zero DEK in memory.
        dek_plaintext = b"\x00" * len(dek_plaintext)

        # Update the envelope in storage.
        envelope["encrypted_dek"] = new_wrap["CiphertextBlob"]
        envelope["kms_key_id"] = new_kms_key_id
        storage.put_envelope(object_id, envelope)

        log.info("dek_rotated", object_id=object_id, new_key=new_kms_key_id)
        return True

    except Exception as exc:
        log.error("dek_rotation_failed", object_id=object_id, error=str(exc))
        return False


def background_kek_rotation(old_kms_key_id: str, new_kms_key_id: str, batch_size: int = 100):
    """
    Re-wrap all DEKs from the old KEK to the new KEK in background batches.
    Old KEK remains enabled for decryption until all objects are migrated.
    New KEK is used for all new objects immediately.
    """
    object_ids = storage.list_objects_by_kms_key(old_kms_key_id)
    total = len(object_ids)
    rotated = 0

    # Process in batches; each batch uses a thread pool to parallelise KMS calls.
    for i in range(0, total, batch_size):
        batch = object_ids[i:i + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(
                lambda oid: rotate_dek_for_object(oid, old_kms_key_id, new_kms_key_id),
                batch,
            ))
        rotated += sum(results)
        log.info("rotation_progress", rotated=rotated, total=total, pct=round(100 * rotated / total, 1))

    # Only when all objects are migrated, schedule old KEK deletion.
    if rotated == total:
        log.info("rotation_complete", old_key=old_kms_key_id, new_key=new_kms_key_id)
        # 30-day pending deletion window — gives time to catch any missed objects.
        kms.schedule_key_deletion(KeyId=old_kms_key_id, PendingWindowInDays=30)
```

**KEK rotation** using AWS KMS automatic rotation:

```bash
# AWS KMS symmetric keys support automatic annual rotation.
# Existing ciphertexts continue to decrypt with the old material.
aws kms enable-key-rotation --key-id alias/payment-service-kek-prod

# Verify rotation is enabled.
aws kms get-key-rotation-status --key-id alias/payment-service-kek-prod
# {"KeyRotationEnabled": true, "NextRotationDate": "2027-05-07T00:00:00Z"}
```

With automatic KEK rotation, KMS retains all previous key material versions for decryption. New encryptions use the latest version. This means applications need no code change for KEK rotation — KMS handles multi-version transparency.

**Versioned key tracking** in application envelopes ensures that even if automatic rotation is not in use, the application can identify which key version encrypted each object:

```go
type KeyEnvelope struct {
    KeyID      string `json:"kid"`         // "alias/payment-service-kek-prod"
    KeyVersion string `json:"kver"`        // "v3" — monotonic version label
    Algorithm  string `json:"alg"`         // "AES-256-GCM"
    EncDEK     []byte `json:"enc_dek"`     // DEK ciphertext — KMS-wrapped
    Nonce      []byte `json:"nonce"`
    Ciphertext []byte `json:"ct"`
}
```

### Step 7: Multi-Tenant SaaS Key Hierarchy

In a multi-tenant SaaS system, the key hierarchy must provide isolation between tenants: a bug that allows tenant A to call decrypt on tenant B's ciphertext should be blocked at the KMS layer, not just the application layer.

Two models:

**Platform-managed keys with tenant isolation:**

```
Root KEK (HSM, platform-owned)
  └── Tenant KEK (one per tenant, in KMS, tagged with tenant_id)
        └── DEK (per object, wrapped by tenant KEK)
```

```python
# Provisioning a new tenant: create a dedicated KMS key per tenant.
def provision_tenant_key(tenant_id: str) -> str:
    response = kms.create_key(
        Description=f"Tenant KEK — {tenant_id}",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[
            {"TagKey": "tenant_id", "TagValue": tenant_id},
            {"TagKey": "environment", "TagValue": "production"},
        ],
    )
    key_id = response["KeyMetadata"]["KeyId"]

    # Alias the key by tenant ID for easy lookup.
    kms.create_alias(
        AliasName=f"alias/tenant-{tenant_id}-kek",
        TargetKeyId=key_id,
    )

    # Restrict the key policy: only the application role for this tenant can use it.
    # The tenant isolation guarantee lives here — not just in the application.
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowTenantApplication",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::123456789012:role/tenant-{tenant_id}-app"
                    },
                    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:EncryptionContext:tenant_id": tenant_id
                        }
                    },
                },
                {
                    "Sid": "AllowKeyAdministration",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/key-administrators"
                    },
                    "Action": ["kms:Describe*", "kms:List*", "kms:GetKeyPolicy"],
                    "Resource": "*",
                },
            ],
        }),
    )
    return key_id
```

**Customer-managed keys (CMK model):**

Some enterprise SaaS customers require control over their own key material — they want to be able to revoke platform access to their data by disabling their key without involving the platform operator.

```
Customer KMS Key (customer's AWS account, customer-managed)
  └── Platform KEK Grant (platform's AWS account given decrypt grant by customer)
        └── DEK (per object, wrapped by customer's key via cross-account grant)
```

```bash
# Customer grants the platform's account access to their key.
# Customer runs this in their own AWS account.
aws kms create-grant \
  --key-id "arn:aws:kms:us-east-1:CUSTOMER_ACCOUNT:key/customer-key-id" \
  --grantee-principal "arn:aws:iam::PLATFORM_ACCOUNT:role/platform-data-service" \
  --operations Encrypt Decrypt GenerateDataKey GenerateDataKeyWithoutPlaintext \
  --name "platform-access-grant" \
  --constraints "EncryptionContextSubset={tenant_id=CUSTOMER_TENANT_ID}"

# Customer can revoke at any time — platform loses the ability to decrypt their data.
aws kms retire-grant \
  --key-id "arn:aws:kms:us-east-1:CUSTOMER_ACCOUNT:key/customer-key-id" \
  --grant-token "$GRANT_TOKEN"
```

The CMK model means platform operators cannot access customer data without the customer's active participation — their key controls the outer layer of the hierarchy. This is the strongest tenant isolation model and is required by some enterprise compliance frameworks.

### Step 8: Telemetry

```
kms_encrypt_requests_total{key_alias, environment, result}       counter
kms_decrypt_requests_total{key_alias, environment, result}       counter
kms_key_rotation_last_timestamp{key_alias}                       gauge (Unix epoch)
dek_rotation_progress_pct{service, old_key_alias, new_key_alias} gauge (0–100)
kms_api_errors_total{key_alias, error_code}                      counter
envelope_encryption_duration_seconds{operation}                  histogram
```

Alert on:

- `kms_api_errors_total{error_code="AccessDeniedException"}` non-zero — IAM misconfiguration or unauthorized access attempt; investigate immediately.
- `kms_decrypt_requests_total` sudden spike on a root KEK alias — root keys should almost never receive decrypt calls in steady state; any spike indicates misconfiguration or compromise.
- `kms_key_rotation_last_timestamp` older than 1.5× the rotation schedule — key rotation missed; trigger manual rotation and alert the on-call.
- `dek_rotation_progress_pct` stuck below 100 for more than the SLA — background rotation job has stalled; old KEK cannot be retired until progress completes.

## Expected Behaviour

| Scenario | Flat key model | Key hierarchy model |
|----------|---------------|---------------------|
| Application credential compromised | Attacker decrypts all objects in the application's scope | Attacker decrypts only the DEKs for objects that application would legitimately access |
| DEK extracted from process memory | DEK exposes the one object or batch it was used for | Same scope; this is the intended blast radius for the DEK tier |
| KEK compromised | Same as root: all objects | Attacker can unwrap DEKs protected by that KEK; objects protected by other KEKs unaffected |
| Multi-tenant authorization bug | Application logic prevents cross-tenant access; one bug exposes all tenant data | KMS key policy enforces tenant isolation; the bug must also bypass KMS encryption context enforcement |
| Customer wants to revoke platform access | Not possible; platform holds the key | Customer disables or deletes their CMK; platform immediately loses decryption capability |
| Key rotation | Re-encrypt all data or accept long-lived material | Re-wrap DEKs with new KEK in background; data ciphertext unchanged; rotation is a KMS-only operation |

## Trade-offs

| Design choice | Security benefit | Cost | Mitigation |
|---------------|-----------------|------|------------|
| Per-object DEK | Minimal blast radius per compromise | One KMS GenerateDataKey call per object write | Cache the current KEK reference; use KMS GenerateDataKeyWithoutPlaintext for pre-generated DEKs; batch where feasible |
| HSM-backed root key | Root material non-extractable; FIPS 140-2 Level 3 | CloudHSM ~$1.50/hr per HSM; minimum 2 for HA; provisioning complexity | Use CloudHSM only for the root tier; service-level KEKs can use standard KMS ($0.03/10,000 API calls) |
| HKDF for per-entity keys | No KMS call per entity; predictable key derivation | Master key rotation rotates all derived keys simultaneously | Acceptable for user-data encryption where master key rotation is coordinated; not for independent per-entity rotation |
| Per-tenant KMS key | KMS-enforced tenant isolation; independent rotation and deletion | KMS key limit (10,000 per region per account) constrains tenant count; quotas can be increased but must be planned | Use key aliases and AWS Organizations multi-account for large tenant counts; or use HKDF derivation from a per-tenant master key for very large tenant counts |
| Customer-managed keys | Customer controls their own data access; strongest isolation | Customer key unavailability causes platform decryption failure; complex onboarding | Implement graceful degradation: if CMK unavailable, serve error rather than attempt cross-key access; customer runbook for key management |
| Background DEK re-encryption | Seamless rotation without downtime | Old KEK must remain enabled until all re-encryption completes; rotation period can be weeks for large datasets | Monitor `dek_rotation_progress_pct`; set a hard deadline by which old KEK is retired regardless (forcing a flush of any stalled re-encryption jobs) |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| KMS key deleted while DEKs still wrapped by it | Decrypt calls return KmsInvalidStateException; data permanently inaccessible | `kms_api_errors_total{error_code="KMSInvalidStateException"}` spike; decrypt failures in application logs | KMS scheduled deletion has a pending window (7–30 days); cancel deletion if within the window (`cancel-key-deletion`); after the window, data is lost — this is why pending windows must be at least 30 days |
| DEK rotation stalls midway | Some objects remain wrapped by the old KEK after the scheduled retirement date | `dek_rotation_progress_pct` metric stuck; old KEK retirement date passed | Investigate why the rotation job stalled (IAM issue, throttling, object enumeration failure); resume from the last checkpoint; do not retire the old KEK until progress reaches 100 |
| Encryption context mismatch on decrypt | KMS returns AccessDeniedException even though the caller has IAM permissions | Decrypt error logs showing `The provided encryption context does not match`; spike in `kms_api_errors_total` | The object's envelope was stored with a different encryption context than the decrypt call uses; correct the application code; this is also what prevents ciphertext transplant attacks |
| KMS key policy prevents automation role from rotating DEKs | Background rotation job fails with AccessDeniedException | Rotation job logs show KMS access failures; `dek_rotation_progress_pct` at 0 | Update the KMS key policy to grant `kms:Encrypt` and `kms:Decrypt` to the rotation role; rotation is a legitimate key operation that must be included in the policy |
| Cross-account CMK grant revoked while data being written | Data writes fail mid-stream; some new objects unencryptable | 5xx error rate spike for writes; KMS errors referencing customer key ARN | Detect missing grant at the start of a write transaction, not mid-stream; health-check CMK access on startup and before write batches |
| Root KEK accidentally used for data encryption | Applications bypass the hierarchy and call the root key directly for data operations | `kms_decrypt_requests_total{key_alias="root-kek-prod"}` shows high volume | Root key policy should deny `kms:GenerateDataKey` and `kms:Decrypt` for all except the KEK-wrapping role; any application call to the root key alias should be blocked by policy |
| HKDF master key compromised | All per-entity derived keys are compromised simultaneously | Incident detection (depends on how master key is stored/accessed) | Rotate master key immediately; all derived keys are invalidated; must re-encrypt all per-entity data; blast radius is the full scope of the HKDF derivation — treat it like a KEK compromise |

## Related Articles

- [Hardware Security Module Integration: Key Management for Production Systems](/articles/cross-cutting/hsm-key-management/)
- [Cryptographic Agility: Designing Systems to Survive Algorithm Transitions](/articles/cross-cutting/cryptographic-agility/)
- [Secrets Rotation Orchestration: Coordinating Vault, KMS, OIDC, and Database Credentials](/articles/cross-cutting/secrets-rotation-orchestration/)
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [Vault API Surface Hardening](/articles/cross-cutting/vault-api-surface-hardening/)
