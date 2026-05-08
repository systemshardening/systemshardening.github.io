---
title: "Python Cryptography DNS Name Constraint Bypass: CVE-2026-34073 on Linux Services"
description: "CVE-2026-34073 allows X.509 certificates violating excluded-subtree DNS name constraints to pass validation in Python's cryptography library. Audit Python services doing TLS on Linux — SSSD, httpx, requests, custom PKI validators — and upgrade to 46.0.6."
slug: python-cryptography-cert-bypass
date: 2026-05-04
lastmod: 2026-05-04
category: linux
tags:
  - tls
  - x509
  - python
  - certificate-validation
  - cve
personas:
  - security-engineer
  - platform-engineer
article_number: 439
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/linux/python-cryptography-cert-bypass/
---

# Python Cryptography DNS Name Constraint Bypass: CVE-2026-34073 on Linux Services

## The Problem

X.509 name constraints let a CA limit which domain names its issued certificates may assert. The `ExcludedSubtrees` component of the `NameConstraints` extension, defined in RFC 5280 Section 4.2.1.10, instructs any validating client to reject a certificate in the chain if it asserts a name falling within a listed subtree. A corporate PKI might exclude `*.competitor.com` from a publicly-trusted intermediate, or mark `*.internal.corp` as excluded on a CA issued to a third-party integration partner. The constraint is a hard boundary; a certificate asserting a name within an excluded subtree is not merely deprioritised — it must be rejected outright.

CVE-2026-34073, disclosed March 2026 and fixed in `pyca/cryptography` 46.0.6, is a failure to enforce that boundary. The Python `cryptography` library, before the fix, parsed the `NameConstraints` extension and correctly read the `ExcludedSubtrees` list from a parent CA certificate, but then delegated constraint enforcement to the OpenSSL C extension layer in a way that skipped the excluded-subtree check entirely. The permitted-subtree check ran. The excluded-subtree check did not. A peer certificate asserting a name that a parent CA had explicitly forbidden passed validation as though the constraint did not exist.

The flaw lives in the C extension layer that wraps OpenSSL's X.509 parsing — specifically in the path that constructs a verification context from the Python-managed certificate chain. When OpenSSL is invoked for chain validation, the excluded-subtree data from the Python-parsed `NameConstraints` extension was not propagated into the OpenSSL `X509_VERIFY_PARAM` structure with the correct flags, so OpenSSL performed its own chain check without visibility into those excluded names. The permitted-subtree values were forwarded; the excluded-subtree values were not. The asymmetry existed silently across multiple library versions before the reporter isolated it.

On Linux, this vulnerability surfaces wherever Python code performs X.509 chain validation against a CA bundle that includes excluded-subtree constraints:

- **SSSD** for certificate-based LDAP and Active Directory authentication. SSSD can use `cryptography` for smart-card and certificate validation. A service account presenting a certificate that violates an excluded-subtree constraint on the organisational CA passes authentication on an unpatched system.
- **Web service clients using `requests` or `httpx`** with a custom CA bundle. Any internal microservice doing mutual TLS against a CA that enforces excluded subtrees is exposed: a client or server presenting a violating certificate is admitted.
- **Certificate transparency monitors** and PKI automation tooling written in Python that audit issued certificates against a constraint policy. The monitor fails to flag violating certificates, undermining the entire purpose of the audit.
- **Custom PKI validators** that call `cryptography.x509` APIs to implement internal policy checks — for example, code that validates whether a certificate chain respects a namespace partition enforced through name constraints.

The fix in 46.0.6 backports the excluded-subtree enforcement into the OpenSSL binding layer, ensuring that both `PermittedSubtrees` and `ExcludedSubtrees` are propagated into the verification context before chain validation runs.

## Threat Model

An attacker exploiting CVE-2026-34073 needs a certificate signed by a CA that the target trusts, where that certificate asserts a name that the signing CA or an ancestor CA has placed in an excluded subtree. This is a narrower precondition than a full PKI compromise, but there are several realistic paths to meeting it:

- **Rogue or mis-issued certificate from a trusted CA**: If a CA trusted by the target environment has signed a certificate for a name it should not have — whether through operator error, a compromised CA key, or a CA that does not itself enforce its own constraint policy — that certificate passes validation on any Python service using an unpatched `cryptography` version. The CA intended to exclude the name; the client ignores the exclusion.
- **SSSD credential interception on a corporate Linux workstation**: A corporate CA excludes an attacker-controlled subdomain from its PKI policy. The attacker obtains a certificate signed by a subordinate CA that does not itself re-state the exclusion (a common PKI configuration gap). SSSD on a Linux workstation running an unpatched `cryptography` version validates the certificate as valid, accepts the LDAP connection, and sends credentials over the attacker's forged LDAP session.
- **mTLS client authentication bypass**: A Python web service requires client certificates and validates them against a CA bundle that includes excluded-subtree constraints. A client presenting a certificate that violates those constraints is admitted, bypassing the namespace enforcement the constraint was meant to provide.
- **Internal PKI namespace escape**: An organisation partitions its PKI by excluding the `*.payments.internal` subtree from certificates issued to the `engineering.internal` intermediate CA. An engineering-team certificate asserting `api.payments.internal` should be rejected by any service validating against the root's `NameConstraints`. On unpatched Python services, it is not rejected, allowing cross-namespace impersonation within an internal environment that depends on certificate-based service identity.

The exploitability depends on what constraints the CA in use actually publishes. Environments running a simple public CA with no `NameConstraints` at all are not directly affected — the bug is only reachable when excluded subtrees are present in the chain. Corporate and government PKI environments that actively use name constraints for namespace enforcement are most directly exposed. Any environment where SSSD, Python web clients, or internal Python PKI tooling validates certificates against a constrained CA should treat this as actively exploitable.

## Hardening Configuration

### Step 1: Identify Affected Python Environments

The vulnerable component is the `cryptography` package. Any version before 46.0.6 is affected when the validation path encounters excluded-subtree constraints. Begin by finding all installations on the host — system packages, user installs, and virtualenvs.

Check the system Python install:

```bash
pip3 show cryptography | grep -E '^Version|^Location'
```

Check system packages on Debian and Ubuntu:

```bash
dpkg -l python3-cryptography
```

Check system packages on RHEL, Fedora, and CentOS:

```bash
rpm -q python3-cryptography
```

Scan for virtualenv and user-level installs by looking for installed `dist-info` directories:

```bash
find /usr /home /opt /srv -name "METADATA" -path "*/cryptography-*.dist-info/METADATA" 2>/dev/null \
  | xargs grep -l "^Version: " \
  | xargs grep "^Version: "
```

This finds both system-path and virtualenv-local installations. The pattern `cryptography-*.dist-info` matches the directory regardless of version, and grepping the `METADATA` file gives the precise version string. Any path containing a version below `46.0.6` is affected.

For containerised services, build-time inspection is not sufficient — the package version baked into the image is what matters at runtime. Check running containers:

```bash
docker ps -q | xargs -I{} docker exec {} pip show cryptography 2>/dev/null | grep -E '^Name|^Version|^Location'
```

Collect the version and install path for every result. Group by location — system path, virtualenv under `/home`, virtualenv under `/opt`, container image — so upgrades can be applied in the right scope.

### Step 2: Upgrade cryptography to 46.0.6 or Later

For virtualenvs, activate each environment and upgrade:

```bash
source /path/to/venv/bin/activate
pip install --upgrade "cryptography>=46.0.6"
pip show cryptography | grep Version
deactivate
```

For applications managed with `pip` directly against the system Python:

```bash
pip3 install --upgrade "cryptography>=46.0.6"
```

For `pipx`-managed tools that depend on `cryptography` (common with `certbot`, `ansible`, and similar tooling):

```bash
pipx upgrade-all
pipx list | grep cryptography
```

For Debian and Ubuntu system packages:

```bash
apt-get update
apt-get install --only-upgrade python3-cryptography
dpkg -l python3-cryptography
```

For RHEL and Fedora:

```bash
dnf upgrade python3-cryptography
rpm -q python3-cryptography
```

For containerised services, rebuild the image with the upgraded package and redeploy. A runtime upgrade inside a running container survives only until the container is replaced; the upgrade must land in the image build:

```bash
pip install --upgrade "cryptography>=46.0.6"
```

Add a version pin to `requirements.txt` or `pyproject.toml` to prevent regression to the vulnerable version:

```bash
cryptography>=46.0.6
```

### Step 3: Audit SSSD Configuration on Linux Hosts

SSSD uses `cryptography` when performing certificate-based authentication for LDAP and Active Directory smart-card login. On a host where SSSD handles authentication, confirm the SSSD version and its underlying Python dependency:

```bash
sssd --version
```

On Debian and Ubuntu:

```bash
dpkg -l sssd sssd-common | grep -E '^ii'
```

On RHEL and Fedora:

```bash
rpm -q sssd sssd-common sssd-ldap
```

SSSD on modern distributions links against the system `python3-cryptography` package for certificate operations. Upgrading the system package — Step 2 — is sufficient to fix the SSSD exposure, but the daemon must be restarted after the upgrade to load the new library version from disk:

```bash
systemctl restart sssd
systemctl status sssd
```

Confirm the new library is loaded by the running SSSD process:

```bash
SSSD_PID=$(systemctl show -p MainPID sssd | cut -d= -f2)
ls -la /proc/${SSSD_PID}/fd | grep -i cryptography || \
  grep cryptography /proc/${SSSD_PID}/maps | head -5
```

If SSSD is configured for smart-card or certificate-based authentication, check `/etc/sssd/sssd.conf` for the relevant sections:

```bash
grep -E 'pam_cert_auth|certificate_verification|krb5_store_password_if_offline' /etc/sssd/sssd.conf
```

Any configuration that enables `pam_cert_auth = True` or `certificate_verification` is exercising the certificate validation path affected by CVE-2026-34073.

### Step 4: Validate Name Constraint Enforcement After Upgrade

After upgrading, confirm that the fix is active by constructing a minimal certificate chain with an excluded-subtree constraint and verifying that a violating certificate is now rejected. This test requires the `cryptography` library itself and should be run inside the relevant virtualenv or against the system Python:

```python
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def make_key():
    return ec.generate_private_key(ec.SECP256R1())

def issue_cert(subject_cn, issuer_name, issuer_key, subject_key,
               extensions=None, is_ca=False):
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if extensions:
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())

ca_key = make_key()
ca_cert = issue_cert(
    subject_cn="Test CA",
    issuer_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]),
    issuer_key=ca_key,
    subject_key=ca_key,
    extensions=[
        (
            x509.NameConstraints(
                permitted_subtrees=None,
                excluded_subtrees=[
                    x509.DNSName("excluded.example.com"),
                ],
            ),
            True,
        )
    ],
    is_ca=True,
)

leaf_key = make_key()
leaf_cert = issue_cert(
    subject_cn="excluded.example.com",
    issuer_name=ca_cert.subject,
    issuer_key=ca_key,
    subject_key=leaf_key,
    extensions=[
        (
            x509.SubjectAlternativeName([x509.DNSName("excluded.example.com")]),
            False,
        )
    ],
    is_ca=False,
)

try:
    leaf_cert.verify_directly_issued_by(ca_cert)
    print("FAIL: excluded name constraint not enforced — library is still vulnerable")
except Exception as e:
    print(f"PASS: excluded name constraint enforced — {type(e).__name__}: {e}")
```

On a patched 46.0.6 installation, this prints a `PASS` line with an `InvalidCertificate` or equivalent exception. On a vulnerable version it prints `FAIL`. Run this test in every Python environment identified in Step 1 to confirm coverage.

### Step 5: Review Custom PKI Validators

Any Python code in the codebase that directly processes `NameConstraints` extensions may have been written to compensate for the library bug — either knowingly or because authors observed that the excluded-subtree check appeared not to run and added manual enforcement. After upgrading to 46.0.6, those workarounds may double-validate, conflict with the corrected library behaviour, or raise unexpected exceptions.

Search the codebase for direct use of name constraint APIs:

```bash
grep -rn "NameConstraints\|excluded_subtrees\|ExcludedSubtrees\|verify_directly_issued_by" \
  /path/to/project/src/ --include="*.py"
```

Also search for patterns that manually iterate SAN values against a list of excluded names:

```bash
grep -rn "excluded\|name_constraints\|subtree" \
  /path/to/project/src/ --include="*.py" -i
```

For each match, review whether the logic was compensating for CVE-2026-34073. If it was, test that removing the workaround produces identical results after the upgrade. If the custom code was implementing policy beyond what `verify_directly_issued_by` covers — for example, policy-layer logic that goes further than the RFC requires — keep it but confirm it no longer conflicts with the corrected C extension layer.

## Expected Behaviour After Hardening

After upgrading to `cryptography` 46.0.6 and restarting all affected services, the excluded-subtree enforcement is active in the C extension layer and cannot be bypassed by a certificate asserting an excluded name.

A certificate asserting `excluded.example.com` where the parent CA's `NameConstraints` extension lists `ExcludedSubtrees: DNS:excluded.example.com` raises `cryptography.exceptions.InvalidCertificate` during chain validation. The error surfaces at the point where the chain is verified — before any application-level logic that would act on a validated certificate has an opportunity to run. The rejection is unconditional: there is no API call that retrieves the validated certificate without going through the chain check that now enforces excluded subtrees.

SSSD rejects smart-card authentication for any certificate that violates the CA's excluded-subtree constraints. The authentication attempt fails at the certificate validation stage and is logged to `/var/log/sssd/sssd_pam.log` with a certificate validation error. The user receives an authentication failure response; no credentials are forwarded to the forged or violating endpoint.

Python web service clients using `requests` or `httpx` with a custom CA bundle raise an `SSLError` wrapping the underlying `InvalidCertificate` exception when the server presents a certificate that violates an excluded subtree in the CA chain. The connection is refused before any application data is exchanged.

## Trade-offs and Operational Considerations

Upgrading `cryptography` inside a virtualenv pulls in the new package version but may also trigger resolution of transitive dependencies that pinned to an older version. Libraries that depend on `cryptography` — `pyOpenSSL`, `paramiko`, `ansible`, `Fernet`-based tooling — should be tested against the upgraded version before deploying to production. The most common issue is a `cffi` ABI mismatch when `cryptography`'s C extension is rebuilt against a newer `cffi` than the virtualenv previously contained. Run the application test suite against the upgraded virtualenv before promotion.

The more significant operational risk is that an internal PKI may have inadvertently issued certificates that violate excluded-subtree constraints without those violations being caught — precisely because CVE-2026-34073 masked the error. Upgrading the library will cause chain validation to start failing for those certificates, breaking authentication or TLS connections that previously worked. Before upgrading in production, audit the internal PKI for certificates that violate any excluded-subtree constraints in the CA hierarchy:

```bash
openssl verify -CAfile /path/to/ca-bundle.pem -x509_strict /path/to/leaf-cert.pem
```

OpenSSL itself has correctly enforced excluded-subtree constraints throughout. If `openssl verify` rejects a certificate that Python previously accepted, that certificate needs to be reissued before the Python upgrade is deployed. Coordinate the reissuance with the PKI team so that affected services do not experience authentication failures at upgrade time.

Containerised workloads with pinned base images warrant particular attention. A `python:3.12-slim` base image built before the 46.0.6 fix may have `cryptography` at an older version baked in. The image rebuild must be explicit — an in-place `pip upgrade` in a running container does not persist. Add the version requirement to the `Dockerfile` and confirm the rebuilt image carries 46.0.6 before deployment.

## Failure Modes

**Upgraded in the system Python but the application runs in a pinned virtualenv.** This is the most common failure mode. The system `python3-cryptography` package reaches 46.0.6, `dpkg -l` confirms it, but the application virtualenv at `/opt/myapp/venv` has `cryptography==44.0.2` in its `requirements.txt`. The application continues to run the vulnerable version. The fix must be applied at the virtualenv level, and the pin in `requirements.txt` must be updated to `>=46.0.6`.

**SSSD upgraded but daemon not restarted.** The shared library is updated on disk, but the running SSSD process has already mapped the old `.so` into its address space. The old code continues to execute. `ldd` on the SSSD binary will show the new library path, but `cat /proc/$(pidof sssd)/maps | grep cryptography` shows the in-memory path at the time the process started. Only `systemctl restart sssd` causes the new library to be loaded. Verify with the `/proc` maps check from Step 3 after the restart.

**Custom compensation code conflicting with the corrected library.** Code that manually iterated `NameConstraints.excluded_subtrees` and rejected certificates matching those entries was written to work around the bug. After the upgrade, the library itself also rejects those certificates — before the custom code runs. If the custom code raises its own exception type and the call stack wraps that in specific error handling, the change in which layer raises the exception may cause the wrapping code to behave differently. Test these paths explicitly by sending a constrained-violating certificate through the validator and tracing the exception chain end-to-end.

**`cryptography` upgraded but `pyOpenSSL` still present and preferred.** Some older `requests` configurations use `pyOpenSSL` as the SSL backend via `urllib3`. If `pyOpenSSL` is installed and active, certificate validation may run through `pyOpenSSL`'s own bindings rather than the `cryptography` C extension layer directly. The CVE fix in `cryptography` 46.0.6 addresses the `cryptography` validation path; if `pyOpenSSL` is the active backend and it has its own handling of name constraints, the fix may not apply. Check which backend `requests` is using and whether `pyOpenSSL` is installed in the environment:

```bash
python3 -c "import urllib3; print(urllib3.util.ssl_.ssl_implementation())"
```

If this prints `pyopenssl`, assess `pyOpenSSL`'s own name constraint handling separately.

## Related Articles

- [PAM Hardening](/articles/linux/pam-hardening/)
- [SSH Certificate Authority](/articles/linux/ssh-certificate-authority/)
- [OT NPE Identity PKI](/articles/cross-cutting/ot-npe-identity-pki/)
- [Python Cryptography Buffer Overflow](/articles/cross-cutting/python-cryptography-buffer-overflow/)
- [TLS Certificate Management](/articles/network/tls-nginx-envoy/)
