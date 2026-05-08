---
title: "Jenkins Security Hardening: Authentication, Plugin Management, and Agent Isolation"
description: "Jenkins is one of the most common CI/CD platforms and one of the most commonly compromised. Default credentials, unauthenticated endpoints, unaudited plugins, and agents with excessive host access create a broad attack surface. Hardening Jenkins requires authentication enforcement, plugin minimisation, and agent sandboxing."
slug: "jenkins-security-hardening"
date: 2026-05-01
lastmod: 2026-05-01
category: "cicd"
tags: ["jenkins", "authentication", "plugins", "agents", "cicd-security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 290
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/jenkins-security-hardening/index.html"
---

# Jenkins Security Hardening: Authentication, Plugin Management, and Agent Isolation

## Problem

Jenkins remains one of the most widely deployed CI/CD platforms, and it is consistently listed among the most frequently exploited systems in production environments. The combination of complexity (thousands of plugins), age (many deployments are a decade old), and privileged access (credentials for every system it deploys to) makes Jenkins an attractive target.

Common vulnerabilities and misconfigurations:

- **Anonymous access to the Jenkins UI and API.** Jenkins ships with security disabled by default in older versions. Many production instances have anonymous read access enabled, exposing build logs, environment variables, and credential names.
- **Default admin credentials.** The initial setup wizard may be bypassed, leaving credentials as `admin`/`admin`. Credential stuffing tools target Jenkins instances at known ports (8080, 8443).
- **Agents running as root or with host mounts.** Jenkins agents execute build jobs. An agent configured with `--privileged` Docker access, or running as root with host filesystem mounts, gives any pipeline code root access to the host.
- **Unapproved plugin installation.** Jenkins plugins run with the same JVM permissions as the Jenkins controller. A malicious plugin — or a legitimate plugin with a supply chain compromise — has access to all stored credentials, can exfiltrate secrets from the credential store, and can modify pipeline execution.
- **Script console access to admins.** The Jenkins script console provides a Groovy interpreter with full JVM access. Any admin (or any user with the Run Scripts permission) can execute arbitrary code in the Jenkins JVM and read all stored credentials.
- **Exposed JNLP agent port.** The JNLP agent port (50000) allows agents to connect to the controller. An attacker who can reach this port can attempt to connect a rogue agent and intercept jobs or inject malicious build steps.
- **No build isolation.** Build jobs run in shared workspaces. A pipeline can read artefacts from previous jobs, access workspace data from concurrent jobs, or persist files to influence future job execution.

**Target systems:** Jenkins LTS 2.440+ (Java 17+); Jenkins Kubernetes Plugin for ephemeral agents; Jenkins Configuration as Code (JCasC) 1.58+; Matrix Authorization Strategy Plugin; Credentials Binding Plugin.

## Threat Model

- **Adversary 1 — Unauthenticated API access:** An attacker reaches the Jenkins URL (public IP, misconfigured Ingress) and accesses the REST API anonymously. They enumerate jobs, read build logs (containing secrets printed to console), and download build artefacts.
- **Adversary 2 — Credential exfiltration via script console:** An attacker who has compromised an admin account (phishing, credential stuffing) uses the Groovy script console to iterate over the Jenkins credential store and print all stored credentials in plaintext.
- **Adversary 3 — Malicious pipeline code execution on agent:** A developer (or an attacker with developer-level access) commits a `Jenkinsfile` that mounts the host Docker socket, reads the agent's IAM role credentials, or exfiltrates the Jenkins agent's workspace files.
- **Adversary 4 — Compromised plugin supply chain:** An attacker compromises the release process for a widely-used Jenkins plugin. The plugin update distributed via the Jenkins Update Centre contains a backdoor that reads the Jenkins credential store at startup.
- **Adversary 5 — JNLP rogue agent:** An attacker connects a rogue agent to the Jenkins controller via the JNLP port. The controller assigns jobs to the rogue agent. Build credentials are transmitted to the rogue agent's environment.
- **Access level:** Adversaries 1 and 2 need network access and possibly valid credentials. Adversary 3 needs pipeline commit access. Adversary 4 exploits the plugin supply chain. Adversary 5 needs network access to port 50000.
- **Objective:** Extract all credentials from the Jenkins credential store; execute arbitrary code; compromise all systems Jenkins deploys to.
- **Blast radius:** Jenkins credential stores contain deployment keys, cloud provider credentials, database passwords, and TLS certificates for every system it manages. Full credential exfiltration is a complete infrastructure compromise.

## Configuration

### Step 1: Enable and Enforce Authentication

```groovy
// Configure via Jenkins Configuration as Code (JCasC).
// /var/jenkins_home/casc_configs/security.yaml

jenkins:
  securityRealm:
    # Use SSO via OIDC (Okta, Azure AD, Google).
    # Requires the OpenID Connect Authentication Plugin.
    oicAuth:
      clientId: "${JENKINS_OIDC_CLIENT_ID}"
      clientSecret: "${JENKINS_OIDC_CLIENT_SECRET}"
      wellKnownOpenIDConfigurationUrl: "https://company.okta.com/oauth2/default/.well-known/openid-configuration"
      userNameField: "email"
      groupsFieldName: "groups"
      disableSslVerification: false

  authorizationStrategy:
    # Matrix-based security: explicit grants per user/group.
    projectMatrix:
      permissions:
        # Admins: full access.
        - "GROUP:hudson.model.Hudson.Administer:jenkins-admins"
        # Developers: read jobs and trigger builds on specific folders.
        - "GROUP:hudson.model.Item.Read:jenkins-developers"
        - "GROUP:hudson.model.Item.Build:jenkins-developers"
        - "GROUP:hudson.model.Item.Cancel:jenkins-developers"
        # Anonymous: no access. This line must be absent (or explicitly denied).
        # Never add: "USER:hudson.model.Hudson.Read:anonymous"

  # Disable CLI over remoting (use HTTP CLI or disable entirely).
  slaveAgentPort: -1     # Disable JNLP port if using Kubernetes agents only.
  crumbIssuer:
    standard:
      excludeClientIPFromCrumb: false  # CSRF protection; keep enabled.

  # Disable Old Data Monitor and other diagnostic endpoints that expose config.
  disabledAdministrativeMonitors:
    - "jenkins.security.RekeySecretAdminMonitor"
```

Disable the script console for non-admin users (and restrict admin access):

```groovy
// Via JCasC — remove Run Scripts permission from all non-admin roles.
// In Matrix Authorization, do NOT grant:
// hudson.model.Hudson.RunScripts to any non-admin group.

// Enforce via Groovy init script (runs at startup):
// /var/jenkins_home/init.groovy.d/disable-script-console.groovy
import jenkins.model.Jenkins
import hudson.security.Permission

def instance = Jenkins.instance
// Verify script console is restricted to admins only — alert if not.
def strategy = instance.authorizationStrategy
// Log a warning if anonymous has any permissions.
```

### Step 2: Plugin Management and Minimisation

```bash
# Audit currently installed plugins.
curl -s -u "admin:${JENKINS_TOKEN}" \
  "https://jenkins.internal/pluginManager/api/json?depth=1" | \
  jq -r '.plugins[] | "\(.shortName) \(.version) \(.active)"' | \
  sort

# Check for plugins with known CVEs.
# Jenkins Security Advisory: https://www.jenkins.io/security/advisories/
# Use the Jenkins CLI to list outdated plugins.
java -jar jenkins-cli.jar -s https://jenkins.internal \
  -auth admin:$TOKEN \
  list-plugins | grep "available"
```

```yaml
# JCasC: pin plugin versions — prevent automatic updates pulling untested versions.
# plugins.yaml (used with plugin-installation-manager-tool)
plugins:
  - groupId: "org.jenkins-ci.plugins"
    artifactId: "kubernetes"
    version: "4029.v5712230ccb_f8"
  - groupId: "org.jenkins-ci.plugins"
    artifactId: "workflow-aggregator"
    version: "596.v8c21c963d92d"
  # Remove unused plugins:
  # - Do not include matrix-project, subversion, cvs, clearcase, or other
  #   plugins not in active use.
```

```bash
# Disable unused built-in plugins.
java -jar jenkins-cli.jar -s https://jenkins.internal -auth admin:$TOKEN \
  disable-plugin ant subversion cvs mercurial \
                 windows-slaves ssh-slaves

# Verify security updates are applied (weekly process).
# jenkins.io/security/advisories — subscribe to email alerts.
```

### Step 3: Kubernetes Ephemeral Agents

Replace persistent agents with ephemeral Kubernetes pods. Each build gets a fresh, isolated pod:

```yaml
# JCasC: configure Kubernetes cloud for ephemeral agents.
jenkins:
  clouds:
    - kubernetes:
        name: "kubernetes"
        serverUrl: ""   # Empty = use in-cluster config.
        namespace: "jenkins-agents"
        jenkinsUrl: "http://jenkins.jenkins-controller:8080"
        jenkinsTunnel: ""   # JNLP disabled; use WebSocket.
        webSocket: true    # WebSocket agent protocol (no JNLP port needed).
        
        podRetention: "never"  # Delete pod immediately after job completes.
        
        templates:
          - name: "default"
            serviceAccount: "jenkins-agent"   # Scoped SA, not cluster-admin.
            
            containers:
              - name: "jnlp"
                image: "jenkins/inbound-agent:latest-jdk17"
                resourceRequestCpu: "500m"
                resourceRequestMemory: "512Mi"
                resourceLimitCpu: "2"
                resourceLimitMemory: "2Gi"
            
            # Security context for the agent pod.
            runAsNonRoot: true
            runAsUser: 1000
            
            # No host path mounts. No Docker socket.
            volumes: []
            
            # Prevent agent pods from escalating privileges.
            activeDeadlineSeconds: 3600   # Kill pods running over 1 hour.
```

```yaml
# RBAC for jenkins-agent service account — minimal permissions.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: jenkins-agent
  namespace: jenkins-agents
rules:
  # Agents need to create/delete their own pods.
  - apiGroups: [""]
    resources: ["pods", "pods/exec", "pods/log"]
    verbs: ["get", "list", "watch", "create", "delete"]
  # NOT: secrets, configmaps, deployments, or any cluster-wide resources.
```

### Step 4: Credential Security

```groovy
// Use Jenkins Credentials Binding Plugin — credentials injected as environment
// variables, never printed to console.

// Jenkinsfile — credential injection.
pipeline {
  agent { label 'kubernetes' }
  stages {
    stage('Deploy') {
      steps {
        withCredentials([
          // Inject as masked environment variable.
          string(credentialsId: 'aws-api-key', variable: 'AWS_ACCESS_KEY'),
          // SSH key injected to temp file, cleaned up after step.
          sshUserPrivateKey(credentialsId: 'deploy-key',
                           keyFileVariable: 'SSH_KEY',
                           usernameVariable: 'SSH_USER'),
        ]) {
          // AWS_ACCESS_KEY is masked in all log output.
          sh 'aws s3 sync ./dist s3://my-bucket/'
        }
        // SSH_KEY temp file is automatically deleted.
      }
    }
  }
}
```

```yaml
# Store Jenkins master credentials in external secrets manager, not Jenkins credential store.
# Use the HashiCorp Vault Plugin or AWS Secrets Manager Credentials Provider.

# JCasC: configure Vault integration.
unclassified:
  hashicorpVault:
    configuration:
      vaultUrl: "https://vault.internal.example.com"
      vaultCredentialId: "vault-approle"  # AppRole for Jenkins to authenticate.
      engineVersion: 2
```

### Step 5: Network Access Controls

```yaml
# Restrict Jenkins access to internal networks only.
# Ingress with IP allowlist.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jenkins
  namespace: jenkins-controller
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # Rate limit login attempts.
    nginx.ingress.kubernetes.io/limit-rps: "5"
    nginx.ingress.kubernetes.io/limit-connections: "10"
spec:
  rules:
    - host: jenkins.internal.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: jenkins
                port:
                  number: 8080
```

```bash
# Block the JNLP agent port from external access.
# If using Kubernetes WebSocket agents, JNLP (50000) is not needed at all.
# Disable in JCasC:
# jenkins:
#   slaveAgentPort: -1  # Disabled.

# If JNLP required, restrict to agent subnet only.
nft add rule inet filter input \
  tcp dport 50000 \
  ip saddr != 10.200.0.0/24 \   # Agent subnet only.
  drop
```

### Step 6: Build Isolation

```groovy
// Jenkinsfile: prevent workspace pollution between builds.
pipeline {
  agent {
    kubernetes {
      // Each build gets a fresh pod with clean workspace.
      yaml '''
        apiVersion: v1
        kind: Pod
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            fsGroup: 1000
          containers:
          - name: build
            image: maven:3.9-eclipse-temurin-17@sha256:abc123
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: false
              capabilities:
                drop: ["ALL"]
            resources:
              limits:
                cpu: "2"
                memory: "4Gi"
      '''
    }
  }

  options {
    // Clean workspace before each build.
    cleanWs()
    // Timeout: kill builds that run too long.
    timeout(time: 60, unit: 'MINUTES')
    // Discard old build logs.
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }
}
```

### Step 7: Audit Logging

```groovy
// Enable audit logging via the Audit Trail Plugin.
// JCasC:
unclassified:
  auditTrailPlugin:
    loggers:
      - logFile:
          log: "/var/log/jenkins/audit.log"
          logSeparator: "\n"
    pattern: ".+"  # Log all URL patterns.
```

```yaml
# Ship audit logs to SIEM.
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/jenkins/audit.log
    fields:
      log_type: jenkins_audit
    fields_under_root: true
```

Alert on: admin login from unexpected IP; script console access; credential read via API; plugin installation without change ticket.

### Step 8: Telemetry

```
jenkins_builds_total{job, result}                      counter
jenkins_build_duration_seconds{job}                    histogram
jenkins_plugins_installed_total{}                      gauge
jenkins_plugins_with_updates_total{}                   gauge
jenkins_credential_access_total{credential, job}       counter
jenkins_failed_logins_total{user}                      counter
jenkins_agent_pod_start_seconds{}                      histogram
jenkins_queue_size{}                                   gauge
```

Alert on:

- `jenkins_failed_logins_total` spike — credential stuffing or brute-force against Jenkins login.
- `jenkins_plugins_with_updates_total` > 0 with security advisory tag — unpatched plugin with known CVE.
- Admin account used outside business hours — potential compromised admin credential.
- Script console accessed (audit log event) — every use requires post-hoc review.
- Agent pod running > 1 hour — potential runaway build or malicious long-running process.

## Expected Behaviour

| Signal | Default Jenkins | Hardened Jenkins |
|--------|----------------|-----------------|
| Anonymous API access | All jobs readable | Authentication required; 401 for anonymous |
| Credential exfiltration via script console | All secrets readable by admin | Script console restricted; Vault integration means secrets never in Jenkins store |
| Build with Docker socket | `--privileged` agent has host root | Kubernetes ephemeral pods; no host mounts; no Docker socket |
| Plugin CVE exploitation | Unpatched plugins loaded indefinitely | Weekly audit; version-pinned plugins; security advisories monitored |
| JNLP rogue agent | Can connect from any network | JNLP disabled; WebSocket agents require Jenkins auth |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Ephemeral Kubernetes agents | Fresh environment per build; no cross-build contamination | Pod startup time (20-60s); requires Kubernetes | Pre-warm pod pool; use spot/preemptible nodes for cost |
| External credential store (Vault) | Secrets never at rest in Jenkins | Vault dependency; more complex setup | Vault HA deployment; break-glass procedure for Vault outage |
| Plugin version pinning | Prevents untested updates from breaking builds | Manual effort to update pins | Automate via Renovate PR; weekly update batch |
| WebSocket agents (no JNLP port) | Eliminates 50000 attack surface | Requires Jenkins 2.289+ and modern agent image | Upgrade path well-documented; no functional regression |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OIDC provider unavailable | Nobody can log into Jenkins | Jenkins UI returns 503 | Keep break-glass admin account in secrets manager; restore OIDC |
| Vault unreachable | Builds fail with credential retrieval error | Build failure alert | Vault HA should prevent; cache credentials with short TTL |
| Agent pod OOMKilled | Build fails mid-run | `jenkins_build_duration_seconds` spike then failure | Increase pod memory limit; add memory monitoring to build |
| Plugin update breaks build | Pipeline fails after weekly plugin update | Build failure alert | Pin plugin version; roll back via JCasC and restart |
| CSRF crumb validation failure | API clients get 403 on POST | API error logs | Ensure API clients include crumb token; use API token auth which bypasses crumb |

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Securing CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
