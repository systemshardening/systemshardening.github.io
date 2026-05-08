---
title: "Maven and Gradle Build Security: Supply Chain Hardening for Java/JVM Projects"
description: "Maven Central and Gradle Plugin Portal are high-value supply chain targets. Dependency verification with checksums and PGP, OWASP Dependency-Check integration, private repository proxies, wrapper JAR validation, artifact signing, and reproducible builds close the attack surface."
slug: maven-gradle-build-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - maven
  - gradle
  - java-security
  - dependency-verification
  - artifact-signing
personas:
  - security-engineer
  - platform-engineer
article_number: 524
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/maven-gradle-build-security/
---

# Maven and Gradle Build Security: Supply Chain Hardening for Java/JVM Projects

## Problem

Maven Central hosts over 600,000 artifacts. The Gradle Plugin Portal hosts thousands more. Both are resolved over the public internet by default, with no verification beyond a version string. A build tool that trusts the registry to serve correct content is one compromised artifact away from running malicious code on every developer machine and CI runner that builds your project.

The attack surface is wider than most Java teams realise. Maven Central artifacts are signed with PGP, but Maven does not verify those signatures by default. Gradle resolves plugins at configuration time — before any task runs — meaning a malicious Gradle plugin can exfiltrate secrets before the build even starts. The Maven Wrapper and Gradle Wrapper JARs are binary files committed to source control or downloaded at runtime; either can be substituted for a backdoored copy without triggering a code review.

This article covers five independent layers of defence: dependency verification with checksums and PGP, OWASP Dependency-Check for known CVE detection, private repository proxies to eliminate direct public registry access from CI, wrapper integrity validation, artifact signing for publication, and reproducible builds that make output deterministic and auditable.

## Threat Model

- **Adversary 1 — Compromised Maven Central artifact:** A widely-used library (e.g., a logging framework) is compromised and serves a modified JAR. Maven resolves it without signature verification.
- **Adversary 2 — Dependency confusion:** An internal package name is published to Maven Central at a higher version. Maven's version resolution picks the public artifact over the internal one.
- **Adversary 3 — Malicious Gradle plugin:** A build plugin is compromised on the Gradle Plugin Portal. The plugin runs at configuration time with full access to the build environment including secrets.
- **Adversary 4 — Wrapper substitution:** The `gradle-wrapper.jar` or `mvnw`/`.mvn/wrapper/maven-wrapper.jar` is replaced in the repository with a backdoored binary. Every developer and CI runner that bootstraps the project executes it.
- **Adversary 5 — Build output tampering:** A compromised CI runner modifies a compiled JAR after the build completes. Without signed artifacts and reproducible build verification, the substitution goes undetected.
- **Blast radius:** A compromised build tool dependency or wrapper JAR runs with full CI environment permissions — all secrets, tokens, and source code are accessible. A compromised published artifact affects every downstream consumer.

## Configuration

### Gradle Dependency Verification

Gradle's built-in dependency verification generates and enforces a `verification-metadata.xml` file that records expected checksums and PGP signatures for every resolved artifact.

```bash
# Generate initial verification metadata for all dependencies:
./gradlew --write-verification-metadata sha256,pgp help

# This creates gradle/verification-metadata.xml.
# Commit this file to version control.
# On subsequent builds, Gradle verifies each artifact against the recorded checksums.
```

```xml
<!-- gradle/verification-metadata.xml (excerpt) -->
<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata
    xmlns="https://schema.gradle.org/dependency-verification"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="https://schema.gradle.org/dependency-verification
        https://schema.gradle.org/dependency-verification/dependency-verification-1.3.xsd">
  <configuration>
    <!-- Require PGP signatures in addition to checksums -->
    <verify-signatures>true</verify-signatures>
    <!-- Fail on signature verification errors (do not warn-only) -->
    <key-servers>
      <key-server uri="hkps://keys.openpgp.org"/>
      <key-server uri="hkps://keyserver.ubuntu.com"/>
    </key-servers>
    <ignored-keys>
      <!-- Add trusted key fingerprints; Gradle refuses untrusted signatures -->
    </ignored-keys>
  </configuration>
  <components>
    <component group="com.fasterxml.jackson.core" name="jackson-databind" version="2.17.1">
      <artifact name="jackson-databind-2.17.1.jar">
        <sha256 value="3e5a35e5...b91a" origin="Generated by Gradle"/>
        <pgp value="7D8EFFC2...A3B1"/>
      </artifact>
      <artifact name="jackson-databind-2.17.1.pom">
        <sha256 value="a4f22c1d...9e3f" origin="Generated by Gradle"/>
      </artifact>
    </component>
  </components>
</verification-metadata>
```

```kotlin
// settings.gradle.kts — restrict plugin resolution to known sources only
pluginManagement {
    repositories {
        // Use your internal Nexus/Artifactory proxy instead of the public portal
        maven {
            url = uri("https://nexus.internal.example.com/repository/gradle-plugins/")
            credentials {
                username = providers.environmentVariable("NEXUS_USER").get()
                password = providers.environmentVariable("NEXUS_PASS").get()
            }
        }
        // Explicitly remove the public Gradle Plugin Portal
        // gradlePluginPortal()   <-- do NOT include this in hardened builds
    }
    // Require dependency verification for plugin dependencies too
    dependencyResolutionManagement {
        repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    }
}
```

When a dependency's checksum or PGP signature does not match `verification-metadata.xml`, the build fails immediately with a clear error identifying the artifact. Review the diff carefully before regenerating: a changed checksum for an existing version is a red flag.

### Maven Dependency Verification

Maven does not have a built-in equivalent of Gradle's `verification-metadata.xml`, but several controls combine to provide equivalent coverage.

**Enforce HTTPS-only resolution.** Maven resolves artifacts over HTTP by default if the repository URL is `http://`. Maven 3.8.1+ blocks HTTP repositories by default; verify your configuration does not re-enable them:

```xml
<!-- .mvn/local-settings.xml — committed to the repository, applies in CI -->
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <mirrors>
    <!-- Block all HTTP (non-TLS) repository access -->
    <mirror>
      <id>block-http</id>
      <mirrorOf>external:http:*</mirrorOf>
      <url>https://0.0.0.0/</url>
      <blocked>true</blocked>
    </mirror>
    <!-- Route all artifact resolution through your internal proxy -->
    <mirror>
      <id>nexus-proxy</id>
      <mirrorOf>central</mirrorOf>
      <url>https://nexus.internal.example.com/repository/maven-public/</url>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>nexus-proxy</id>
      <username>${env.NEXUS_USER}</username>
      <password>${env.NEXUS_PASS}</password>
    </server>
  </servers>
</settings>
```

```bash
# Verify all dependency checksums against Maven Central's published checksums:
./mvnw dependency:resolve -Dmaven.artifact.threads=4

# Maven validates SHA-1/MD5 checksums on all downloaded artifacts by default.
# To upgrade to SHA-256 enforcement (Maven 3.9+):
# Set in .mvn/maven.config:
echo "-Daether.checksums.algorithms=SHA-256,SHA-1" >> .mvn/maven.config

# List all resolved dependencies with their sources for audit:
./mvnw dependency:tree -Dverbose
```

**Pin the Maven Wrapper download URL and checksum** in `.mvn/wrapper/maven-wrapper.properties`:

```properties
# .mvn/wrapper/maven-wrapper.properties
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip
distributionSha256Sum=706f01b20dec0305a822ab614d51f32b07ee11d0218175e55450242e49d2156e
wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.2.0/maven-wrapper-3.2.0.jar
wrapperSha256Sum=e436f7f9f4c5fa41b26e0e3db91f1dfa64ca1af6a33b8e0d2c8b7f8d4f1e2a3
```

Maven Wrapper 3.2.0+ validates `wrapperSha256Sum` before executing the wrapper JAR. If the JAR on disk does not match, the wrapper refuses to run.

### OWASP Dependency-Check Integration

OWASP Dependency-Check scans your resolved dependencies against the National Vulnerability Database (NVD) and flags JARs with known CVEs.

**Maven integration:**

```xml
<!-- pom.xml -->
<build>
  <plugins>
    <plugin>
      <groupId>org.owasp</groupId>
      <artifactId>dependency-check-maven</artifactId>
      <version>9.2.0</version>
      <configuration>
        <!-- Fail the build if any dependency has a CVSS score >= 7.0 (high) -->
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <!-- Suppress false positives with a reviewed suppression file -->
        <suppressionFiles>
          <suppressionFile>${project.basedir}/.owasp/suppressions.xml</suppressionFile>
        </suppressionFiles>
        <!-- Use a local NVD mirror or API key for reliable CI performance -->
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
        <!-- Include transitive dependencies -->
        <skipProvidedScope>false</skipProvidedScope>
        <skipRuntimeScope>false</skipRuntimeScope>
        <formats>
          <format>HTML</format>
          <format>JUNIT</format>
          <format>SARIF</format>
        </formats>
      </configuration>
      <executions>
        <execution>
          <goals>
            <!-- Run during the verify phase in CI -->
            <goal>check</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

```bash
# Run the check:
./mvnw verify -Ddependency-check.skip=false

# For pull request scanning only (faster feedback):
./mvnw org.owasp:dependency-check-maven:check \
  -DfailBuildOnCVSS=7 \
  -DnvdApiKey="${NVD_API_KEY}"
```

**Gradle integration:**

```kotlin
// build.gradle.kts
plugins {
    id("org.owasp.dependencycheck") version "9.2.0"
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    suppressionFile = "config/owasp-suppressions.xml"
    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: ""
    }
    formats = listOf("HTML", "JUNIT", "SARIF")
    // Scan all configurations including testImplementation
    scanConfigurations = configurations.names.toList()
}
```

```bash
# Run in CI:
./gradlew dependencyCheckAnalyze

# The SARIF output can be uploaded to GitHub Advanced Security:
# (add to your GitHub Actions workflow)
# - uses: github/codeql-action/upload-sarif@v3
#   with:
#     sarif_file: build/reports/dependency-check-report.sarif
```

Maintain a suppression file under version control. Each suppression must include a `notes` element explaining why the CVE is acceptable and an expiry date:

```xml
<!-- config/owasp-suppressions.xml -->
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <suppress until="2026-09-01Z">
    <notes>CVE-2024-XXXXX: only exploitable via the XML parser path we do not use.
    Reviewed by security team 2026-05-07. Ticket: SEC-4421.</notes>
    <cve>CVE-2024-XXXXX</cve>
  </suppress>
</suppressions>
```

### Private Nexus/Artifactory Proxy

Routing all artifact resolution through an internal proxy (Nexus Repository Manager or JFrog Artifactory) eliminates direct internet access from CI runners and provides a single point for security policy enforcement.

**Artifactory proxy group repository** — create a virtual repository that aggregates:
1. Your internal release/snapshot repositories (highest priority).
2. A remote proxy of Maven Central with malware scanning enabled.
3. A remote proxy of the Gradle Plugin Portal (if using Gradle plugins).

```xml
<!-- Maven settings that enforce proxy use in CI -->
<!-- Injected via MAVEN_OPTS or -s flag in CI, never stored in the repo root -->
<settings>
  <mirrors>
    <mirror>
      <id>artifactory-virtual</id>
      <!-- Mirror ALL repositories, including snapshots -->
      <mirrorOf>*</mirrorOf>
      <url>https://artifactory.internal.example.com/artifactory/libs-virtual/</url>
    </mirror>
  </mirrors>
  <profiles>
    <profile>
      <id>artifactory</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://artifactory.internal.example.com/artifactory/libs-virtual/</url>
          <snapshots>
            <enabled>false</enabled>
          </snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>artifactory</activeProfile>
  </activeProfiles>
</settings>
```

```kotlin
// settings.gradle.kts — enforce proxy-only resolution in Gradle
dependencyResolutionManagement {
    // FAIL if any build script adds its own repositories
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            name = "ArtifactoryVirtual"
            url = uri("https://artifactory.internal.example.com/artifactory/libs-virtual/")
            credentials {
                username = providers.environmentVariable("ARTIFACTORY_USER").orNull
                password = providers.environmentVariable("ARTIFACTORY_PASS").orNull
            }
        }
    }
}
```

Block outbound TCP/443 from CI runners to `repo1.maven.org`, `plugins.gradle.org`, and `repo.maven.apache.org` at the network level. Resolution that bypasses the proxy fails the build at the network layer rather than silently succeeding.

### Wrapper Security

Both the Maven Wrapper and Gradle Wrapper bootstrap the build tool from a downloaded binary. That binary must be verified.

**Gradle Wrapper validation:**

```bash
# Verify the wrapper JAR using the official Gradle checksum API:
EXPECTED=$(curl -s "https://services.gradle.org/versions/current" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['wrapperChecksumUrl'])")
ACTUAL=$(sha256sum gradle/wrapper/gradle-wrapper.jar | awk '{print $1}')

EXPECTED_HASH=$(curl -s "$EXPECTED")
if [ "$ACTUAL" != "$EXPECTED_HASH" ]; then
  echo "FAIL: gradle-wrapper.jar checksum mismatch"
  echo "  expected: $EXPECTED_HASH"
  echo "  actual:   $ACTUAL"
  exit 1
fi
echo "OK: gradle-wrapper.jar verified"
```

Add this check to your CI pipeline as a step that runs before `./gradlew`:

```yaml
# .github/workflows/verify-wrapper.yml (or inline in your main workflow)
- name: Validate Gradle Wrapper
  uses: gradle/actions/wrapper-validation@v4
  # This action verifies gradle-wrapper.jar against Gradle's published checksums
  # and fails the workflow if the JAR has been tampered with.
```

**Gradle Wrapper properties** — pin the distribution checksum:

```properties
# gradle/wrapper/gradle-wrapper.properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.7-bin.zip
distributionSha256Sum=194717442575a6f96e1c1befa2c30e9a4fc90f701d7aee33eb879b79e7ff05c0
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
```

With `distributionSha256Sum` set, the wrapper verifies the downloaded distribution ZIP before extracting it. A tampered distribution fails immediately.

### Signing Artifacts for Publication

Artifacts published to Maven Central must be signed with PGP. Artifacts published to internal repositories should be as well.

**Maven GPG signing:**

```xml
<!-- pom.xml — signing plugin, activated during the release profile -->
<profiles>
  <profile>
    <id>release</id>
    <build>
      <plugins>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-gpg-plugin</artifactId>
          <version>3.2.4</version>
          <executions>
            <execution>
              <id>sign-artifacts</id>
              <phase>verify</phase>
              <goals>
                <goal>sign</goal>
              </goals>
              <configuration>
                <!-- Key fingerprint from CI secret, not hardcoded -->
                <keyname>${env.GPG_KEY_FINGERPRINT}</keyname>
                <passphraseServerId>gpg-passphrase</passphraseServerId>
                <!-- Use gpg2 for non-interactive passphrase handling in CI -->
                <gpgArguments>
                  <arg>--pinentry-mode</arg>
                  <arg>loopback</arg>
                </gpgArguments>
              </configuration>
            </execution>
          </executions>
        </plugin>
      </plugins>
    </build>
  </profile>
</profiles>
```

```bash
# CI: import the signing key from a secret, then sign during deploy
echo "${GPG_PRIVATE_KEY}" | gpg --batch --import
./mvnw deploy -P release \
  -Dgpg.passphrase="${GPG_PASSPHRASE}" \
  -DskipTests
```

**Gradle signing plugin:**

```kotlin
// build.gradle.kts
plugins {
    signing
    `maven-publish`
}

signing {
    // Read key material from environment variables — never from files committed to git
    val signingKey: String? = System.getenv("GPG_SIGNING_KEY")
    val signingPassword: String? = System.getenv("GPG_SIGNING_PASSWORD")
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            // signing{} above will sign all published artifacts
        }
    }
    repositories {
        maven {
            name = "NexusReleases"
            url = uri("https://nexus.internal.example.com/repository/releases/")
            credentials {
                username = System.getenv("NEXUS_USER")
                password = System.getenv("NEXUS_PASS")
            }
        }
    }
}
```

Store the GPG private key as a CI secret (GitHub Actions secret, Vault secret, or equivalent). Rotate it annually and record the rotation in your key management inventory.

### Reproducible Builds

A reproducible build produces byte-for-byte identical output from the same source input. Without reproducibility, a compromised CI runner can alter build output without touching source code. With reproducibility, two independent build systems can compare their outputs; a discrepancy indicates tampering.

**Maven reproducible builds** — the `maven-artifact` plugin records build metadata and enables output comparison:

```xml
<!-- pom.xml -->
<properties>
  <!-- SOURCE_DATE_EPOCH makes timestamp-dependent output deterministic -->
  <!-- Set in CI: export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) -->
  <project.build.outputTimestamp>2026-05-07T00:00:00Z</project.build.outputTimestamp>
</properties>

<build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-artifact-plugin</artifactId>
      <version>3.5.1</version>
      <executions>
        <execution>
          <id>buildinfo</id>
          <goals>
            <!-- Generates a .buildinfo file recording checksums of all outputs -->
            <goal>buildinfo</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
    <!-- Ensure JAR manifest timestamps are neutralised -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-jar-plugin</artifactId>
      <version>3.4.2</version>
      <configuration>
        <archive>
          <manifestEntries>
            <!-- Do not include JDK version or build machine hostname in manifest -->
            <Built-By>reproducible-build</Built-By>
          </manifestEntries>
        </archive>
      </configuration>
    </plugin>
  </plugins>
</build>
```

```bash
# CI: set SOURCE_DATE_EPOCH from the last git commit timestamp
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
./mvnw verify artifact:compare
# artifact:compare checks the local build output against the previously published .buildinfo
```

**Gradle reproducible builds:**

```kotlin
// build.gradle.kts
tasks.withType<AbstractArchiveTask>().configureEach {
    // Neutralise filesystem timestamps in ZIP/JAR entries
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// Set SOURCE_DATE_EPOCH in CI from the last git commit:
// export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
// Gradle 7+ respects SOURCE_DATE_EPOCH for archive timestamps automatically.
```

```bash
# Verify reproducibility by building twice and comparing outputs:
./gradlew clean jar
cp build/libs/myapp-1.0.jar /tmp/first-build.jar

./gradlew clean jar
sha256sum build/libs/myapp-1.0.jar /tmp/first-build.jar
# Both hashes must match for the build to be reproducible.

# For publication, generate and publish a .buildinfo alongside the JAR:
./gradlew clean jar generateMetadataFileForMavenJavaPublication
```

## Expected Behaviour

- Every Gradle build verifies `verification-metadata.xml` checksums; a new or modified dependency that is not in the metadata file fails the build.
- Every Maven build resolves artifacts over TLS through the internal proxy; direct connections to Maven Central are blocked at the network layer.
- OWASP Dependency-Check runs on every pull request; a dependency with CVSS >= 7 blocks merge until remediated or suppressed with a documented justification.
- The Gradle wrapper validation action fails the workflow if `gradle-wrapper.jar` does not match the published Gradle checksum.
- Published artifacts are PGP-signed; the signing key is stored in a secrets manager, not committed to the repository.
- Maven builds with `SOURCE_DATE_EPOCH` set produce the same SHA-256 output on two consecutive runs from clean.

## Trade-offs

| Control | Security Gain | Operational Cost | Mitigation |
|---|---|---|---|
| `verification-metadata.xml` | Detects compromised or substituted JARs | Must update on every dependency version bump | Run `--write-verification-metadata` in a dedicated update PR; the diff surfaces exactly which artifacts changed. |
| OWASP Dependency-Check | Catches known CVEs before they reach production | NVD API rate limits can slow CI; false positives accumulate | Use an NVD API key; maintain a suppression file with expiry dates reviewed quarterly. |
| Private proxy (Nexus/Artifactory) | Eliminates direct internet access from CI; caches approved versions | Proxy must be highly available; cache invalidation policy needed | Run the proxy in HA mode; configure a retention policy that keeps last N versions of each artifact. |
| PGP wrapper distribution checksum | Detects tampered wrapper JARs | Wrapper checksum must be updated with each Gradle version bump | Use the `gradle/actions/wrapper-validation` action; it fetches the authoritative checksum automatically. |
| Reproducible builds | Enables independent build verification; detects CI runner compromise | Some plugins emit non-deterministic output (timestamps, random UUIDs in manifests) | Identify non-deterministic plugins with `reproducible-builds.org/tools/`; configure them to use stable values. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Verification metadata out of date | Build fails: "Checksums for artifact X are missing from verification-metadata.xml" | Immediate build failure | Run `./gradlew --write-verification-metadata sha256,pgp help`; review the diff before committing. |
| NVD API unavailable | OWASP check fails or skips CVE data | CI job exits non-zero; log shows HTTP 503 from NVD | Configure `failOnError=false` for NVD connectivity failures only; alert separately. |
| Proxy outage | All dependency resolution fails in CI | Build failure at dependency resolution phase | Runbook: switch mirror URL to secondary proxy; DNS failover if proxies are behind a load balancer. |
| GPG key expiry | Maven deploy fails: "secret key not available" | Release pipeline failure | Set a calendar reminder 30 days before key expiry; extend validity with `gpg --edit-key`. |
| Non-reproducible output after plugin update | `artifact:compare` or SHA-256 diff fails between two builds | CI reproducibility check fails | Bisect plugin upgrades; file a bug with the plugin maintainer; pin to last reproducible version. |

## Related Articles

- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Private Package Registry Security: Dependency Confusion and Namespace Protection](/articles/cicd/private-package-registry-security/)
- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [SBOM Generation and Consumption: CycloneDX, SPDX, and Dependency Graphs](/articles/cicd/sbom/)
