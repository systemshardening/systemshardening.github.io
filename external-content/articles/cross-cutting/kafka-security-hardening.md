---
title: "Kafka Security Hardening: Authentication, ACLs, Encryption, and Schema Registry"
description: "An unprotected Kafka cluster is an open message bus: any client can produce or consume any topic. SASL authentication, ACLs, inter-broker TLS, and Schema Registry access controls close these gaps."
slug: "kafka-security-hardening"
date: 2026-04-30
lastmod: 2026-04-30
category: "cross-cutting"
tags: ["kafka", "sasl", "acl", "tls", "message-queue"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 253
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cross-cutting/kafka-security-hardening/index.html"
---

# Kafka Security Hardening: Authentication, ACLs, Encryption, and Schema Registry

## Problem

Apache Kafka is deployed at the centre of many production data pipelines: event streaming, change data capture, ML feature pipelines, audit log aggregation. Its default configuration has no authentication, no authorisation, and no encryption. Any client with network access can:

- Consume messages from any topic, including topics carrying PII, financial transactions, or security audit events.
- Produce messages to any topic, injecting fraudulent events into payment streams, poisoning ML training data, or flooding consumers.
- Create or delete topics, disrupting downstream services.
- Read the consumer group offsets of any group, revealing consumption patterns.

The specific gaps in default and partially-configured clusters:

- Listener configuration using `PLAINTEXT` protocol; all data in transit is unencrypted.
- No SASL configuration; any client connecting to the broker is accepted without credentials.
- ACLs exist but the default is `ALLOW` (not `DENY`); every principal has permission to everything unless explicitly denied.
- Inter-broker communication uses `PLAINTEXT`; a network attacker can observe or inject inter-broker replication traffic.
- Schema Registry has no authentication; any client can register, read, or delete schemas.
- MirrorMaker 2 replication uses a service account with overly broad ACLs.
- ZooKeeper (in older deployments) accessible without authentication; contains all cluster metadata.

**Target systems:** Kafka 3.6+ (KRaft mode preferred over ZooKeeper); Confluent Platform 7.6+; Amazon MSK 3.6+; Schema Registry 7.6+; MirrorMaker 2; Strimzi Kafka Operator 0.39+ (Kubernetes).

## Threat Model

- **Adversary 1 — Unauthenticated consumer:** An internal attacker (or a compromised service) connects to Kafka without credentials and consumes messages from the payments or audit topic.
- **Adversary 2 — Fraudulent producer:** An attacker injects crafted messages into a financial transaction topic, triggering fraudulent transfers or corrupting downstream analytics.
- **Adversary 3 — Topic deletion DoS:** An attacker with `ClusterAdmin` or unrestricted `Topic:Delete` permission deletes production topics, losing all buffered messages.
- **Adversary 4 — Network eavesdropping:** A network attacker intercepts inter-broker or client-broker traffic. Without TLS, all message payloads, consumer offsets, and metadata are in plaintext.
- **Adversary 5 — Schema Registry poisoning:** An attacker registers a malicious schema version that changes the field types in a way that causes consumers to deserialise data incorrectly, corrupting downstream systems.
- **Access level:** Adversaries 1 and 2 have internal network access (VPC or pod network). Adversary 3 has Kafka client credentials with overly broad ACLs. Adversary 4 has network capture capability. Adversary 5 has Schema Registry client access.
- **Objective:** Exfiltrate messages, inject fraudulent data, disrupt consumers, corrupt schemas.
- **Blast radius:** An unauthenticated Kafka cluster on an internal network is fully accessible to any compromised internal host. A destroyed topic is unrecoverable (unless retention-based; otherwise data is gone permanently).

## Configuration

### Step 1: Enable TLS for All Listeners

Configure TLS on both the client-facing listener and inter-broker listener:

```properties
# server.properties

# Listener configuration.
listeners=SASL_SSL://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
advertised.listeners=SASL_SSL://<broker-hostname>:9092
inter.broker.listener.name=SASL_SSL
listener.security.protocol.map=SASL_SSL:SASL_SSL,CONTROLLER:SASL_SSL

# TLS configuration.
ssl.keystore.location=/etc/kafka/ssl/kafka.server.keystore.jks
ssl.keystore.password=<keystore-password>
ssl.key.password=<key-password>
ssl.truststore.location=/etc/kafka/ssl/kafka.server.truststore.jks
ssl.truststore.password=<truststore-password>

# Require client TLS (mTLS for broker-to-broker).
ssl.client.auth=required   # For inter-broker. Use "requested" for clients.

# Protocol versions.
ssl.enabled.protocols=TLSv1.3,TLSv1.2
ssl.protocol=TLSv1.3
```

Generate certificates using cert-manager or openssl:

```bash
# Generate broker keystore.
keytool -keystore kafka.server.keystore.jks -alias localhost \
  -keyalg RSA -keysize 2048 -validity 365 -genkey \
  -dname "CN=<broker-hostname>,OU=Kafka,O=Example,C=US" \
  -storepass <keystore-password> -keypass <key-password>

# Generate CSR and sign with internal CA.
keytool -keystore kafka.server.keystore.jks -alias localhost \
  -certreq -file broker.csr -storepass <keystore-password>

openssl x509 -req -CA ca.crt -CAkey ca.key \
  -in broker.csr -out broker-signed.crt -days 365 -CAcreateserial

# Import signed cert and CA into keystore.
keytool -keystore kafka.server.keystore.jks \
  -alias CARoot -import -file ca.crt -storepass <keystore-password>
keytool -keystore kafka.server.keystore.jks \
  -alias localhost -import -file broker-signed.crt -storepass <keystore-password>

# Create truststore with the CA cert.
keytool -keystore kafka.server.truststore.jks \
  -alias CARoot -import -file ca.crt -storepass <truststore-password>
```

### Step 2: Configure SASL Authentication

SASL/SCRAM-SHA-512 is the recommended mechanism for username/password auth; SASL/OAUTHBEARER works with OIDC identity providers.

**SASL/SCRAM setup:**

```properties
# server.properties
sasl.enabled.mechanisms=SCRAM-SHA-512
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512

# KRaft controller listener.
sasl.mechanism.controller.protocol=SCRAM-SHA-512
```

```bash
# Create SCRAM credentials for each service account.
# In KRaft mode: use kafka-configs.sh.

kafka-configs.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --alter \
  --add-config 'SCRAM-SHA-512=[iterations=8192,password=<strong-random-password>]' \
  --entity-type users \
  --entity-name payments-producer

kafka-configs.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --alter \
  --add-config 'SCRAM-SHA-512=[iterations=8192,password=<strong-random-password>]' \
  --entity-type users \
  --entity-name analytics-consumer
```

**JAAS configuration for the broker:**

```
# /etc/kafka/kafka_server_jaas.conf
KafkaServer {
  org.apache.kafka.common.security.scram.ScramLoginModule required
  username="inter-broker"
  password="<inter-broker-password>";
};
```

```bash
# Pass JAAS config to the broker.
export KAFKA_OPTS="-Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf"
```

**Client configuration:**

```properties
# client.properties (for producers and consumers)
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required \
  username="payments-producer" \
  password="<password>";
ssl.truststore.location=/etc/kafka/ssl/client.truststore.jks
ssl.truststore.password=<truststore-password>
```

### Step 3: ACL Design — Default Deny

Kafka's default ACL behaviour depends on `allow.everyone.if.no.acl.found`:

```properties
# server.properties — CRITICAL configuration.
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
allow.everyone.if.no.acl.found=false   # Default DENY; must explicitly grant access.
super.users=User:admin;User:inter-broker
```

With `allow.everyone.if.no.acl.found=false`, every principal needs explicit ACL grants.

Define ACLs per service:

```bash
# Payments producer: can produce to the payments topic only.
kafka-acls.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --add \
  --allow-principal User:payments-producer \
  --operation Write \
  --operation DescribeConfigs \
  --topic payments

# Analytics consumer: can consume from analytics topics only.
kafka-acls.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --add \
  --allow-principal User:analytics-consumer \
  --operation Read \
  --operation Describe \
  --topic 'analytics-*' \
  --resource-pattern-type prefixed

# Allow consumer group offset commits.
kafka-acls.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --add \
  --allow-principal User:analytics-consumer \
  --operation Read \
  --group 'analytics-consumer-group'

# MirrorMaker 2 replication account: read source, write to destination.
kafka-acls.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --add \
  --allow-principal User:mirrormaker \
  --operation Read \
  --topic '*' \
  --resource-pattern-type prefixed

# Do NOT grant: Create, Delete, Alter, AlterConfigs to service accounts.
# Reserve those for the admin account with a separate secured credential.
```

Audit current ACLs:

```bash
kafka-acls.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --list
```

### Step 4: Topic-Level Hardening

Prevent accidental or malicious topic deletion and configure retention:

```bash
# Set retention on the payments topic (7 days; adjust to business requirement).
kafka-configs.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/admin.properties \
  --alter \
  --add-config 'retention.ms=604800000,min.insync.replicas=2' \
  --entity-type topics \
  --entity-name payments

# Enable topic-level deletion protection via ACL (no DELETE ACL for non-admin principals).
# Separately: disable auto topic creation.
```

```properties
# server.properties
auto.create.topics.enable=false   # Topics must be created explicitly; prevents namespace pollution.
delete.topic.enable=true           # Allow deletion, but control it via ACLs.
min.insync.replicas=2              # Require at least 2 replicas to acknowledge; prevents data loss.
```

### Step 5: Schema Registry Authentication

```yaml
# schema-registry.properties

# Enable HTTPS.
listeners=https://0.0.0.0:8081
ssl.keystore.location=/etc/schema-registry/ssl/schema-registry.keystore.jks
ssl.keystore.password=<keystore-password>

# Basic auth for Schema Registry clients.
authentication.method=BASIC
authentication.roles=admin,developer,read-only
authentication.realm=SchemaRegistry

# User credentials (use LDAP or an external auth provider for production).
# /etc/schema-registry/password.properties
# admin: <bcrypt-hash>,admin
# svc-payments: <bcrypt-hash>,developer
# monitoring: <bcrypt-hash>,read-only
```

Apply role-based access within Schema Registry:

```bash
# Grant a service account read-only access to Schema Registry.
curl -X POST \
  -u admin:<admin-password> \
  -H "Content-Type: application/json" \
  -d '{"operation": "READ", "resourceType": "SUBJECT", "resourceName": "*"}' \
  https://schema-registry:8081/security/1.0/principals/User:svc-analytics/roles/ResourceOwner/bindings
```

### Step 6: MirrorMaker 2 Hardening

MirrorMaker 2 replicates topics between clusters. Configure it with minimum necessary permissions:

```properties
# mm2.properties

# Source cluster authentication.
source.bootstrap.servers=source-kafka:9092
source.security.protocol=SASL_SSL
source.sasl.mechanism=SCRAM-SHA-512
source.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required \
  username="mirrormaker-source" password="<password>";

# Destination cluster authentication.
target.bootstrap.servers=target-kafka:9092
target.security.protocol=SASL_SSL
target.sasl.mechanism=SCRAM-SHA-512
target.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required \
  username="mirrormaker-target" password="<password>";

# Replicate only specific topics (allowlist, not all topics).
source->target.topics=payments,audit-events,analytics-.*

# Exclude internal topics.
source->target.topics.exclude=__consumer_offsets,__transaction_state,_schemas
```

ACLs for MirrorMaker source account (source cluster):

```bash
# Read access to replicated topics only.
kafka-acls.sh --bootstrap-server source-kafka:9092 \
  --add --allow-principal User:mirrormaker-source \
  --operation Read --operation Describe \
  --topic 'payments' --topic 'audit-events'

# Consumer group for checkpoint tracking.
kafka-acls.sh --bootstrap-server source-kafka:9092 \
  --add --allow-principal User:mirrormaker-source \
  --operation Read --operation Describe --operation Write \
  --group 'mm2-offsets.*' --resource-pattern-type prefixed
```

### Step 7: Monitoring and Alerting

```
kafka_broker_active_controller_count                          gauge (alert if != 1)
kafka_broker_under_replicated_partitions                      gauge (alert if > 0)
kafka_consumer_lag{topic, group}                              gauge
kafka_acl_change_total{operation, resource}                   counter
kafka_authentication_failure_total{mechanism, listener}       counter
kafka_topic_deleted_total                                     counter
schema_registry_schema_registered_total{subject}              counter
schema_registry_authentication_failure_total                  counter
```

Alert on:

- `kafka_authentication_failure_total` spike — credential brute force or service misconfiguration.
- `kafka_topic_deleted_total` non-zero for production topics — unauthorised or accidental deletion; check ACL audit log.
- `kafka_acl_change_total` — any ACL change should be pre-approved; unexpected ACL grants are a red flag.
- `schema_registry_authentication_failure_total` — Schema Registry under access attempt.

## Expected Behaviour

| Signal | Default Kafka | Hardened Kafka |
|--------|--------------|---------------|
| Unauthenticated client connects | Accepted; full access | Rejected at handshake |
| Client reads payments topic without ACL | Succeeds (allow.everyone=true) | Denied (allow.everyone=false) |
| Inter-broker traffic | Plaintext | TLS-encrypted |
| Topic deleted by service account | Succeeds (no ACL restriction) | Denied (no Delete ACL granted) |
| Schema registered without auth | Succeeds | BASIC auth required |
| New topic auto-created | Created on produce | Blocked; admin must pre-create |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| SASL/SCRAM | Strong password-based auth | Password rotation requires broker config update | Automate via kafka-configs.sh in secrets rotation pipeline. |
| Default-deny ACLs | Least privilege enforced | Initial setup requires enumerating all ACLs | Generate ACL configs from service topology in GitOps; apply via IaC. |
| mTLS inter-broker | Broker impersonation prevented | Certificate rotation required | cert-manager automates rotation; Kafka supports hot reload of keystore in 3.x+. |
| Schema Registry BASIC auth | Prevents schema poisoning | Additional credential to manage | Integrate with LDAP/OIDC for SSO; same IdP as other services. |
| `auto.create.topics.enable=false` | Prevents topic proliferation | Services must pre-create topics | Add topic creation to service deployment; IaC manages topic lifecycle. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SCRAM credentials rotated without broker update | Producers/consumers fail to authenticate | `kafka_authentication_failure_total` spike; consumer lag grows | Rotate credentials atomically: create new creds, update clients, then revoke old. |
| Certificate expiry | TLS handshake fails; all connections drop | Broker logs show `SSLHandshakeException`; all consumers disconnect | Renew certificates; Kafka 3.x supports keystore hot reload without restart. |
| ACL misconfiguration blocks legitimate consumer | Consumer lag grows; zero messages consumed | Consumer lag alert; client logs show `TopicAuthorizationException` | Add correct ACL; consumer reconnects automatically. |
| `allow.everyone.if.no.acl.found=false` with no ACLs | All clients denied; cluster effectively unusable | All operations fail after enabling auth | Pre-create all required ACLs before enabling auth; test in staging first. |
| Schema Registry password lost | Clients cannot authenticate; schema lookups fail | Producer/consumer errors on schema operations | Reset BASIC auth config; update `password.properties`; restart Schema Registry. |
| MirrorMaker replication lag | Destination cluster lags source; DR failover has data gap | `kafka_consumer_lag{group="mm2-*"}` rising | Investigate network; increase MirrorMaker parallelism; ensure source ACLs allow reads. |

## Related Articles

- [Message Queue Hardening](/articles/cross-cutting/message-queue-hardening/)
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [cert-manager PKI Hardening](/articles/kubernetes/cert-manager-pki-hardening/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
- [OAuth 2.0 and OIDC Implementation Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
