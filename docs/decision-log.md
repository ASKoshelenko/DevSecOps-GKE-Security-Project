# Architecture Decision Records (ADR)

This document captures key architectural decisions for the DevSecOps GKE Security Project. Each record follows the ADR format: Context, Decision, Consequences.

---

## ADR-001: Use Workload Identity Federation Instead of Service Account Keys

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

The APT group (INC-2026-0042) gained initial access to the GCP environment through a stolen service account key exfiltrated from a compromised developer workstation. The key had `roles/editor` at the project level and no expiration, allowing persistent unauthorized access until discovered. Service account keys have fundamental security weaknesses:

- No automatic expiration (default: permanent)
- Can be copied, stored, and used from any location
- No inherent binding to the user or system that requested them
- Limited audit trail (no information about the original requester)
- Difficult to detect theft vs. legitimate use

### Decision

Eliminate all service account keys and implement Workload Identity Federation (WIF) for all external authentication flows.

- **GitHub Actions to GCP:** WIF pool with GitHub OIDC provider, restricted by org, repo, branch, and runner type
- **GKE pods to GCP APIs:** GKE Workload Identity (pod-level SA mapping via annotations)
- **Organization Policy:** `constraints/iam.disableServiceAccountKeyCreation` enforced project-wide

### Consequences

**Positive:**
- No long-lived credentials to steal or leak
- Tokens expire after 1 hour and cannot be refreshed without re-authentication
- Full audit trail linking API calls to specific GitHub workflows, users, and branches
- Branch-based access control (only `main` can trigger deployments)
- Runner environment restriction (only `github-hosted` runners accepted)

**Negative:**
- Higher configuration complexity compared to simply creating a SA key
- Dependency on GitHub OIDC provider availability
- Developers must understand the OIDC flow for troubleshooting
- Cannot use SA keys for local development (must use `gcloud auth` or ADC)

**Risks:**
- If GitHub OIDC provider has an outage, CI/CD pipelines will fail
- Mitigation: Cloud Build provides a secondary pipeline path with native GCP identity

---

## ADR-002: Choose Falco for Runtime Detection

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

The APT group deployed cryptominer pods and created persistence markers (`/tmp/.x` magic files) inside containers. Runtime detection is needed to catch activities that static scanning (Trivy) cannot detect: live process execution, file creation, network connections, and system call patterns.

Candidates evaluated:

| Tool | Architecture | K8s Integration | License | Maturity |
|------|-------------|----------------|---------|----------|
| **Falco** | eBPF / kernel module | Native (pods, namespaces, labels in alerts) | Apache 2.0 | CNCF Graduated |
| **Sysdig Secure** | eBPF (Falco-based) | Native | Commercial | Mature |
| **Tracee** | eBPF | Good | Apache 2.0 | CNCF Sandbox |

### Decision

Deploy Falco as the runtime detection engine, deployed as a DaemonSet with eBPF driver.

### Consequences

**Positive:**
- eBPF-based: zero user-space overhead, kernel-level visibility
- CNCF graduated: strong community, regular updates, proven in production
- Native Kubernetes context: alerts include pod name, namespace, deployment, labels
- Flexible rule language with macros and lists
- Pre-built rules for common threats: crypto mining, reverse shell, container escape, privilege escalation
- No application modification required
- Integrates with ELK, Prometheus, and PagerDuty

**Negative:**
- eBPF requires compatible kernel version (Linux 5.8+ for best features)
- Rule tuning needed to reduce false positives in production
- DaemonSet consumes resources on every node
- No network-level visibility (need Suricata for that)

**Trade-offs vs. alternatives:**
- Sysdig Secure: More polished UI but commercial license and cost; Falco provides the same core engine for free
- Tracee: Promising but CNCF Sandbox maturity; Falco has a larger rule ecosystem and broader adoption

---

## ADR-003: Choose Suricata for Network IDS

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

The APT group used C2 backconnect channels on specific ports (4444/Metasploit, 8443/Cobalt Strike, 6666-6667/IRC). While firewall rules block these ports, we need deeper network inspection for:
- Protocol detection regardless of port (e.g., IRC on port 443)
- Payload inspection for known malicious signatures
- TLS JA3/JA3S fingerprinting for encrypted C2
- Stratum protocol detection for crypto mining

Candidates evaluated:

| Tool | Architecture | Performance | Output Format | Maturity |
|------|-------------|------------|---------------|----------|
| **Suricata** | Multi-threaded | High | eve.json (structured JSON) | OISF-backed |
| **Snort** | Single-threaded (v2), multi-threaded (v3) | Moderate | Unified2 (binary) | Cisco-backed |
| **Zeek** | Connection-level analysis | High | TSV/JSON | CNCF project |

### Decision

Deploy Suricata as the network IDS, running as a DaemonSet that monitors node network interfaces.

### Consequences

**Positive:**
- Multi-threaded from the ground up: critical for high-throughput GKE clusters with many concurrent connections
- `eve.json` structured JSON output: integrates directly with Filebeat, Logstash, BigQuery without parsing
- Rich protocol detection: HTTP, TLS, DNS, SSH, SMTP, SMB, and more
- JA3/JA3S TLS fingerprinting for encrypted C2 detection
- Lua scripting for custom detection logic
- Emerging Threats and ET Pro rulesets available
- Active development by OISF with frequent rule updates

**Negative:**
- Requires careful tuning to avoid performance impact on GKE nodes
- DaemonSet mode adds resource overhead
- Encrypted traffic limits payload inspection (JA3 helps but is not full inspection)
- Rule management requires ongoing effort

**Trade-offs vs. alternatives:**
- Snort v2: Single-threaded, cannot handle GKE traffic volume; Snort v3 improves but Suricata's multi-threading is more mature
- Zeek: Excellent for connection analysis and metadata but lacks signature-based detection; best used alongside Suricata rather than instead of it

---

## ADR-004: Use ELK Stack for SIEM

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

Multiple security data sources need centralized collection, correlation, and visualization:
- Falco runtime alerts
- Suricata network IDS alerts
- Cloud Audit Logs
- VPC Flow Logs
- Trivy scan reports

Candidates evaluated:

| Tool | Deployment | Cost | K8s Support | Query Language |
|------|-----------|------|-------------|---------------|
| **ELK Stack** | Self-managed on K8s | Open-source (basic) | Native (ECK operator) | KQL, Lucene |
| **Splunk** | SaaS or self-managed | License per GB ingested | Good | SPL |
| **Chronicle** | GCP-native SaaS | Volume-based pricing | Good | YARA-L |

### Decision

Deploy the ELK (Elasticsearch, Logstash, Kibana) stack on GKE using the ECK (Elastic Cloud on Kubernetes) operator, with Filebeat DaemonSets for log collection.

### Consequences

**Positive:**
- Open-source: no per-GB licensing costs, crucial for high-volume security logging
- Kubernetes-native: ECK operator manages Elasticsearch clusters declaratively
- Filebeat DaemonSet: automatic log collection from all pods without sidecar injection
- Logstash: powerful enrichment pipeline (GeoIP, K8s metadata, threat intel correlation)
- Kibana: dashboards, alerting, and threat hunting UI out of the box
- Large ecosystem of pre-built security dashboards and detection rules
- Full control over data retention and storage

**Negative:**
- Operational overhead of managing Elasticsearch cluster (node scaling, shard management, upgrades)
- Elasticsearch requires significant memory (JVM heap) and disk for indexing
- No built-in SOAR (Security Orchestration, Automation, and Response) capabilities
- Basic license lacks machine learning anomaly detection (requires Elastic Security subscription)

**Trade-offs vs. alternatives:**
- Splunk: Superior query language (SPL) and out-of-box security content, but expensive at scale; SPL cost would exceed the project budget
- Chronicle: GCP-native with strong detection rules, but vendor lock-in and less flexible customization

---

## ADR-005: BigQuery for Vulnerability Analytics

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

Trivy Operator generates vulnerability scan results stored as Kubernetes CRDs. For long-term analysis, trend tracking, compliance reporting, and executive dashboards, this data needs to be stored in an analytical database. The data volume is moderate (thousands of vulnerability records per scan cycle) but queries need to span weeks or months.

### Decision

Use BigQuery as the analytical store for vulnerability data, fed by a Cloud Logging sink (raw logs) and a Python ETL script (parsed vulnerabilities).

**Table design:**
- `trivy_raw_logs`: Partitioned by `DATE(timestamp)`, clustered by severity/namespace/cluster
- `vulnerabilities`: Partitioned by `DATE(scan_timestamp)`, clustered by severity/image/namespace
- `require_partition_filter = TRUE` on both tables to prevent accidental full-table scans

### Consequences

**Positive:**
- Serverless: no cluster management, auto-scaling, no capacity planning
- Standard SQL: analysts and developers already know the query language
- Cost-effective: pay only for bytes scanned; partition pruning eliminates irrelevant data
- Native GCP integration: Cloud Logging can sink directly to BigQuery
- Supports views for pre-computed aggregations (latest vulnerabilities, summaries)
- Ideal for compliance reporting with scheduled queries

**Negative:**
- Not suitable for real-time alerting (ELK handles that)
- Streaming inserts have a per-row cost (use batched inserts in ETL script)
- No built-in visualization (use Looker Studio or Data Studio for dashboards)
- Partition filter requirement means queries must always include a date range

**Trade-offs vs. alternatives:**
- Elasticsearch: Already deployed for SIEM; could hold vulnerability data too, but BigQuery is more cost-effective for analytical queries spanning months
- Cloud SQL: Relational but requires server management; BigQuery is serverless and better for analytical patterns

---

## ADR-006: Trivy Operator for Vulnerability Scanning

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

Continuous vulnerability scanning of container images running in the GKE cluster is needed to detect vulnerable packages, misconfigurations, exposed secrets, and compliance violations. The scanner must operate as a Kubernetes-native component, automatically scanning new workloads as they are deployed.

Candidates evaluated:

| Tool | Architecture | Scope | K8s Native | License |
|------|-------------|-------|-----------|---------|
| **Trivy Operator** | K8s Operator + Jobs | Images, Config, Secrets, RBAC, SBOM, Compliance | Yes (CRD-based) | Apache 2.0 |
| **Grype** | CLI / CI integration | Images only | No (needs wrapper) | Apache 2.0 |
| **Clair** | Server + API | Images only | Partial | Apache 2.0 |
| **Prisma Cloud** | SaaS agent | Full | Yes | Commercial |

### Decision

Deploy Trivy Operator via Helm with Kustomize overlays for GKE-specific configurations. Standalone mode (each scan job downloads its own DB) for simplicity, with migration path to ClientServer mode for larger clusters.

### Consequences

**Positive:**
- Kubernetes operator pattern: auto-discovers and scans workloads, stores results as CRDs
- Comprehensive scanning: vulnerabilities, config audit, exposed secrets, RBAC, infra assessment, SBOM generation
- Compliance reporting: NSA and CIS benchmarks out of the box
- Active Aqua Security community with frequent updates
- CRD-based results: `kubectl get vulnerabilityreports` for immediate access
- Integrates with Cloud Logging via stdout JSON for BigQuery pipeline

**Negative:**
- Standalone mode: each scan job downloads ~40MB vulnerability DB (network overhead)
- Scan jobs consume node resources (mitigated by resource limits in values.yaml)
- Large clusters may need ClientServer mode to reduce DB download duplication
- CRD storage in etcd can grow large without compression (enabled via `compressLogs: true`)

**Trade-offs vs. alternatives:**
- Grype: Faster CLI scanning but no Kubernetes operator; would need custom CronJob + controller
- Clair: Requires separate server deployment, image-only scanning, less active community
- Prisma Cloud: Most comprehensive but commercial license and agent-based (SaaS dependency)

---

## ADR-007: Kind for Local Testing

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Security Team

### Context

Security demonstrations (container escape, API server crash) require a deliberately vulnerable Kubernetes cluster. This cluster must run specific (old) Kubernetes versions with intentional misconfigurations that would never be acceptable in production. Running these tests on GKE would be expensive and risky.

Candidates evaluated:

| Tool | Multi-node | Custom K8s Version | kubeadm-based | Docker Requirement |
|------|-----------|-------------------|---------------|-------------------|
| **Kind** | Yes | Yes (exact version) | Yes | Docker |
| **Minikube** | Limited | Yes | No (custom VM) | Docker/HyperKit/etc. |
| **k3d** | Yes | Limited (k3s versions) | No (k3s) | Docker |

### Decision

Use Kind (Kubernetes in Docker) for all local security testing, with a custom configuration that intentionally enables vulnerable settings.

### Consequences

**Positive:**
- Multi-node clusters: control-plane + worker, matching real cluster topology
- Exact Kubernetes version pinning: `kindest/node:v1.23.17` with SHA256 digest
- kubeadm-based: identical API server flags, kubelet configuration, and etcd setup to real clusters
- Fast creation: cluster ready in under 2 minutes
- Disposable: `kind delete cluster` for immediate cleanup
- kubeadm config patches: full control over API server, kubelet, and etcd settings
- Extra mounts: host filesystem and Docker socket for escape demonstrations

**Negative:**
- Docker-in-Docker: some syscall behavior differs from bare-metal (kernel CVEs depend on host kernel)
- Not suitable for GKE-specific features (Binary Authorization, Workload Identity)
- Single-host networking: does not replicate cloud VPC topology
- Resource-constrained: limited by developer workstation resources

**Trade-offs vs. alternatives:**
- Minikube: Simpler setup but limited multi-node support; VM-based mode slower than Kind
- k3d: Fast but uses k3s (different from kubeadm); cannot reproduce exact K8s API server flags

---

## ADR-008: Modular Terraform Structure

**Date:** 2026-02-18
**Status:** Accepted
**Deciders:** Infrastructure Team

### Context

The infrastructure spans multiple GCP services (VPC, GKE, BigQuery, IAM, Cloud Build) with complex dependencies. A monolithic Terraform configuration would be difficult to review, test, and maintain. Different team members work on different infrastructure components.

### Decision

Organize Terraform as a root module calling child modules, with one module per logical infrastructure component:

```
terraform/
  main.tf              # Root orchestration with dependency management
  modules/
    network/           # VPC, subnets, firewall, NAT
    gke/               # GKE cluster, node pools, security config
    bigquery/          # Dataset, tables, views
    iam/               # Service accounts, WIF, role bindings
    cloudbuild/        # Build triggers, pipeline configs
```

### Consequences

**Positive:**
- **Reusability:** Modules can be versioned and shared across environments (dev/staging/prod)
- **Independent testing:** Each module can be planned and validated in isolation
- **Team collaboration:** Network team owns `network/`, security team owns `iam/`, etc.
- **Blast radius:** Changes to one module produce a focused plan diff
- **Clear interfaces:** Module variables and outputs define explicit contracts
- **State segmentation:** Future migration to separate state files per module is straightforward

**Negative:**
- Cross-module dependencies require careful `depends_on` management
- Module outputs must be explicitly declared and wired through the root module
- More files to navigate compared to a single flat configuration
- Module versioning adds release management overhead if extracted to a registry

**Design principles applied:**
- Each module is self-contained with its own `main.tf`, `variables.tf`, `outputs.tf`
- Variables include validation rules and descriptive documentation
- Sensitive outputs are marked with `sensitive = true`
- Labels propagate from root to all modules for consistent cost tracking
- API enablement happens in the root module to avoid race conditions
