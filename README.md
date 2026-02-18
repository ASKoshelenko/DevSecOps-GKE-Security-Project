# DevSecOps GKE Security Project

## Executive Summary

This project implements a comprehensive security posture for GCP/GKE infrastructure in response to an active threat from a Russian APT group (tracked internally as **INC-2026-0042**). The threat actor employed crypto mining and cloud penetration tactics, gaining initial access through a stolen service account key exfiltrated from a compromised developer workstation.

The stolen key granted `roles/editor` on the production project, enabling lateral movement into GKE clusters, data exfiltration from BigQuery, and deployment of cryptominer pods through Cloud Build impersonation. The attacker's tactics included creation of "magic" marker files in `/tmp`, C2 backconnect channels through specific ports (4444, 8443, 6666/6667), and persistent access mechanisms.

This project eliminates the root cause (long-lived SA keys), deploys defense-in-depth detection and prevention controls, and documents the entire security architecture as Infrastructure as Code.

---

## Threat Model

### APT Profile

| Attribute | Detail |
|-----------|--------|
| **Internal Tracking** | INC-2026-0042 |
| **Attribution** | Russian-nexus APT group |
| **Initial Access** | Stolen GCP service account key from compromised developer workstation |
| **Objectives** | Crypto mining, persistent cloud access, data exfiltration |
| **Capabilities** | GCP API manipulation, Kubernetes workload deployment, network pivoting |

### Tactics, Techniques, and Procedures (TTPs)

| Tactic | Technique | Observable |
|--------|-----------|------------|
| **Initial Access** | Valid Accounts: Cloud Accounts (T1078.004) | SA key used from non-corporate IP |
| **Execution** | Deploy Container (T1610) | Cryptominer pods deployed via Cloud Build |
| **Persistence** | Create Account (T1136) | Magic file `/tmp/.x` as persistence marker |
| **Command & Control** | Non-Standard Port (T1571) | Backconnect on ports 4444, 8443, 6666/6667 |
| **Impact** | Resource Hijacking (T1496) | Crypto mining consuming cluster resources |
| **Lateral Movement** | Exploitation of Remote Services (T1210) | Pivoted from Cloud Build to GKE |
| **Defense Evasion** | Impersonation (T1656) | Impersonated Cloud Build SA for deployments |

### Response Strategy

| Problem | Solution | Implementation |
|---------|----------|----------------|
| Stolen SA keys | Workload Identity Federation | `federation/terraform-wif.tf` |
| No runtime detection | Falco + Suricata IDS | `helm/falco/`, `helm/suricata/` |
| No centralized logging | ELK Stack + BigQuery | `bigquery/`, `scripts/` |
| No vulnerability management | Trivy Operator | `helm/trivy-operator/` |
| Manual infrastructure | Terraform + Cloud Build | `terraform/`, `cloudbuild/` |
| Insecure CI/CD | Hardened GitHub Actions | `github-actions/` |

---

## Architecture

```
                                   Internet
                                      |
                              +-------+-------+
                              | Cloud Armor   |
                              | WAF / DDoS    |
                              +-------+-------+
                                      |
                              +-------+-------+
                              | Cloud Load    |
                              | Balancer      |
                              +-------+-------+
                                      |
+---------------------------------------------------------------------+
|                      GCP Project (devsecops-demo)                   |
|                                                                     |
|  +-------------------------------+   +---------------------------+  |
|  |   VPC: devsecops-vpc-prod     |   |   IAM & Identity          |  |
|  |                               |   |                           |  |
|  |  Firewall Rules:              |   |  Workload Identity Pool   |  |
|  |  - DENY C2 ports (pri:100)   |   |  +-- GitHub OIDC Provider |  |
|  |  - DENY crypto ports (pri:500)|  |  +-- Deployer SA          |  |
|  |  - ALLOW internal (pri:1000) |   |  +-- Reader SA            |  |
|  |  - ALLOW health checks       |   |  +-- Scanner SA           |  |
|  |  - VPC Flow Logs enabled     |   |  +-- BigQuery Writer SA   |  |
|  |                               |   |  +-- Cloud Build SA       |  |
|  |  Cloud NAT (controlled egress)|   |                           |  |
|  |  Cloud Router (BGP ASN 64514)|   |  Org Policy Constraints:  |  |
|  |                               |   |  - No SA key creation     |  |
|  +-------------------------------+   +---------------------------+  |
|                |                                                    |
|  +-------------+---------------------------------------------+     |
|  |              GKE Cluster: devsecops-gke                   |     |
|  |              (Private, Shielded, Workload Identity)       |     |
|  |                                                           |     |
|  |  +-------------------+  +-------------------+             |     |
|  |  | Node Pool         |  | Security Stack    |             |     |
|  |  | e2-standard-4 x2  |  |                   |             |     |
|  |  | Shielded Nodes    |  | +---------------+ |             |     |
|  |  | Binary AuthZ      |  | | Trivy Operator| |             |     |
|  |  | Network Policy    |  | | (vuln scanner)| |             |     |
|  |  | (Calico)          |  | +---------------+ |             |     |
|  |  +-------------------+  | +---------------+ |             |     |
|  |                         | | Falco         | |             |     |
|  |  +-------------------+  | | (runtime IDS) | |             |     |
|  |  | App Workloads     |  | +---------------+ |             |     |
|  |  | (namespaced)      |  | +---------------+ |             |     |
|  |  | Pod Security:     |  | | Suricata      | |             |     |
|  |  |   restricted      |  | | (network IDS) | |             |     |
|  |  +-------------------+  | +---------------+ |             |     |
|  |                         | +---------------+ |             |     |
|  |                         | | ELK Stack     | |             |     |
|  |                         | | (SIEM)        | |             |     |
|  |                         | +---------------+ |             |     |
|  |                         +-------------------+             |     |
|  +-----------------------------------------------------------+     |
|                |                        |                           |
|  +-------------+-------+   +-----------+-----------+               |
|  | Cloud Logging        |   | BigQuery              |               |
|  | Log Sink -------->   |   | Dataset: security_    |               |
|  | (Trivy, Falco,       |   |          findings     |               |
|  |  Suricata logs)      |   | +-- trivy_raw_logs    |               |
|  +-----------------------+   | +-- vulnerabilities   |               |
|                              | +-- latest_vulns (v)  |               |
|  +---------------------------| +-- vuln_summary (v)  |               |
|  | Cloud Build           |   +------------------------+              |
|  | +-- Trivy Deploy     |             |                             |
|  | +-- Terraform CI/CD  |   +---------+----------+                  |
|  +---------------------------| extract_vulns.py   |                  |
|                              | (incremental ETL)  |                  |
|                              +--------------------+                  |
+---------------------------------------------------------------------+
                |
   +------------+-------------+
   | GitHub Actions            |
   | (OIDC Federation)        |
   | +-- terraform plan/apply |
   | +-- security scanning    |
   | +-- container builds     |
   +---------------------------+
```

---

## Project Structure

```
devsecops-project/
|
|-- terraform/                          # Infrastructure as Code
|   |-- main.tf                         # Root module orchestrating all infrastructure
|   |-- variables.tf                    # Configurable parameters with validation
|   |-- outputs.tf                      # Exported values for CI/CD and operations
|   |-- providers.tf                    # Google, Google-Beta, Kubernetes providers
|   |-- backend.tf                      # GCS remote state configuration
|   |-- modules/
|       |-- network/                    # VPC, subnets, firewall rules, Cloud NAT
|       |   |-- main.tf                 # C2 port blocking, crypto mining prevention
|       |   |-- variables.tf
|       |   |-- outputs.tf
|       |-- gke/                        # Private GKE cluster with security hardening
|       |-- bigquery/                   # Dataset and tables for security findings
|       |-- iam/                        # Workload Identity, service accounts, RBAC
|       |-- cloudbuild/                 # CI/CD pipeline triggers and configs
|
|-- helm/                               # Kubernetes security tooling
|   |-- trivy-operator/                 # Vulnerability scanner
|   |   |-- values.yaml                 # Production Helm values
|   |   |-- kustomization.yaml          # GKE-specific overlays
|   |-- falco/                          # Runtime threat detection (eBPF)
|   |-- suricata/                       # Network intrusion detection
|
|-- bigquery/                           # Analytics and vulnerability tracking
|   |-- create_tables.sql               # DDL for tables and views
|   |-- schemas/
|       |-- trivy_raw_logs.json         # Raw log table schema
|       |-- vulnerabilities.json        # Parsed vulnerability table schema
|
|-- scripts/                            # Automation and ETL
|   |-- extract_vulnerabilities.py      # BigQuery ETL for Trivy findings
|
|-- k8s-security/                       # Security demonstrations (authorized testing)
|   |-- kind-config.yaml                # Intentionally vulnerable Kind cluster
|   |-- setup-vulnerable-cluster.sh     # Automated vulnerable cluster setup
|   |-- container-escape/               # Container escape demonstrations
|   |   |-- README.md                   # Attack scenarios documentation
|   |   |-- Dockerfile                  # Image with security testing tools
|   |-- master-plane-crash/             # API server DoS demonstrations
|   |-- pod-security/                   # Pod Security Standards examples
|
|-- github-actions/                     # CI/CD security
|   |-- vulnerable-workflow/            # Vulnerable GitHub Actions PoC
|   |   |-- .github/workflows/
|   |   |   |-- terraform-plan.yml      # pull_request_target vulnerability demo
|   |   |-- ATTACK.md                   # Step-by-step attack walkthrough
|   |-- secure-workflow/                # Hardened alternative
|
|-- federation/                         # Workload Identity Federation
|   |-- terraform-wif.tf               # WIF pool, provider, SAs, bindings
|
|-- ids-ips/                            # IDS/IPS configurations
|
|-- docs/                               # Documentation
|   |-- k8s-security-bulletins-research.md  # CVE research and version matrix
|   |-- trivy-compression-research.md       # Trivy DB compression analysis
|   |-- diagrams/
|   |   |-- architecture.md             # Detailed ASCII architecture diagrams
|   |-- decision-log.md                 # Architecture Decision Records (ADRs)
|   |-- mitre-attack-mapping.md         # MITRE ATT&CK technique mapping
|   |-- incident-response-playbook.md   # IR playbooks for detected threats
```

---

## Task Solutions

### Task 1: K8s Security Bulletins and Vulnerable Cluster

**CVEs Chosen:**

| CVE | Category | CVSS | Why Selected |
|-----|----------|------|-------------|
| CVE-2022-0185 | Container Escape | 8.4 | Kernel-level heap overflow via `fs_context.c`, demonstrates escape from unprivileged container |
| CVE-2022-0847 (Dirty Pipe) | Container Escape | 7.8 | Most reliable escape, no special privileges needed, works on any container |
| CVE-2022-0492 | Container Escape | 7.8 | cgroup `release_agent` escape, works without explicit privileges |
| CVE-2022-3172 | API Server | 8.2 | Request redirection via aggregated API servers |
| CVE-2019-11253 | API Server DoS | 7.5 | YAML bomb causing resource exhaustion |
| CVE-2020-8554 | Network MITM | 5.0 | ExternalIP hijacking, no upstream fix exists |

**Cluster Setup:** Kind cluster running K8s v1.23.17 with intentional misconfigurations including anonymous auth, AlwaysAllow authorization, insecure API port, exposed etcd, and host filesystem mounts.

**Key files:**
- `docs/k8s-security-bulletins-research.md`
- `k8s-security/kind-config.yaml`
- `k8s-security/setup-vulnerable-cluster.sh`

---

### Task 2: Container Escape Demonstration

**CVE Used:** CVE-2022-0847 (Dirty Pipe) as the primary demonstration, with CVE-2022-0185 and CVE-2022-0492 as supplementary scenarios.

**Exploitation Method:** Dirty Pipe overwrites read-only files through the pipe buffer `PIPE_BUF_FLAG_CAN_MERGE` flag. The attacker opens a SUID binary, creates a pipe, uses `splice()` to load the target file's page cache, then writes a malicious payload that overwrites the page cache, modifying the binary on disk.

**Why Dirty Pipe for the demo:**
- Extremely reliable (no race conditions or heap spraying)
- Works from any container, even heavily restricted ones
- Requires only `open()`, `read()`, `splice()`, and `write()` syscalls
- Simple exploit (under 100 lines of C)

**Mitigation Applied:** Pod Security Standards (`restricted` profile), seccomp profiles (`RuntimeDefault`), drop all capabilities, non-root containers, GKE Shielded Nodes, and Falco runtime detection rules.

**Key files:**
- `k8s-security/container-escape/README.md`
- `k8s-security/container-escape/Dockerfile`

---

### Task 3: Master Plane Crash

**Attack Vector:** YAML "Billion Laughs" bomb (CVE-2019-11253 pattern) targeting the API server's YAML/JSON parser. Exponentially expanding YAML anchors and aliases consume all available memory on the API server, causing OOM or unresponsiveness.

**Supplementary Attacks:**
- Excessive watch request flooding (resource exhaustion)
- Large ConfigMap creation (etcd pressure)
- Rapid namespace creation/deletion (controller loop stress)

**Impact:** API server becomes unresponsive, `kubectl` commands timeout, cluster management operations fail, potentially affecting all workloads if liveness probes cannot reach the API server.

**Mitigation Applied:**
- `--max-request-bytes` configuration on API server
- `APIPriorityAndFairness` (enabled by default in K8s >= 1.20)
- RBAC least privilege (no wildcard permissions)
- `--anonymous-auth=false`
- Audit logging with comprehensive policy
- Private cluster with master authorized networks

**Key files:**
- `docs/k8s-security-bulletins-research.md` (Section 6.2, 6.3)

---

### Task 4: Terraform + Cloud Build CI/CD

**Infrastructure Modules:**

| Module | Purpose | Key Security Feature |
|--------|---------|---------------------|
| `network` | VPC, subnets, firewall rules | C2 port blocking, crypto mining prevention, VPC flow logs |
| `gke` | Private GKE cluster | Workload Identity, Binary AuthZ, Shielded Nodes, Calico |
| `bigquery` | Security findings dataset | Partitioned tables, CMEK encryption |
| `iam` | Service accounts, WIF | Zero SA keys, least-privilege roles |
| `cloudbuild` | CI/CD pipelines | Least-privilege SA, trigger-based execution |

**Why Modular Terraform:**
1. **Reusability** -- Modules can be shared across environments (dev/staging/prod)
2. **Testing** -- Each module can be validated independently
3. **Team collaboration** -- Different teams own different modules
4. **Blast radius** -- Changes to one module do not require re-planning others
5. **Version control** -- Module versions can be pinned and promoted

**Pipeline Stages:**
1. `terraform validate` -- Syntax and internal consistency
2. `terraform plan` -- Preview changes with security review
3. Manual approval gate (for production)
4. `terraform apply` -- Execute changes with audit trail
5. Post-apply health checks

**Key files:**
- `terraform/main.tf`
- `terraform/modules/network/main.tf`

---

### Task 5: Trivy Operator Deployment

**Helm Configuration Highlights:**
- **Mode:** Standalone (each scan job downloads its own DB)
- **Scanners enabled:** Vulnerability, ConfigAudit, ExposedSecrets, RBAC Assessment, Infra Assessment, SBOM Generation
- **Compliance:** NSA and CIS benchmark reports every 6 hours
- **Security context:** Non-root (UID 65534), read-only root filesystem, all capabilities dropped, RuntimeDefault seccomp
- **Resource limits:** 500m CPU / 1Gi memory per scan job to prevent node exhaustion
- **Log compression:** Enabled (`compressLogs: true`) to reduce etcd storage pressure

**Log Compression Findings (from Trivy source code analysis):**
The vulnerability database uses two compression layers:
1. **Gzip** -- OCI layer compression for DB distribution (`application/vnd.oci.image.layer.v1.tar+gzip`)
2. **Zstd** (Zstandard) -- Internal advisory data compression within BoltDB using `github.com/klauspost/compress/zstd`

The full DB download is approximately 35-45 MB compressed, expanding to 150-200 MB on disk. Individual advisories achieve approximately 60-70% compression ratio with zstd.

**Key files:**
- `helm/trivy-operator/values.yaml`
- `helm/trivy-operator/kustomization.yaml`
- `docs/trivy-compression-research.md`

---

### Task 6: Log Sink to BigQuery

**Architecture:**
```
Trivy Operator (GKE) --> Cloud Logging --> Log Sink --> BigQuery
                                                         |
                                          +--------------+-----------+
                                          |              |           |
                                   trivy_raw_logs  vulnerabilities  views
```

**Table Schemas:**

| Table | Partition | Clustering | Purpose |
|-------|-----------|------------|---------|
| `trivy_raw_logs` | `DATE(timestamp)` | severity, namespace, cluster | Raw Cloud Logging entries |
| `vulnerabilities` | `DATE(scan_timestamp)` | severity, image, namespace | Parsed CVE findings |
| `latest_vulnerabilities` (view) | -- | -- | Deduplicated current posture |
| `vulnerability_summary` (view) | -- | -- | Aggregated counts per workload |

**Why Partitioning by Day:**
- **Cost:** BigQuery charges per bytes scanned; partition pruning eliminates irrelevant days
- **Query performance:** Most security queries filter by time window (last 24h, last 7d)
- **Data lifecycle:** Partition expiration enables automatic data retention management
- **Compliance:** `require_partition_filter = TRUE` prevents accidental full-table scans

**Why Clustering on Severity:**
- The most common query pattern is "show me CRITICAL and HIGH vulnerabilities"
- Clustering physically co-locates rows with the same severity, reducing I/O
- Secondary clustering on image and namespace matches the next most common filters

**Key files:**
- `bigquery/create_tables.sql`
- `bigquery/schemas/trivy_raw_logs.json`
- `bigquery/schemas/vulnerabilities.json`

---

### Task 7: Vulnerability Extraction Script

**Script Architecture:**
```
CLI Arguments --> BigQueryExtractor --> read_raw_logs() --> parse_trivy_report()
                                            |                      |
                                     Query with partition    Parse JSON payload
                                     pruning + incremental   Extract VulnerabilityReport CRD
                                     filtering               Handle multiple formats
                                            |                      |
                                            v                      v
                                   write_vulnerabilities() <-- VulnerabilityRecord batch
                                            |
                                     Streaming insert with retry
```

**Design Decisions:**
- **Incremental processing:** Tracks `MAX(scan_timestamp)` from the vulnerabilities table to avoid reprocessing
- **Multiple format support:** Handles full CRD format, direct report format, and status-wrapped format
- **Batched writes:** Configurable batch size (default 1000) using BigQuery streaming insert API
- **Retry logic:** Exponential backoff with 3 retries for transient BigQuery errors
- **Dry-run mode:** Full parsing and validation without writing, for testing
- **CVSS extraction:** Tries multiple fields (`score`, `cvss.nvd.V3Score`, `cvss.redhat.V3Score`)

**Sample Analysis Queries:**
```sql
-- Top 10 most critical unfixed vulnerabilities
SELECT vulnerability_id, severity, COUNT(*) as affected_images
FROM `project.security_findings.latest_vulnerabilities`
WHERE severity = 'CRITICAL' AND fixed_version IS NULL
GROUP BY vulnerability_id, severity
ORDER BY affected_images DESC LIMIT 10;

-- Vulnerability trend over last 30 days
SELECT DATE(scan_timestamp) as scan_date, severity, COUNT(*) as count
FROM `project.security_findings.vulnerabilities`
WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY scan_date, severity ORDER BY scan_date;
```

**Key files:**
- `scripts/extract_vulnerabilities.py`

---

### Task 8: Vulnerable GitHub Actions PoC

**Attack Scenario:** A `pull_request_target` workflow that checks out the PR head ref and authenticates to GCP via Workload Identity Federation before running `terraform plan` on the attacker's code.

**Why `pull_request_target` Is Dangerous:**

| Aspect | `pull_request` | `pull_request_target` |
|--------|---------------|----------------------|
| Runs code from | Merge commit | Base branch |
| Secrets access | No (for forks) | **Yes** |
| GITHUB_TOKEN | Read-only (forks) | **Write permissions** |
| OIDC token | Not available (forks) | **Available** |

The critical mistake: checking out the PR's code (`ref: github.event.pull_request.head.sha`) in a `pull_request_target` workflow gives untrusted code access to all workflow secrets and permissions.

**Token Theft Path:**
1. Attacker opens PR with malicious Terraform external data source
2. `pull_request_target` fires with elevated permissions
3. Workflow checks out attacker's code
4. GCP OIDC token exchanged (access token now in environment)
5. `terraform plan` executes attacker's data sources
6. Attacker's script reads `GOOGLE_OAUTH_ACCESS_TOKEN` and exfiltrates it

**Terraform Plan Is NOT Read-Only:** `external` data sources execute shell commands, `http` data sources make requests, custom providers run Go code, and module sources can point to attacker repos.

**Secure Alternative:**
- Use `pull_request` trigger (no secrets for forks)
- If `pull_request_target` is needed, never checkout PR code
- Use GitHub Environments with required reviewers
- Scope WIF to protected branches only

**Real-world references:** GitHub Security Lab research on "pwn requests", OWASP Top 10 CI/CD Security Risks.

**Key files:**
- `github-actions/vulnerable-workflow/.github/workflows/terraform-plan.yml`
- `github-actions/vulnerable-workflow/ATTACK.md`

---

### Task 9: Workload Identity Federation

**Why SA Keys Were Eliminated:** The APT group's initial access was a stolen service account key. SA keys are long-lived (no expiration by default), can be copied and used from anywhere, and leave no trace of where they were used beyond the API call itself. WIF eliminates all of these risks.

**WIF Architecture:**
```
GitHub Actions Runner                    GCP
       |                                  |
  [1]  | Request OIDC token              |
       | --------------------------->     |
       |                    GitHub OIDC   |
       |                    Provider      |
  [2]  | <-- JWT with claims:            |
       |     sub, repository, ref,        |
       |     actor, workflow, event_name  |
       |                                  |
  [3]  | Present JWT to GCP STS -------> | Validate JWT against
       |                                  | WIF Pool + Provider:
       |                                  | - Check org match
       |                                  | - Check repo match
       |                                  | - Check runner type
       |                                  |
  [4]  | <-- Federated token             | Issue federated token
       |                                  |
  [5]  | Exchange for SA token --------> | IAM conditions:
       |                                  | - Branch restriction
       |                                  | - Workflow restriction
       |                                  |
  [6]  | <-- Short-lived SA token        | 1-hour expiry
       |     (cannot be exported)         | Full audit trail
```

**GKE Workload Identity:** Pods authenticate as Google SAs without keys by annotating the Kubernetes service account with `iam.gke.io/gcp-service-account`.

**Organization Policy Constraints:** `constraints/iam.disableServiceAccountKeyCreation` prevents any new SA key creation project-wide.

**Key files:**
- `federation/terraform-wif.tf`
- `terraform/modules/iam/`

---

### Task 10: IDS/IPS Setup

**Why Falco (Runtime Detection):**
- eBPF-based kernel-level system call monitoring (zero overhead on application)
- CNCF graduated project with active community
- Native Kubernetes context enrichment (pod, namespace, deployment labels in alerts)
- Flexible rule language with macro support
- Pre-built rulesets for crypto mining, container escape, reverse shell detection

**Why Suricata over Snort (Network IDS):**
- **Multi-threaded architecture** -- Suricata uses multiple threads per interface, critical for high-throughput GKE clusters
- **eve.json output** -- Structured JSON log output integrates directly with ELK/BigQuery
- **Protocol detection** -- Application-layer detection regardless of port
- **Lua scripting** -- Advanced rule customization
- **Active development** -- OISF-backed, frequent rule updates

**Detection Rules for APT TTPs:**

| Detection | Tool | Rule |
|-----------|------|------|
| Magic file in `/tmp` | Falco | File creation matching `/tmp/.x` pattern |
| C2 on port 4444 | Suricata + Firewall | Egress deny + IDS alert on Metasploit patterns |
| C2 on port 8443 | Suricata + Firewall | Cobalt Strike beacon detection signature |
| IRC C2 channel | Suricata | IRC protocol detection on any port |
| Crypto mining | Suricata + Falco | Stratum protocol detection + CPU anomaly |
| Container escape | Falco | `nsenter`, `/proc/1/root` access, capability changes |
| SA key creation | Cloud Audit Logs | `CreateServiceAccountKey` API call alert |

**ELK Integration:**
```
Falco/Suricata --> Filebeat (DaemonSet) --> Logstash --> Elasticsearch --> Kibana
                                               |
                                        Parse, enrich,
                                        normalize fields
```

**Key directories:**
- `helm/falco/`
- `helm/suricata/`
- `ids-ips/`

---

## Technology Choice Justifications

| Technology | Chosen | Alternative Considered | Rationale |
|-----------|--------|----------------------|-----------|
| **Runtime IDS** | Falco | Sysdig Secure, Tracee | eBPF-based, CNCF graduated, native K8s context in alerts, open-source |
| **Network IDS** | Suricata | Snort, Zeek | Multi-threaded, eve.json structured output, superior performance at scale |
| **SIEM** | ELK Stack | Splunk, Chronicle | Open-source, K8s-native deployment, cost-effective, rich visualization |
| **Vuln Scanner** | Trivy Operator | Grype, Clair, Prisma | K8s operator pattern, comprehensive scanning (images, config, RBAC, SBOM), active community |
| **IaC** | Terraform | Pulumi, Crossplane | Industry standard, mature GCP provider, declarative state management, module ecosystem |
| **CI/CD** | Cloud Build | Jenkins, ArgoCD, GitHub Actions | GCP-native, serverless (no infra to manage), native Workload Identity support |
| **Identity** | WIF | SA Keys, Vault | No key management, short-lived tokens, built-in audit trail, GCP-native |
| **Analytics** | BigQuery | Elasticsearch, Splunk | Serverless, standard SQL interface, cost-effective for analytical workloads, partition pruning |
| **Local Testing** | Kind | Minikube, k3d | Multi-node support, kubeadm-based (closer to production), Docker-in-Docker |
| **Container Runtime** | containerd | Docker, CRI-O | GKE default, lower overhead, industry standard via CNCF |

---

## Security Controls Summary

| MITRE ATT&CK Technique | Prevention Controls | Detection Controls |
|------------------------|--------------------|--------------------|
| T1078.004 Valid Accounts: Cloud | WIF (no keys), Org Policy | Cloud Audit Logs, SA usage alerts |
| T1610 Deploy Container | Binary Authorization, RBAC | Falco (unexpected container), Cloud Audit |
| T1136 Create Account | IAM least privilege, Org Policy | Audit Log monitoring for SA creation |
| T1571 Non-Standard Port | Firewall egress deny (C2 ports) | Suricata IDS, VPC Flow Logs |
| T1496 Resource Hijacking | Resource quotas, Network Policy | Falco (CPU anomaly), Suricata (Stratum) |
| T1210 Exploitation of Remote Services | Pod Security Standards, Shielded Nodes | Falco (syscall anomaly), Trivy (CVE scan) |
| T1656 Impersonation | WIF branch restrictions | Cloud Audit Logs, workflow attribution |
| T1611 Escape to Host | Seccomp, AppArmor, drop capabilities | Falco (nsenter, /proc access) |
| T1071 Application Layer Protocol | Network Policy, egress filtering | Suricata (protocol anomaly) |
| T1059 Command and Scripting | Read-only filesystem, non-root | Falco (shell in container) |

---

## Quick Start

### Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated with project owner permissions
- Terraform >= 1.5.0
- `kubectl`, `helm`, `kind` (for local testing)
- Python 3.9+ (for extraction script)

### 1. Create Terraform State Bucket

```bash
export PROJECT_ID="your-project-id"
gsutil mb -p $PROJECT_ID -l us-central1 gs://${PROJECT_ID}-terraform-state
gsutil versioning set on gs://${PROJECT_ID}-terraform-state
```

### 2. Deploy Infrastructure

```bash
cd terraform/
terraform init
terraform plan -var="project_id=${PROJECT_ID}"
terraform apply -var="project_id=${PROJECT_ID}"
```

### 3. Connect to GKE

```bash
gcloud container clusters get-credentials devsecops-gke \
  --zone us-central1-a --project $PROJECT_ID
```

### 4. Deploy Security Stack

```bash
# Trivy Operator
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aquasecurity/trivy-operator \
  -n trivy-system --create-namespace -f helm/trivy-operator/values.yaml

# Apply Kustomize overlays
kubectl apply -k helm/trivy-operator/
```

### 5. Create BigQuery Tables

```bash
bq query --use_legacy_sql=false --project_id=$PROJECT_ID \
  < bigquery/create_tables.sql
```

### 6. Run Vulnerability Extraction

```bash
python3 scripts/extract_vulnerabilities.py \
  --project-id $PROJECT_ID --dataset security_findings
```

### Local Testing (Kind)

```bash
cd k8s-security/
./setup-vulnerable-cluster.sh create
```

---

## Testing

### Terraform Validation

```bash
cd terraform/
terraform validate
terraform plan -var="project_id=${PROJECT_ID}"
```

### Trivy Operator Health

```bash
kubectl get pods -n trivy-system
kubectl get vulnerabilityreports -A
kubectl get configauditreports -A
```

### Vulnerability Extraction Dry Run

```bash
python3 scripts/extract_vulnerabilities.py \
  --project-id $PROJECT_ID --dataset security_findings --dry-run
```

### Security Demo Validation

```bash
# Verify vulnerable cluster is running
kubectl get nodes --context kind-vuln-k8s-lab

# Verify anonymous API access (should succeed on vulnerable cluster)
curl -s http://localhost:8080/api/v1/namespaces

# Verify C2 port blocking (on production GKE)
# This connection should be denied by the firewall rule
kubectl run test --image=busybox --rm -it -- nc -w 3 evil.example.com 4444
```

---

## References

### CVEs and Security Bulletins
- [GKE Security Bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins)
- [CVE-2022-0847 (Dirty Pipe)](https://dirtypipe.cm4all.com/)
- [CVE-2022-0185 Writeup](https://www.willsroot.io/2022/01/cve-2022-0185.html)
- [CVE-2021-22555 Writeup](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
- [CVE-2024-21626 runc Advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)

### Tools and Documentation
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
- [Falco](https://falco.org/docs/)
- [Suricata](https://docs.suricata.io/)
- [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [GKE Hardening Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

### CI/CD Security
- [GitHub Actions Security: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Terraform Plan Is Not Harmless](https://cycode.com/blog/terraform-plan-is-not-harmless/)

### Frameworks
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
