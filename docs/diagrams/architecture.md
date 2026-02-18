# Architecture Diagrams

Detailed ASCII diagrams for the DevSecOps GKE Security Project.

---

## 1. Overall System Architecture

```
                              +-------------------+
                              |    Internet        |
                              +--------+----------+
                                       |
                              +--------+----------+
                              |   Cloud Armor      |
                              |   WAF + DDoS       |
                              |   Protection       |
                              +--------+----------+
                                       |
                              +--------+----------+
                              |  Cloud Load        |
                              |  Balancer (L7)     |
                              +--------+----------+
                                       |
+=======================================================================+
|                     GCP Project: devsecops-demo                       |
|                                                                       |
|  +-----------------------------+    +------------------------------+  |
|  |     VPC: devsecops-vpc      |    |   Cloud IAM                  |  |
|  |                             |    |                              |  |
|  |  Subnet: 10.0.0.0/20       |    |  +------------------------+  |  |
|  |  Pods:   10.16.0.0/14      |    |  | WIF Pool: github-pool  |  |  |
|  |  Svc:    10.20.0.0/20      |    |  | Provider: github-oidc  |  |  |
|  |  Master: 172.16.0.0/28     |    |  +------------------------+  |  |
|  |                             |    |                              |  |
|  |  +----Firewall Rules----+  |    |  Service Accounts:           |  |
|  |  | PRI 100: DENY C2     |  |    |  +-- trivy-operator-sa      |  |
|  |  |   4444,5555,6666,    |  |    |  +-- cloudbuild-sa          |  |
|  |  |   6667,8443,9090,    |  |    |  +-- bigquery-writer-sa     |  |
|  |  |   1337,31337,12345   |  |    |  +-- github-deployer-sa     |  |
|  |  | PRI 200: DENY IPs    |  |    |  +-- github-reader-sa       |  |
|  |  |   (threat intel)     |  |    |  +-- github-scanner-sa      |  |
|  |  | PRI 500: DENY crypto |  |    |                              |  |
|  |  |   3333,3334,8332,    |  |    |  Org Policy:                 |  |
|  |  |   8333,8545,30303    |  |    |  - disableServiceAccount     |  |
|  |  | PRI 1000: ALLOW int  |  |    |    KeyCreation               |  |
|  |  +-----------------------+  |    +------------------------------+  |
|  |                             |                                     |
|  |  Cloud NAT + Router         |                                     |
|  |  (controlled egress)        |                                     |
|  +-----------------------------+                                     |
|           |                                                          |
|  +--------+-------------------------------------------------+       |
|  |           GKE: devsecops-gke (Private Cluster)            |       |
|  |           K8s: 1.27.x | Nodes: e2-standard-4 x2          |       |
|  |           Shielded | Binary AuthZ | Calico Network Policy |       |
|  |                                                           |       |
|  |  +==================+  +================================+ |       |
|  |  | App Namespaces   |  |  Security Namespace             | |       |
|  |  |                  |  |  (trivy-system, falco, elk)     | |       |
|  |  | +------+ +-----+|  |                                  | |       |
|  |  | | App  | | App ||  |  +----------+  +----------+     | |       |
|  |  | | Pod  | | Pod ||  |  |  Trivy   |  |  Falco   |     | |       |
|  |  | | (PSS:| | (PSS||  |  | Operator |  | DaemonSet|     | |       |
|  |  | | rest)| | rest)||  |  | (vuln    |  | (eBPF    |     | |       |
|  |  | +------+ +-----+|  |  |  scan)   |  |  syscall |     | |       |
|  |  |                  |  |  +----------+  |  monitor)|     | |       |
|  |  | Network Policy:  |  |                +----------+     | |       |
|  |  | default-deny     |  |  +----------+  +----------+    | |       |
|  |  +==================+  |  | Suricata |  | ELK      |    | |       |
|  |                        |  | DaemonSet|  | Stack    |    | |       |
|  |                        |  | (network |  | (SIEM)   |    | |       |
|  |                        |  |  IDS)    |  +----------+    | |       |
|  |                        |  +----------+                   | |       |
|  |                        +================================+ |       |
|  +-----------------------------------------------------------+       |
|           |                        |                   |             |
|  +--------+------+    +-----------+---------+  +------+----------+  |
|  | Cloud Logging  |    | BigQuery             |  | Cloud Build    |  |
|  |                |    | security_findings    |  |                |  |
|  | Trivy logs ----+--> | +- trivy_raw_logs   |  | Trivy deploy   |  |
|  | Falco alerts   |    | +- vulnerabilities  |  | TF plan/apply  |  |
|  | Suricata eve   |    | +- latest_vulns (v) |  | (least-priv SA)|  |
|  | VPC flow logs  |    | +- vuln_summary (v) |  |                |  |
|  +----------------+    +---------------------+  +----------------+  |
+=======================================================================+
         |                         |
+--------+----------+    +---------+----------+
| GitHub Repository  |    | GitHub Actions     |
| (Source of Truth)  |    | (OIDC Federation)  |
|                    |    | terraform plan     |
| terraform/         |    | terraform apply    |
| helm/              |    | trivy scan         |
| scripts/           |    | container build    |
+--------------------+    +--------------------+
```

---

## 2. Network Topology

```
                          Internet
                              |
                     +--------+--------+
                     |  Cloud Armor    |
                     |  (L7 WAF)      |
                     +--------+--------+
                              |
                     +--------+--------+
                     | External LB     |
                     | (HTTPS only)    |
                     +--------+--------+
                              |
==================================== VPC Boundary ====================================
|                                                                                     |
|  VPC: devsecops-vpc-prod                                                            |
|  Routing: REGIONAL                                                                  |
|                                                                                     |
|  +---Subnet: 10.0.0.0/20---------------------------------------------------+      |
|  |                                                                           |      |
|  |  +----GKE Control Plane----+     +--------GKE Nodes---------+            |      |
|  |  | 172.16.0.0/28 (private) |     | 10.0.0.0/20 (private)   |            |      |
|  |  |                         |     |                          |            |      |
|  |  | API Server (HTTPS/443)  +-----+ Node 1: e2-standard-4   |            |      |
|  |  | etcd (internal only)    |     | Node 2: e2-standard-4   |            |      |
|  |  | Controller Manager      |     |                          |            |      |
|  |  | Scheduler               |     | Workload Identity       |            |      |
|  |  +-----------+-------------+     | metadata server active  |            |      |
|  |              |                   +-----+---+----+-----------+            |      |
|  |   Master Authorized                   |   |    |                        |      |
|  |   Networks only                       |   |    |                        |      |
|  |                              +--------+   |    +--------+               |      |
|  |                              |            |             |               |      |
|  |                  +-----------+---+  +-----+------+ +----+----------+   |      |
|  |                  | Pod CIDR      |  | Svc CIDR   | | Secondary     |   |      |
|  |                  | 10.16.0.0/14  |  | 10.20.0/20 | | Ranges        |   |      |
|  |                  |               |  |            | |               |   |      |
|  |                  | Pod-to-Pod    |  | ClusterIP  | | Alias IP      |   |      |
|  |                  | via Calico    |  | Services   | | (VPC-native)  |   |      |
|  |                  +---------------+  +------------+ +---------------+   |      |
|  +-----------------------------------------------------------------------+      |
|                                    |                                             |
|                           +--------+--------+                                    |
|                           | Cloud Router    |                                    |
|                           | BGP ASN: 64514 |                                    |
|                           +--------+--------+                                    |
|                                    |                                             |
|                           +--------+--------+                                    |
|                           | Cloud NAT       |                                    |
|                           | AUTO_ONLY alloc |                                    |
|                           | All subnets     |                                    |
|                           +--------+--------+                                    |
|                                    |                                             |
=====================================================================================
                                     |
                            Controlled Egress
                            (logged, firewalled)
                                     |
                              +------+------+
                              |  Internet   |
                              +-------------+

  FIREWALL RULE EVALUATION ORDER:
  ================================
  Priority 100:  DENY --> C2 ports (4444, 5555, 6666, 6667, 8443, 9090,
                          1337, 31337, 12345, 65535) TCP + UDP
  Priority 200:  DENY --> Known malicious IPs (from threat intel feeds)
  Priority 500:  DENY --> Crypto mining ports (3333, 3334, 8332, 8333,
                          8545, 30303, 45700) TCP
  Priority 1000: ALLOW -> Internal VPC traffic (node, pod, service CIDRs)
  Priority 1000: ALLOW -> GCP health check probes (35.191.0.0/16, etc.)
  Priority 1000: ALLOW -> Master-to-node (443, 8443, 10250, 10255)
  Priority 65534: DENY --> Everything else (implicit)

  All DENY rules have log_config enabled for forensics.
```

---

## 3. Log Flow Pipeline

```
+===========================================================================+
|                           GKE Cluster                                     |
|                                                                           |
|  +--Trivy Operator--+  +--Falco DaemonSet--+  +--Suricata DaemonSet--+  |
|  | VulnerabilityRpt |  | Syscall alerts     |  | eve.json events     |  |
|  | ConfigAuditRpt   |  | Rule matches       |  | Protocol alerts     |  |
|  | ComplianceRpt    |  | K8s context        |  | Flow records        |  |
|  +--------+---------+  +---------+----------+  +---------+-----------+  |
|           |                      |                       |               |
|           v                      v                       v               |
|  +--------+----------------------+---+-----------------------+---------+ |
|  |                    stdout (JSON format)                             | |
|  |               GKE Logging Agent (Fluent Bit)                        | |
|  +----------------------------------+---------------------------------+ |
+=========================================|===============================+
                                          |
                                          v
                             +------------+-------------+
                             |      Cloud Logging       |
                             |                          |
                             |  Log Router:             |
                             |  +-- _Default sink       |
                             |  +-- BigQuery sink       |
                             |      (filter: Trivy      |
                             |       operator logs)     |
                             +-----+----------+--------+
                                   |          |
                          +--------+    +-----+--------+
                          |             |              |
                          v             v              v
                   +------+----+ +-----+------+ +-----+------+
                   | Cloud     | | BigQuery   | | Pub/Sub    |
                   | Storage   | | (analytics)| | (optional) |
                   | (archive) | |            | |            |
                   +-----------+ +-----+------+ +-----+------+
                                       |              |
                                       v              v
                              +--------+-------+  +---+-----------+
                              | trivy_raw_logs |  | Alert         |
                              | (partitioned)  |  | Notification  |
                              +--------+-------+  | (PagerDuty,   |
                                       |          |  Slack, etc.)  |
                                       v          +---------------+
                              +--------+-------+
                              | extract_vulns  |
                              | .py (ETL)      |
                              +--------+-------+
                                       |
                                       v
                              +--------+-------+
                              | vulnerabilities|
                              | (partitioned,  |
                              |  clustered)    |
                              +--------+-------+
                                       |
                          +------------+------------+
                          |                         |
                          v                         v
                   +------+--------+    +-----------+------+
                   | latest_vulns  |    | vuln_summary     |
                   | (view: dedup) |    | (view: aggregate)|
                   +---------------+    +------------------+


   PARALLEL PATH: ELK STACK (SIEM)
   =================================

   +--Falco/Suricata--+     +---Filebeat---+     +---Logstash---+
   | stdout logs      +---->| DaemonSet    +---->| Parse &       |
   |                  |     | tails pod    |     | enrich:       |
   +------------------+     | log files    |     | - GeoIP       |
                            +--------------+     | - K8s labels  |
                                                 | - Threat intel|
                                                 +------+--------+
                                                        |
                                                        v
                                                 +------+--------+
                                                 | Elasticsearch |
                                                 | (indexed,     |
                                                 |  searchable)  |
                                                 +------+--------+
                                                        |
                                                        v
                                                 +------+--------+
                                                 |    Kibana     |
                                                 | - Dashboards  |
                                                 | - Alerts      |
                                                 | - Threat hunt |
                                                 +---------------+
```

---

## 4. CI/CD Pipeline Flow

```
  Developer                     GitHub                          GCP
     |                            |                              |
     |  git push / PR             |                              |
     +--------------------------->|                              |
     |                            |                              |
     |                    +-------+--------+                     |
     |                    | Trigger Event  |                     |
     |                    | (push / PR)    |                     |
     |                    +-------+--------+                     |
     |                            |                              |
     |                    +-------+--------+                     |
     |                    | GitHub Actions |                     |
     |                    | Workflow Start |                     |
     |                    +-------+--------+                     |
     |                            |                              |
     |              +-------------+-------------+                |
     |              |                           |                |
     |              v                           v                |
     |     +--------+-------+       +-----------+---------+     |
     |     | On PR:          |       | On merge to main:  |     |
     |     | terraform plan  |       | terraform apply    |     |
     |     | trivy scan      |       | helm deploy        |     |
     |     | (read-only SA)  |       | (deployer SA)      |     |
     |     +--------+-------+       +-----------+---------+     |
     |              |                           |                |
     |              |     OIDC Token Exchange   |                |
     |              |                           |                |
     |              +-------------+-------------+                |
     |                            |                              |
     |                            v                              |
     |                   +--------+--------+                     |
     |                   | Request OIDC    |                     |
     |                   | Token from      |                     |
     |                   | GitHub OIDC     |                     |
     |                   | Provider        |                     |
     |                   +--------+--------+                     |
     |                            |                              |
     |                            | JWT with claims:             |
     |                            | sub, repository, ref,        |
     |                            | actor, workflow              |
     |                            |                              |
     |                            +----------------------------->|
     |                            |                     +--------+--------+
     |                            |                     | GCP STS         |
     |                            |                     | Validate JWT:   |
     |                            |                     | - Check issuer  |
     |                            |                     | - Check org     |
     |                            |                     | - Check repo    |
     |                            |                     | - Check runner  |
     |                            |                     +--------+--------+
     |                            |                              |
     |                            |                     +--------+--------+
     |                            |                     | IAM Conditions  |
     |                            |                     | - Branch check  |
     |                            |                     |   (main only    |
     |                            |                     |    for deploy)  |
     |                            |                     +--------+--------+
     |                            |                              |
     |                            |<-----------------------------+
     |                            |  Short-lived SA token        |
     |                            |  (1 hour, non-exportable)    |
     |                            |                              |
     |                    +-------+--------+                     |
     |                    | Execute:       |                     |
     |                    | - TF init      +-------------------->|
     |                    | - TF plan/apply|   API calls with    |
     |                    | - Helm deploy  |   SA token          |
     |                    | - Trivy scan   |                     |
     |                    +-------+--------+                     |
     |                            |                              |
     |                    +-------+--------+                     |
     |                    | Post results:  |                     |
     |                    | - PR comment   |                     |
     |                    | - Status check |                     |
     |                    +-------+--------+                     |
     |                            |                              |
     |<---------------------------+                              |
     |  PR updated with results   |                              |


   CLOUD BUILD PARALLEL PATH:
   ============================

   GitHub Repo (push) ---> Cloud Build Trigger ---> Build Steps:
                                                    1. docker build
                                                    2. docker push (Artifact Registry)
                                                    3. gcloud deploy (GKE)
                                                    4. helm upgrade (security stack)
                                                    Uses: cloudbuild-sa (least privilege)
```

---

## 5. Incident Response Flow

```
  +===========+     +===========+     +===========+
  |  Falco    |     | Suricata  |     | Cloud     |
  |  Alert    |     | Alert     |     | Audit Log |
  +-----+-----+     +-----+-----+     +-----+-----+
        |                 |                   |
        +--------+--------+--------+----------+
                 |                 |
                 v                 v
        +--------+--------+ +-----+----------+
        | ELK / Kibana    | | BigQuery       |
        | (real-time)     | | (analytics)    |
        +--------+--------+ +-----+----------+
                 |                 |
                 v                 v
        +--------+-----------------+---------+
        |         Alert Engine               |
        |  - Severity classification         |
        |  - Correlation rules               |
        |  - False positive filtering        |
        +--------+---------+---------+-------+
                 |         |         |
     +-----------+   +-----+---+  +--+------------+
     |               |         |  |               |
     v               v         v  v               v
  +--+------+   +----+---+  +-+--+-----+   +-----+-----+
  | P1:     |   | P2:    |  | P3:      |   | P4:       |
  | CRITICAL|   | HIGH   |  | MEDIUM   |   | LOW       |
  | PagerDuty   | Slack  |  | Jira     |   | Log only  |
  | + Phone |   | alert  |  | ticket   |   |           |
  +----+----+   +---+----+  +----+-----+   +-----------+
       |            |             |
       v            v             v
  +----+------------+-------------+----+
  |       Incident Response Team       |
  |                                    |
  |  1. TRIAGE (5 min)                 |
  |     - Confirm alert                |
  |     - Assess scope                 |
  |     - Assign severity              |
  |                                    |
  |  2. CONTAIN (15 min)               |
  |     - Isolate affected pods        |
  |     - Block C2 IPs                 |
  |     - Rotate credentials           |
  |     - Cordon affected nodes        |
  |                                    |
  |  3. INVESTIGATE (1-4 hrs)          |
  |     - Analyze Falco/Suricata logs  |
  |     - Review Cloud Audit Logs      |
  |     - Forensic image capture       |
  |     - Timeline reconstruction      |
  |                                    |
  |  4. ERADICATE (2-8 hrs)            |
  |     - Remove attacker artifacts    |
  |     - Patch vulnerabilities        |
  |     - Update firewall rules        |
  |     - Re-deploy clean workloads    |
  |                                    |
  |  5. RECOVER (1-2 days)             |
  |     - Restore from known-good      |
  |     - Validate security controls   |
  |     - Resume normal operations     |
  |                                    |
  |  6. POST-INCIDENT (1 week)         |
  |     - Root cause analysis          |
  |     - Update detection rules       |
  |     - Improve runbooks             |
  |     - Lessons learned              |
  +------------------------------------+
```

---

## 6. Workload Identity Token Exchange Flow

```
  GitHub Actions Runner                   GCP Identity Platform
  =====================                   ====================

  +---------------------+
  | Workflow Step:       |
  | google-github-       |
  |  actions/auth@v2    |
  +----------+----------+
             |
  [1] Request OIDC token
  from GitHub's built-in
  OIDC provider
             |
             v
  +----------+----------+     +-----------------------------+
  | GitHub OIDC         |     |  JWT Claims Include:        |
  | Provider            +---->|  iss: token.actions.github  |
  | (token.actions.     |     |       usercontent.com       |
  |  githubusercontent   |     |  sub: repo:org/repo:ref:    |
  |  .com)              |     |       refs/heads/main       |
  +---------------------+     |  aud: https://iam.google    |
             |                |       apis.com/...          |
  [2] JWT issued              |  repository: org/repo       |
             |                |  ref: refs/heads/main       |
             v                |  actor: username             |
  +----------+----------+    |  workflow: deploy.yml        |
  | Present JWT to      |    |  runner_env: github-hosted   |
  | GCP STS endpoint    |    +-----------------------------+
  +----------+----------+
             |
  [3] STS Token Exchange
             |
             v
  +----------+-----------------------------------------------------+
  | GCP Security Token Service (STS)                                |
  |                                                                 |
  |  Step A: Locate WIF Pool + Provider                             |
  |     Pool: projects/123456/locations/global/                     |
  |           workloadIdentityPools/github-actions-pool              |
  |     Provider: github-oidc-provider                              |
  |                                                                 |
  |  Step B: Validate JWT                                           |
  |     - Verify signature against GitHub JWKS                      |
  |     - Check issuer matches provider config                      |
  |     - Check audience matches provider config                    |
  |     - Check token expiry                                        |
  |                                                                 |
  |  Step C: Evaluate Provider Attribute Condition                  |
  |     assertion.repository_owner == 'devsecops-demo'              |
  |     && assertion.repository == 'devsecops-demo/devsecops-project|'
  |     && assertion.runner_environment == 'github-hosted'          |
  |     --> PASS / REJECT                                           |
  |                                                                 |
  |  Step D: Map Attributes                                         |
  |     google.subject          <-- assertion.sub                   |
  |     attribute.repository    <-- assertion.repository            |
  |     attribute.ref           <-- assertion.ref                   |
  |     attribute.actor         <-- assertion.actor                 |
  |     attribute.workflow      <-- assertion.workflow              |
  |     attribute.event_name    <-- assertion.event_name            |
  |     attribute.job_workflow_ref <-- assertion.job_workflow_ref   |
  |                                                                 |
  |  Step E: Issue Federated Token                                  |
  +----------------------------+------------------------------------+
                               |
  [4] Federated token          |
                               v
  +----------------------------+------------------------------------+
  | IAM Service Account Impersonation                               |
  |                                                                 |
  |  Check IAM bindings on target SA:                               |
  |                                                                 |
  |  Deployer SA (github-deployer-prod):                            |
  |     member: principalSet://iam.googleapis.com/.../              |
  |             attribute.repository/org/repo                       |
  |     role: roles/iam.workloadIdentityUser                        |
  |     condition:                                                  |
  |       request.auth.claims.ref == 'refs/heads/main'              |
  |       --> Branch restriction: only main can deploy              |
  |                                                                 |
  |  Reader SA (github-reader-prod):                                |
  |     member: principalSet://iam.googleapis.com/.../              |
  |             attribute.repository/org/repo                       |
  |     role: roles/iam.workloadIdentityUser                        |
  |     condition: NONE (any branch can read)                       |
  |                                                                 |
  +----------------------------+------------------------------------+
                               |
  [5] Short-lived SA           |
      access token             |
      (1 hour TTL)             |
                               v
  +----------------------------+------------------------------------+
  | GitHub Actions Runner receives token                            |
  |                                                                 |
  |  Token properties:                                              |
  |  - Expires in 1 hour                                            |
  |  - Scoped to specific SA's IAM roles                            |
  |  - Cannot be refreshed without re-authenticating                |
  |  - Full audit trail in Cloud Audit Logs                         |
  |  - Cannot be exported or copied to external systems             |
  |                                                                 |
  |  Available as:                                                  |
  |  - GOOGLE_OAUTH_ACCESS_TOKEN env var                            |
  |  - CLOUDSDK_AUTH_ACCESS_TOKEN env var                           |
  |  - gcloud/terraform/kubectl auto-configured                     |
  +----------------------------------------------------------------+
```
