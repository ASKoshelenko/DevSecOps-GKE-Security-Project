# MITRE ATT&CK Mapping

Mapping of APT TTPs observed in incident INC-2026-0042 to the MITRE ATT&CK framework, with detection and prevention controls implemented in this project.

---

## APT Kill Chain Overview

```
 INITIAL       EXECUTION     PERSISTENCE    PRIVILEGE      DEFENSE       LATERAL       COLLECTION    C2            IMPACT
 ACCESS                                     ESCALATION     EVASION       MOVEMENT
 =========     =========     ===========    ===========    =========     =========     ==========    =========     =========
 T1078.004     T1610         T1136          T1611          T1656         T1210         T1530         T1571         T1496
 Valid         Deploy        Create         Escape to      Imperson-     Exploit       Data from     Non-Std       Resource
 Accounts:     Container     Account        Host           ation         Remote Svc    Cloud Store   Port          Hijacking
 Cloud                                                                                                             (Crypto)
     |             |             |              |              |             |             |             |             |
     v             v             v              v              v             v             v             v             v
 Stolen SA     Crypto-       /tmp/.x        Container      Cloud Build   GKE lateral   BigQuery      4444,8443     CPU/GPU
 key from      miner pod     magic file     breakout       SA imperson   movement      exfil         6666,6667     mining
 dev laptop    via CB        as marker      to node        for deploy    via kubectl                 IRC C2
```

---

## Detailed Technique Mapping

### Reconnaissance (TA0043)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1526 | Cloud Service Discovery | Enumerated GCP APIs, GKE clusters, BigQuery datasets using stolen SA key | Cloud Audit Logs: `*.list`, `*.get` API calls from unusual IPs | WIF eliminates static keys; IAM least privilege limits enumeration scope |
| T1580 | Cloud Infrastructure Discovery | Mapped VPC topology, firewall rules, node pools | Cloud Audit Logs: Compute API read operations | Viewer role restricted to specific SAs via WIF |

### Initial Access (TA0001)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Used stolen SA key (`roles/editor`) from compromised developer workstation | Cloud Audit Logs: SA usage from non-corporate IPs, unusual API call patterns, geographic anomaly | **WIF (ADR-001):** Eliminated all SA keys; Org Policy `disableServiceAccountKeyCreation`; Short-lived tokens only |
| T1199 | Trusted Relationship | Leveraged CI/CD pipeline trust to deploy workloads | Cloud Build audit logs: unexpected build triggers | WIF branch restrictions (only `main` can deploy); Required reviewers on GitHub Environments |

### Execution (TA0002)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1610 | Deploy Container | Deployed cryptominer pods via compromised Cloud Build SA | **Falco:** `Launch Suspicious Network Tool in Container`, unexpected container images; Cloud Audit Logs: `container.v1.projects.zones.clusters.createPod` | Binary Authorization (only signed images); RBAC restricting pod creation; Image admission policies |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Executed shell commands inside compromised containers | **Falco:** `Terminal shell in container`, `Run shell untrusted` rules | Read-only root filesystem; Drop all capabilities; Non-root user |
| T1609 | Container Administration Command | Used `kubectl exec` to interact with running containers | **Falco:** `Attach/Exec Pod`; Cloud Audit Logs: `io.k8s.core.v1.pods.exec` | RBAC: restrict `pods/exec` verb; Audit logging |

### Persistence (TA0003)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1136 | Create Account | Created backdoor SA keys for persistent access; magic file `/tmp/.x` as persistence marker | **Falco:** `Modify binary dirs`, `Create files below /tmp`; Cloud Audit Logs: `CreateServiceAccountKey` | Org Policy: `disableServiceAccountKeyCreation`; Pod Security Standards: read-only root FS |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Generated additional SA keys for exfiltration | Cloud Audit Logs: `google.iam.admin.v1.CreateServiceAccountKey` alert | WIF: no SA keys to create; Org Policy enforcement |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | Created CronJobs for periodic cryptominer restarts | **Falco:** unexpected CronJob creation; `kubectl get cronjobs` monitoring | RBAC: restrict CronJob creation; Admission controllers |

### Privilege Escalation (TA0004)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1611 | Escape to Host | Container escape via kernel exploits (CVE-2022-0847 Dirty Pipe, CVE-2022-0185) | **Falco:** `Container Drift Detected`, `nsenter`, `/proc/1/root` access, `mount` in container; `Launch Package Management Process in Container` | Pod Security Standards (`restricted`); Seccomp RuntimeDefault; Drop ALL capabilities; GKE Shielded Nodes; Node auto-upgrade |
| T1068 | Exploitation for Privilege Escalation | Exploited kernel CVEs from within container | **Falco:** anomalous syscall patterns; **Trivy:** CVE detection in node OS | Patched node images; GKE Sandbox (gVisor); Seccomp profiles blocking dangerous syscalls |

### Defense Evasion (TA0005)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1656 | Impersonation | Impersonated Cloud Build SA to deploy workloads | Cloud Audit Logs: SA impersonation events; unexpected `generateAccessToken` calls | WIF: tokens bound to specific workflows and branches; IAM Conditions |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Attempted to disable audit logging | Cloud Audit Logs: `SetIamPolicy` on logging resources; `UpdateSink` events | IAM: restrict logging admin roles; Organization-level log sinks (cannot be disabled at project level) |
| T1070.004 | Indicator Removal: File Deletion | Deleted magic files after use to avoid detection | **Falco:** `Delete or rename shell history`, file deletion alerts | Immutable logging; Cloud Logging (logs cannot be deleted retroactively) |

### Credential Access (TA0006)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata | Attempted metadata server access for SA tokens | **Falco:** `Contact GCE Instance Metadata Server`; **Suricata:** HTTP to 169.254.169.254 | GKE Workload Identity (replaces metadata-based SA); Metadata concealment |
| T1528 | Steal Application Access Token | Stole GCP access tokens from CI/CD environment | **Suricata:** unusual outbound HTTP with bearer tokens; GitHub Actions audit logs | WIF: tokens expire in 1 hour; Environment protection rules; Never checkout untrusted code with `pull_request_target` |

### Discovery (TA0007)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1613 | Container and Resource Discovery | Enumerated pods, services, namespaces, secrets | **Falco:** `K8s Service Account Token Accessed`; Cloud Audit Logs: excessive list/get operations | RBAC least privilege; Network Policies; Service account token automount disabled |
| T1049 | System Network Connections Discovery | Mapped internal cluster network topology | **Falco:** `Launch Suspicious Network Tool`; **Suricata:** network scanning patterns | Network Policies (default deny); Pod Security Standards |

### Lateral Movement (TA0008)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1210 | Exploitation of Remote Services | Pivoted from compromised container to other cluster workloads | **Falco:** unexpected network connections between namespaces; **Suricata:** internal lateral movement | Network Policies (default deny between namespaces); Calico microsegmentation; RBAC |
| T1021.004 | Remote Services: SSH | Attempted SSH from compromised pod to nodes | **Suricata:** SSH on internal network; **Falco:** `Launch Remote File Copy Tools in Container` | Network Policies blocking SSH; Firewall rules; No SSH keys in containers |

### Collection (TA0009)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1530 | Data from Cloud Storage Object | Accessed Terraform state in GCS; queried BigQuery datasets | Cloud Audit Logs: `storage.objects.get` on state bucket; BigQuery audit: unexpected queries | IAM: reader SA has `bigquery.dataViewer` only; State bucket restricted to CI SA; VPC Service Controls |
| T1119 | Automated Collection | Scripted data exfiltration from BigQuery | Cloud Audit Logs: high-volume query patterns; BigQuery slot usage anomalies | BigQuery IAM: restrict `bigquery.jobs.create`; Data Loss Prevention (DLP) API |

### Command and Control (TA0011)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1571 | Non-Standard Port | C2 backconnect on ports 4444 (Metasploit), 8443 (Cobalt Strike), 6666/6667 (IRC) | **Suricata:** protocol anomaly detection; **VPC Flow Logs:** connections to blocked ports; **Firewall rule logs:** denied egress | **Firewall rules (PRI 100):** DENY egress to C2 ports (TCP+UDP); Cloud NAT logging |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communication (encrypted) | **Suricata:** JA3/JA3S fingerprinting matching known C2 frameworks; TLS certificate anomalies | Egress proxy with TLS inspection; Allow-list for outbound HTTPS destinations |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Encrypted C2 channel to avoid IDS detection | **Suricata:** JA3 fingerprint matching; certificate age/issuer analysis | Egress filtering by SNI; Certificate transparency monitoring |
| T1090.003 | Proxy: Multi-hop Proxy | Routed C2 through multiple proxies to obscure origin | **Suricata:** Tor exit node detection; VPN protocol signatures | Firewall: block known Tor exit nodes and VPN providers; DNS filtering |

### Exfiltration (TA0010)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1567 | Exfiltration Over Web Service | Exfiltrated data via HTTPS to attacker-controlled servers | **Suricata:** large outbound transfers; **VPC Flow Logs:** volume anomalies | Egress firewall rules; DLP; Network Policies restricting egress |
| T1537 | Transfer Data to Cloud Account | Attempted to copy data to attacker's GCP project | Cloud Audit Logs: cross-project API calls; IAM: deny cross-project access | VPC Service Controls (perimeter); IAM: no cross-project roles |

### Impact (TA0040)

| ID | Technique | APT Usage | Detection | Prevention |
|----|-----------|-----------|-----------|------------|
| T1496 | Resource Hijacking | Deployed cryptocurrency miners consuming cluster CPU/GPU | **Falco:** `Detect crypto miners using the Stratum protocol`, high CPU alerts; **Suricata:** Stratum protocol detection on ports 3333/3334; Cloud Monitoring: CPU usage anomalies | **Firewall rules (PRI 500):** DENY egress to crypto mining ports; Resource Quotas; LimitRanges; Node auto-scaling limits |
| T1485 | Data Destruction | Potential for destroying infrastructure or data | Cloud Audit Logs: destructive API calls (`delete`, `destroy`); Terraform state anomalies | IAM least privilege; Binary Authorization; Terraform state versioning in GCS; Backups |
| T1498 | Network Denial of Service | API server DoS via YAML bombs (CVE-2019-11253 pattern) | Cloud Monitoring: API server latency spikes; Falco: excessive API requests | `APIPriorityAndFairness`; `--max-request-bytes`; Private cluster; Master authorized networks |

---

## Controls Coverage Matrix

Summary of which controls detect or prevent each technique:

```
                   | Falco | Suricata | Firewall | WIF | RBAC | PSS | Trivy | Audit | BigQuery |
                   | (run  | (net     | (egress  |     |      |     | (scan)| Logs  | (analyt) |
                   | time) |  IDS)    |  deny)   |     |      |     |       |       |          |
===================|=======|==========|==========|=====|======|=====|=======|=======|==========|
T1078.004 ValidAcct|       |          |          |PREV |      |     |       | DET   |  DET     |
T1610 DeployContain| DET   |          |          |     | PREV |     | DET   | DET   |          |
T1136 CreateAccount| DET   |          |          |PREV |      |     |       | DET   |  DET     |
T1611 EscapeToHost | DET   |          |          |     |      |PREV | DET   |       |          |
T1656 Impersonation|       |          |          |PREV |      |     |       | DET   |  DET     |
T1571 NonStdPort   |       | DET      | PREV     |     |      |     |       |       |  DET     |
T1496 Crypto Mining| DET   | DET      | PREV     |     |      |     |       |       |  DET     |
T1210 LateralMvmt  | DET   | DET      |          |     | PREV |     |       | DET   |          |
T1530 CloudData    |       |          |          |     | PREV |     |       | DET   |  DET     |
T1552.005 Metadata | DET   | DET      |          |PREV |      |     |       |       |          |
T1528 StealToken   |       | DET      |          |PREV |      |     |       | DET   |          |
T1059.004 Shell    | DET   |          |          |     |      |PREV |       |       |          |
T1609 ContainerCmd | DET   |          |          |     | PREV |     |       | DET   |          |
T1613 Discovery    | DET   |          |          |     | PREV |     |       | DET   |          |
T1567 Exfiltration |       | DET      | PREV     |     |      |     |       |       |  DET     |
T1498 NetworkDoS   | DET   | DET      |          |     |      |     |       | DET   |          |
===================|=======|==========|==========|=====|======|=====|=======|=======|==========|

Legend: PREV = Prevents   DET = Detects
```

---

## Detection Rule Examples

### Falco Rules for APT TTPs

```yaml
# Detect magic file creation in /tmp (APT persistence marker)
- rule: APT Magic File Created in Tmp
  desc: Detects creation of hidden files in /tmp matching APT marker pattern
  condition: >
    evt.type in (open, openat, creat) and
    evt.dir = < and
    fd.name startswith /tmp/. and
    container.id != host
  output: >
    APT persistence marker file created in /tmp
    (file=%fd.name user=%user.name container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository)
  priority: CRITICAL
  tags: [apt, persistence, mitre_t1136]

# Detect crypto mining Stratum protocol
- rule: Detect Crypto Mining Stratum Protocol
  desc: Detects outbound connections using Stratum mining protocol
  condition: >
    evt.type in (connect, sendto) and
    evt.dir = < and
    fd.sport in (3333, 3334, 8332, 8333, 8545, 30303, 45700) and
    container.id != host
  output: >
    Crypto mining connection detected
    (port=%fd.sport dest=%fd.sip container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [crypto, impact, mitre_t1496]

# Detect container escape attempt
- rule: Container Escape via nsenter
  desc: Detects use of nsenter to escape container namespace
  condition: >
    spawned_process and
    proc.name = nsenter and
    container.id != host
  output: >
    Container escape attempt via nsenter
    (command=%proc.cmdline user=%user.name container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [escape, privilege_escalation, mitre_t1611]
```

### Suricata Rules for APT TTPs

```
# Detect Metasploit C2 on any port
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"APT C2 - Metasploit Meterpreter"; content:"|00 00 00|"; depth:4; content:"|00 00 00|"; distance:0; flowbits:set,meterpreter; classtype:trojan-activity; sid:9000001; rev:1;)

# Detect Cobalt Strike beacon
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"APT C2 - Cobalt Strike Beacon TLS"; ja3.hash; content:"72a589da586844d7f0818ce684948eea"; classtype:trojan-activity; sid:9000002; rev:1;)

# Detect IRC C2 channel
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"APT C2 - IRC Channel Communication"; flow:established,to_server; content:"JOIN #"; nocase; classtype:trojan-activity; sid:9000003; rev:1;)

# Detect Stratum mining protocol
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"CRYPTO - Stratum Mining Protocol"; flow:established,to_server; content:"{"; content:"\"method\""; distance:0; content:"\"mining."; distance:0; classtype:policy-violation; sid:9000004; rev:1;)
```

---

## MITRE ATT&CK Navigator Layers

The techniques covered in this project map to the following ATT&CK matrices:

- **Enterprise Cloud** (IaaS/SaaS): T1078.004, T1530, T1537, T1580, T1526
- **Containers**: T1610, T1611, T1609, T1613
- **Enterprise (General)**: T1059, T1071, T1496, T1571, T1573

For interactive visualization, import the technique IDs into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
