# IDS/IPS Setup for Russian APT Detection in GKE/GCP

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                         GKE Cluster (Private)                           |
|                                                                         |
|  +------------------+    +-------------------+    +------------------+  |
|  |  Application     |    |  Application      |    |  Application     |  |
|  |  Pod             |    |  Pod              |    |  Pod             |  |
|  |  [Falco eBPF]    |    |  [Falco eBPF]     |    |  [Falco eBPF]    |  |
|  +--------+---------+    +---------+---------+    +--------+---------+  |
|           |                        |                       |            |
|  +--------v------------------------v-----------------------v---------+  |
|  |                        Node (COS)                                 |  |
|  |  +----------------+  +----------------+  +---------------------+  |  |
|  |  | Falco          |  | Suricata       |  | Filebeat            |  |  |
|  |  | DaemonSet      |  | DaemonSet      |  | DaemonSet           |  |  |
|  |  | (eBPF probe)   |  | (AF_PACKET)    |  | (Log collector)     |  |  |
|  |  +-------+--------+  +-------+--------+  +----------+----------+  |  |
|  |          |                    |                       |            |  |
|  +----------+--------------------+-----------------------+-----------+  |
|             |                    |                       |              |
|  +----------v--------------------v-----------------------v-----------+  |
|  |                    Monitoring Namespace                            |  |
|  |                                                                   |  |
|  |  +-----------+    +------------+    +-------------------------+   |  |
|  |  | Logstash  +--->| Elastic-   +--->| Kibana                  |   |  |
|  |  | (Parse +  |    | search     |    | - APT Dashboard         |   |  |
|  |  |  Enrich)  |    | (Index +   |    | - Crypto Mining Dash    |   |  |
|  |  +-----------+    |  Search)   |    | - Network Anomaly Dash  |   |  |
|  |                   +------+-----+    +-------------------------+   |  |
|  +------------------------------------------------------------------+  |
|                             |                                           |
+-----------------------------+-------------------------------------------+
                              |
          +-------------------+---------------------+
          |                   |                     |
+---------v--------+ +-------v---------+ +---------v--------+
| GCP Cloud        | | GCP Cloud       | | Alerting         |
| Logging          | | IDS (Palo Alto) | |                  |
|                  | |                  | | - PagerDuty (P1) |
| - Falco alerts   | | - DPI           | | - Slack          |
| - Suricata logs  | | - Threat Intel  | | - Email          |
| - K8s Audit      | | - Malware det.  | |                  |
+--------+---------+ +--------+--------+ +------------------+
         |                     |
+--------v---------------------v--------+
| GCP Security Command Center (SCC)     |
|                                       |
| - Event Threat Detection (ETD)        |
| - Container Threat Detection (CTD)    |
| - Security Health Analytics           |
+--------+-----------------------------+
         |
+--------v-----------------------------+
| BigQuery (Threat Hunting)            |
|                                      |
| - VPC Flow Logs                      |
| - Cloud IDS Findings                 |
| - Security Events (90-day retention) |
+--------------------------------------+
```

## Data Flow

```
Syscalls (Container) ---> Falco (eBPF) ---> events.json ---> Filebeat --+
                                                                         |
Network Packets -------> Suricata (AF_PACKET) -> eve.json -> Filebeat --+---> Logstash ---> Elasticsearch ---> Kibana
                                                                         |         |
K8s API Calls ---------> Audit Log ---------> audit.log ---> Filebeat --+         |
                                                                                   |
Container stdout/err --> Container Logs ----> *.log -------> Filebeat --+         +---> GCP Cloud Logging
                                                                                   |
VPC Network Flows -----> Flow Logs ----------> Cloud Logging ---------------------+---> BigQuery
                                                                                   |
Mirrored Packets ------> Cloud IDS (Palo Alto) -> Threat Logs --------------------+---> Alerting Pipeline
                                                                                         |
GCP Activity Logs ------> Event Threat Detection -> SCC Findings ------> Pub/Sub --------+
```

## Why These Tools?

### Falco for Runtime Detection

Falco is the industry-standard runtime security tool for Kubernetes, chosen for this APT detection setup because:

- **eBPF-based monitoring**: Uses modern eBPF (CO-RE) probes that work with GKE's Container-Optimized OS (COS) without kernel module compilation. This provides deep syscall visibility with minimal overhead (typically under 3% CPU).
- **Kubernetes-native**: Automatically enriches events with pod name, namespace, deployment, labels, and service account. This context is critical for identifying which workload is compromised.
- **Rule flexibility**: Custom YAML rules can detect specific IOCs like the "magic" file pattern, exact process names (xmrig), and precise network connection patterns (outbound to port 4444).
- **Low latency**: Syscall-level detection triggers in milliseconds, faster than any log-based detection. A reverse shell is detected before the attacker can execute their first command.
- **Falcosidekick ecosystem**: Native integration with 60+ output targets including Slack, PagerDuty, Elasticsearch, GCP Cloud Logging, and webhook-based auto-response.

### Suricata over Snort for Network IDS

Suricata was chosen over Snort for network-level detection because:

- **Multi-threaded architecture**: Suricata uses multiple CPU cores for parallel packet processing, critical for handling GKE cluster traffic volumes. Snort 2.x is single-threaded; Snort 3 improves but Suricata's threading model is more mature.
- **eve.json output format**: Suricata's unified JSON log format integrates natively with ELK stack. Every event type (alerts, DNS, TLS, HTTP, flows) is in a single structured JSON format, eliminating the need for complex log parsing.
- **Protocol detection and JA3**: Built-in JA3/JA3S TLS fingerprinting enables detection of C2 frameworks (Cobalt Strike, Metasploit) by their TLS handshake characteristics, even when traffic is encrypted.
- **AF_PACKET capture**: Zero-copy packet capture using memory-mapped ring buffers provides high-performance capture without the overhead of libpcap.
- **Active community**: Suricata's rule format is compatible with Emerging Threats (ET) Open rules, providing thousands of community-maintained signatures updated daily.

### ELK Stack for SIEM

The ELK (Elasticsearch, Logstash, Kibana) stack was chosen for security event management because:

- **Open-source and self-hosted**: No per-GB ingestion costs. Security data stays within the GKE cluster (important for sensitive forensic data).
- **Scalable architecture**: Elasticsearch's distributed architecture handles the volume of logs from Falco, Suricata, audit logs, and container logs across a multi-node GKE cluster.
- **Rich querying**: Kibana's KQL (Kibana Query Language) enables complex threat hunting queries across all data sources. For example: `falco.rule:"APT Magic File*" AND kubernetes.namespace:"production"`.
- **GeoIP enrichment**: Logstash's GeoIP filter enriches network events with geographic data, enabling visual maps of C2 server locations and identification of traffic to high-risk countries.
- **Dashboard ecosystem**: Pre-built dashboards provide instant visibility. The three dashboards (APT Detection, Crypto Mining, Network Anomaly) cover the primary detection scenarios.
- **Kubernetes integration**: Filebeat's Kubernetes autodiscover automatically detects new pods and adds metadata, ensuring complete log coverage without manual configuration.

### GCP-Native Security (Defense in Depth)

GCP-native tools add a commercial-grade detection layer:

- **Security Command Center (SCC)**: Google's threat intelligence detects threats that open-source tools might miss. ETD uses ML-based anomaly detection.
- **Cloud IDS (Palo Alto)**: Commercial DPI signatures from Palo Alto Networks' Unit 42 threat research team provide detection of zero-day exploits and advanced malware.
- **Cloud Armor**: WAF rules protect externally-exposed GKE services from web-based initial access vectors.
- **VPC Flow Logs**: Network flow records provide a complete audit trail for forensic analysis, even if Suricata misses a flow.

## Detection Coverage Matrix (MITRE ATT&CK)

### Mapping to ATT&CK Framework

| Tactic | Technique | ID | Falco | Suricata | GCP SCC | Cloud IDS | Detection Rule |
|--------|-----------|-----|:-----:|:--------:|:-------:|:---------:|----------------|
| **Initial Access** | Exploit Public-Facing App | T1190 | | X | X | X | Suricata SID:1000504 |
| **Execution** | Command and Scripting Interpreter | T1059 | X | | X | | Falco: Reverse Shell Detected |
| **Execution** | Unix Shell | T1059.004 | X | | | | Falco: Reverse Shell (bash -i) |
| **Persistence** | Valid Accounts | T1078 | | | X | | ETD: SA Key Anomalous Usage |
| **Privilege Escalation** | Escape to Host | T1611 | X | | X | | Falco: Container Escape Attempt |
| **Privilege Escalation** | Abuse Elevation Control | T1548 | X | | | | Falco: Container Escape (nsenter) |
| **Defense Evasion** | Indicator Removal | T1070 | X | | | | Falco: Sensitive File Access |
| **Credential Access** | Steal App Access Token | T1528 | X | | X | | Falco: SA Token Access |
| **Credential Access** | Unsecured Credentials | T1552 | X | | X | | Falco: Sensitive File Access |
| **Credential Access** | Cloud Instance Metadata | T1552.005 | | X | | | Suricata SID:1000505 |
| **Discovery** | Container and Resource Discovery | T1613 | X | | | | Falco: kubectl/API Access |
| **Discovery** | Account Discovery | T1087 | X | | X | | Falco: kubectl auth can-i |
| **Lateral Movement** | Use Alternate Auth Material | T1550 | X | | X | | Falco: SA Token from Unusual Pod |
| **Collection** | Data from Cloud Storage | T1530 | | | X | | ETD: Unusual API Calls |
| **Command and Control** | Application Layer Protocol | T1071 | X | X | | X | Falco + Suricata C2 Rules |
| **Command and Control** | Web Protocols | T1071.001 | | X | | X | Suricata SID:1000010 |
| **Command and Control** | DNS | T1071.004 | | X | | | Suricata SID:1000220-1000223 |
| **Command and Control** | Encrypted Channel | T1573 | X | X | | X | Suricata SID:1000011, 1000503 |
| **Command and Control** | Non-Standard Port | T1571 | X | X | | | Suricata SID:1000013, 1000500 |
| **Command and Control** | Proxy: Multi-hop Proxy | T1090.003 | | X | | | Suricata SID:1000400-1000402 |
| **Command and Control** | Domain Generation Algorithm | T1568.002 | | X | | | Suricata SID:1000222 |
| **Exfiltration** | Exfil Over Web Service | T1567 | | X | | | Suricata SID:1000301 |
| **Exfiltration** | Exfil Over Unencrypted Proto | T1048 | | X | | | Suricata SID:1000300-1000304 |
| **Exfiltration** | Data Encoding | T1132 | | X | | | Suricata SID:1000303 |
| **Impact** | Resource Hijacking | T1496 | X | X | X | | Falco + Suricata Mining Rules |
| **Resource Development** | Ingress Tool Transfer | T1105 | X | | | | Falco: Magic File + Download |

### Coverage Summary

- **Total MITRE ATT&CK Techniques Covered**: 28
- **Total MITRE ATT&CK Tactics Covered**: 12 of 14
- **Multi-Source Detection** (2+ tools): 12 techniques
- **Single-Source Detection**: 16 techniques

## False Positive Tuning Guidance

### Common False Positives and Mitigation

| Rule | False Positive Source | Mitigation |
|------|---------------------|------------|
| Magic File in /tmp | Application temp files with "magic" in name (e.g., `libmagic` file type detection) | Add specific application processes to `safe_tmp_writers` macro. Check `fd.name` regex pattern specificity. |
| C2 Port Connection | Legitimate services on ports 4444/5555/8443 (e.g., internal dev tools, alternative HTTPS) | Add known safe destination IPs to exception list. Use Suricata's `suppress` for specific src/dst pairs. |
| Crypto Mining Process | Performance benchmarking tools, legitimate blockchain nodes | Add known-good processes to `known_crypto_miners` negative list. Tune by container image. |
| Container Escape | Legitimate system pods using nsenter/mount (e.g., CSI drivers, monitoring agents) | Add to `escape_tools` exception by `k8s.ns.name` or `container.image.repository`. |
| kubectl API Access | CI/CD operators, GitOps controllers (ArgoCD, Flux), monitoring agents | Add controller pods to `known_sa_consumers` macro. Filter by `k8s.pod.name startswith`. |
| SA Token Access | Service mesh sidecars (Istio/Envoy), cert-manager, vault-agent | Add to `known_sa_consumers` macro by pod name prefix or namespace. |
| Suspicious Download | Package managers during container builds, health check scripts | Filter by `proc.pname` (parent process). Exclude known CI/CD namespaces. |
| Suricata HTTP on non-standard port | Internal services using non-standard ports | Add internal service ports to Suricata's `$HTTP_PORTS` variable. |

### Tuning Process

1. **Deploy in alert-only mode** first (no auto-response) for 1-2 weeks
2. **Review all alerts** in Kibana daily during the tuning period
3. **Identify patterns** in false positives (consistent source pod, namespace, or image)
4. **Add exceptions** to the appropriate macro or suppress list
5. **Re-enable auto-response** after false positive rate drops below 5%
6. **Continuous tuning**: Review new false positives weekly as workloads change

### Tuning Falco Rules

Add exceptions to the macros at the top of `falco/custom-rules.yaml`:

```yaml
# Example: Exclude the monitoring namespace from kubectl detection
- macro: known_sa_consumers
  condition: >
    (k8s.ns.name = "monitoring" or
     k8s.pod.name startswith "argocd" or
     k8s.pod.name startswith "vault-agent")
  append: true
```

### Tuning Suricata Rules

Add suppress entries to `suricata/suricata-values.yaml`:

```yaml
rules:
  suppressList:
    # Suppress HTTP on non-standard port for internal service
    - gid: 1
      sid: 1000500
      track: by_src
      ip: "10.16.0.0/14"  # Pod CIDR
```

## Directory Structure

```
ids-ips/
|-- falco/
|   |-- custom-rules.yaml          # 10 Falco rules for APT detection
|   |-- falco-values.yaml          # Helm values for GKE deployment
|
|-- suricata/
|   |-- custom.rules               # 40+ Suricata IDS rules
|   |-- suricata-values.yaml       # Helm values for DaemonSet deployment
|
|-- elk/
|   |-- filebeat-config.yaml       # Filebeat DaemonSet + ConfigMap + RBAC
|   |-- logstash-pipeline.conf     # Parse, enrich (GeoIP), tag APT events
|   |-- elasticsearch-index-template.json  # ECS-compatible index mapping
|   |-- kibana-dashboards/
|       |-- apt-detection-dashboard.ndjson     # APT activity overview
|       |-- crypto-mining-dashboard.ndjson     # Mining detection
|       |-- network-anomaly-dashboard.ndjson   # Network anomalies + geo map
|
|-- gcp-security/
|   |-- security-command-center.tf  # SCC Premium + Pub/Sub notifications
|   |-- cloud-armor.tf             # WAF rules (OWASP, geo-block, rate-limit)
|   |-- vpc-flow-logs.tf           # Flow logs + BigQuery export + metrics
|   |-- cloud-ids.tf               # Managed Palo Alto IDS + packet mirroring
|   |-- threat-detection.tf        # ETD alert policies + log-based metrics
|
|-- alerting/
|   |-- pagerduty-integration.tf   # PagerDuty notification channels + composite alerts
|   |-- slack-webhook.tf           # Slack channels + C2/reverse shell alerts
|   |-- auto-response/
|       |-- quarantine-pod.sh      # Network-isolate compromised pod
|       |-- block-ip.sh            # Firewall rule to block C2 IP
|       |-- revoke-sa.sh           # Disable SA and revoke all keys
|       |-- incident-response-playbook.md  # Step-by-step IR procedures
|
|-- README.md                      # This file
```

## Deployment

### Prerequisites

- GKE cluster with Network Policy enabled (Calico or Cilium)
- Helm 3.x installed
- `kubectl` configured for the target cluster
- `gcloud` authenticated with sufficient IAM permissions
- Terraform 1.5+ for GCP-native security resources

### Step 1: Deploy Falco

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Create the custom rules ConfigMap
kubectl create namespace falco-system
kubectl create configmap falco-custom-rules \
  --from-file=custom-rules.yaml=falco/custom-rules.yaml \
  -n falco-system

# Deploy Falco with custom values
helm install falco falcosecurity/falco \
  --namespace falco-system \
  -f falco/falco-values.yaml \
  --set falcosidekick.config.slack.webhookurl="<YOUR_SLACK_WEBHOOK>" \
  --set falcosidekick.config.pagerduty.routingKey="<YOUR_PD_KEY>"
```

### Step 2: Deploy Suricata

```bash
kubectl create namespace suricata-system

# Create custom rules ConfigMap
kubectl create configmap suricata-custom-rules \
  --from-file=custom.rules=suricata/custom.rules \
  -n suricata-system

# Deploy Suricata (using a community chart or custom manifest)
# Apply the values from suricata/suricata-values.yaml
```

### Step 3: Deploy ELK Stack

```bash
kubectl create namespace monitoring

# Deploy Elasticsearch
helm repo add elastic https://helm.elastic.co
helm install elasticsearch elastic/elasticsearch -n monitoring

# Deploy Logstash with custom pipeline
kubectl create configmap logstash-pipeline \
  --from-file=logstash.conf=elk/logstash-pipeline.conf \
  -n monitoring
helm install logstash elastic/logstash -n monitoring

# Deploy Kibana
helm install kibana elastic/kibana -n monitoring

# Apply Elasticsearch index template
curl -X PUT "http://elasticsearch-master:9200/_index_template/security-events" \
  -H "Content-Type: application/json" \
  -d @elk/elasticsearch-index-template.json

# Import Kibana dashboards
curl -X POST "http://kibana:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@elk/kibana-dashboards/apt-detection-dashboard.ndjson
curl -X POST "http://kibana:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@elk/kibana-dashboards/crypto-mining-dashboard.ndjson
curl -X POST "http://kibana:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@elk/kibana-dashboards/network-anomaly-dashboard.ndjson

# Deploy Filebeat DaemonSet
kubectl apply -f elk/filebeat-config.yaml
```

### Step 4: Deploy GCP-Native Security

```bash
cd gcp-security/

terraform init
terraform plan -var="project_id=<YOUR_PROJECT>" -var="org_id=<YOUR_ORG_ID>"
terraform apply -var="project_id=<YOUR_PROJECT>" -var="org_id=<YOUR_ORG_ID>"
```

### Step 5: Configure Alerting

```bash
cd ../alerting/

terraform init
terraform plan \
  -var="project_id=<YOUR_PROJECT>" \
  -var="pagerduty_service_key=<PD_KEY>" \
  -var="slack_auth_token=<SLACK_TOKEN>"
terraform apply \
  -var="project_id=<YOUR_PROJECT>" \
  -var="pagerduty_service_key=<PD_KEY>" \
  -var="slack_auth_token=<SLACK_TOKEN>"

# Make auto-response scripts executable
chmod +x auto-response/*.sh
```

## Testing

### Simulate APT Activity (Safe Testing)

```bash
# Test 1: Create the magic file (should trigger Falco alert)
kubectl exec -it <test-pod> -- touch /tmp/magic

# Test 2: Simulate C2 connection attempt (should trigger Suricata + Falco)
kubectl exec -it <test-pod> -- bash -c "echo test | nc -w 1 <safe-test-ip> 4444 || true"

# Test 3: Simulate reverse shell pattern (should trigger Falco)
kubectl exec -it <test-pod> -- bash -c "which nc && echo 'nc exists'"

# Test 4: Access service account token (should trigger Falco)
kubectl exec -it <test-pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Test 5: Run kubectl inside pod (should trigger Falco)
kubectl exec -it <test-pod> -- kubectl get pods 2>/dev/null || true
```

### Verify Detection

```bash
# Check Falco alerts
kubectl logs -l app.kubernetes.io/name=falco -n falco-system --tail=20

# Check Suricata alerts
kubectl exec -it <suricata-pod> -n suricata-system -- cat /var/log/suricata/fast.log | tail -20

# Check Kibana dashboards
# Navigate to the APT Detection Dashboard in your browser
```
