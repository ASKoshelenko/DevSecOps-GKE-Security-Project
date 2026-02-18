# Incident Response Playbook

Step-by-step playbooks for security incidents detected by the DevSecOps monitoring stack. Each playbook follows the NIST SP 800-61 incident response lifecycle: Preparation, Detection, Containment, Eradication, Recovery, Post-Incident.

---

## Table of Contents

1. [IR-001: APT Detection Triggered](#ir-001-apt-detection-triggered)
2. [IR-002: Crypto Mining Detected](#ir-002-crypto-mining-detected)
3. [IR-003: Container Escape Detected](#ir-003-container-escape-detected)
4. [IR-004: Service Account Key Compromise](#ir-004-service-account-key-compromise)
5. [IR-005: C2 Communication Detected](#ir-005-c2-communication-detected)
6. [General Procedures](#general-procedures)

---

## IR-001: APT Detection Triggered

**Severity:** P1 - CRITICAL
**SLA:** Triage within 5 minutes, contain within 15 minutes
**MITRE ATT&CK:** T1078.004, T1136, T1610, T1571, T1496

### Trigger Conditions

- Falco alert: `APT Magic File Created in Tmp` (magic file `/tmp/.x` or similar pattern)
- Multiple correlated alerts within a short time window (C2 + persistence + execution)
- Cloud Audit Log: SA key creation + unusual API activity from same principal
- Combination of any two indicators from the APT profile (INC-2026-0042)

### Detection Verification

| Step | Action | Tool | Expected Output |
|------|--------|------|-----------------|
| 1 | Confirm Falco alert is not a false positive | Kibana | Review alert context: pod, namespace, image, user |
| 2 | Check for correlated alerts in the last 1 hour | Kibana | Search for same pod/namespace/node across Falco + Suricata |
| 3 | Verify magic file existence | kubectl | `kubectl exec <pod> -- ls -la /tmp/` |
| 4 | Check pod image against known-good registry | kubectl | `kubectl describe pod <pod> -n <ns>` -- verify image source |
| 5 | Review Cloud Audit Logs for SA activity | BigQuery/Console | Query for principal activity in last 24 hours |

### Containment

| Step | Action | Command | Notes |
|------|--------|---------|-------|
| 1 | **Isolate the pod** -- Apply deny-all NetworkPolicy | `kubectl apply -f -` (see below) | Cuts all network access immediately |
| 2 | **Cordon the node** -- Prevent new pod scheduling | `kubectl cordon <node-name>` | Affected node receives no new workloads |
| 3 | **Capture forensic snapshot** | `kubectl logs <pod> > /evidence/pod.log` | Preserve logs before pod termination |
| 4 | **Block attacker IPs** | Update `c2_blocked_ips` in Terraform | Add attacker source IPs to firewall deny list |
| 5 | **Rotate all SA credentials** | See [General: Credential Rotation](#credential-rotation) | Even WIF tokens -- revoke active sessions |
| 6 | **Notify incident commander** | PagerDuty / Phone | Escalate to P1 |

**Network isolation policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolate
  namespace: <affected-namespace>
spec:
  podSelector:
    matchLabels:
      <label-of-affected-pod>
  policyTypes:
  - Ingress
  - Egress
  # Empty ingress/egress = deny all
```

### Investigation

| Step | Action | Query/Command |
|------|--------|---------------|
| 1 | **Timeline reconstruction** | BigQuery: Query all logs for affected pod/SA in the last 7 days, ordered by timestamp |
| 2 | **Identify initial access vector** | Cloud Audit Logs: First API call from the suspicious principal |
| 3 | **Map lateral movement** | Falco/Suricata: Network connections from affected pod to other pods/nodes |
| 4 | **Identify all compromised resources** | `gcloud asset search-all-iam-policies --query="policy:<suspicious-sa>"` |
| 5 | **Check for persistence mechanisms** | Falco: File creation events; `kubectl get cronjobs,jobs -A`; Cloud Audit: SA key creation |
| 6 | **Capture container filesystem** | `kubectl cp <pod>:/tmp /evidence/container-tmp/` |
| 7 | **Review VPC Flow Logs** | BigQuery: Query flow logs for affected node IPs |

### Eradication

| Step | Action | Notes |
|------|--------|-------|
| 1 | Delete compromised pods | `kubectl delete pod <pod> -n <ns> --grace-period=0` |
| 2 | Delete any attacker-created resources | CronJobs, Secrets, ConfigMaps, ServiceAccounts |
| 3 | Remove unauthorized IAM bindings | `gcloud projects remove-iam-policy-binding` |
| 4 | Delete any created SA keys | `gcloud iam service-accounts keys delete` |
| 5 | Update firewall rules with attacker IPs | `terraform apply` with updated `c2_blocked_ips` |
| 6 | Patch vulnerabilities exploited | Node upgrade, image rebuild, config fix |

### Recovery

| Step | Action | Notes |
|------|--------|-------|
| 1 | Redeploy workloads from known-good images | Use last verified image digest |
| 2 | Uncordon nodes after forensic capture | `kubectl uncordon <node-name>` |
| 3 | Verify all security controls are active | Falco, Suricata, Trivy, Network Policies |
| 4 | Run full Trivy scan of all namespaces | `kubectl get vulnerabilityreports -A` |
| 5 | Validate BigQuery pipeline is processing | Check `extract_vulnerabilities.py` logs |
| 6 | Monitor for re-compromise indicators | Enhanced alerting for 30 days |

---

## IR-002: Crypto Mining Detected

**Severity:** P2 - HIGH
**SLA:** Triage within 15 minutes, contain within 30 minutes
**MITRE ATT&CK:** T1496 (Resource Hijacking)

### Trigger Conditions

- Falco alert: `Detect crypto miners using the Stratum protocol`
- Suricata alert: `CRYPTO - Stratum Mining Protocol` (SID 9000004)
- Firewall log: Denied egress to crypto mining ports (3333, 3334, 8332, 8333, 8545, 30303, 45700)
- Cloud Monitoring: Sustained CPU usage above 90% on GKE nodes without corresponding workload increase
- Falco alert: `Outbound connection to common miner pool port`

### Detection Verification

| Step | Action | Tool |
|------|--------|------|
| 1 | Confirm mining process in the pod | `kubectl exec <pod> -- ps aux` -- look for `xmrig`, `minerd`, `stratum` |
| 2 | Check network connections | `kubectl exec <pod> -- ss -tulnp` -- look for connections to mining ports |
| 3 | Verify CPU consumption | `kubectl top pods -n <ns>` -- identify abnormal CPU usage |
| 4 | Check Suricata eve.json for Stratum protocol matches | Kibana: filter by `alert.signature_id:9000004` |
| 5 | Review pod creation event | `kubectl get events -n <ns> --sort-by=.lastTimestamp` |

### Containment

| Step | Action | Command |
|------|--------|---------|
| 1 | **Kill the mining process** (immediate) | `kubectl exec <pod> -- kill -9 <pid>` |
| 2 | **Apply deny-all egress NetworkPolicy** | See IR-001 network isolation policy |
| 3 | **Scale down the deployment to zero** | `kubectl scale deployment/<name> -n <ns> --replicas=0` |
| 4 | **Verify firewall denied the connection** | Check firewall logs for crypto port blocks |
| 5 | **If node is compromised** | `kubectl cordon <node>` and drain: `kubectl drain <node> --force --ignore-daemonsets` |

### Investigation

| Step | Action |
|------|--------|
| 1 | **How did the miner get deployed?** Check the deployment's image, creation timestamp, and creator |
| 2 | **Was the image tampered with?** Compare image digest to Artifact Registry; check for unauthorized pushes |
| 3 | **Was Cloud Build compromised?** Review Cloud Build history for unauthorized triggers |
| 4 | **Are other namespaces affected?** `kubectl get pods -A -o wide` and check CPU usage across cluster |
| 5 | **What is the mining wallet address?** Extract from process arguments or config files in the container |
| 6 | **How long has mining been active?** Cloud Monitoring CPU timeline; BigQuery log analysis |

### Eradication and Recovery

| Step | Action |
|------|--------|
| 1 | Delete the compromised deployment/pod |
| 2 | Rebuild the container image from source (if image was tampered) |
| 3 | Rotate any credentials the compromised pod had access to |
| 4 | Verify resource quotas and limit ranges are enforced in all namespaces |
| 5 | Add the mining pool IPs to `c2_blocked_ips` firewall variable |
| 6 | Verify Stratum port blocking is active in firewall rules |

---

## IR-003: Container Escape Detected

**Severity:** P1 - CRITICAL
**SLA:** Triage within 5 minutes, contain within 10 minutes
**MITRE ATT&CK:** T1611 (Escape to Host)

### Trigger Conditions

- Falco alert: `Container Escape via nsenter`
- Falco alert: `Read sensitive file by container` (accessing `/proc/1/root`, host `/etc/shadow`)
- Falco alert: `Launch Privileged Container` (unexpected)
- Falco alert: `Mount in container` (non-standard mount operations)
- Falco alert: `Container Drift Detected` (new binary executed not in original image)
- Falco alert: `Detect release_agent File Container Escapes`

### Detection Verification

| Step | Action | Tool |
|------|--------|------|
| 1 | Confirm the escape indicator | Falco alert details: syscall, process tree, file access pattern |
| 2 | Check if the container has host access | `kubectl get pod <pod> -o yaml` -- check `hostPID`, `hostNetwork`, `privileged` |
| 3 | Verify node integrity | SSH to node (via `gcloud compute ssh`): check for new processes, files, network connections |
| 4 | Check for kubelet credential theft | Node: `ls -la /var/lib/kubelet/` -- verify no unauthorized access |
| 5 | Check for Docker socket access | `kubectl exec <pod> -- ls -la /var/run/docker.sock` |

### Containment -- IMMEDIATE

**This is the highest priority incident. Node compromise means potential cluster compromise.**

| Step | Action | Command |
|------|--------|---------|
| 1 | **Isolate the pod network** | Apply deny-all NetworkPolicy immediately |
| 2 | **Cordon the node** | `kubectl cordon <node-name>` |
| 3 | **Drain the node** | `kubectl drain <node-name> --force --ignore-daemonsets --delete-emptydir-data` |
| 4 | **If host is confirmed compromised:** | Stop the node: `gcloud compute instances stop <instance>` |
| 5 | **Create disk snapshot for forensics** | `gcloud compute disks snapshot <disk> --snapshot-names=forensic-<date>` |
| 6 | **Check all other nodes** | `kubectl get pods -A -o wide` -- identify pods with privileged access |
| 7 | **Rotate kubelet credentials** | Rotate the GKE cluster credentials via API |

### Investigation

| Step | Action |
|------|--------|
| 1 | **Identify the escape method** | Falco alert details will show: nsenter, /proc/1/root, release_agent, or exploit binary |
| 2 | **Determine what the attacker did on the host** | Forensic analysis of the disk snapshot: check `/tmp`, process accounting, auth.log |
| 3 | **Check for lateral movement from the node** | Did the attacker access other nodes via kubelet credentials? |
| 4 | **Verify which CVE was exploited** | Kernel version on the node vs. known escape CVEs (Dirty Pipe, fs_context, etc.) |
| 5 | **Check if the attacker created new pods** | Cloud Audit Logs: pod creation events from the compromised node's kubelet identity |
| 6 | **Verify Kubernetes secrets integrity** | `kubectl get secrets -A` -- check for unauthorized access or modification |

### Eradication

| Step | Action |
|------|--------|
| 1 | **Replace the compromised node** | Create new node pool or delete/recreate the node |
| 2 | **Patch the vulnerability** | Upgrade node image to latest; enable auto-upgrade |
| 3 | **Enforce Pod Security Standards** | Label all namespaces with `pod-security.kubernetes.io/enforce=restricted` |
| 4 | **Audit all pods for escape vectors** | Check for privileged, hostPID, hostNetwork, SYS_ADMIN capability |
| 5 | **Deploy/update Falco rules** | Add specific rules for the exploit method observed |

### Recovery

| Step | Action |
|------|--------|
| 1 | Replace the node with a new instance from a clean image |
| 2 | Verify Pod Security Standards are enforced cluster-wide |
| 3 | Run Trivy scan to verify no vulnerable images remain |
| 4 | Verify Falco DaemonSet is running on all nodes |
| 5 | Monitor the cluster closely for 7 days for re-compromise indicators |

---

## IR-004: Service Account Key Compromise

**Severity:** P1 - CRITICAL
**SLA:** Triage within 5 minutes, contain within 15 minutes
**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)

### Trigger Conditions

- Cloud Audit Log: `google.iam.admin.v1.CreateServiceAccountKey` (any key creation, should never happen with WIF)
- Cloud Audit Log: SA used from IP outside known GitHub Actions runner ranges or corporate network
- Cloud Audit Log: SA used during non-business hours with unusual API call patterns
- Org Policy violation alert: `disableServiceAccountKeyCreation` constraint bypassed
- Security Command Center finding: leaked credential in public repository

### Detection Verification

| Step | Action | Command |
|------|--------|---------|
| 1 | Identify the compromised SA | Cloud Audit Logs: `protoPayload.authenticationInfo.principalEmail` |
| 2 | List all keys for the SA | `gcloud iam service-accounts keys list --iam-account=<SA_EMAIL>` |
| 3 | Identify the suspicious key ID | Match key ID from audit logs to the key list |
| 4 | Determine the scope of the SA | `gcloud projects get-iam-policy <PROJECT> --filter="bindings.members:<SA>"` |
| 5 | Review API calls made with the key | BigQuery: query Cloud Audit Logs for the SA in last 30 days |

### Containment -- IMMEDIATE

| Step | Action | Command |
|------|--------|---------|
| 1 | **Delete the compromised key** | `gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL>` |
| 2 | **Delete ALL keys for the SA** | Iterate over all keys and delete |
| 3 | **Disable the SA** (if safe) | `gcloud iam service-accounts disable <SA_EMAIL>` |
| 4 | **Revoke active sessions** | `gcloud auth revoke <SA_EMAIL>` from any cached sessions |
| 5 | **Re-enforce Org Policy** | Verify `disableServiceAccountKeyCreation` is enforced |
| 6 | **Block attacker IP at firewall** | Add to `c2_blocked_ips` and apply immediately |

### Investigation

| Step | Action |
|------|--------|
| 1 | **How was the key obtained?** Developer workstation compromise, committed to repo, CI artifact leak |
| 2 | **What API calls were made?** Full audit trail from Cloud Audit Logs for the SA principal |
| 3 | **Were new resources created?** Compute instances, IAM bindings, Cloud Functions, GCS objects |
| 4 | **Were other keys created?** Check for persistence via additional SA key creation |
| 5 | **Was data exfiltrated?** BigQuery audit logs, GCS access logs, Compute API exports |
| 6 | **Was the Terraform state accessed?** GCS bucket access logs for the state bucket |

### Eradication

| Step | Action |
|------|--------|
| 1 | Delete all unauthorized resources created by the attacker |
| 2 | Remove any IAM bindings added by the attacker |
| 3 | Delete any additional SA keys created for persistence |
| 4 | If the Terraform state was modified: restore from GCS versioning |
| 5 | Verify WIF is the only authentication method for all external flows |
| 6 | Run `gcloud iam service-accounts keys list` on ALL SAs to verify zero keys |

### Recovery and Prevention

| Step | Action |
|------|--------|
| 1 | Confirm Org Policy `disableServiceAccountKeyCreation` is enforced at org level |
| 2 | Verify all CI/CD uses WIF (no SA keys in GitHub secrets, Jenkins credentials, etc.) |
| 3 | Rotate any secrets that the compromised SA had access to |
| 4 | Run security scan on the developer workstation that was compromised |
| 5 | Implement endpoint detection on developer workstations |
| 6 | Review developer security training program |

---

## IR-005: C2 Communication Detected

**Severity:** P1 - CRITICAL
**SLA:** Triage within 5 minutes, contain within 10 minutes
**MITRE ATT&CK:** T1571 (Non-Standard Port), T1071 (Application Layer Protocol)

### Trigger Conditions

- Suricata alert: `APT C2 - Metasploit Meterpreter` (SID 9000001)
- Suricata alert: `APT C2 - Cobalt Strike Beacon TLS` (SID 9000002)
- Suricata alert: `APT C2 - IRC Channel Communication` (SID 9000003)
- Firewall log: Denied egress to C2 ports (4444, 5555, 6666, 6667, 8443, 9090)
- VPC Flow Log: Persistent connections to unrecognized external IPs
- Falco alert: `Outbound connection to known C2 server`

### Detection Verification

| Step | Action | Tool |
|------|--------|------|
| 1 | Confirm the alert is not a false positive | Suricata: review full eve.json record including payload, flow, and TLS details |
| 2 | Identify the source pod | Correlate source IP from Suricata alert with GKE pod network |
| 3 | Verify the destination IP reputation | VirusTotal, AbuseIPDB, or internal threat intel |
| 4 | Check JA3 fingerprint | Compare against known C2 framework JA3 hashes |
| 5 | Review connection frequency and volume | VPC Flow Logs: connection pattern analysis |
| 6 | Check if firewall successfully blocked | Firewall logs: denied entries for the same flow |

### Containment -- IMMEDIATE

| Step | Action | Command |
|------|--------|---------|
| 1 | **Apply deny-all egress NetworkPolicy** | Immediately cut all outbound from the affected pod |
| 2 | **Block the C2 IP at firewall** | `terraform apply` with C2 IP added to `c2_blocked_ips` |
| 3 | **Kill the process making the connection** | `kubectl exec <pod> -- kill -9 <pid>` |
| 4 | **Cordon the node** | `kubectl cordon <node>` |
| 5 | **Capture network traffic** | If possible, start packet capture on the node for forensics |
| 6 | **Notify SOC/CIRT** | Escalate to P1 with all indicators |

### Investigation

| Step | Action |
|------|--------|
| 1 | **Identify the C2 framework** | Suricata signature, JA3 hash, beacon interval pattern |
| 2 | **Determine C2 protocol** | Meterpreter (TCP), Cobalt Strike (HTTPS beacon), IRC, DNS tunneling |
| 3 | **How long has C2 been active?** | VPC Flow Logs: first connection to the C2 IP |
| 4 | **What commands were executed?** | Falco: process execution timeline in the affected pod |
| 5 | **Was data exfiltrated?** | VPC Flow Logs: bytes transferred to external IPs |
| 6 | **Are other pods communicating with the same C2?** | Suricata/VPC Flow Logs: search for the C2 IP across all sources |
| 7 | **How did the C2 agent get into the container?** | Image analysis, pod event history, deployment change history |

### Eradication

| Step | Action |
|------|--------|
| 1 | Delete the compromised pod |
| 2 | Rebuild the container image (if the image contains the C2 agent) |
| 3 | Block the C2 IP, domain, and JA3 hash in Suricata rules |
| 4 | Add the C2 IP to the `c2_blocked_ips` Terraform variable permanently |
| 5 | Update Suricata rules with new C2 indicators |
| 6 | Scan all running container images for the C2 agent binary |

### Recovery

| Step | Action |
|------|--------|
| 1 | Redeploy workloads from verified clean images |
| 2 | Verify all firewall deny rules are active and logging |
| 3 | Verify Suricata is running on all nodes and processing traffic |
| 4 | Share C2 indicators (IPs, domains, JA3 hashes) with threat intel team |
| 5 | Update Suricata and Falco rule sets with new indicators |
| 6 | Monitor for reconnection attempts for 30 days |

---

## General Procedures

### Credential Rotation

When any credential compromise is suspected:

```bash
# 1. List all SA keys (should be zero with WIF)
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  echo "=== $sa ==="
  gcloud iam service-accounts keys list --iam-account="$sa" \
    --filter="keyType=USER_MANAGED"
done

# 2. Delete any user-managed keys found
gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL

# 3. Verify Org Policy enforcement
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
  --project=PROJECT_ID

# 4. Rotate GKE cluster credentials
gcloud container clusters update devsecops-gke \
  --zone=us-central1-a \
  --start-credential-rotation

# 5. Complete the rotation
gcloud container clusters update devsecops-gke \
  --zone=us-central1-a \
  --complete-credential-rotation
```

### Evidence Preservation

For any P1/P2 incident, preserve the following before any destructive action:

| Evidence | Command | Storage |
|----------|---------|---------|
| Pod logs | `kubectl logs <pod> --all-containers > evidence/pod-logs.txt` | GCS evidence bucket |
| Pod description | `kubectl get pod <pod> -o yaml > evidence/pod-spec.yaml` | GCS evidence bucket |
| Container filesystem | `kubectl cp <pod>:/tmp evidence/container-tmp/` | GCS evidence bucket |
| Node disk snapshot | `gcloud compute disks snapshot <disk>` | Compute snapshots |
| Network capture | `kubectl exec <pod> -- tcpdump -w /tmp/capture.pcap` | GCS evidence bucket |
| Cloud Audit Logs | BigQuery export for the incident time range | BigQuery / GCS |
| Falco alerts | Elasticsearch export for the incident time range | GCS evidence bucket |
| Suricata alerts | Elasticsearch export for the incident time range | GCS evidence bucket |
| VPC Flow Logs | BigQuery export for the incident time range | BigQuery / GCS |

### Communication Template

**Incident notification (internal):**

```
INCIDENT: [IR-XXX] [Title]
SEVERITY: P[1-4]
STATUS:   [Detected/Contained/Investigating/Eradicated/Recovered]
TIME:     [Detection timestamp UTC]

SUMMARY:
[2-3 sentence description of what was detected]

IMPACT:
[What systems/data are affected]

CURRENT ACTIONS:
[What is being done right now]

NEXT UPDATE: [ETA]
INCIDENT COMMANDER: [Name]
```

### Severity Classification

| Severity | Description | Response SLA | Examples |
|----------|-------------|-------------|---------|
| **P1 - CRITICAL** | Active compromise, data breach, or widespread impact | Triage: 5 min, Contain: 15 min | APT detection, container escape, SA key compromise, active C2 |
| **P2 - HIGH** | Confirmed malicious activity with limited scope | Triage: 15 min, Contain: 30 min | Crypto mining, single-pod compromise, failed C2 attempt |
| **P3 - MEDIUM** | Suspicious activity requiring investigation | Triage: 1 hour, Investigate: 4 hours | Policy violation, unusual API patterns, new vulnerability |
| **P4 - LOW** | Informational, potential false positive | Triage: 4 hours, Review: 24 hours | New Trivy finding, minor config drift, noisy Falco rule |
