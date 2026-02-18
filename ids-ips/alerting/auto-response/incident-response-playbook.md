# Incident Response Playbook: Russian APT Detection in GKE/GCP

## Classification

| Field | Value |
|-------|-------|
| **Threat Actor** | Russian APT (State-sponsored) |
| **Target Environment** | GKE Cluster on GCP |
| **Severity** | CRITICAL (P1) |
| **MITRE ATT&CK Campaign** | T1105, T1071, T1496, T1611, T1059 |
| **Last Updated** | 2026-02-18 |

---

## Table of Contents

1. [Threat Overview](#1-threat-overview)
2. [Detection Sources](#2-detection-sources)
3. [Triage Procedure](#3-triage-procedure)
4. [Containment Actions](#4-containment-actions)
5. [Investigation Procedure](#5-investigation-procedure)
6. [Eradication](#6-eradication)
7. [Recovery](#7-recovery)
8. [Post-Incident Activities](#8-post-incident-activities)
9. [Quick Reference Commands](#9-quick-reference-commands)

---

## 1. Threat Overview

### Known APT Indicators of Compromise (IOCs)

| IOC | Description | Detection Source |
|-----|-------------|-----------------|
| `/tmp/magic` file | Marker file created after successful initial access | Falco Rule: "APT Magic File Created in /tmp" |
| Port 4444 outbound | Metasploit reverse TCP handler | Suricata SID:1000001, Falco C2 Rule |
| Port 5555 outbound | Custom RAT backconnect | Suricata SID:1000002, Falco C2 Rule |
| Port 8443 outbound | Cobalt Strike HTTPS C2 | Suricata SID:1000003, Falco C2 Rule |
| Crypto miner processes | XMRig, minerd, etc. | Falco Rule: "Crypto Mining Process Detected" |
| SA key theft | Stolen service account credentials | GCP ETD: SA_KEY_ANOMALOUS_USAGE |
| Container escape | nsenter, chroot, mount abuse | Falco Rule: "Container Escape Attempt Detected" |

### Attack Flow (Expected Sequence)

```
Initial Access          Execution              Persistence
     |                     |                      |
     v                     v                      v
[Exploit CVE]  -->  [Deploy payload]  -->  [Create magic file]
                          |                       |
                          v                       v
                   [Reverse shell]  -->  [Steal SA tokens]
                          |                       |
                          v                       v
                   [Container escape]  -->  [Deploy crypto miner]
                          |                       |
                          v                       v
                   [C2 connection]  -->  [Data exfiltration]
```

---

## 2. Detection Sources

### Primary Detection (Real-time)

| Source | What It Detects | Alert Channel |
|--------|----------------|---------------|
| **Falco** | Runtime syscalls: file creation, process exec, network connections | ELK + Slack + PagerDuty |
| **Suricata** | Network traffic: C2 protocols, mining pool connections, DNS anomalies | ELK + Slack |
| **GCP SCC/ETD** | Cloud-level: crypto mining, SA abuse, unusual API calls | Pub/Sub + PagerDuty |
| **Cloud IDS** | Deep packet inspection: malware, exploits, spyware signatures | Cloud Logging + PagerDuty |

### Secondary Detection (Enrichment)

| Source | What It Provides |
|--------|-----------------|
| **VPC Flow Logs** | Network flow records for forensic analysis |
| **K8s Audit Logs** | API server interaction history |
| **Container Logs** | Application-level IOCs |
| **BigQuery** | Historical data for threat hunting |

---

## 3. Triage Procedure

**Time Target: Complete triage within 15 minutes of alert**

### Step 3.1: Verify the Alert

1. Check the alert source and severity in the notification (Slack/PagerDuty)
2. Open the Kibana APT Detection Dashboard: `https://<kibana-url>/app/dashboards#/view/apt-detection-dashboard-v1`
3. Confirm the alert is not a known false positive (check the tuning guide in README.md)
4. Correlate across multiple sources:
   - If Falco AND Suricata both alert -> HIGH CONFIDENCE
   - If only one source alerts -> MEDIUM CONFIDENCE (investigate further)

### Step 3.2: Identify Scope

```bash
# Get the affected pod details
kubectl get pod <pod-name> -n <namespace> -o wide

# Check if multiple pods are affected
kubectl get pods --all-namespaces -o wide | grep <node-name>

# Check for lateral movement indicators
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -50
```

### Step 3.3: Assess Severity

| Condition | Severity | Action |
|-----------|----------|--------|
| Magic file + C2 connection | CRITICAL (P1) | Immediate containment |
| C2 connection only | HIGH (P2) | Rapid containment |
| Crypto miner only | HIGH (P2) | Containment within 1 hour |
| Suspicious file in /tmp | MEDIUM (P3) | Investigation within 4 hours |
| Single anomalous DNS query | LOW (P4) | Investigation within 24 hours |

---

## 4. Containment Actions

**Time Target: Complete containment within 30 minutes of confirmed incident**

### Step 4.1: Network Isolation (FIRST ACTION)

Quarantine the compromised pod to block C2 communication:

```bash
# Quarantine the pod (applies deny-all NetworkPolicy)
./auto-response/quarantine-pod.sh <namespace> <pod-name>
```

This:
- Blocks ALL inbound and outbound traffic for the pod
- Preserves the pod for forensic investigation
- Labels the pod with `quarantine=true`
- Saves forensic data to `/tmp/forensics-<pod>/`

### Step 4.2: Block C2 Server IP

If the C2 destination IP is known (from Suricata or Falco alerts):

```bash
# Block the C2 IP at the firewall level
./auto-response/block-ip.sh <c2-ip-address>
```

This:
- Creates a high-priority egress deny firewall rule
- Blocks ALL VPC instances from reaching the C2 server
- Enables firewall rule logging for monitoring

### Step 4.3: Revoke Compromised Credentials

If service account abuse is detected:

```bash
# Disable the service account and revoke all keys
./auto-response/revoke-sa.sh <sa-email@project.iam.gserviceaccount.com>
```

This:
- Deletes all user-managed SA keys
- Disables the service account
- Records audit trail of the action

### Step 4.4: Prevent Lateral Movement

```bash
# Apply a cluster-wide deny-all policy for the affected namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-lockdown
  namespace: <affected-namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
EOF
```

---

## 5. Investigation Procedure

**Time Target: Complete initial investigation within 2 hours**

### Step 5.1: Collect Evidence

```bash
# 1. Save pod details
kubectl describe pod <pod-name> -n <namespace> > evidence/pod-describe.txt

# 2. Save pod logs (all containers)
kubectl logs <pod-name> -n <namespace> --all-containers > evidence/pod-logs.txt

# 3. Save pod YAML
kubectl get pod <pod-name> -n <namespace> -o yaml > evidence/pod-yaml.txt

# 4. Check for the magic file
kubectl exec <pod-name> -n <namespace> -- ls -la /tmp/
kubectl exec <pod-name> -n <namespace> -- cat /tmp/magic 2>/dev/null

# 5. Check running processes
kubectl exec <pod-name> -n <namespace> -- ps auxwww

# 6. Check network connections
kubectl exec <pod-name> -n <namespace> -- ss -tunapl 2>/dev/null || \
kubectl exec <pod-name> -n <namespace> -- netstat -tunapl 2>/dev/null

# 7. Check command history
kubectl exec <pod-name> -n <namespace> -- cat /root/.bash_history 2>/dev/null
kubectl exec <pod-name> -n <namespace> -- cat /home/*/.bash_history 2>/dev/null

# 8. Check for added/modified binaries
kubectl exec <pod-name> -n <namespace> -- find /tmp /var/tmp /dev/shm -type f -newer /etc/hostname

# 9. Check crontabs
kubectl exec <pod-name> -n <namespace> -- crontab -l 2>/dev/null
kubectl exec <pod-name> -n <namespace> -- cat /etc/crontab 2>/dev/null
```

### Step 5.2: Analyze Logs

```bash
# Falco alerts for the affected pod
# In Kibana: falco.output_fields.k8s_pod:<pod-name>

# Suricata alerts for the pod's IP
# In Kibana: suricata.src_ip:<pod-ip> OR suricata.dest_ip:<pod-ip>

# Kubernetes audit logs for the pod
# In Kibana: k8s_audit.objectRef.name:<pod-name>

# GCP Cloud Logging
gcloud logging read \
  'resource.type="k8s_container" AND resource.labels.pod_name="<pod-name>"' \
  --project=<project-id> --limit=500 --format=json
```

### Step 5.3: Determine Attack Timeline

Build a timeline from the earliest IOC to the latest:

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| T+0 | Initial access | K8s audit | Pod created / exec initiated |
| T+? | Magic file created | Falco | /tmp/magic file written |
| T+? | C2 connection | Suricata | Outbound to X.X.X.X:4444 |
| T+? | Reverse shell | Falco | bash -i >& /dev/tcp/... |
| T+? | SA token theft | Falco | /var/run/secrets/... read |
| T+? | Container escape | Falco | nsenter -t 1 -m -u -i -n |
| T+? | Crypto miner | Falco | xmrig process detected |

### Step 5.4: Check for Lateral Movement

```bash
# Check all pods on the same node
kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName=<node-name>

# Check for new pods created recently
kubectl get pods --all-namespaces --sort-by='.metadata.creationTimestamp' | tail -20

# Check for RBAC changes
kubectl get clusterrolebindings --sort-by='.metadata.creationTimestamp' | tail -10
kubectl get rolebindings --all-namespaces --sort-by='.metadata.creationTimestamp' | tail -10

# Check for new service accounts
kubectl get serviceaccounts --all-namespaces --sort-by='.metadata.creationTimestamp' | tail -10
```

---

## 6. Eradication

**Time Target: Complete eradication within 4 hours of containment**

### Step 6.1: Remove Malicious Workloads

```bash
# Delete the compromised pod (after evidence collection is complete)
kubectl delete pod <pod-name> -n <namespace> --grace-period=0

# If the pod is managed by a deployment, check the deployment
kubectl get deployment -n <namespace>

# Check if the container image is compromised
# If yes, remove the deployment
kubectl delete deployment <deployment-name> -n <namespace>
```

### Step 6.2: Remove Persistence Mechanisms

```bash
# Check for rogue CronJobs
kubectl get cronjobs --all-namespaces
kubectl delete cronjob <suspicious-cronjob> -n <namespace>

# Check for rogue DaemonSets
kubectl get daemonsets --all-namespaces
kubectl delete daemonset <suspicious-daemonset> -n <namespace>

# Check for modified ConfigMaps/Secrets
kubectl get configmaps --all-namespaces --sort-by='.metadata.creationTimestamp' | tail -20
kubectl get secrets --all-namespaces --sort-by='.metadata.creationTimestamp' | tail -20

# Check for webhook configurations (advanced persistence)
kubectl get mutatingwebhookconfigurations
kubectl get validatingwebhookconfigurations
```

### Step 6.3: Rotate Credentials

```bash
# Rotate all SA keys in the project
gcloud iam service-accounts list --project=<project-id>

# For each SA with user-managed keys:
gcloud iam service-accounts keys list --iam-account=<sa-email>
# Delete old keys and create new ones if needed

# Rotate GKE cluster credentials
# WARNING: This causes brief API server downtime
# gcloud container clusters get-credentials <cluster-name> --zone=<zone>
```

---

## 7. Recovery

### Step 7.1: Verify Clean State

```bash
# Scan all running containers with Trivy
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u | while read image; do
  echo "Scanning: $image"
  trivy image --severity HIGH,CRITICAL "$image"
done

# Check for remaining IOCs
kubectl exec -it <pod> -- find /tmp -name "*magic*" -ls
kubectl exec -it <pod> -- find /tmp /var/tmp /dev/shm -type f -executable -ls
```

### Step 7.2: Redeploy Clean Workloads

```bash
# Rebuild and redeploy from known-good source
# Use CI/CD pipeline with image signing (Binary Authorization)
# Verify image signatures before deployment
```

### Step 7.3: Remove Emergency Controls

```bash
# Remove quarantine NetworkPolicies
kubectl delete networkpolicy -l security.devsecops/type=quarantine --all-namespaces

# Remove emergency lockdown policies
kubectl delete networkpolicy emergency-lockdown -n <namespace>

# Review and remove temporary firewall rules
gcloud compute firewall-rules list --filter="name~block-c2"
# Delete after confirming they are no longer needed
```

---

## 8. Post-Incident Activities

### Step 8.1: Document the Incident

Create an incident report including:
- Timeline of events
- IOCs discovered
- Actions taken
- Impact assessment
- Root cause analysis

### Step 8.2: Update Detections

- Add new IOCs to Suricata rules (new C2 IPs, domains)
- Update Falco rules if new TTPs were discovered
- Update Cloud Armor blocked IPs
- Add JA3 fingerprints to the blocklist

### Step 8.3: Improve Defenses

- Patch the vulnerability that allowed initial access
- Review and tighten Pod Security Standards
- Implement additional network segmentation
- Review RBAC and minimize service account permissions
- Enable/verify Binary Authorization for image signing

### Step 8.4: Lessons Learned

Hold a blameless post-incident review within 72 hours covering:
- What went well in detection and response
- What could be improved
- Action items with owners and deadlines

---

## 9. Quick Reference Commands

### Containment

```bash
# Quarantine pod
./auto-response/quarantine-pod.sh <namespace> <pod>

# Block C2 IP
./auto-response/block-ip.sh <ip-address>

# Revoke service account
./auto-response/revoke-sa.sh <sa-email>
```

### Investigation

```bash
# Check Falco alerts (last 1 hour)
kubectl logs -l app=falco -n falco-system --since=1h | grep -i "critical\|emergency"

# Check Suricata alerts
cat /var/log/suricata/fast.log | tail -50

# Check K8s audit logs
gcloud logging read 'resource.type="k8s_cluster" AND protoPayload.methodName=~"pods.(create|exec)"' \
  --project=<project> --limit=50 --freshness=1h

# List all quarantined pods
kubectl get pods --all-namespaces -l quarantine=true
```

### Dashboards

| Dashboard | URL |
|-----------|-----|
| APT Detection | `https://<kibana>/app/dashboards#/view/apt-detection-dashboard-v1` |
| Crypto Mining | `https://<kibana>/app/dashboards#/view/crypto-mining-dashboard-v1` |
| Network Anomaly | `https://<kibana>/app/dashboards#/view/network-anomaly-dashboard-v1` |
| GCP SCC | `https://console.cloud.google.com/security/command-center` |
| Cloud IDS | `https://console.cloud.google.com/net-security/ids/endpoints` |

---

## Escalation Contacts

| Role | Contact | When to Escalate |
|------|---------|-----------------|
| On-call Security Engineer | PagerDuty (auto) | Any P1/P2 alert |
| Security Team Lead | Slack #security-critical | Confirmed APT activity |
| CISO | Phone (per runbook) | Data exfiltration confirmed |
| Legal | Email (per runbook) | Regulated data compromised |
| GCP Support | Premium Support ticket | Need GCP-side investigation |
