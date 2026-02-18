# Control Plane Protection Guide

## Overview

Protecting the Kubernetes control plane requires a multi-layered approach covering the API server, etcd, scheduler, controller manager, and the network connecting them. This guide provides comprehensive mitigation strategies for control plane attacks.

## 1. API Priority and Fairness (APF)

APF is the primary mechanism for protecting the API server from being overwhelmed. It classifies and prioritizes API requests, ensuring that critical system operations continue even under load.

### How APF Works

API requests are classified into **FlowSchemas** that map to **PriorityLevelConfigurations**. Each priority level gets a guaranteed share of API server capacity.

### Configuration

```yaml
# Priority Level: Protect system-critical requests
apiVersion: flowcontrol.apiserver.k8s.io/v1beta2
kind: PriorityLevelConfiguration
metadata:
  name: system-critical
spec:
  type: Limited
  limited:
    # Guaranteed 40% of API server capacity
    assuredConcurrencyShares: 40
    limitResponse:
      type: Queue
      queuing:
        # Queue depth for burst handling
        queues: 64
        handSize: 6
        queueLengthLimit: 50

---
# Priority Level: Limit user workloads to prevent DoS
apiVersion: flowcontrol.apiserver.k8s.io/v1beta2
kind: PriorityLevelConfiguration
metadata:
  name: user-workloads
spec:
  type: Limited
  limited:
    # Only 15% of capacity for user workloads
    assuredConcurrencyShares: 15
    limitResponse:
      type: Queue
      queuing:
        queues: 16
        handSize: 4
        queueLengthLimit: 25

---
# FlowSchema: Route kube-system requests to system-critical priority
apiVersion: flowcontrol.apiserver.k8s.io/v1beta2
kind: FlowSchema
metadata:
  name: system-critical-requests
spec:
  priorityLevelConfiguration:
    name: system-critical
  matchingPrecedence: 100
  rules:
    - subjects:
        - kind: ServiceAccount
          serviceAccount:
            namespace: kube-system
            name: "*"
      resourceRules:
        - verbs: ["*"]
          apiGroups: ["*"]
          resources: ["*"]
          namespaces: ["*"]

---
# FlowSchema: Limit LIST operations from non-system accounts
apiVersion: flowcontrol.apiserver.k8s.io/v1beta2
kind: FlowSchema
metadata:
  name: limit-expensive-lists
spec:
  priorityLevelConfiguration:
    name: user-workloads
  matchingPrecedence: 500
  rules:
    - subjects:
        - kind: Group
          group:
            name: "system:authenticated"
      resourceRules:
        - verbs: ["list", "watch"]
          apiGroups: ["*"]
          resources: ["*"]
          namespaces: ["*"]
```

### API Server Flags

```bash
kube-apiserver \
  # Enable APF (enabled by default in K8s 1.20+)
  --enable-priority-and-fairness=true \
  # Maximum concurrent non-mutating requests
  --max-requests-inflight=400 \
  # Maximum concurrent mutating requests
  --max-mutating-requests-inflight=200
```

## 2. Rate Limiting

### API Server Level

```bash
kube-apiserver \
  --max-requests-inflight=400 \
  --max-mutating-requests-inflight=200 \
  # Event rate limiting
  --event-ttl=1h
```

### Client-Side Rate Limiting

Configure controllers and operators with appropriate QPS and burst limits:

```yaml
# Example: Helm values for a controller
controller:
  kubeAPIQPS: 20        # Requests per second
  kubeAPIBurst: 30      # Burst above QPS
```

### Nginx Ingress Rate Limiting (for API access via ingress)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-server-ingress
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "5"
```

## 3. Resource Quotas

Resource quotas limit the total resources that can be consumed in a namespace, preventing any single tenant from exhausting cluster resources.

### Comprehensive Resource Quota

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: control-plane-protection
  namespace: default
spec:
  hard:
    # Limit number of objects (prevents object bomb attacks)
    pods: "100"
    services: "50"
    secrets: "100"
    configmaps: "100"
    persistentvolumeclaims: "50"
    replicationcontrollers: "50"
    resourcequotas: "5"
    services.loadbalancers: "5"
    services.nodeports: "10"

    # Limit compute resources
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"

    # Limit storage
    requests.storage: "100Gi"

    # Limit ephemeral storage (prevents disk exhaustion)
    requests.ephemeral-storage: "50Gi"
    limits.ephemeral-storage: "100Gi"

---
# Limit object sizes with LimitRange
apiVersion: v1
kind: LimitRange
metadata:
  name: object-size-limits
  namespace: default
spec:
  limits:
    - type: Container
      max:
        cpu: "4"
        memory: "8Gi"
      min:
        cpu: "50m"
        memory: "64Mi"
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
    - type: Pod
      max:
        cpu: "8"
        memory: "16Gi"
```

## 4. Network Policies for API Server Access

Restrict which pods can communicate with the API server:

```yaml
# Deny all egress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []

---
# Allow specific pods to access the API server
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-access
  namespace: production
spec:
  podSelector:
    matchLabels:
      api-access: "true"
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to: []
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow API server (adjust CIDR for your cluster)
    - to:
        - ipBlock:
            cidr: 10.96.0.1/32  # kubernetes.default service IP
      ports:
        - port: 443
          protocol: TCP

---
# Deny access to etcd from all pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-etcd-access
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      component: etcd
  policyTypes:
    - Ingress
  ingress:
    # Only allow API server to talk to etcd
    - from:
        - podSelector:
            matchLabels:
              component: kube-apiserver
      ports:
        - port: 2379
          protocol: TCP
        - port: 2380
          protocol: TCP
```

## 5. etcd Security

### Enable TLS for etcd

```bash
etcd \
  # Client-to-server TLS
  --cert-file=/etc/kubernetes/pki/etcd/server.crt \
  --key-file=/etc/kubernetes/pki/etcd/server.key \
  --client-cert-auth=true \
  --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt \
  # Peer-to-peer TLS
  --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt \
  --peer-key-file=/etc/kubernetes/pki/etcd/peer.key \
  --peer-client-cert-auth=true \
  --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt \
  # Listen only on secure interfaces
  --listen-client-urls=https://127.0.0.1:2379 \
  --listen-peer-urls=https://127.0.0.1:2380 \
  # Database quotas
  --quota-backend-bytes=8589934592 \
  --auto-compaction-mode=periodic \
  --auto-compaction-retention=1h
```

### Enable Encryption at Rest

```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      # Use KMS for production
      - kms:
          name: my-kms-provider
          endpoint: unix:///var/run/kmsplugin/socket.sock
          cachesize: 1000
          timeout: 3s
      # Fallback: AES-CBC encryption
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      # Identity provider for reading unencrypted data during migration
      - identity: {}
```

```bash
kube-apiserver \
  --encryption-provider-config=/etc/kubernetes/encryption-config.yaml
```

### etcd Monitoring

Monitor these etcd metrics:
- `etcd_server_has_leader`: Must always be 1
- `etcd_mvcc_db_total_size_in_bytes`: Database size
- `etcd_server_proposals_failed_total`: Failed consensus proposals
- `etcd_disk_wal_fsync_duration_seconds`: Disk latency
- `etcd_server_slow_apply_total`: Slow operations

## 6. Audit Logging

Enable comprehensive audit logging to detect abnormal API usage:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests to secrets at Metadata level
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]

  # Log all changes to RBAC at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # Log all exec/attach operations
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Log authentication attempts
  - level: Metadata
    nonResourceURLs:
      - "/api*"
      - "/version"

  # Log all write operations
  - level: Request
    verbs: ["create", "update", "patch", "delete"]

  # Default: log metadata for everything else
  - level: Metadata
```

```bash
kube-apiserver \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=10 \
  --audit-log-maxsize=100
```

## 7. Admission Webhooks for Protection

Deploy admission webhooks that reject dangerous requests:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: control-plane-protection
webhooks:
  - name: limit-large-objects.security.example.com
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["configmaps", "secrets"]
    clientConfig:
      service:
        name: admission-webhook
        namespace: security-system
        path: "/validate-size"
    failurePolicy: Fail
    timeoutSeconds: 5  # Short timeout to prevent webhook DoS
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

## 8. Summary Checklist

| Control | Protects Against | Priority |
|---------|-----------------|----------|
| API Priority & Fairness | API flood, watch bomb | CRITICAL |
| Request rate limits | Concurrent request exhaustion | CRITICAL |
| etcd TLS + auth | Direct etcd access/corruption | CRITICAL |
| Encryption at rest | Secret extraction from etcd | HIGH |
| Resource quotas | Object bomb, storage exhaustion | HIGH |
| Network policies | Unauthorized API/etcd access | HIGH |
| Audit logging | Anomaly detection | HIGH |
| etcd quotas | Database size exhaustion | MEDIUM |
| Admission webhooks | Large object creation | MEDIUM |
| etcd auto-compaction | Historical data buildup | MEDIUM |
| Client rate limiting | Controller-induced load | MEDIUM |
| etcd backup/restore | Recovery from corruption | CRITICAL |
