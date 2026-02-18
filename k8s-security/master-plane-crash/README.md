# Master Plane / API Server Crash - Security Demonstration

## Overview

The Kubernetes control plane (master plane) is the brain of the cluster. It consists of:

- **kube-apiserver**: The front-end for the Kubernetes API
- **etcd**: The distributed key-value store for all cluster data
- **kube-scheduler**: Assigns pods to nodes
- **kube-controller-manager**: Runs controller loops

Crashing or degrading any of these components can render the entire cluster inoperable. This directory demonstrates various denial-of-service (DoS) and corruption attacks against the control plane.

## WARNING

**These demonstrations are for AUTHORIZED SECURITY TESTING AND EDUCATION ONLY.**

Control plane attacks can cause data loss, cluster corruption, and extended downtime. Only run these against ephemeral test clusters (Kind, Minikube) that you can safely destroy.

## Prerequisites

- A running vulnerable Kind cluster (see `../setup-vulnerable-cluster.sh`)
- `kubectl` configured for the cluster
- Python 3.x with `requests` and `kubernetes` packages
- Basic understanding of Kubernetes architecture

## Attack Scenarios

### Scenario 1: API Server Denial of Service

**File:** `api-server-dos.sh`

Multiple techniques for overwhelming or crashing the API server:

1. **CVE-2022-3172**: Aggregated API server redirect DoS
2. **Watch bomb**: Opening thousands of watch connections
3. **Expensive LIST requests**: LIST without pagination on large collections
4. **Malformed requests**: Requests that trigger expensive error handling
5. **Webhook timeout exhaustion**: Slow admission webhooks blocking all requests

### Scenario 2: etcd Corruption

**File:** `etcd-corruption.sh`

Demonstrates how direct etcd access (when unprotected) can corrupt cluster state:

1. **Direct etcd writes**: Modify cluster objects, bypassing validation
2. **Key deletion**: Remove critical cluster configuration
3. **Compaction abuse**: Force compaction that disrupts watches
4. **Large value writes**: Write oversized values that degrade performance

### Scenario 3: API Server Resource Exhaustion

**File:** `api-flood.py`

Python script demonstrating programmatic resource exhaustion:

1. **Concurrent LIST operations**: Flood with expensive API calls
2. **Large object creation**: Create many large ConfigMaps/Secrets
3. **Watch connection exhaustion**: Open maximum concurrent watches
4. **Namespace bomb**: Create thousands of namespaces

### Scenario 4: Crash-Inducing Pod

**File:** `crash-pod.yaml`

A pod that generates crash-inducing API calls from within the cluster.

## Attack Flow Diagram

```
                     ATTACKER
                        |
          +-------------+-------------+
          |             |             |
     API Server      etcd       Webhooks
     DoS Attack    Corruption   Exhaustion
          |             |             |
          v             v             v
    +----------+  +---------+  +-----------+
    | API Srv  |  |  etcd   |  | Admission |
    | OOM/Hang |  | Corrupt |  | Timeouts  |
    +----+-----+  +----+----+  +-----+-----+
         |             |              |
         +-------------+--------------+
                       |
              CLUSTER UNAVAILABLE
              - No new deployments
              - No scaling
              - No healing
              - Running pods orphaned
```

## Files in This Directory

| File | Description |
|------|-------------|
| `README.md` | This file - overview and explanation |
| `api-server-dos.sh` | API server DoS demonstrations |
| `etcd-corruption.sh` | etcd corruption scenarios |
| `crash-pod.yaml` | Pod that generates crash-inducing API calls |
| `api-flood.py` | Python script for API server flood attacks |
| `mitigation.md` | Control plane protection strategies |

## Impact of Control Plane Attacks

When the control plane is down:

1. **No new workloads** can be scheduled
2. **Existing pods continue running** but cannot be managed
3. **Self-healing is disabled** (crashed pods are not restarted)
4. **Services may degrade** (no endpoint updates)
5. **Autoscaling stops** working
6. **Certificate rotation** fails
7. **Security policies** cannot be enforced or updated

## Defense Layers

1. **API Priority and Fairness** - Prioritize critical API requests
2. **Rate Limiting** - Limit request rates per client
3. **Resource Quotas** - Limit object creation per namespace
4. **Network Policies** - Restrict API server access
5. **etcd Authentication** - Require client certificates for etcd
6. **Admission Webhooks** - Validate and reject dangerous requests
7. **Audit Logging** - Detect abnormal API usage patterns

See `mitigation.md` for detailed protection strategies.
