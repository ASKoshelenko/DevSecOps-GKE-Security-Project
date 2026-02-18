# Container Escape to Host - Security Demonstration

## Overview

Container escape is one of the most critical attack vectors in Kubernetes security. When an attacker breaks out of a container's isolation boundary, they gain access to the underlying host, and from there can potentially compromise the entire cluster.

This directory contains demonstrations of multiple container escape techniques, ranging from trivial (privileged containers) to advanced (kernel CVE exploitation).

## WARNING

**These demonstrations are for AUTHORIZED SECURITY TESTING AND EDUCATION ONLY.**

Never run these on production systems or without explicit written authorization. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

## Prerequisites

- A running vulnerable Kind cluster (see `../setup-vulnerable-cluster.sh`)
- `kubectl` configured to access the cluster
- Basic understanding of Linux namespaces, cgroups, and container runtimes

## Attack Scenarios

### Scenario 1: Privileged Container Escape (Trivial)

**File:** `escape-demo.sh`

The most straightforward escape. A container running with `privileged: true` has virtually no isolation from the host. The attacker can:

1. Access the host filesystem via `/proc/1/root`
2. Use `nsenter` to enter the host's namespaces (PID, network, mount)
3. Access the Docker socket to spawn new containers on the host
4. Read sensitive host files (kubelet credentials, SSH keys, etc.)
5. Pivot to other nodes in the cluster

**Why this works:** Privileged containers disable most Linux security mechanisms:
- All Linux capabilities are granted
- seccomp filters are disabled
- AppArmor/SELinux profiles are not applied
- Device cgroup restrictions are removed
- `/proc` and `/sys` are mounted read-write

### Scenario 2: CVE-2022-0185 - File System Context Overflow

**File:** `cve-2022-0185-exploit.md`

A heap-based buffer overflow in the Linux kernel's `legacy_parse_param()` function in `fs/fs_context.c`. This allows a container with `CAP_SYS_ADMIN` (within a user namespace) to corrupt kernel memory and escape to the host.

**Affected kernels:** < 5.16.2

### Scenario 3: CVE-2022-0492 - cgroup release_agent Escape

**File:** `non-privileged-escape/exploit-via-cgroups.sh`

Exploits the cgroup `release_agent` mechanism to execute arbitrary commands on the host. Works on containers that:
- Run as root (UID 0)
- Have the `SYS_ADMIN` capability (or can create user namespaces)
- Have cgroupfs mounted writable

### Scenario 4: Mount Namespace Manipulation

**File:** `non-privileged-escape/exploit-via-mountns.sh`

Exploits misconfigured mount propagation or access to `/proc/<pid>/root` to traverse mount namespace boundaries and access the host filesystem.

## Attack Flow Diagram

```
                                    +-------------------+
                                    |   CLUSTER ADMIN   |
                                    |   COMPROMISE      |
                                    +--------^----------+
                                             |
                                    +--------+----------+
                                    | Steal kubelet     |
                                    | credentials &     |
                                    | pivot to other    |
                                    | nodes             |
                                    +--------^----------+
                                             |
+------------------+               +---------+----------+
| Attacker gains   |               |  HOST ACCESS       |
| code execution   +-------------->+  - Read /etc/shadow|
| inside container |  Container    |  - Docker socket   |
| (e.g., via RCE   |  Escape      |  - SSH keys        |
| in application)  |               |  - Host processes  |
+------------------+               +--------------------+
```

## Files in This Directory

| File | Description |
|------|-------------|
| `README.md` | This file - overview and explanation |
| `Dockerfile` | Container image with exploit/demo tools |
| `privileged-pod.yaml` | Pod spec enabling container escape |
| `escape-demo.sh` | Main escape demonstration script |
| `cve-2022-0185-exploit.md` | CVE-2022-0185 documentation |
| `mitigation.md` | How to prevent container escapes |
| `non-privileged-escape/` | Escapes without explicit privileges |

## Defense Layers

Preventing container escapes requires defense in depth:

1. **Pod Security Standards** - Enforce `restricted` profile
2. **Seccomp Profiles** - Block dangerous syscalls
3. **AppArmor/SELinux** - Mandatory access control
4. **OPA/Gatekeeper** - Policy-as-code admission control
5. **Runtime Security** - Falco, Tracee for anomaly detection
6. **Image Scanning** - Trivy, Grype for vulnerability scanning
7. **Network Policies** - Limit blast radius
8. **Least Privilege RBAC** - Minimize permissions

See `mitigation.md` for detailed prevention strategies.
