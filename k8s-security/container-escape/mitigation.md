# Container Escape Mitigation Guide

## Overview

Preventing container escapes requires defense in depth -- multiple overlapping security layers so that the failure of any single control does not result in compromise. This document covers the key mitigation strategies.

## 1. Pod Security Standards (PSS)

Pod Security Standards replace the deprecated PodSecurityPolicy (PSP) and are built into Kubernetes since v1.23 (stable in v1.25).

### Restricted Profile (Strongest)

The `restricted` profile prevents all known container escape vectors:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforce = reject pods that violate
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Warn = allow but warn
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    # Audit = log violations
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
```

The restricted profile enforces:
- Cannot run as privileged
- Cannot use host namespaces (hostPID, hostNetwork, hostIPC)
- Cannot mount hostPath volumes
- Must drop ALL capabilities (can only add NET_BIND_SERVICE)
- Must run as non-root
- Must set `allowPrivilegeEscalation: false`
- Must use RuntimeDefault or Localhost seccomp profile
- Cannot use certain volume types (hostPath, nfs, etc.)

### Baseline Profile (Minimum)

The `baseline` profile prevents the most obvious escapes:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: latest
```

The baseline profile prevents:
- Privileged containers
- Host namespace sharing
- Dangerous capabilities (SYS_ADMIN, NET_RAW, etc.)
- hostPath volumes
- Host ports

## 2. Seccomp Profiles

Seccomp (Secure Computing Mode) filters syscalls at the kernel level. Even if an attacker has root inside a container, they cannot make blocked syscalls.

### RuntimeDefault Profile

Kubernetes provides a `RuntimeDefault` seccomp profile that blocks ~44 dangerous syscalls:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        seccompProfile:
          type: RuntimeDefault
```

### Custom Seccomp Profile (Block Container Escape Syscalls)

For maximum protection, create a custom profile that blocks filesystem and namespace syscalls:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "arch_prctl", "bind", "brk",
        "capget", "capset", "chdir", "chmod", "chown", "clock_getres",
        "clock_gettime", "clock_nanosleep", "close", "connect", "dup",
        "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl",
        "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve",
        "execveat", "exit", "exit_group", "faccessat", "faccessat2",
        "fadvise64", "fallocate", "fchmod", "fchmodat", "fchown",
        "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr",
        "flock", "fork", "fstat", "fstatfs", "fsync", "ftruncate",
        "futex", "getcwd", "getdents", "getdents64", "getegid",
        "geteuid", "getgid", "getgroups", "getpeername", "getpgrp",
        "getpid", "getppid", "getpriority", "getrandom", "getresgid",
        "getresuid", "getrlimit", "getsid", "getsockname", "getsockopt",
        "get_robust_list", "get_thread_area", "gettid", "gettimeofday",
        "getuid", "getxattr", "inotify_add_watch", "inotify_init",
        "inotify_init1", "inotify_rm_watch", "io_cancel", "io_destroy",
        "io_getevents", "io_setup", "io_submit", "ioctl", "kill",
        "lgetxattr", "listen", "listxattr", "llistxattr", "lseek",
        "lstat", "madvise", "memfd_create", "mincore", "mkdir",
        "mkdirat", "mmap", "mprotect", "mremap", "msgctl", "msgget",
        "msgrcv", "msgsnd", "msync", "munmap", "nanosleep", "newfstatat",
        "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll",
        "prctl", "pread64", "preadv", "prlimit64", "pselect6",
        "pwrite64", "pwritev", "read", "readahead", "readlink",
        "readlinkat", "readv", "recvfrom", "recvmmsg", "recvmsg",
        "rename", "renameat", "renameat2", "restart_syscall", "rmdir",
        "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
        "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait",
        "sched_getaffinity", "sched_getparam", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min",
        "sched_setaffinity", "sched_setscheduler", "sched_yield",
        "seccomp", "select", "semctl", "semget", "semop", "semtimedop",
        "sendfile", "sendmmsg", "sendmsg", "sendto", "setgid", "setgroups",
        "set_robust_list", "set_thread_area", "set_tid_address",
        "setitimer", "setpgid", "setpriority", "setsid", "setsockopt",
        "setuid", "shmat", "shmctl", "shmdt", "shmget", "shutdown",
        "sigaltstack", "socket", "socketpair", "splice", "stat",
        "statfs", "statx", "symlink", "symlinkat", "sync",
        "sync_file_range", "sysinfo", "tee", "tgkill", "time",
        "timer_create", "timer_delete", "timer_getoverrun",
        "timer_gettime", "timer_settime", "timerfd_create",
        "timerfd_gettime", "timerfd_settime", "times", "tkill",
        "truncate", "umask", "uname", "unlink", "unlinkat", "utime",
        "utimensat", "utimes", "vfork", "wait4", "waitid", "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "clone"
      ],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 2114060288,
          "op": "SCMP_CMP_MASKED_EQ",
          "comment": "Block CLONE_NEWUSER to prevent user namespace creation"
        }
      ]
    }
  ]
}
```

**Blocked syscalls** (prevented by omission from the allow-list):
- `unshare` - Prevents user namespace creation (CVE-2022-0185)
- `mount` / `umount2` - Prevents filesystem manipulation
- `pivot_root` - Prevents root filesystem changes
- `ptrace` - Prevents process debugging/manipulation
- `reboot` - Prevents system reboot
- `init_module` / `finit_module` - Prevents kernel module loading
- `fsopen` / `fsconfig` / `fsmount` - Prevents CVE-2022-0185
- `keyctl` - Prevents key management abuse
- `bpf` - Prevents eBPF abuse

## 3. AppArmor Profiles

AppArmor provides mandatory access control at the kernel level.

### Container Escape Prevention Profile

```
#include <tunables/global>

profile k8s-container-hardened flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Allow normal container operations
  network,
  capability net_bind_service,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_boot,
  deny capability sys_chroot,

  # Deny namespace manipulation
  deny /proc/*/ns/* rw,
  deny /proc/sys/kernel/ns_last_pid rw,

  # Deny host filesystem access
  deny /proc/1/root/** rw,
  deny /proc/sysrq-trigger rw,
  deny /proc/sys/kernel/core_pattern w,

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny module loading
  deny /lib/modules/** rw,
  deny /usr/lib/modules/** rw,

  # Deny Docker socket access
  deny /var/run/docker.sock rw,
  deny /run/containerd/containerd.sock rw,

  # Deny sensitive file access
  deny /etc/shadow r,
  deny /etc/gshadow r,

  # Allow application files
  /app/** r,
  /app/bin/* ix,
  /tmp/** rw,
  /var/tmp/** rw,
}
```

### Apply in Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-container-hardened
spec:
  containers:
    - name: app
      image: myapp:latest
```

## 4. OPA / Gatekeeper Policies

OPA Gatekeeper acts as an admission controller, rejecting pods that violate security policies before they are created.

### Deny Privileged Containers

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
  parameters:
    allowPrivilegedContainers: false
```

### Deny Host Namespaces

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNamespace
metadata:
  name: deny-host-namespaces
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
  parameters:
    allowHostPID: false
    allowHostIPC: false
    allowHostNetwork: false
```

### Deny Host Path Volumes

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostFilesystem
metadata:
  name: deny-host-path
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
  parameters:
    allowedHostPaths: []
```

## 5. Runtime Security (Detection)

Even with prevention in place, runtime detection provides a safety net.

### Falco Rules for Container Escape Detection

```yaml
- rule: Container Escape via nsenter
  desc: Detect nsenter usage which may indicate container escape attempt
  condition: >
    spawned_process and proc.name = "nsenter" and
    container.id != host
  output: >
    nsenter executed in container (user=%user.name command=%proc.cmdline
    container=%container.name image=%container.image.repository)
  priority: CRITICAL

- rule: Access to Host Proc via Container
  desc: Detect access to /proc/1/root from within a container
  condition: >
    open_read and container.id != host and
    fd.name startswith /proc/1/root
  output: >
    Container accessing host filesystem via /proc/1/root
    (user=%user.name command=%proc.cmdline fd.name=%fd.name
    container=%container.name)
  priority: CRITICAL

- rule: Docker Socket Access from Container
  desc: Detect access to Docker socket from within a container
  condition: >
    (open_read or open_write) and container.id != host and
    fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
```

## 6. Network Policies

Limit the blast radius of a compromised container:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-and-api
  namespace: production
spec:
  podSelector: {}
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
    # Deny access to metadata API (cloud providers)
    # Deny access to Kubernetes API server
    # Deny access to node network
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # Cloud metadata
              - 10.96.0.0/12        # K8s service network
              - 10.0.0.0/8          # Private network (adjust)
```

## 7. Image Security

- Scan images with Trivy/Grype before deployment
- Use distroless or scratch base images
- Never run as root in the image (`USER nonroot` in Dockerfile)
- Remove unnecessary tools (shells, package managers, curl)
- Sign images with Cosign/Notary

## 8. Summary Checklist

| Control | Prevents | Priority |
|---------|----------|----------|
| PSS Restricted Profile | Privileged, host access | CRITICAL |
| Seccomp RuntimeDefault | Dangerous syscalls | CRITICAL |
| Drop ALL capabilities | Capability abuse | HIGH |
| Non-root containers | Privilege escalation | HIGH |
| No hostPath mounts | Filesystem access | HIGH |
| No Docker socket | Runtime compromise | HIGH |
| AppArmor/SELinux | File/network access | HIGH |
| OPA/Gatekeeper | Policy enforcement | HIGH |
| Network Policies | Lateral movement | MEDIUM |
| Runtime Detection (Falco) | Active monitoring | MEDIUM |
| Image Scanning | Known vulnerabilities | MEDIUM |
| RBAC Least Privilege | API access | HIGH |
