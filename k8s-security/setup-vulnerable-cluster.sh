#!/usr/bin/env bash
# =============================================================================
# Setup Vulnerable Kubernetes Cluster for Security Demonstrations
# =============================================================================
#
# PURPOSE: Creates a deliberately vulnerable Kind cluster for demonstrating
# Kubernetes security attack vectors in an authorized testing environment.
#
# PREREQUISITES:
#   - Docker installed and running
#   - kind CLI installed (https://kind.sigs.k8s.io/)
#   - kubectl installed
#   - Sufficient system resources (4GB+ RAM, 2+ CPU cores)
#
# VULNERABLE K8s VERSION: 1.23.17
# This version contains multiple known CVEs documented below.
#
# WARNING: This cluster is INTENTIONALLY INSECURE. Run only in isolated
# environments for authorized security testing and education.
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CLUSTER_NAME="${CLUSTER_NAME:-vuln-k8s-lab}"
KIND_CONFIG="$(dirname "$0")/kind-config.yaml"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
K8S_VERSION="1.23.17"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BLUE}========================================${NC}"; echo -e "${BLUE} $*${NC}"; echo -e "${BLUE}========================================${NC}\n"; }
log_cve()     { echo -e "${RED}[CVE]${NC}   $*"; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight_checks() {
    log_section "Preflight Checks"

    # Check Docker
    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        log_info  "  macOS:  brew install --cask docker"
        log_info  "  Linux:  curl -fsSL https://get.docker.com | sh"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    log_info "Docker is installed and running."

    # Check kind
    if ! command -v kind &>/dev/null; then
        log_error "kind is not installed."
        log_info  "  Install: go install sigs.k8s.io/kind@latest"
        log_info  "  Or:      brew install kind"
        exit 1
    fi
    log_info "kind is installed: $(kind version)"

    # Check kubectl
    if ! command -v kubectl &>/dev/null; then
        log_warn "kubectl is not installed. Installing via kind is possible but kubectl is recommended."
        log_info "  Install: brew install kubectl"
    else
        log_info "kubectl is installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
    fi

    # Check Kind config file exists
    if [[ ! -f "$KIND_CONFIG" ]]; then
        log_error "Kind configuration file not found: $KIND_CONFIG"
        exit 1
    fi
    log_info "Kind config found: $KIND_CONFIG"

    # Check system resources
    local available_mem
    if [[ "$(uname)" == "Darwin" ]]; then
        available_mem=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024/1024)}')
    else
        available_mem=$(free -g 2>/dev/null | awk '/^Mem:/{print $7}' || echo "unknown")
    fi
    log_info "Available memory: ~${available_mem}GB"
}

# ---------------------------------------------------------------------------
# Document CVEs present in this K8s version
# ---------------------------------------------------------------------------
document_cves() {
    log_section "Known CVEs in Kubernetes v${K8S_VERSION}"

    echo -e "${RED}This cluster version contains the following known vulnerabilities:${NC}\n"

    log_cve "CVE-2022-3172 - API Server DoS via Aggregated API Servers"
    echo "    Severity: HIGH (CVSS 8.2)"
    echo "    An attacker who can create or update ApiService objects can cause"
    echo "    kube-apiserver to send traffic to arbitrary URLs, leading to DoS"
    echo "    or information disclosure."
    echo ""

    log_cve "CVE-2022-3162 - Unauthorized Read of Custom Resources"
    echo "    Severity: MEDIUM (CVSS 6.5)"
    echo "    Users authorized to list or watch a namespace-scoped custom resource"
    echo "    can read custom resources in other namespaces."
    echo ""

    log_cve "CVE-2022-3294 - Node Address Validation Bypass"
    echo "    Severity: HIGH (CVSS 8.8)"
    echo "    Users may have access to secure endpoints in the control plane network."
    echo "    Kubernetes API server nodes can be accessed via the proxy subresource."
    echo ""

    log_cve "CVE-2023-2728 - ServiceAccount Token Secret Bypass"
    echo "    Severity: MEDIUM (CVSS 6.5)"
    echo "    Users who can create pods and persistentvolumes may gain additional"
    echo "    privileges by mounting service account token secrets."
    echo ""

    log_cve "CVE-2022-0185 - Linux Kernel File System Context Overflow"
    echo "    Severity: HIGH (CVSS 8.4)"
    echo "    Heap overflow in legacy_parse_param in fs/fs_context.c. Allows"
    echo "    an unprivileged user in a container with CAP_SYS_ADMIN to escape"
    echo "    the container to the host. (Depends on host kernel version.)"
    echo ""

    log_cve "CVE-2022-0492 - cgroup release_agent Container Escape"
    echo "    Severity: HIGH (CVSS 7.8)"
    echo "    The cgroup release_agent feature allows writing to arbitrary files"
    echo "    on the host, enabling container escape from unprivileged containers"
    echo "    in certain configurations."
    echo ""

    log_cve "Additional Misconfigurations Enabled in This Cluster:"
    echo "    - Anonymous authentication enabled (--anonymous-auth=true)"
    echo "    - Authorization mode set to AlwaysAllow (no RBAC)"
    echo "    - Insecure API server port enabled on 0.0.0.0:8080"
    echo "    - etcd listening without TLS on all interfaces"
    echo "    - Kubelet read-only port exposed (10255)"
    echo "    - Pod Security admission disabled"
    echo "    - Host filesystem mounted into cluster nodes"
    echo "    - Docker socket mounted into cluster nodes"
    echo ""
}

# ---------------------------------------------------------------------------
# Create the vulnerable cluster
# ---------------------------------------------------------------------------
create_cluster() {
    log_section "Creating Vulnerable Kind Cluster"

    # Check if cluster already exists
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "Cluster '${CLUSTER_NAME}' already exists."
        read -rp "Delete and recreate? [y/N]: " confirm
        if [[ "${confirm,,}" == "y" ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name "${CLUSTER_NAME}"
        else
            log_info "Using existing cluster."
            return 0
        fi
    fi

    log_info "Creating Kind cluster '${CLUSTER_NAME}' with Kubernetes v${K8S_VERSION}..."
    log_warn "This uses an INTENTIONALLY VULNERABLE configuration."
    echo ""

    # Create the cluster
    if kind create cluster \
        --name "${CLUSTER_NAME}" \
        --config "${KIND_CONFIG}" \
        --wait 120s; then
        log_info "Cluster created successfully!"
    else
        log_error "Cluster creation failed. Check Docker and system resources."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Post-creation setup: make the cluster even more vulnerable
# ---------------------------------------------------------------------------
post_setup() {
    log_section "Post-Creation Vulnerable Configuration"

    # Set kubectl context
    kubectl cluster-info --context "kind-${CLUSTER_NAME}" 2>/dev/null || true
    log_info "kubectl context set to kind-${CLUSTER_NAME}"

    # ---- 1. Create a namespace without pod security enforcement ----
    log_info "Creating 'insecure-ns' namespace with no security restrictions..."
    kubectl create namespace insecure-ns 2>/dev/null || true

    # In K8s 1.23+, Pod Security Standards use namespace labels
    # We explicitly set them to the most permissive mode
    kubectl label namespace insecure-ns \
        pod-security.kubernetes.io/enforce=privileged \
        pod-security.kubernetes.io/warn=privileged \
        pod-security.kubernetes.io/audit=privileged \
        --overwrite 2>/dev/null || true

    # ---- 2. Create an overprivileged service account ----
    log_info "Creating overprivileged ServiceAccount 'attack-sa'..."
    kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: attack-sa
  namespace: insecure-ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: attack-sa-cluster-admin
subjects:
  - kind: ServiceAccount
    name: attack-sa
    namespace: insecure-ns
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

    # ---- 3. Disable default network policies ----
    log_info "Ensuring no NetworkPolicies restrict traffic..."
    kubectl delete networkpolicies --all -n insecure-ns 2>/dev/null || true

    # ---- 4. Create a permissive RBAC for anonymous users ----
    log_info "Granting anonymous users cluster-wide read access..."
    kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-view
subjects:
  - kind: User
    name: system:anonymous
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
EOF

    log_info "Post-creation setup complete."
}

# ---------------------------------------------------------------------------
# Print access information
# ---------------------------------------------------------------------------
print_access_info() {
    log_section "Cluster Access Information"

    echo -e "${CYAN}Cluster Name:${NC}      ${CLUSTER_NAME}"
    echo -e "${CYAN}K8s Version:${NC}       v${K8S_VERSION}"
    echo -e "${CYAN}kubectl Context:${NC}   kind-${CLUSTER_NAME}"
    echo ""
    echo -e "${CYAN}Exposed Ports:${NC}"
    echo "  - API Server (secure):    https://localhost:$(docker port "${CLUSTER_NAME}-control-plane" 6443/tcp 2>/dev/null | head -1 | cut -d: -f2 || echo 'N/A')"
    echo "  - API Server (insecure):  http://localhost:8080"
    echo "  - Kubelet Read-Only:      http://localhost:10255"
    echo "  - etcd (no TLS):          http://localhost:2379"
    echo ""
    echo -e "${CYAN}Insecure Namespace:${NC} insecure-ns"
    echo -e "${CYAN}Attack SA:${NC}          attack-sa (cluster-admin)"
    echo ""
    echo -e "${YELLOW}Quick test commands:${NC}"
    echo "  kubectl get nodes"
    echo "  kubectl get pods -A"
    echo "  curl -s http://localhost:8080/api/v1/namespaces    # Anonymous API access"
    echo "  curl -s http://localhost:10255/pods                # Kubelet read-only"
    echo ""
}

# ---------------------------------------------------------------------------
# Print demo scenarios
# ---------------------------------------------------------------------------
print_demos() {
    log_section "Available Security Demo Scenarios"

    echo -e "${CYAN}1. Container Escape${NC}"
    echo "   Directory: ${SCRIPT_DIR}/container-escape/"
    echo "   - escape-demo.sh         : Privileged container breakout"
    echo "   - non-privileged-escape/  : Escapes without explicit privileges"
    echo ""

    echo -e "${CYAN}2. Master Plane / API Server Crash${NC}"
    echo "   Directory: ${SCRIPT_DIR}/master-plane-crash/"
    echo "   - api-server-dos.sh      : API server denial of service"
    echo "   - etcd-corruption.sh     : etcd data corruption"
    echo "   - api-flood.py           : API server resource exhaustion"
    echo ""

    echo -e "${CYAN}3. Pod Security Policies / Standards${NC}"
    echo "   Directory: ${SCRIPT_DIR}/pod-security/"
    echo "   - restricted-pss.yaml    : Restricted Pod Security Standard"
    echo "   - baseline-pss.yaml      : Baseline Pod Security Standard"
    echo "   - gatekeeper-constraints/: OPA Gatekeeper policies"
    echo ""
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
teardown() {
    log_section "Tearing Down Vulnerable Cluster"
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        kind delete cluster --name "${CLUSTER_NAME}"
        log_info "Cluster '${CLUSTER_NAME}' deleted."
    else
        log_warn "Cluster '${CLUSTER_NAME}' not found."
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  create    Create the vulnerable Kind cluster (default)"
    echo "  delete    Delete the cluster and clean up"
    echo "  info      Print access information for an existing cluster"
    echo "  cves      List known CVEs in the target K8s version"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CLUSTER_NAME   Name of the Kind cluster (default: vuln-k8s-lab)"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local command="${1:-create}"

    case "${command}" in
        create)
            echo -e "${RED}"
            echo "============================================================"
            echo " WARNING: INTENTIONALLY VULNERABLE KUBERNETES CLUSTER"
            echo " FOR AUTHORIZED SECURITY TESTING AND EDUCATION ONLY"
            echo "============================================================"
            echo -e "${NC}"
            preflight_checks
            document_cves
            create_cluster
            post_setup
            print_access_info
            print_demos
            log_info "Vulnerable cluster is ready for security demonstrations."
            log_warn "Remember to delete this cluster when done: $0 delete"
            ;;
        delete|teardown|destroy)
            teardown
            ;;
        info)
            print_access_info
            print_demos
            ;;
        cves)
            document_cves
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: ${command}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
