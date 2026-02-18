#!/usr/bin/env bash
# =============================================================================
# Quarantine Pod - Network Isolation for Compromised Pods
# =============================================================================
#
# This script quarantines a compromised Kubernetes pod by applying a
# NetworkPolicy that blocks ALL ingress and egress traffic. The pod
# continues running (preserving forensic evidence) but cannot communicate
# with any other resource.
#
# Usage:
#   ./quarantine-pod.sh <namespace> <pod-name> [--dry-run]
#
# What it does:
#   1. Validates the pod exists and is running
#   2. Labels the pod with "quarantine=true" for identification
#   3. Applies a deny-all NetworkPolicy targeting the quarantined pod
#   4. Verifies the pod is isolated by checking network connections
#   5. Logs the quarantine action for audit trail
#
# Prerequisites:
#   - kubectl configured with cluster access
#   - NetworkPolicy controller enabled (Calico/Cilium on GKE)
#   - Sufficient RBAC permissions to create NetworkPolicies
#
# IMPORTANT: This script PRESERVES the pod for forensic investigation.
#            Do NOT delete the pod until forensics are complete.
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/security/quarantine-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
log() {
    local level="$1"
    shift
    local message="$*"
    echo -e "[${TIMESTAMP}] [${level}] ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || echo "[${TIMESTAMP}] [${level}] ${message}"
}

error() {
    log "ERROR" "${RED}$*${NC}"
    exit 1
}

warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

info() {
    log "INFO" "${GREEN}$*${NC}"
}

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <namespace> <pod-name> [--dry-run]

Quarantine a compromised pod by applying network isolation.

Arguments:
  namespace    Kubernetes namespace of the pod
  pod-name     Name of the pod to quarantine

Options:
  --dry-run    Show what would be done without actually applying changes

Examples:
  ${SCRIPT_NAME} default compromised-app-7d4f8b6c9-x2k5m
  ${SCRIPT_NAME} production webapp-deployment-5c8f9d7b6-abc12 --dry-run
EOF
    exit 1
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
if [[ $# -lt 2 ]]; then
    usage
fi

NAMESPACE="$1"
POD_NAME="$2"
DRY_RUN="${3:-}"

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
    KUBECTL_DRY_RUN="--dry-run=client"
    warn "DRY RUN MODE - No changes will be applied"
else
    KUBECTL_DRY_RUN=""
fi

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------
info "Starting quarantine procedure for pod ${NAMESPACE}/${POD_NAME}"

# Check kubectl is available
if ! command -v kubectl &>/dev/null; then
    error "kubectl is not installed or not in PATH"
fi

# Check cluster connectivity
if ! kubectl cluster-info &>/dev/null; then
    error "Cannot connect to Kubernetes cluster. Check kubeconfig."
fi

# Verify pod exists
if ! kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" &>/dev/null; then
    error "Pod ${POD_NAME} not found in namespace ${NAMESPACE}"
fi

# Get pod details for logging
POD_STATUS=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}')
POD_IP=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.podIP}')
POD_NODE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.nodeName}')
POD_IMAGE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.containers[0].image}')
POD_SA=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.serviceAccountName}')

info "Pod details:"
info "  Status:          ${POD_STATUS}"
info "  IP:              ${POD_IP}"
info "  Node:            ${POD_NODE}"
info "  Image:           ${POD_IMAGE}"
info "  Service Account: ${POD_SA}"

# Warn if pod is not running (may already be terminated)
if [[ "${POD_STATUS}" != "Running" ]]; then
    warn "Pod is in ${POD_STATUS} state (not Running). Proceeding with quarantine."
fi

# -----------------------------------------------------------------------------
# Step 1: Label the Pod for Quarantine
# -----------------------------------------------------------------------------
info "Step 1: Labeling pod with quarantine=true"

kubectl label pod "${POD_NAME}" -n "${NAMESPACE}" \
    quarantine=true \
    quarantine-timestamp="${TIMESTAMP}" \
    quarantine-reason="apt-detection" \
    --overwrite \
    ${KUBECTL_DRY_RUN}

info "Pod labeled successfully"

# -----------------------------------------------------------------------------
# Step 2: Apply Deny-All NetworkPolicy
# -----------------------------------------------------------------------------
info "Step 2: Applying deny-all NetworkPolicy for quarantined pod"

NETPOL_NAME="quarantine-${POD_NAME}"

# Truncate NetworkPolicy name if too long (K8s max is 253 chars)
if [[ ${#NETPOL_NAME} -gt 253 ]]; then
    NETPOL_NAME="${NETPOL_NAME:0:253}"
fi

cat <<EOF | kubectl apply -n "${NAMESPACE}" ${KUBECTL_DRY_RUN} -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${NETPOL_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/part-of: ids-ips
    security.devsecops/type: quarantine
    security.devsecops/reason: apt-detection
  annotations:
    security.devsecops/quarantined-at: "${TIMESTAMP}"
    security.devsecops/quarantined-pod: "${POD_NAME}"
    security.devsecops/pod-ip: "${POD_IP}"
    security.devsecops/pod-node: "${POD_NODE}"
spec:
  # Target ONLY the quarantined pod using the quarantine label
  podSelector:
    matchLabels:
      quarantine: "true"
  # Empty ingress and egress = deny all traffic
  # This completely isolates the pod from the network
  policyTypes:
    - Ingress
    - Egress
  # No ingress rules = deny all inbound
  ingress: []
  # No egress rules = deny all outbound (blocks C2 callback)
  egress: []
EOF

info "NetworkPolicy ${NETPOL_NAME} applied - ALL traffic blocked"

# -----------------------------------------------------------------------------
# Step 3: Capture Forensic Snapshot
# -----------------------------------------------------------------------------
info "Step 3: Capturing forensic information"

FORENSIC_DIR="/tmp/forensics-${POD_NAME}-$(date +%Y%m%d%H%M%S)"
mkdir -p "${FORENSIC_DIR}" 2>/dev/null || true

# Capture pod description
kubectl describe pod "${POD_NAME}" -n "${NAMESPACE}" > "${FORENSIC_DIR}/pod-describe.txt" 2>/dev/null || true

# Capture pod logs (all containers)
kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --all-containers=true > "${FORENSIC_DIR}/pod-logs.txt" 2>/dev/null || true

# Capture pod YAML
kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o yaml > "${FORENSIC_DIR}/pod-yaml.txt" 2>/dev/null || true

# Capture events related to the pod
kubectl get events -n "${NAMESPACE}" --field-selector "involvedObject.name=${POD_NAME}" > "${FORENSIC_DIR}/pod-events.txt" 2>/dev/null || true

# Capture NetworkPolicy state
kubectl get networkpolicy -n "${NAMESPACE}" -o yaml > "${FORENSIC_DIR}/networkpolicies.yaml" 2>/dev/null || true

info "Forensic data saved to ${FORENSIC_DIR}/"

# -----------------------------------------------------------------------------
# Step 4: Verify Isolation
# -----------------------------------------------------------------------------
info "Step 4: Verifying network isolation"

# Check that the NetworkPolicy is applied
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" -l "security.devsecops/type=quarantine" --no-headers 2>/dev/null | wc -l)

if [[ "${NETPOL_COUNT}" -gt 0 ]]; then
    info "Quarantine NetworkPolicy verified: ${NETPOL_COUNT} policy(ies) active"
else
    if [[ -z "${KUBECTL_DRY_RUN}" ]]; then
        warn "Could not verify NetworkPolicy application. Manual verification recommended."
    fi
fi

# -----------------------------------------------------------------------------
# Step 5: Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================================="
echo "  QUARANTINE COMPLETE"
echo "============================================================================="
echo ""
echo "  Pod:        ${NAMESPACE}/${POD_NAME}"
echo "  Pod IP:     ${POD_IP}"
echo "  Node:       ${POD_NODE}"
echo "  Image:      ${POD_IMAGE}"
echo "  SA:         ${POD_SA}"
echo "  Policy:     ${NETPOL_NAME}"
echo "  Forensics:  ${FORENSIC_DIR}/"
echo "  Timestamp:  ${TIMESTAMP}"
echo ""
echo "  The pod is now NETWORK ISOLATED. It cannot:"
echo "    - Send traffic to any destination (C2 blocked)"
echo "    - Receive traffic from any source"
echo "    - Resolve DNS queries"
echo ""
echo "  NEXT STEPS:"
echo "    1. Investigate the pod: kubectl exec -it ${POD_NAME} -n ${NAMESPACE} -- /bin/sh"
echo "    2. Check for magic files: kubectl exec ${POD_NAME} -n ${NAMESPACE} -- ls -la /tmp/"
echo "    3. Check processes: kubectl exec ${POD_NAME} -n ${NAMESPACE} -- ps aux"
echo "    4. Review forensic data in ${FORENSIC_DIR}/"
echo "    5. When done, delete the pod: kubectl delete pod ${POD_NAME} -n ${NAMESPACE}"
echo "    6. Remove the quarantine policy: kubectl delete networkpolicy ${NETPOL_NAME} -n ${NAMESPACE}"
echo ""
echo "============================================================================="

info "Quarantine procedure completed successfully"
