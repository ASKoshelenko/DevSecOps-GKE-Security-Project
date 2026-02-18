#!/usr/bin/env bash
# =============================================================================
# Trivy Operator Deployment Script
# =============================================================================
# Deploys the Trivy Operator to a GKE cluster using Helm with production
# configuration defined in values.yaml.
#
# This script:
#   1. Validates prerequisites (helm, kubectl, cluster connectivity)
#   2. Adds/updates the Aqua Security Helm repository
#   3. Creates the trivy-system namespace with proper labels
#   4. Deploys or upgrades the Trivy Operator using Helm
#   5. Optionally applies Kustomize patches
#   6. Verifies the deployment is healthy
#
# USAGE:
#   ./install.sh                    # Deploy with defaults
#   ./install.sh --dry-run          # Preview without applying
#   ./install.sh --uninstall        # Remove the operator
#   ./install.sh --upgrade          # Upgrade existing deployment
#   ./install.sh --version 0.25.0   # Deploy specific chart version
#
# PREREQUISITES:
#   - helm 3.x installed
#   - kubectl configured with GKE cluster access
#   - Sufficient RBAC permissions (cluster-admin or equivalent)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly NAMESPACE="trivy-system"
readonly RELEASE_NAME="trivy-operator"
readonly CHART_REPO_NAME="aquasecurity"
readonly CHART_REPO_URL="https://aquasecurity.github.io/helm-charts/"
readonly CHART_NAME="${CHART_REPO_NAME}/trivy-operator"
readonly VALUES_FILE="${SCRIPT_DIR}/values.yaml"
readonly KUSTOMIZATION_FILE="${SCRIPT_DIR}/kustomization.yaml"

# Chart version - update this when upgrading
CHART_VERSION="${CHART_VERSION:-0.25.0}"

# Timeout for Helm operations
HELM_TIMEOUT="${HELM_TIMEOUT:-10m}"

# Color output (disabled if not a terminal)
if [ -t 1 ]; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly YELLOW='\033[1;33m'
  readonly BLUE='\033[0;34m'
  readonly NC='\033[0m' # No Color
else
  readonly RED=''
  readonly GREEN=''
  readonly YELLOW=''
  readonly BLUE=''
  readonly NC=''
fi

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
DRY_RUN=false
UNINSTALL=false
UPGRADE=false
SKIP_KUSTOMIZE=false
EXTRA_HELM_ARGS=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy the Trivy Operator to a GKE cluster.

Options:
  --dry-run           Preview the deployment without applying changes
  --uninstall         Remove the Trivy Operator from the cluster
  --upgrade           Upgrade an existing deployment
  --version VERSION   Specify the Helm chart version (default: ${CHART_VERSION})
  --skip-kustomize    Skip applying Kustomize patches
  --timeout DURATION  Helm operation timeout (default: ${HELM_TIMEOUT})
  -h, --help          Show this help message

Environment Variables:
  CHART_VERSION       Helm chart version (overridden by --version flag)
  HELM_TIMEOUT        Helm operation timeout (overridden by --timeout flag)
  KUBECONFIG          Path to kubeconfig file

Examples:
  $(basename "$0")                          # Fresh install with defaults
  $(basename "$0") --dry-run                # Preview changes
  $(basename "$0") --upgrade --version 0.26.0  # Upgrade to specific version
  $(basename "$0") --uninstall              # Remove operator
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)
      DRY_RUN=true
      EXTRA_HELM_ARGS+=("--dry-run")
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    --upgrade)
      UPGRADE=true
      shift
      ;;
    --version)
      CHART_VERSION="$2"
      shift 2
      ;;
    --skip-kustomize)
      SKIP_KUSTOMIZE=true
      shift
      ;;
    --timeout)
      HELM_TIMEOUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# -----------------------------------------------------------------------------
# Prerequisite Checks
# -----------------------------------------------------------------------------
check_prerequisites() {
  log_info "Checking prerequisites..."

  # Check for required CLI tools
  local missing_tools=()
  for tool in helm kubectl; do
    if ! command -v "${tool}" &>/dev/null; then
      missing_tools+=("${tool}")
    fi
  done

  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${missing_tools[*]}"
    log_error "Install them and ensure they are in your PATH."
    exit 1
  fi

  # Verify Helm version (must be 3.x)
  local helm_version
  helm_version=$(helm version --short 2>/dev/null | grep -oE 'v[0-9]+' | head -1)
  if [[ "${helm_version}" != "v3" ]]; then
    log_error "Helm 3.x is required. Found: $(helm version --short 2>/dev/null)"
    exit 1
  fi
  log_ok "Helm 3.x detected"

  # Verify cluster connectivity
  if ! kubectl cluster-info &>/dev/null; then
    log_error "Cannot connect to Kubernetes cluster. Check your kubeconfig."
    log_error "For GKE: gcloud container clusters get-credentials <CLUSTER> --region <REGION>"
    exit 1
  fi

  local context
  context=$(kubectl config current-context 2>/dev/null)
  log_ok "Connected to cluster: ${context}"

  # Check for cluster-admin or sufficient RBAC
  if ! kubectl auth can-i create namespace --all-namespaces &>/dev/null; then
    log_warn "Current user may not have sufficient RBAC permissions."
    log_warn "cluster-admin role or equivalent is recommended."
  fi

  # Verify values file exists
  if [[ ! -f "${VALUES_FILE}" ]]; then
    log_error "Values file not found: ${VALUES_FILE}"
    exit 1
  fi
  log_ok "Values file found: ${VALUES_FILE}"
}

# -----------------------------------------------------------------------------
# Helm Repository Setup
# -----------------------------------------------------------------------------
setup_helm_repo() {
  log_info "Configuring Helm repository..."

  # Add or update the Aqua Security Helm repository
  if helm repo list 2>/dev/null | grep -q "${CHART_REPO_NAME}"; then
    log_info "Updating existing ${CHART_REPO_NAME} Helm repository..."
    helm repo update "${CHART_REPO_NAME}"
  else
    log_info "Adding ${CHART_REPO_NAME} Helm repository..."
    helm repo add "${CHART_REPO_NAME}" "${CHART_REPO_URL}"
  fi

  # Verify the chart is available
  if ! helm search repo "${CHART_NAME}" --version "${CHART_VERSION}" 2>/dev/null | grep -q trivy-operator; then
    log_error "Chart ${CHART_NAME} version ${CHART_VERSION} not found."
    log_error "Available versions:"
    helm search repo "${CHART_NAME}" --versions | head -10
    exit 1
  fi
  log_ok "Chart ${CHART_NAME}:${CHART_VERSION} is available"
}

# -----------------------------------------------------------------------------
# Namespace Setup
# -----------------------------------------------------------------------------
create_namespace() {
  log_info "Setting up namespace: ${NAMESPACE}"

  if kubectl get namespace "${NAMESPACE}" &>/dev/null; then
    log_info "Namespace ${NAMESPACE} already exists"
  else
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_info "[DRY RUN] Would create namespace: ${NAMESPACE}"
    else
      kubectl create namespace "${NAMESPACE}"
      log_ok "Created namespace: ${NAMESPACE}"
    fi
  fi

  # Apply labels for log filtering and identification
  if [[ "${DRY_RUN}" == "false" ]]; then
    kubectl label namespace "${NAMESPACE}" \
      app.kubernetes.io/part-of=devsecops-platform \
      app.kubernetes.io/managed-by=helm \
      security.devsecops.io/component=vulnerability-scanner \
      --overwrite
    log_ok "Namespace labels applied"
  fi

  # Apply Pod Security Standards (enforce restricted profile)
  if [[ "${DRY_RUN}" == "false" ]]; then
    kubectl label namespace "${NAMESPACE}" \
      pod-security.kubernetes.io/enforce=restricted \
      pod-security.kubernetes.io/audit=restricted \
      pod-security.kubernetes.io/warn=restricted \
      --overwrite
    log_ok "Pod Security Standards applied (restricted)"
  fi
}

# -----------------------------------------------------------------------------
# Helm Install / Upgrade
# -----------------------------------------------------------------------------
deploy_operator() {
  local action="install"
  local helm_cmd="install"

  # Check if already installed
  if helm status "${RELEASE_NAME}" -n "${NAMESPACE}" &>/dev/null; then
    if [[ "${UPGRADE}" == "true" || "${DRY_RUN}" == "true" ]]; then
      action="upgrade"
      helm_cmd="upgrade"
    else
      log_warn "Release '${RELEASE_NAME}' already exists in namespace '${NAMESPACE}'."
      log_warn "Use --upgrade to upgrade the existing release."
      exit 1
    fi
  fi

  log_info "Running Helm ${action} for ${RELEASE_NAME}..."
  log_info "  Chart:     ${CHART_NAME}"
  log_info "  Version:   ${CHART_VERSION}"
  log_info "  Namespace: ${NAMESPACE}"
  log_info "  Values:    ${VALUES_FILE}"
  log_info "  Timeout:   ${HELM_TIMEOUT}"

  # Build the Helm command
  local helm_args=(
    "${helm_cmd}" "${RELEASE_NAME}" "${CHART_NAME}"
    --namespace "${NAMESPACE}"
    --version "${CHART_VERSION}"
    --values "${VALUES_FILE}"
    --timeout "${HELM_TIMEOUT}"
    --create-namespace
    --atomic
    --wait
  )

  # Add extra args (like --dry-run)
  helm_args+=("${EXTRA_HELM_ARGS[@]}")

  # Execute
  if helm "${helm_args[@]}"; then
    log_ok "Helm ${action} completed successfully"
  else
    log_error "Helm ${action} failed"
    log_error "Check the Helm release status: helm status ${RELEASE_NAME} -n ${NAMESPACE}"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Kustomize Patches (Optional)
# -----------------------------------------------------------------------------
apply_kustomize() {
  if [[ "${SKIP_KUSTOMIZE}" == "true" ]]; then
    log_info "Skipping Kustomize patches (--skip-kustomize)"
    return
  fi

  if [[ ! -f "${KUSTOMIZATION_FILE}" ]]; then
    log_info "No kustomization.yaml found, skipping patches"
    return
  fi

  log_info "Applying Kustomize patches..."

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY RUN] Would apply kustomize patches from: ${SCRIPT_DIR}"
    kubectl kustomize "${SCRIPT_DIR}"
  else
    kubectl apply -k "${SCRIPT_DIR}" --server-side
    log_ok "Kustomize patches applied"
  fi
}

# -----------------------------------------------------------------------------
# Uninstall
# -----------------------------------------------------------------------------
uninstall_operator() {
  log_info "Uninstalling Trivy Operator..."

  if ! helm status "${RELEASE_NAME}" -n "${NAMESPACE}" &>/dev/null; then
    log_warn "Release '${RELEASE_NAME}' not found in namespace '${NAMESPACE}'"
    return
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY RUN] Would uninstall: helm uninstall ${RELEASE_NAME} -n ${NAMESPACE}"
    return
  fi

  helm uninstall "${RELEASE_NAME}" -n "${NAMESPACE}" --timeout "${HELM_TIMEOUT}"
  log_ok "Helm release uninstalled"

  # Clean up CRDs (Helm does not remove CRDs on uninstall)
  log_info "Cleaning up Trivy Operator CRDs..."
  kubectl get crds -o name | grep aquasecurity | while read -r crd; do
    log_info "Deleting CRD: ${crd}"
    kubectl delete "${crd}" --timeout=60s || log_warn "Failed to delete ${crd}"
  done

  # Optionally delete the namespace
  read -rp "Delete namespace '${NAMESPACE}'? [y/N] " confirm
  if [[ "${confirm}" =~ ^[Yy]$ ]]; then
    kubectl delete namespace "${NAMESPACE}" --timeout=120s
    log_ok "Namespace deleted"
  fi
}

# -----------------------------------------------------------------------------
# Post-Deployment Verification
# -----------------------------------------------------------------------------
verify_deployment() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY RUN] Skipping deployment verification"
    return
  fi

  log_info "Verifying deployment..."

  # Wait for operator pod to be ready
  log_info "Waiting for operator pod to be ready..."
  if kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=trivy-operator \
    -n "${NAMESPACE}" \
    --timeout=120s &>/dev/null; then
    log_ok "Operator pod is ready"
  else
    log_error "Operator pod is not ready after 120s"
    kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=trivy-operator
    exit 1
  fi

  # Display deployment status
  echo ""
  log_info "=== Deployment Status ==="
  echo ""
  kubectl get deployment -n "${NAMESPACE}" -o wide
  echo ""
  kubectl get pods -n "${NAMESPACE}" -o wide
  echo ""

  # Check CRDs are installed
  log_info "Installed Trivy CRDs:"
  kubectl get crds | grep aquasecurity || log_warn "No Trivy CRDs found"
  echo ""

  # Display Helm release info
  log_info "Helm release info:"
  helm status "${RELEASE_NAME}" -n "${NAMESPACE}" --show-desc
  echo ""

  log_ok "Trivy Operator deployment verified successfully"
  echo ""
  log_info "Useful commands:"
  log_info "  View operator logs:         kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=trivy-operator -f"
  log_info "  List vulnerability reports: kubectl get vulnerabilityreports -A"
  log_info "  List config audit reports:  kubectl get configauditreports -A"
  log_info "  List exposed secrets:       kubectl get exposedsecretreports -A"
  log_info "  List SBOM reports:          kubectl get sbomreports -A"
  log_info "  List compliance reports:    kubectl get clustercompliancereports -A"
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
main() {
  echo ""
  echo "============================================="
  echo "  Trivy Operator Deployment"
  echo "  Chart Version: ${CHART_VERSION}"
  echo "============================================="
  echo ""

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "DRY RUN MODE - No changes will be applied"
    echo ""
  fi

  check_prerequisites

  if [[ "${UNINSTALL}" == "true" ]]; then
    uninstall_operator
    exit 0
  fi

  setup_helm_repo
  create_namespace
  deploy_operator
  apply_kustomize
  verify_deployment

  log_ok "Trivy Operator deployment complete!"
}

main "$@"
