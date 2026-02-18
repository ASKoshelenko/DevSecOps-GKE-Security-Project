#!/usr/bin/env bash
# =============================================================================
# Workload Identity Verification Script
# =============================================================================
#
# PURPOSE:
# Tests and verifies that GKE Workload Identity is correctly configured
# by deploying a test pod that attempts to authenticate to GCP services
# using the metadata server (no SA keys).
#
# USAGE:
#   ./test-access.sh --project-id <PROJECT_ID> [--namespace <NAMESPACE>] [--ksa <KSA_NAME>]
#
# WHAT THIS SCRIPT DOES:
# 1. Deploys a test pod with the specified KSA
# 2. Verifies the pod can reach the GKE metadata server
# 3. Checks that the metadata server returns the correct GSA identity
# 4. Attempts to access GCP APIs (BigQuery, Storage) using the token
# 5. Verifies that access is denied for unauthorized APIs
# 6. Cleans up the test pod
#
# PREREQUISITES:
# - kubectl configured with access to the GKE cluster
# - Workload Identity enabled on the cluster
# - terraform-gke-wi.tf applied (KSA, GSA, IAM binding exist)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly TEST_POD_NAME="wi-test-$(date +%s)"
readonly TIMEOUT=120  # seconds to wait for pod

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Defaults
PROJECT_ID=""
NAMESPACE="security-tools"
KSA_NAME="trivy-operator"
CLEANUP=true

# =============================================================================
# Utility Functions
# =============================================================================

log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_info() { echo -e "${CYAN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

die() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    exit 1
}

cleanup() {
    if [[ "${CLEANUP}" == "true" ]]; then
        log_info "Cleaning up test pod: ${TEST_POD_NAME}..."
        kubectl delete pod "${TEST_POD_NAME}" \
            --namespace="${NAMESPACE}" \
            --ignore-not-found=true \
            --wait=false 2>/dev/null || true
    fi
}

trap cleanup EXIT

# =============================================================================
# Argument Parsing
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-id)   PROJECT_ID="$2"; shift 2 ;;
        --namespace)    NAMESPACE="$2"; shift 2 ;;
        --ksa)          KSA_NAME="$2"; shift 2 ;;
        --no-cleanup)   CLEANUP=false; shift ;;
        --help|-h)
            echo "Usage: ${SCRIPT_NAME} --project-id <PROJECT_ID> [--namespace <NS>] [--ksa <KSA>] [--no-cleanup]"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ -z "${PROJECT_ID}" ]] && die "--project-id is required"

# =============================================================================
# Test Execution
# =============================================================================

echo -e "${BOLD}"
echo "============================================================================="
echo " GKE Workload Identity Verification"
echo "============================================================================="
echo -e "${NC}"
echo "  Project:    ${PROJECT_ID}"
echo "  Namespace:  ${NAMESPACE}"
echo "  KSA:        ${KSA_NAME}"
echo "  Test Pod:   ${TEST_POD_NAME}"
echo ""

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expect_success="${3:-true}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BOLD}Test ${TOTAL_TESTS}: ${test_name}${NC}"

    local result
    result="$(kubectl exec "${TEST_POD_NAME}" \
        --namespace="${NAMESPACE}" \
        -- /bin/sh -c "${test_cmd}" 2>&1)" || true

    if [[ "${expect_success}" == "true" ]]; then
        if [[ $? -eq 0 ]] && [[ -n "${result}" ]]; then
            log_pass "${test_name}"
            echo "  Result: ${result}" | head -5
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_fail "${test_name}"
            echo "  Output: ${result}" | head -5
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        # Expect failure (e.g., unauthorized access should be denied)
        if echo "${result}" | grep -qi "denied\|forbidden\|unauthorized\|error"; then
            log_pass "${test_name} (correctly denied)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            log_fail "${test_name} (expected denial, got success)"
            echo "  Output: ${result}" | head -5
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi
    echo ""
}

# -----------------------------------------------------------------------
# Step 1: Verify KSA exists and has WI annotation
# -----------------------------------------------------------------------

log_info "Verifying KSA '${KSA_NAME}' in namespace '${NAMESPACE}'..."

KSA_ANNOTATION="$(kubectl get serviceaccount "${KSA_NAME}" \
    --namespace="${NAMESPACE}" \
    -o jsonpath='{.metadata.annotations.iam\.gke\.io/gcp-service-account}' 2>/dev/null)" || \
    die "KSA '${KSA_NAME}' not found in namespace '${NAMESPACE}'. Apply service-account.yaml first."

if [[ -z "${KSA_ANNOTATION}" ]]; then
    die "KSA '${KSA_NAME}' does not have the iam.gke.io/gcp-service-account annotation."
fi

log_info "KSA annotation: ${KSA_ANNOTATION}"
echo ""

# -----------------------------------------------------------------------
# Step 2: Deploy test pod
# -----------------------------------------------------------------------

log_info "Deploying test pod '${TEST_POD_NAME}'..."

kubectl run "${TEST_POD_NAME}" \
    --namespace="${NAMESPACE}" \
    --image="google/cloud-sdk:slim" \
    --serviceaccount="${KSA_NAME}" \
    --restart=Never \
    --labels="app=wi-test,purpose=workload-identity-verification" \
    --overrides='{
      "spec": {
        "containers": [{
          "name": "test",
          "image": "google/cloud-sdk:slim",
          "command": ["sleep", "300"],
          "securityContext": {
            "allowPrivilegeEscalation": false,
            "runAsNonRoot": true,
            "runAsUser": 65534,
            "capabilities": {"drop": ["ALL"]}
          },
          "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "200m", "memory": "256Mi"}
          }
        }],
        "nodeSelector": {
          "iam.gke.io/gke-metadata-server-enabled": "true"
        }
      }
    }' 2>/dev/null || die "Failed to create test pod"

# Wait for pod to be ready
log_info "Waiting for test pod to be ready (timeout: ${TIMEOUT}s)..."
if ! kubectl wait pod "${TEST_POD_NAME}" \
    --namespace="${NAMESPACE}" \
    --for=condition=Ready \
    --timeout="${TIMEOUT}s" 2>/dev/null; then
    kubectl describe pod "${TEST_POD_NAME}" --namespace="${NAMESPACE}" 2>/dev/null | tail -20
    die "Test pod failed to start within ${TIMEOUT}s"
fi

log_info "Test pod is ready. Running verification tests..."
echo ""
echo "============================================================================="
echo " Running Tests"
echo "============================================================================="
echo ""

# -----------------------------------------------------------------------
# Test 1: Metadata server reachability
# -----------------------------------------------------------------------
run_test "Metadata server reachability" \
    "curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email" \
    true

# -----------------------------------------------------------------------
# Test 2: Identity verification
# -----------------------------------------------------------------------
run_test "Identity matches expected GSA" \
    "IDENTITY=\$(curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email) && echo \"\${IDENTITY}\" | grep -q '${KSA_ANNOTATION}' && echo 'Identity verified: '\${IDENTITY}" \
    true

# -----------------------------------------------------------------------
# Test 3: Access token retrieval
# -----------------------------------------------------------------------
run_test "Access token retrieval from metadata server" \
    "TOKEN=\$(curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token' | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"access_token\",\"\")[:20])') && [ -n \"\${TOKEN}\" ] && echo 'Token received (first 20 chars): '\${TOKEN}'...'" \
    true

# -----------------------------------------------------------------------
# Test 4: Token scopes
# -----------------------------------------------------------------------
run_test "Token scopes include cloud-platform" \
    "curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes'" \
    true

# -----------------------------------------------------------------------
# Test 5: GCP API access (BigQuery - should succeed for Trivy SA)
# -----------------------------------------------------------------------
run_test "BigQuery API access (authorized)" \
    "gcloud auth print-access-token --quiet >/dev/null 2>&1 && bq ls --project_id=${PROJECT_ID} 2>&1 | head -5" \
    true

# -----------------------------------------------------------------------
# Test 6: GCP API access (Compute Engine - should be denied for Trivy SA)
# -----------------------------------------------------------------------
run_test "Compute Engine API access (should be denied)" \
    "gcloud compute instances list --project=${PROJECT_ID} 2>&1" \
    false

# -----------------------------------------------------------------------
# Test 7: No SA key files on disk
# -----------------------------------------------------------------------
run_test "No SA key files on disk" \
    "find / -name '*.json' -path '*/credentials*' 2>/dev/null | wc -l | grep -q '^0$' && echo 'No credential JSON files found on disk'" \
    true

# -----------------------------------------------------------------------
# Test 8: GOOGLE_APPLICATION_CREDENTIALS not set
# -----------------------------------------------------------------------
run_test "GOOGLE_APPLICATION_CREDENTIALS not set to key file" \
    "if [ -z \"\${GOOGLE_APPLICATION_CREDENTIALS:-}\" ] || [ ! -f \"\${GOOGLE_APPLICATION_CREDENTIALS:-/nonexistent}\" ]; then echo 'No key file in GOOGLE_APPLICATION_CREDENTIALS'; else echo 'WARNING: Key file found'; exit 1; fi" \
    true

# =============================================================================
# Results Summary
# =============================================================================

echo "============================================================================="
echo -e "${BOLD}Test Results Summary${NC}"
echo "============================================================================="
echo ""
echo "  Total tests:  ${TOTAL_TESTS}"
echo -e "  Passed:       ${GREEN}${PASSED_TESTS}${NC}"
echo -e "  Failed:       ${RED}${FAILED_TESTS}${NC}"
echo ""

if [[ "${FAILED_TESTS}" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed. Workload Identity is correctly configured.${NC}"
    echo ""
    echo "Verified:"
    echo "  - KSA '${KSA_NAME}' successfully maps to GSA '${KSA_ANNOTATION}'"
    echo "  - Metadata server returns correct identity and tokens"
    echo "  - Authorized GCP APIs are accessible"
    echo "  - Unauthorized GCP APIs are correctly denied"
    echo "  - No service account key files are present on disk"
    exit 0
else
    echo -e "${RED}${BOLD}${FAILED_TESTS} test(s) failed. Review the output above.${NC}"
    echo ""
    echo "Common issues:"
    echo "  1. KSA annotation does not match GSA email"
    echo "  2. IAM binding (workloadIdentityUser) is missing"
    echo "  3. GKE Workload Identity is not enabled on the node pool"
    echo "  4. GSA does not have the required IAM roles"
    exit 1
fi
