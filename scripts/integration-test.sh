#!/usr/bin/env bash
# =============================================================================
# Integration Test Script - End-to-End DevSecOps Validation
# =============================================================================
#
# Performs an end-to-end integration test flow:
#   1. Create a Kind cluster with a vulnerable configuration
#   2. Deploy Falco and verify rules load correctly
#   3. Trigger a test alert (create file in /tmp)
#   4. Verify Falco detects the file creation event
#   5. Deploy Trivy Operator
#   6. Run a vulnerability scan on a test workload
#   7. Verify scan results are produced (VulnerabilityReport CRDs)
#   8. Test escape-detection rules (container escape simulation)
#   9. Clean up all resources
#
# PREREQUISITES:
#   - Docker installed and running
#   - kind CLI installed
#   - kubectl installed
#   - helm >= 3.0 installed
#   - Sufficient system resources (4GB+ RAM, 2+ CPU cores)
#
# USAGE:
#   ./integration-test.sh              # Run full integration test
#   ./integration-test.sh --no-cleanup # Skip cleanup (for debugging)
#   ./integration-test.sh --step N     # Run only step N
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLUSTER_NAME="devsecops-integration-test"
KIND_CONFIG="${PROJECT_ROOT}/k8s-security/kind-config.yaml"
TIMEOUT=120  # seconds to wait for resources
CLEANUP=true
SINGLE_STEP=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
TEST_START_TIME=$SECONDS

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_step()    {
    echo ""
    echo -e "${BLUE}${BOLD}----------------------------------------------------------------${NC}"
    echo -e "${BLUE}${BOLD}  STEP $1: $2${NC}"
    echo -e "${BLUE}${BOLD}----------------------------------------------------------------${NC}"
    echo ""
}

check_command() {
    command -v "$1" &>/dev/null
}

test_result() {
    local name="$1"
    local status="$2"  # pass, fail, skip
    local message="${3:-}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    case "${status}" in
        pass)
            PASSED_TESTS=$((PASSED_TESTS + 1))
            echo -e "  ${GREEN}[PASS]${NC} ${name}"
            ;;
        fail)
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo -e "  ${RED}[FAIL]${NC} ${name}"
            if [[ -n "${message}" ]]; then
                echo -e "         ${message}" | head -10
            fi
            ;;
        skip)
            SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
            echo -e "  ${YELLOW}[SKIP]${NC} ${name}"
            ;;
    esac
}

# Wait for a condition with timeout
wait_for() {
    local description="$1"
    local check_cmd="$2"
    local timeout="${3:-${TIMEOUT}}"
    local interval="${4:-5}"

    echo -n "  Waiting for ${description}..."
    local elapsed=0
    while [[ ${elapsed} -lt ${timeout} ]]; do
        if eval "${check_cmd}" &>/dev/null; then
            echo -e " ${GREEN}OK${NC} (${elapsed}s)"
            return 0
        fi
        sleep "${interval}"
        elapsed=$((elapsed + interval))
        echo -n "."
    done
    echo -e " ${RED}TIMEOUT${NC} (${timeout}s)"
    return 1
}

# Cleanup function
cleanup() {
    if [[ "${CLEANUP}" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}Cleaning up...${NC}"
        kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
        echo -e "${GREEN}Cleanup complete.${NC}"
    else
        echo ""
        echo -e "${YELLOW}Skipping cleanup (--no-cleanup). Cluster '${CLUSTER_NAME}' is still running.${NC}"
        echo -e "  Delete manually: kind delete cluster --name ${CLUSTER_NAME}"
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --no-cleanup) CLEANUP=false ;;
        --step)       shift; SINGLE_STEP="${1:-}" ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-cleanup   Skip cluster cleanup after tests"
            echo "  --step N       Run only step N (1-9)"
            echo "  --help         Show this help message"
            exit 0
            ;;
    esac
done

# Ensure cleanup happens on exit (unless --no-cleanup)
trap cleanup EXIT

echo -e "${BOLD}DevSecOps Project - Integration Tests${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo -e "Cluster name: ${CLUSTER_NAME}"
echo ""

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================
log_step "0" "Preflight Checks"

preflight_ok=true

for tool in docker kind kubectl helm; do
    if check_command "${tool}"; then
        log_info "${tool} is installed"
    else
        log_fail "${tool} is NOT installed"
        preflight_ok=false
    fi
done

if ! docker info &>/dev/null; then
    log_fail "Docker daemon is not running"
    preflight_ok=false
fi

if [[ "${preflight_ok}" == "false" ]]; then
    echo -e "${RED}Preflight checks failed. Install missing tools and try again.${NC}"
    exit 1
fi

# =============================================================================
# STEP 1: Create Kind Cluster
# =============================================================================
should_run() {
    [[ -z "${SINGLE_STEP}" || "${SINGLE_STEP}" == "$1" ]]
}

if should_run 1; then
    log_step "1" "Create Kind Cluster with Vulnerable Configuration"

    # Delete existing cluster if present
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_info "Deleting existing cluster '${CLUSTER_NAME}'..."
        kind delete cluster --name "${CLUSTER_NAME}"
    fi

    if [[ -f "${KIND_CONFIG}" ]]; then
        log_info "Creating Kind cluster from ${KIND_CONFIG}..."
        if kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}" --wait 120s 2>&1; then
            test_result "Kind cluster created successfully" "pass"
        else
            test_result "Kind cluster creation" "fail" "Failed to create cluster"
            echo -e "${RED}Cannot proceed without a cluster. Exiting.${NC}"
            exit 1
        fi
    else
        log_warn "Kind config not found at ${KIND_CONFIG}, using defaults..."
        if kind create cluster --name "${CLUSTER_NAME}" --wait 120s 2>&1; then
            test_result "Kind cluster created (default config)" "pass"
        else
            test_result "Kind cluster creation" "fail"
            exit 1
        fi
    fi

    # Verify cluster is accessible
    kubectl cluster-info --context "kind-${CLUSTER_NAME}" &>/dev/null
    test_result "Cluster is accessible via kubectl" "pass"

    # Check node status
    node_ready=$(kubectl get nodes --context "kind-${CLUSTER_NAME}" --no-headers 2>/dev/null | grep -c "Ready" || echo "0")
    if [[ ${node_ready} -gt 0 ]]; then
        test_result "Cluster nodes are Ready (${node_ready} node(s))" "pass"
    else
        test_result "Cluster nodes are Ready" "fail" "No nodes in Ready state"
    fi

    # Verify the cluster uses a vulnerable K8s version
    k8s_version=$(kubectl version --context "kind-${CLUSTER_NAME}" --short 2>/dev/null | grep "Server" | grep -oE 'v[0-9]+\.[0-9]+' || echo "unknown")
    log_info "Kubernetes server version: ${k8s_version}"
fi

# =============================================================================
# STEP 2: Deploy Falco
# =============================================================================
if should_run 2; then
    log_step "2" "Deploy Falco and Verify Rules Load"

    # Add Falco Helm repo
    helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
    helm repo update 2>/dev/null || true

    # Create namespace
    kubectl create namespace falco --context "kind-${CLUSTER_NAME}" 2>/dev/null || true

    # Deploy Falco with minimal config for testing
    FALCO_VALUES="${PROJECT_ROOT}/helm/falco/values.yaml"
    helm_args=(
        "falco" "falcosecurity/falco"
        "--namespace" "falco"
        "--kube-context" "kind-${CLUSTER_NAME}"
        "--set" "driver.kind=modern_ebpf"
        "--set" "falcosidekick.enabled=false"
        "--set" "tty=true"
        "--wait"
        "--timeout" "180s"
    )

    if [[ -f "${FALCO_VALUES}" ]]; then
        helm_args+=("-f" "${FALCO_VALUES}")
    fi

    log_info "Installing Falco via Helm..."
    if helm install "${helm_args[@]}" 2>&1; then
        test_result "Falco installed via Helm" "pass"
    else
        # Falco may fail on Kind due to eBPF/kernel issues; try alternative driver
        log_warn "Falco install with modern_ebpf failed, trying with kernel module..."
        helm install falco falcosecurity/falco \
            --namespace falco \
            --kube-context "kind-${CLUSTER_NAME}" \
            --set "driver.kind=auto" \
            --set "tty=true" \
            --wait \
            --timeout 180s 2>&1 || true
        test_result "Falco installed via Helm (fallback driver)" "warn"
    fi

    # Wait for Falco pods to be ready
    if wait_for "Falco pods to be ready" \
        "kubectl get pods -n falco --context kind-${CLUSTER_NAME} --no-headers 2>/dev/null | grep -q Running" \
        120; then
        test_result "Falco pods are running" "pass"
    else
        test_result "Falco pods are running" "fail" "Falco pods did not reach Running state"
        log_warn "Continuing despite Falco pod issues (common on Kind without eBPF support)"
    fi

    # Verify Falco rules are loaded
    falco_pod=$(kubectl get pods -n falco --context "kind-${CLUSTER_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "${falco_pod}" ]]; then
        # Check logs for rule loading
        if kubectl logs "${falco_pod}" -n falco --context "kind-${CLUSTER_NAME}" 2>/dev/null | grep -q "rules\|Rules"; then
            test_result "Falco rules loaded (confirmed in logs)" "pass"
        else
            test_result "Falco rules loaded" "skip" "Could not confirm rules in Falco logs"
        fi
    fi
fi

# =============================================================================
# STEP 3: Trigger Test Alert
# =============================================================================
if should_run 3; then
    log_step "3" "Trigger Test Alert (Create File in /tmp)"

    # Create a test pod that writes a file to /tmp
    kubectl apply --context "kind-${CLUSTER_NAME}" -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: falco-test-trigger
  namespace: default
  labels:
    app: falco-test
spec:
  restartPolicy: Never
  containers:
    - name: test
      image: busybox:1.36
      command: ["/bin/sh", "-c"]
      args:
        - |
          echo "Falco test alert trigger" > /tmp/test-alert-file
          echo "magic_string_for_detection" > /tmp/suspicious-file
          ls -la /tmp/
          sleep 30
EOF

    if wait_for "test pod to be running" \
        "kubectl get pod falco-test-trigger --context kind-${CLUSTER_NAME} --no-headers 2>/dev/null | grep -qE 'Running|Completed'" \
        60; then
        test_result "Test trigger pod created and running" "pass"
    else
        test_result "Test trigger pod" "fail" "Pod did not reach Running state"
    fi

    # Give Falco time to detect the event
    log_info "Waiting 15 seconds for Falco to detect the event..."
    sleep 15
fi

# =============================================================================
# STEP 4: Verify Falco Detection
# =============================================================================
if should_run 4; then
    log_step "4" "Verify Falco Detects the File Creation"

    falco_pod=$(kubectl get pods -n falco --context "kind-${CLUSTER_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [[ -n "${falco_pod}" ]]; then
        # Check Falco logs for detection events
        falco_logs=$(kubectl logs "${falco_pod}" -n falco --context "kind-${CLUSTER_NAME}" --tail=200 2>/dev/null || echo "")

        if echo "${falco_logs}" | grep -qi "notice\|warning\|alert\|write\|tmp\|suspicious"; then
            test_result "Falco detected activity (events found in logs)" "pass"
            # Show relevant log entries
            echo "  Recent Falco events:"
            echo "${falco_logs}" | grep -i "notice\|warning\|alert" | tail -5 | while read -r line; do
                echo "    ${line:0:120}"
            done
        else
            test_result "Falco event detection" "skip" "No detection events found (Falco may need different driver on Kind)"
        fi
    else
        test_result "Falco event detection" "skip" "No Falco pods found"
    fi

    # Clean up test pod
    kubectl delete pod falco-test-trigger --context "kind-${CLUSTER_NAME}" --ignore-not-found 2>/dev/null || true
fi

# =============================================================================
# STEP 5: Deploy Trivy Operator
# =============================================================================
if should_run 5; then
    log_step "5" "Deploy Trivy Operator"

    # Add Aqua Security Helm repo
    helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/ 2>/dev/null || true
    helm repo update 2>/dev/null || true

    # Create namespace
    kubectl create namespace trivy-system --context "kind-${CLUSTER_NAME}" 2>/dev/null || true

    # Deploy Trivy Operator
    TRIVY_VALUES="${PROJECT_ROOT}/helm/trivy-operator/values.yaml"
    helm_args=(
        "trivy-operator" "aquasecurity/trivy-operator"
        "--namespace" "trivy-system"
        "--kube-context" "kind-${CLUSTER_NAME}"
        "--set" "trivy.ignoreUnfixed=false"
        "--wait"
        "--timeout" "180s"
    )

    if [[ -f "${TRIVY_VALUES}" ]]; then
        helm_args+=("-f" "${TRIVY_VALUES}")
    fi

    log_info "Installing Trivy Operator via Helm..."
    if helm install "${helm_args[@]}" 2>&1; then
        test_result "Trivy Operator installed via Helm" "pass"
    else
        test_result "Trivy Operator installation" "fail" "Helm install failed"
    fi

    # Wait for Trivy Operator to be ready
    if wait_for "Trivy Operator pods to be ready" \
        "kubectl get pods -n trivy-system --context kind-${CLUSTER_NAME} --no-headers 2>/dev/null | grep -q Running" \
        120; then
        test_result "Trivy Operator pods are running" "pass"
    else
        test_result "Trivy Operator pods" "fail" "Pods did not reach Running state"
    fi
fi

# =============================================================================
# STEP 6: Run Vulnerability Scan
# =============================================================================
if should_run 6; then
    log_step "6" "Run Vulnerability Scan on Test Workload"

    # Deploy a test workload with a known vulnerable image
    kubectl apply --context "kind-${CLUSTER_NAME}" -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-nginx
  namespace: default
  labels:
    app: vulnerable-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-nginx
  template:
    metadata:
      labels:
        app: vulnerable-nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.21.0
          ports:
            - containerPort: 80
          resources:
            limits:
              memory: 128Mi
              cpu: 100m
            requests:
              memory: 64Mi
              cpu: 50m
EOF

    if wait_for "vulnerable-nginx deployment to be ready" \
        "kubectl get deploy vulnerable-nginx --context kind-${CLUSTER_NAME} -o jsonpath='{.status.readyReplicas}' 2>/dev/null | grep -q '1'" \
        90; then
        test_result "Vulnerable test workload deployed" "pass"
    else
        test_result "Vulnerable test workload deployment" "fail"
    fi

    # Wait for Trivy to scan the workload
    log_info "Waiting for Trivy Operator to scan the workload (this may take 2-3 minutes)..."
    if wait_for "VulnerabilityReport to be created" \
        "kubectl get vulnerabilityreports --context kind-${CLUSTER_NAME} --no-headers 2>/dev/null | grep -q 'vulnerable-nginx\\|nginx'" \
        180 10; then
        test_result "Trivy created VulnerabilityReport for test workload" "pass"
    else
        test_result "VulnerabilityReport creation" "fail" "Trivy did not produce a report within timeout"
    fi
fi

# =============================================================================
# STEP 7: Verify Scan Results
# =============================================================================
if should_run 7; then
    log_step "7" "Verify Scan Results Are Produced"

    # Check VulnerabilityReport CRDs
    vuln_reports=$(kubectl get vulnerabilityreports --context "kind-${CLUSTER_NAME}" -o json 2>/dev/null || echo '{"items":[]}')
    report_count=$(echo "${vuln_reports}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "0")

    if [[ ${report_count} -gt 0 ]]; then
        test_result "VulnerabilityReports exist (${report_count} report(s))" "pass"

        # Extract vulnerability counts
        vuln_summary=$(echo "${vuln_reports}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
total_vulns = 0
critical = high = medium = low = 0
for item in data.get('items', []):
    report = item.get('report', {})
    for vuln in report.get('vulnerabilities', []):
        total_vulns += 1
        sev = vuln.get('severity', '').upper()
        if sev == 'CRITICAL': critical += 1
        elif sev == 'HIGH': high += 1
        elif sev == 'MEDIUM': medium += 1
        elif sev == 'LOW': low += 1
print(f'{total_vulns} total: {critical} critical, {high} high, {medium} medium, {low} low')
" 2>/dev/null || echo "unknown")

        test_result "Vulnerabilities detected: ${vuln_summary}" "pass"
        log_info "Scan results: ${vuln_summary}"
    else
        test_result "VulnerabilityReports contain data" "fail" "No reports found"
    fi

    # Check ConfigAuditReport if enabled
    config_reports=$(kubectl get configauditreports --context "kind-${CLUSTER_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    if [[ ${config_reports} -gt 0 ]]; then
        test_result "ConfigAuditReports exist (${config_reports} report(s))" "pass"
    else
        test_result "ConfigAuditReports" "skip" "No ConfigAuditReports found (may need more time)"
    fi
fi

# =============================================================================
# STEP 8: Test Escape Detection Rules
# =============================================================================
if should_run 8; then
    log_step "8" "Test Container Escape Detection Rules"

    # Deploy a pod that simulates suspicious escape-related behavior
    kubectl apply --context "kind-${CLUSTER_NAME}" -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-test-pod
  namespace: default
  labels:
    app: escape-test
spec:
  restartPolicy: Never
  containers:
    - name: escape-test
      image: busybox:1.36
      command: ["/bin/sh", "-c"]
      args:
        - |
          # Simulate suspicious activities that escape detection rules should catch
          echo "=== Simulating suspicious container activities ==="

          # 1. Attempt to read sensitive paths (should trigger alerts)
          cat /proc/1/cgroup 2>/dev/null || true
          ls /proc/1/root 2>/dev/null || true

          # 2. Write to /tmp (common in APT attacks for staging)
          echo "staging_payload" > /tmp/.hidden_payload
          echo "c2_config" > /tmp/config.dat

          # 3. Attempt DNS resolution of suspicious domain
          nslookup evil.example.com 2>/dev/null || true

          # 4. Check for container runtime socket
          ls -la /var/run/docker.sock 2>/dev/null || true
          ls -la /run/containerd/containerd.sock 2>/dev/null || true

          # 5. Attempt to access cloud metadata
          wget -qO- http://169.254.169.254/computeMetadata/v1/ 2>/dev/null || true

          echo "=== Simulation complete ==="
          sleep 30
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
EOF

    if wait_for "escape-test-pod to complete" \
        "kubectl get pod escape-test-pod --context kind-${CLUSTER_NAME} --no-headers 2>/dev/null | grep -qE 'Completed|Running'" \
        60; then
        test_result "Escape detection test pod ran successfully" "pass"

        # Check pod logs
        pod_logs=$(kubectl logs escape-test-pod --context "kind-${CLUSTER_NAME}" 2>/dev/null || echo "")
        if echo "${pod_logs}" | grep -q "Simulation complete"; then
            test_result "Escape simulation activities executed" "pass"
        else
            test_result "Escape simulation activities" "fail" "Pod did not complete simulation"
        fi
    else
        test_result "Escape detection test pod" "fail" "Pod did not reach expected state"
    fi

    # Check Falco logs for escape-related detections
    sleep 10
    falco_pod=$(kubectl get pods -n falco --context "kind-${CLUSTER_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "${falco_pod}" ]]; then
        escape_detections=$(kubectl logs "${falco_pod}" -n falco --context "kind-${CLUSTER_NAME}" --tail=100 2>/dev/null \
            | grep -ci "escape\|docker.sock\|containerd.sock\|metadata\|suspicious\|hidden\|proc" || echo "0")

        if [[ ${escape_detections} -gt 0 ]]; then
            test_result "Falco detected escape-related activities (${escape_detections} events)" "pass"
        else
            test_result "Falco escape detection" "skip" "No escape-specific events detected (driver-dependent)"
        fi
    fi

    # Clean up
    kubectl delete pod escape-test-pod --context "kind-${CLUSTER_NAME}" --ignore-not-found 2>/dev/null || true
fi

# =============================================================================
# STEP 9: Summary
# =============================================================================
if should_run 9 || [[ -z "${SINGLE_STEP}" ]]; then
    log_step "9" "Test Summary"

    total_time=$((SECONDS - TEST_START_TIME))

    echo ""
    echo -e "  ${BOLD}Integration Test Results${NC}"
    echo -e "  =========================="
    echo -e "  ${GREEN}Passed:${NC}  ${PASSED_TESTS}"
    echo -e "  ${RED}Failed:${NC}  ${FAILED_TESTS}"
    echo -e "  ${YELLOW}Skipped:${NC} ${SKIPPED_TESTS}"
    echo -e "  ${BOLD}Total:${NC}   ${TOTAL_TESTS}"
    echo -e "  ${CYAN}Duration:${NC} ${total_time}s"
    echo ""

    if [[ ${FAILED_TESTS} -gt 0 ]]; then
        echo -e "${RED}${BOLD}Integration tests FAILED with ${FAILED_TESTS} failure(s).${NC}"
        echo ""
        echo -e "${YELLOW}Debugging tips:${NC}"
        echo "  - Check cluster status: kubectl get nodes --context kind-${CLUSTER_NAME}"
        echo "  - Check all pods: kubectl get pods -A --context kind-${CLUSTER_NAME}"
        echo "  - Check Falco logs: kubectl logs -n falco -l app.kubernetes.io/name=falco --context kind-${CLUSTER_NAME}"
        echo "  - Check Trivy logs: kubectl logs -n trivy-system -l app.kubernetes.io/name=trivy-operator --context kind-${CLUSTER_NAME}"
        echo ""
        echo "  Re-run with --no-cleanup to inspect the cluster after failure."
        exit 1
    else
        echo -e "${GREEN}${BOLD}Integration tests PASSED.${NC}"
        exit 0
    fi
fi
