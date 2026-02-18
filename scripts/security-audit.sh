#!/usr/bin/env bash
# =============================================================================
# Security Audit Script
# =============================================================================
#
# Comprehensive security validation for the DevSecOps project:
#   1. Detect hardcoded credentials and secrets (gitleaks patterns)
#   2. Verify no service account keys exist in any config
#   3. Verify container images use specific digests or tags
#   4. Check RBAC configurations for least privilege
#   5. Verify network policies are defined
#   6. Check Pod Security Standards compliance
#   7. Validate Terraform security configurations
#   8. Check GitHub Actions workflow security
#
# PREREQUISITES:
#   - gitleaks (optional, for enhanced secret detection)
#   - grep, awk, sed (standard Unix tools)
#   - python3 (for YAML/JSON parsing)
#
# USAGE:
#   ./security-audit.sh              # Run all checks
#   ./security-audit.sh --strict     # Treat warnings as failures
#   ./security-audit.sh --junit      # Output JUnit XML to reports/
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORTS_DIR="${PROJECT_ROOT}/reports"
STRICT_MODE=false
JUNIT_OUTPUT=false

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0
SKIPPED_CHECKS=0
JUNIT_RESULTS=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
log_pass()    { echo -e "  ${GREEN}[PASS]${NC}    $*"; }
log_fail()    { echo -e "  ${RED}[FAIL]${NC}    $*"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
log_skip()    { echo -e "  ${YELLOW}[SKIP]${NC}    $*"; }
log_section() {
    echo ""
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $*${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo ""
}

check_command() {
    command -v "$1" &>/dev/null
}

record_result() {
    local name="$1"
    local status="$2"  # pass, fail, warn, skip
    local message="${3:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "${status}" in
        pass)
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            log_pass "${name}"
            ;;
        fail)
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            log_fail "${name}"
            if [[ -n "${message}" ]]; then
                echo -e "            ${message}" | head -20
            fi
            ;;
        warn)
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            if [[ "${STRICT_MODE}" == "true" ]]; then
                FAILED_CHECKS=$((FAILED_CHECKS + 1))
                log_fail "${name} (strict mode)"
            else
                log_warn "${name}"
            fi
            if [[ -n "${message}" ]]; then
                echo -e "            ${message}" | head -10
            fi
            ;;
        skip)
            SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
            log_skip "${name}"
            ;;
    esac

    if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
        local escaped_name escaped_message
        escaped_name=$(echo "${name}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        escaped_message=$(echo "${message}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' | head -50)

        case "${status}" in
            pass)
                JUNIT_RESULTS+="    <testcase classname=\"security-audit\" name=\"${escaped_name}\"/>"$'\n'
                ;;
            fail)
                JUNIT_RESULTS+="    <testcase classname=\"security-audit\" name=\"${escaped_name}\">"$'\n'
                JUNIT_RESULTS+="      <failure message=\"Security check failed\">${escaped_message}</failure>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
            warn)
                JUNIT_RESULTS+="    <testcase classname=\"security-audit\" name=\"${escaped_name}\">"$'\n'
                JUNIT_RESULTS+="      <system-out>WARNING: ${escaped_message}</system-out>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
            skip)
                JUNIT_RESULTS+="    <testcase classname=\"security-audit\" name=\"${escaped_name}\">"$'\n'
                JUNIT_RESULTS+="      <skipped/>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
        esac
    fi
}

write_junit_xml() {
    mkdir -p "${REPORTS_DIR}"
    local output_file="${REPORTS_DIR}/security-audit.xml"
    cat > "${output_file}" <<XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="security-audit" tests="${TOTAL_CHECKS}" failures="${FAILED_CHECKS}" skipped="${SKIPPED_CHECKS}" time="0">
${JUNIT_RESULTS}  </testsuite>
</testsuites>
XMLEOF
    echo -e "${CYAN}JUnit XML report written to: ${output_file}${NC}"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --strict)  STRICT_MODE=true ;;
        --junit)   JUNIT_OUTPUT=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --strict   Treat warnings as failures"
            echo "  --junit    Output results in JUnit XML format"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}"
            exit 1
            ;;
    esac
done

echo -e "${BOLD}DevSecOps Project - Security Audit${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
if [[ "${STRICT_MODE}" == "true" ]]; then
    echo -e "${YELLOW}Strict mode: ON (warnings are treated as failures)${NC}"
fi
echo ""

# =============================================================================
# SECTION 1: Credential and Secret Detection
# =============================================================================
log_section "1. Credential and Secret Detection"

# --- 1a. Check for service account key files ---
sa_key_files=$(find "${PROJECT_ROOT}" \
    -name "*.json" \
    -not -path "*/.terraform/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/reports/*" \
    -exec grep -l '"type":\s*"service_account"' {} \; 2>/dev/null || true)

if [[ -n "${sa_key_files}" ]]; then
    record_result "No GCP service account key files" "fail" "Found SA key files:\n${sa_key_files}"
else
    record_result "No GCP service account key files in project" "pass"
fi

# --- 1b. Check for private keys ---
private_key_files=$(find "${PROJECT_ROOT}" \
    -not -path "*/.terraform/*" \
    -not -path "*/.git/*" \
    -not -path "*/node_modules/*" \
    \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" \) 2>/dev/null || true)

if [[ -n "${private_key_files}" ]]; then
    record_result "No private key files" "fail" "Found key files:\n${private_key_files}"
else
    record_result "No private key files (.pem, .key, .p12, .pfx, .jks)" "pass"
fi

# --- 1c. Check for .env files ---
env_files=$(find "${PROJECT_ROOT}" \
    -name ".env" -o -name ".env.*" -o -name "*.env" \
    | grep -v ".pre-commit" \
    | grep -v "node_modules" 2>/dev/null || true)

if [[ -n "${env_files}" ]]; then
    record_result "No .env files with potential secrets" "warn" "Found .env files:\n${env_files}"
else
    record_result "No .env files found" "pass"
fi

# --- 1d. Hardcoded credentials using regex patterns (gitleaks-style) ---
SECRET_PATTERNS=(
    # GCP service account keys
    '"private_key":\s*"-----BEGIN'
    '"private_key_id":\s*"[a-f0-9]{40}"'
    # AWS credentials
    'AKIA[0-9A-Z]{16}'
    'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}'
    # Generic secrets
    'password\s*[:=]\s*["\x27][^\s"'\'']{8,}["\x27]'
    'secret\s*[:=]\s*["\x27][^\s"'\'']{8,}["\x27]'
    'api[_-]?key\s*[:=]\s*["\x27][^\s"'\'']{16,}["\x27]'
    'token\s*[:=]\s*["\x27][^\s"'\'']{16,}["\x27]'
    # Base64-encoded secrets (long base64 strings in env vars)
    '[A-Z_]+_KEY\s*=\s*[A-Za-z0-9+/]{40,}={0,2}'
    # GitHub tokens
    'gh[pousr]_[A-Za-z0-9_]{36,}'
    # Slack tokens
    'xox[baprs]-[0-9]+-[A-Za-z0-9]+'
)

hardcoded_found=false
hardcoded_output=""

for pattern in "${SECRET_PATTERNS[@]}"; do
    matches=$(grep -rn \
        --include="*.tf" \
        --include="*.yaml" \
        --include="*.yml" \
        --include="*.py" \
        --include="*.sh" \
        --include="*.json" \
        --include="*.toml" \
        --include="*.cfg" \
        --exclude-dir=".terraform" \
        --exclude-dir=".git" \
        --exclude-dir="node_modules" \
        --exclude-dir="reports" \
        --exclude="*test*" \
        --exclude="*security-audit*" \
        -iE "${pattern}" "${PROJECT_ROOT}" 2>/dev/null \
        | grep -v "description\|#\|//\|variable\|example\|placeholder\|TODO\|FIXME\|mock\|fake\|dummy\|test_" || true)

    if [[ -n "${matches}" ]]; then
        hardcoded_found=true
        hardcoded_output+="${matches}"$'\n'
    fi
done

if [[ "${hardcoded_found}" == "true" ]]; then
    record_result "No hardcoded credentials (regex patterns)" "fail" "Potential secrets found:\n${hardcoded_output}"
else
    record_result "No hardcoded credentials detected (regex patterns)" "pass"
fi

# --- 1e. Run gitleaks if available ---
if check_command gitleaks; then
    gitleaks_output=$(gitleaks detect --source="${PROJECT_ROOT}" --no-git --redact --verbose 2>&1) || gitleaks_rc=$?
    gitleaks_rc=${gitleaks_rc:-0}

    if [[ ${gitleaks_rc} -eq 0 ]]; then
        record_result "gitleaks: no secrets detected" "pass"
    else
        leak_count=$(echo "${gitleaks_output}" | grep -c "Secret:" 2>/dev/null || echo "unknown")
        record_result "gitleaks: ${leak_count} potential secrets detected" "fail" "${gitleaks_output}"
    fi
else
    record_result "gitleaks (enhanced secret detection)" "skip"
    echo -e "            ${YELLOW}Install: brew install gitleaks${NC}"
fi

# =============================================================================
# SECTION 2: Container Image Security
# =============================================================================
log_section "2. Container Image Security"

# --- 2a. Check that Helm values use specific image tags (not :latest) ---
latest_tags=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -E "(image|repository):\s*.*:latest" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v ".terraform\|node_modules\|.git\|#\|test" || true)

if [[ -n "${latest_tags}" ]]; then
    record_result "No :latest image tags" "warn" "Found :latest tags:\n${latest_tags}"
else
    record_result "No :latest image tags in configurations" "pass"
fi

# --- 2b. Check for images without any tag or digest ---
untagged_images=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -E "^\s*image:\s*[a-z][a-z0-9./-]+\s*$" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v ".terraform\|node_modules\|.git\|#\|test\|kind" || true)

if [[ -n "${untagged_images}" ]]; then
    record_result "No untagged container images" "warn" "Found untagged images:\n${untagged_images}"
else
    record_result "All container images have tags or digests" "pass"
fi

# --- 2c. Check for image pull policy ---
always_pull=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -E "imagePullPolicy:\s*(Always|IfNotPresent|Never)" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v ".terraform\|node_modules\|.git" || true)

if echo "${always_pull}" | grep -q "IfNotPresent\|Always" 2>/dev/null; then
    record_result "Image pull policy is configured" "pass"
else
    record_result "Image pull policy not explicitly set" "warn" "Consider setting imagePullPolicy explicitly"
fi

# =============================================================================
# SECTION 3: RBAC and Least Privilege
# =============================================================================
log_section "3. RBAC and Least Privilege"

# --- 3a. Check for cluster-admin bindings (excluding system) ---
cluster_admin_bindings=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -A5 "kind:\s*ClusterRoleBinding" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -B2 "name:\s*cluster-admin" \
    | grep -v "system:\|kube-system\|#\|.git\|test" || true)

# Filter out intentionally vulnerable configs (k8s-security directory)
safe_cluster_admin=$(echo "${cluster_admin_bindings}" | grep -v "k8s-security" || true)

if [[ -n "${safe_cluster_admin}" ]]; then
    record_result "No unnecessary cluster-admin bindings" "warn" "Found cluster-admin bindings outside k8s-security/:\n${safe_cluster_admin}"
else
    record_result "No unnecessary cluster-admin bindings (production configs)" "pass"
fi

# --- 3b. Check for wildcard permissions in RBAC ---
wildcard_rbac=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -E '^\s*-\s*"\*"' "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v "k8s-security\|.git\|node_modules\|test\|#" || true)

if [[ -n "${wildcard_rbac}" ]]; then
    record_result "No wildcard RBAC permissions" "warn" "Found wildcard permissions:\n${wildcard_rbac}"
else
    record_result "No wildcard RBAC permissions in production configs" "pass"
fi

# --- 3c. Check Terraform IAM for overprivileged roles ---
overprivileged_roles=$(grep -rn \
    --include="*.tf" \
    -E 'role\s*=\s*"roles/(owner|editor)"' "${PROJECT_ROOT}/terraform" 2>/dev/null \
    | grep -v "#\|test" || true)

if [[ -n "${overprivileged_roles}" ]]; then
    record_result "No overprivileged IAM roles (owner/editor)" "fail" "Found overprivileged roles:\n${overprivileged_roles}"
else
    record_result "No overprivileged IAM roles (no roles/owner or roles/editor)" "pass"
fi

# --- 3d. Check for SA key creation in Terraform ---
sa_key_creation=$(grep -rn \
    --include="*.tf" \
    "google_service_account_key" "${PROJECT_ROOT}/terraform" 2>/dev/null \
    | grep -v "#\|test" || true)

if [[ -n "${sa_key_creation}" ]]; then
    record_result "No SA key creation in Terraform" "fail" "Found SA key resources:\n${sa_key_creation}"
else
    record_result "No service account key creation in Terraform (using WIF)" "pass"
fi

# =============================================================================
# SECTION 4: Network Security
# =============================================================================
log_section "4. Network Security"

# --- 4a. Check for NetworkPolicy definitions ---
network_policies=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    "kind:\s*NetworkPolicy" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v ".git\|node_modules\|test" || true)

if [[ -n "${network_policies}" ]]; then
    policy_count=$(echo "${network_policies}" | wc -l | tr -d ' ')
    record_result "NetworkPolicy resources defined (${policy_count} found)" "pass"
else
    record_result "NetworkPolicy resources defined" "warn" "No NetworkPolicy manifests found. Consider adding network segmentation."
fi

# --- 4b. Check Terraform firewall rules for C2 port blocking ---
c2_firewall=$(grep -rn \
    --include="*.tf" \
    -E "(deny_c2|c2_blocked_ports|4444|8443)" "${PROJECT_ROOT}/terraform" 2>/dev/null \
    | grep -v "#" || true)

if [[ -n "${c2_firewall}" ]]; then
    record_result "C2 port blocking firewall rules present" "pass"
else
    record_result "C2 port blocking firewall rules" "warn" "No C2 port blocking found in Terraform firewall rules"
fi

# --- 4c. Check for crypto mining port blocking ---
crypto_firewall=$(grep -rn \
    --include="*.tf" \
    -E "(crypto_mining|3333|8545|30303)" "${PROJECT_ROOT}/terraform" 2>/dev/null \
    | grep -v "#" || true)

if [[ -n "${crypto_firewall}" ]]; then
    record_result "Crypto mining port blocking firewall rules present" "pass"
else
    record_result "Crypto mining port blocking firewall rules" "warn" "Consider blocking common crypto mining ports"
fi

# --- 4d. Check for private cluster configuration ---
private_cluster=$(grep -rn \
    --include="*.tf" \
    "enable_private_nodes\|enable_private_endpoint\|private_cluster_config" "${PROJECT_ROOT}/terraform" 2>/dev/null \
    | grep -v "#" || true)

if [[ -n "${private_cluster}" ]]; then
    record_result "GKE private cluster configuration present" "pass"
else
    record_result "GKE private cluster configuration" "warn" "Consider enabling private cluster for GKE"
fi

# =============================================================================
# SECTION 5: Pod Security Standards
# =============================================================================
log_section "5. Pod Security Standards"

# --- 5a. Check for runAsNonRoot ---
run_as_nonroot=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    "runAsNonRoot:\s*true" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v "k8s-security\|.git\|node_modules" || true)

if [[ -n "${run_as_nonroot}" ]]; then
    count=$(echo "${run_as_nonroot}" | wc -l | tr -d ' ')
    record_result "runAsNonRoot: true configured (${count} occurrences)" "pass"
else
    record_result "runAsNonRoot configuration" "warn" "No runAsNonRoot: true found. Containers may run as root."
fi

# --- 5b. Check for readOnlyRootFilesystem ---
readonly_fs=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    "readOnlyRootFilesystem:\s*true" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v "k8s-security\|.git\|node_modules" || true)

if [[ -n "${readonly_fs}" ]]; then
    record_result "readOnlyRootFilesystem: true configured" "pass"
else
    record_result "readOnlyRootFilesystem configuration" "warn" "Consider setting readOnlyRootFilesystem: true"
fi

# --- 5c. Check for allowPrivilegeEscalation ---
no_priv_esc=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    "allowPrivilegeEscalation:\s*false" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v "k8s-security\|.git\|node_modules" || true)

if [[ -n "${no_priv_esc}" ]]; then
    record_result "allowPrivilegeEscalation: false configured" "pass"
else
    record_result "allowPrivilegeEscalation configuration" "warn" "Consider setting allowPrivilegeEscalation: false"
fi

# --- 5d. Check for dropped capabilities ---
drop_all=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    -A1 "drop:" "${PROJECT_ROOT}" 2>/dev/null \
    | grep "ALL" \
    | grep -v "k8s-security\|.git\|node_modules" || true)

if [[ -n "${drop_all}" ]]; then
    record_result "Capabilities drop ALL configured" "pass"
else
    record_result "Capabilities drop ALL" "warn" "Consider dropping all capabilities and adding only needed ones"
fi

# --- 5e. Check for seccomp profile ---
seccomp=$(grep -rn \
    --include="*.yaml" \
    --include="*.yml" \
    "seccompProfile" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v "k8s-security\|.git\|node_modules" || true)

if [[ -n "${seccomp}" ]]; then
    record_result "Seccomp profile configured" "pass"
else
    record_result "Seccomp profile configuration" "warn" "Consider adding seccomp profiles (RuntimeDefault)"
fi

# =============================================================================
# SECTION 6: GitHub Actions Workflow Security
# =============================================================================
log_section "6. GitHub Actions Workflow Security"

WORKFLOW_DIR="${PROJECT_ROOT}/github-actions"

# --- 6a. Check for pull_request_target (dangerous trigger) ---
prt_usage=$(grep -rn \
    --include="*.yml" \
    --include="*.yaml" \
    "pull_request_target" "${WORKFLOW_DIR}" 2>/dev/null \
    | grep -v "#.*pull_request_target\|VULNERABLE\|vulnerable\|WARNING\|test" || true)

# Note: In our project, the vulnerable workflow is intentionally insecure for demo
prt_in_secure=$(grep -rn \
    --include="*.yml" \
    --include="*.yaml" \
    "pull_request_target" "${WORKFLOW_DIR}/secure-workflow" 2>/dev/null || true)

if [[ -n "${prt_in_secure}" ]]; then
    record_result "No pull_request_target in secure workflows" "fail" "Found in secure workflows:\n${prt_in_secure}"
else
    record_result "No pull_request_target in secure workflows" "pass"
fi

# --- 6b. Check for pinned action versions ---
unpinned_actions=$(grep -rn \
    --include="*.yml" \
    --include="*.yaml" \
    -E "uses:\s+[^#]+@(main|master|latest|v[0-9]+)\s*$" "${WORKFLOW_DIR}/secure-workflow" 2>/dev/null || true)

if [[ -n "${unpinned_actions}" ]]; then
    record_result "All actions use pinned versions (SHA)" "warn" "Found unpinned actions:\n${unpinned_actions}"
else
    record_result "Action version pinning check (secure workflows)" "pass"
fi

# --- 6c. Check for excessive permissions ---
write_all_perms=$(grep -rn \
    --include="*.yml" \
    --include="*.yaml" \
    -E "permissions:\s*write-all" "${WORKFLOW_DIR}/secure-workflow" 2>/dev/null || true)

if [[ -n "${write_all_perms}" ]]; then
    record_result "No write-all permissions in secure workflows" "fail" "Found write-all:\n${write_all_perms}"
else
    record_result "No write-all permissions in secure workflows" "pass"
fi

# =============================================================================
# SECTION 7: Terraform Security Configurations
# =============================================================================
log_section "7. Terraform Security Configurations"

TF_DIR="${PROJECT_ROOT}/terraform"

# --- 7a. Workload Identity Federation configured ---
wif_config=$(grep -rn \
    --include="*.tf" \
    "workload_identity_pool\|iam_workload_identity" "${TF_DIR}" 2>/dev/null || true)

if [[ -n "${wif_config}" ]]; then
    record_result "Workload Identity Federation configured" "pass"
else
    record_result "Workload Identity Federation" "warn" "Consider using WIF instead of SA keys"
fi

# --- 7b. Binary Authorization configured ---
binary_auth=$(grep -rn \
    --include="*.tf" \
    "binary_authorization\|enable_binary_authorization" "${TF_DIR}" 2>/dev/null || true)

if [[ -n "${binary_auth}" ]]; then
    record_result "Binary Authorization configured for GKE" "pass"
else
    record_result "Binary Authorization for GKE" "warn" "Consider enabling Binary Authorization"
fi

# --- 7c. Shielded nodes configured ---
shielded=$(grep -rn \
    --include="*.tf" \
    "enable_shielded_nodes\|shielded_instance_config" "${TF_DIR}" 2>/dev/null || true)

if [[ -n "${shielded}" ]]; then
    record_result "Shielded GKE nodes configured" "pass"
else
    record_result "Shielded GKE nodes" "warn" "Consider enabling Shielded Nodes for GKE"
fi

# --- 7d. Audit logging configured ---
audit_logging=$(grep -rn \
    --include="*.tf" \
    "logging_service\|logging_config\|log_config" "${TF_DIR}" 2>/dev/null || true)

if [[ -n "${audit_logging}" ]]; then
    record_result "Audit logging configured" "pass"
else
    record_result "Audit logging configuration" "warn" "Ensure GKE audit logging is enabled"
fi

# --- 7e. Terraform state encryption ---
state_encryption=$(grep -rn \
    --include="*.tf" \
    -E "(encryption_key|encrypt\s*=\s*true)" "${TF_DIR}" 2>/dev/null || true)

# GCS backend has encryption at rest by default
gcs_backend=$(grep -rn \
    --include="*.tf" \
    'backend "gcs"' "${TF_DIR}" 2>/dev/null || true)

if [[ -n "${state_encryption}" || -n "${gcs_backend}" ]]; then
    record_result "Terraform state encryption (GCS provides encryption at rest)" "pass"
else
    record_result "Terraform state encryption" "warn" "Ensure Terraform state is encrypted"
fi

# --- 7f. Check for sensitive outputs marked as sensitive ---
sensitive_outputs=$(grep -rn \
    --include="*.tf" \
    -B2 "sensitive\s*=\s*true" "${TF_DIR}" 2>/dev/null || true)

potential_sensitive=$(grep -rn \
    --include="*.tf" \
    -E 'output\s+".*?(password|secret|key|token|certificate|endpoint)' "${TF_DIR}" 2>/dev/null || true)

unmarked_sensitive=""
while IFS= read -r line; do
    output_name=$(echo "${line}" | grep -oE '"[^"]*"' | head -1 | tr -d '"')
    if [[ -n "${output_name}" ]]; then
        is_marked=$(grep -A5 "output \"${output_name}\"" "${line%%:*}" 2>/dev/null | grep -c "sensitive\s*=\s*true" || true)
        if [[ "${is_marked}" -eq 0 ]]; then
            unmarked_sensitive+="${line}\n"
        fi
    fi
done <<< "${potential_sensitive}"

if [[ -z "${unmarked_sensitive}" ]]; then
    record_result "Sensitive outputs marked as sensitive" "pass"
else
    record_result "Sensitive outputs marked as sensitive" "warn" "Potentially sensitive outputs not marked:\n${unmarked_sensitive}"
fi

# =============================================================================
# SECTION 8: General Best Practices
# =============================================================================
log_section "8. General Best Practices"

# --- 8a. .gitignore exists and covers sensitive patterns ---
GITIGNORE="${PROJECT_ROOT}/.gitignore"
if [[ -f "${GITIGNORE}" ]]; then
    missing_patterns=()
    for pattern in "*.tfstate" "*.tfstate.*" ".terraform" "*.pem" "*.key" ".env" "*.p12"; do
        if ! grep -q "${pattern}" "${GITIGNORE}" 2>/dev/null; then
            missing_patterns+=("${pattern}")
        fi
    done

    if [[ ${#missing_patterns[@]} -eq 0 ]]; then
        record_result ".gitignore covers sensitive patterns" "pass"
    else
        record_result ".gitignore missing patterns" "warn" "Missing: ${missing_patterns[*]}"
    fi
else
    record_result ".gitignore file exists" "warn" "No .gitignore found - sensitive files may be committed"
fi

# --- 8b. No TODO/FIXME security items ---
security_todos=$(grep -rn \
    --include="*.tf" \
    --include="*.yaml" \
    --include="*.yml" \
    --include="*.py" \
    --include="*.sh" \
    -iE "(TODO|FIXME|HACK|XXX).*(secur|auth|cred|secret|password|vuln|encrypt)" "${PROJECT_ROOT}" 2>/dev/null \
    | grep -v ".git\|node_modules\|test\|security-audit" || true)

if [[ -n "${security_todos}" ]]; then
    todo_count=$(echo "${security_todos}" | wc -l | tr -d ' ')
    record_result "No security-related TODOs/FIXMEs (${todo_count} found)" "warn" "${security_todos}"
else
    record_result "No security-related TODOs/FIXMEs" "pass"
fi

# --- 8c. Scripts have proper error handling ---
scripts_without_set_e=$(find "${PROJECT_ROOT}/scripts" -name "*.sh" -exec grep -L "set -e" {} \; 2>/dev/null || true)

if [[ -n "${scripts_without_set_e}" ]]; then
    record_result "All shell scripts use 'set -e'" "warn" "Missing set -e:\n${scripts_without_set_e}"
else
    record_result "All shell scripts use 'set -e' for error handling" "pass"
fi

# =============================================================================
# Summary
# =============================================================================
log_section "Security Audit Summary"

echo -e "  ${GREEN}Passed:${NC}   ${PASSED_CHECKS}"
echo -e "  ${RED}Failed:${NC}   ${FAILED_CHECKS}"
echo -e "  ${YELLOW}Warnings:${NC} ${WARNING_CHECKS}"
echo -e "  ${YELLOW}Skipped:${NC}  ${SKIPPED_CHECKS}"
echo -e "  ${BOLD}Total:${NC}    ${TOTAL_CHECKS}"
echo ""

if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
    write_junit_xml
fi

# Calculate risk score
risk_score=$((FAILED_CHECKS * 10 + WARNING_CHECKS * 3))
echo -e "  ${BOLD}Risk Score:${NC} ${risk_score} (lower is better)"
echo ""

if [[ ${risk_score} -gt 50 ]]; then
    echo -e "  ${RED}${BOLD}Risk Level: HIGH${NC}"
elif [[ ${risk_score} -gt 20 ]]; then
    echo -e "  ${YELLOW}${BOLD}Risk Level: MEDIUM${NC}"
else
    echo -e "  ${GREEN}${BOLD}Risk Level: LOW${NC}"
fi
echo ""

if [[ ${FAILED_CHECKS} -gt 0 ]]; then
    echo -e "${RED}${BOLD}Security audit FAILED with ${FAILED_CHECKS} critical finding(s).${NC}"
    exit 1
else
    if [[ ${WARNING_CHECKS} -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}Security audit PASSED with ${WARNING_CHECKS} warning(s).${NC}"
    else
        echo -e "${GREEN}${BOLD}Security audit PASSED with no findings.${NC}"
    fi
    exit 0
fi
