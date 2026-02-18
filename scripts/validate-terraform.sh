#!/usr/bin/env bash
# =============================================================================
# Terraform Validation Script
# =============================================================================
#
# Runs comprehensive validation and security scanning on all Terraform code:
#   1. terraform fmt -check   (formatting consistency)
#   2. terraform validate     (syntax and reference validation per module)
#   3. tflint                 (linting with GCP ruleset)
#   4. tfsec / checkov        (security scanning for misconfigurations)
#   5. terrascan              (compliance scanning against CIS/NIST)
#
# Results are optionally exported in JUnit XML format for CI integration.
#
# PREREQUISITES:
#   - terraform >= 1.5.0
#   - tflint (with google plugin)
#   - tfsec or trivy (for security scanning)
#   - checkov (pip install checkov)
#   - terrascan (https://github.com/tenable/terrascan)
#
# USAGE:
#   ./validate-terraform.sh              # Run all checks
#   ./validate-terraform.sh --junit      # Output JUnit XML to reports/
#   ./validate-terraform.sh --fix        # Auto-fix formatting issues
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_ROOT="${PROJECT_ROOT}/terraform"
REPORTS_DIR="${PROJECT_ROOT}/reports"
JUNIT_OUTPUT=false
AUTO_FIX=false

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
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
log_info()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_skip()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
log_section() {
    echo ""
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}  $*${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo ""
}

check_command() {
    if command -v "$1" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

record_result() {
    local name="$1"
    local status="$2"  # pass, fail, skip
    local duration="${3:-0}"
    local message="${4:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "${status}" in
        pass)
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            log_info "${name}"
            ;;
        fail)
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            log_fail "${name}"
            if [[ -n "${message}" ]]; then
                echo -e "        ${message}" | head -20
            fi
            ;;
        skip)
            SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1))
            log_skip "${name} (tool not installed)"
            ;;
    esac

    if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
        local escaped_name
        escaped_name=$(echo "${name}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        local escaped_message
        escaped_message=$(echo "${message}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g' | head -50)

        case "${status}" in
            pass)
                JUNIT_RESULTS+="    <testcase classname=\"terraform\" name=\"${escaped_name}\" time=\"${duration}\"/>"$'\n'
                ;;
            fail)
                JUNIT_RESULTS+="    <testcase classname=\"terraform\" name=\"${escaped_name}\" time=\"${duration}\">"$'\n'
                JUNIT_RESULTS+="      <failure message=\"Check failed\">${escaped_message}</failure>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
            skip)
                JUNIT_RESULTS+="    <testcase classname=\"terraform\" name=\"${escaped_name}\" time=\"${duration}\">"$'\n'
                JUNIT_RESULTS+="      <skipped message=\"Tool not installed\"/>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
        esac
    fi
}

write_junit_xml() {
    mkdir -p "${REPORTS_DIR}"
    local output_file="${REPORTS_DIR}/terraform-validation.xml"

    cat > "${output_file}" <<XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="terraform-validation" tests="${TOTAL_CHECKS}" failures="${FAILED_CHECKS}" skipped="${SKIPPED_CHECKS}" time="0">
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
        --junit)   JUNIT_OUTPUT=true ;;
        --fix)     AUTO_FIX=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --junit    Output results in JUnit XML format to reports/"
            echo "  --fix      Auto-fix formatting issues (terraform fmt)"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Verify Terraform directory exists
# ---------------------------------------------------------------------------
if [[ ! -d "${TF_ROOT}" ]]; then
    echo -e "${RED}ERROR: Terraform directory not found: ${TF_ROOT}${NC}"
    exit 1
fi

echo -e "${BOLD}DevSecOps Project - Terraform Validation${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo -e "Terraform root: ${TF_ROOT}"
echo ""

# =============================================================================
# CHECK 1: Terraform Format
# =============================================================================
log_section "1. Terraform Format Check (terraform fmt)"

if check_command terraform; then
    start_time=$SECONDS

    if [[ "${AUTO_FIX}" == "true" ]]; then
        echo "Running terraform fmt (auto-fix mode)..."
        fmt_output=$(terraform -chdir="${TF_ROOT}" fmt -recursive 2>&1) || true
        if [[ -n "${fmt_output}" ]]; then
            record_result "terraform fmt (auto-fixed)" "pass" "$((SECONDS - start_time))"
            echo "  Fixed files:"
            echo "${fmt_output}" | while read -r line; do echo "    - ${line}"; done
        else
            record_result "terraform fmt (no changes needed)" "pass" "$((SECONDS - start_time))"
        fi
    else
        fmt_output=$(terraform -chdir="${TF_ROOT}" fmt -check -recursive -diff 2>&1) || fmt_rc=$?
        fmt_rc=${fmt_rc:-0}

        if [[ ${fmt_rc} -eq 0 ]]; then
            record_result "terraform fmt -check (all files formatted correctly)" "pass" "$((SECONDS - start_time))"
        else
            record_result "terraform fmt -check (formatting issues found)" "fail" "$((SECONDS - start_time))" "${fmt_output}"
            echo -e "  ${YELLOW}Tip: Run with --fix to auto-format, or: terraform fmt -recursive${NC}"
        fi
    fi
else
    record_result "terraform fmt" "skip"
fi

# =============================================================================
# CHECK 2: Terraform Validate (per module)
# =============================================================================
log_section "2. Terraform Validate (per module)"

if check_command terraform; then
    # Find all directories that contain .tf files
    tf_dirs=()
    while IFS= read -r -d '' dir; do
        tf_dirs+=("${dir}")
    done < <(find "${TF_ROOT}" -name "*.tf" -exec dirname {} \; | sort -u | tr '\n' '\0')

    if [[ ${#tf_dirs[@]} -eq 0 ]]; then
        log_warn "No .tf files found in ${TF_ROOT}"
    else
        for tf_dir in "${tf_dirs[@]}"; do
            relative_dir="${tf_dir#${PROJECT_ROOT}/}"
            start_time=$SECONDS

            # terraform validate requires init first; use a temporary backend
            # to avoid needing real GCP credentials
            init_output=$(terraform -chdir="${tf_dir}" init -backend=false -input=false -no-color 2>&1) || init_rc=$?
            init_rc=${init_rc:-0}

            if [[ ${init_rc} -ne 0 ]]; then
                record_result "terraform validate: ${relative_dir} (init failed)" "fail" "$((SECONDS - start_time))" "${init_output}"
                continue
            fi

            validate_output=$(terraform -chdir="${tf_dir}" validate -no-color 2>&1) || validate_rc=$?
            validate_rc=${validate_rc:-0}

            if [[ ${validate_rc} -eq 0 ]]; then
                record_result "terraform validate: ${relative_dir}" "pass" "$((SECONDS - start_time))"
            else
                record_result "terraform validate: ${relative_dir}" "fail" "$((SECONDS - start_time))" "${validate_output}"
            fi

            # Clean up .terraform directory to avoid polluting the repo
            rm -rf "${tf_dir}/.terraform" "${tf_dir}/.terraform.lock.hcl" 2>/dev/null || true
        done
    fi
else
    record_result "terraform validate" "skip"
fi

# =============================================================================
# CHECK 3: TFLint with GCP Ruleset
# =============================================================================
log_section "3. TFLint (with GCP ruleset)"

if check_command tflint; then
    # Create a temporary tflint config if one does not exist
    TFLINT_CONFIG="${TF_ROOT}/.tflint.hcl"
    TFLINT_CONFIG_CREATED=false

    if [[ ! -f "${TFLINT_CONFIG}" ]]; then
        TFLINT_CONFIG_CREATED=true
        cat > "${TFLINT_CONFIG}" <<'TFLINTEOF'
plugin "google" {
  enabled = true
  version = "0.27.1"
  source  = "github.com/terraform-linters/tflint-ruleset-google"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

config {
  call_module_type = "local"
}
TFLINTEOF
        echo "Created temporary .tflint.hcl with GCP ruleset."
    fi

    # Initialize tflint plugins
    echo "Initializing tflint plugins..."
    tflint_init_output=$(tflint --init --config="${TFLINT_CONFIG}" --chdir="${TF_ROOT}" 2>&1) || true

    # Run tflint on the root module
    start_time=$SECONDS
    tflint_output=$(tflint --config="${TFLINT_CONFIG}" --chdir="${TF_ROOT}" --format=compact --no-color 2>&1) || tflint_rc=$?
    tflint_rc=${tflint_rc:-0}

    if [[ ${tflint_rc} -eq 0 ]]; then
        record_result "tflint: terraform/ (root module)" "pass" "$((SECONDS - start_time))"
    else
        record_result "tflint: terraform/ (root module)" "fail" "$((SECONDS - start_time))" "${tflint_output}"
    fi

    # Run tflint on each submodule
    if [[ -d "${TF_ROOT}/modules" ]]; then
        for module_dir in "${TF_ROOT}/modules"/*/; do
            if [[ -d "${module_dir}" ]]; then
                module_name=$(basename "${module_dir}")
                start_time=$SECONDS

                module_output=$(tflint --config="${TFLINT_CONFIG}" --chdir="${module_dir}" --format=compact --no-color 2>&1) || module_rc=$?
                module_rc=${module_rc:-0}

                if [[ ${module_rc} -eq 0 ]]; then
                    record_result "tflint: modules/${module_name}" "pass" "$((SECONDS - start_time))"
                else
                    record_result "tflint: modules/${module_name}" "fail" "$((SECONDS - start_time))" "${module_output}"
                fi
            fi
        done
    fi

    # Clean up temporary config
    if [[ "${TFLINT_CONFIG_CREATED}" == "true" ]]; then
        rm -f "${TFLINT_CONFIG}"
    fi
else
    record_result "tflint" "skip"
    echo -e "  ${YELLOW}Install: brew install tflint${NC}"
fi

# =============================================================================
# CHECK 4: Security Scanning (tfsec / trivy config)
# =============================================================================
log_section "4. Security Scanning (tfsec / trivy)"

SECURITY_SCANNER_RAN=false

# Try tfsec first
if check_command tfsec; then
    SECURITY_SCANNER_RAN=true
    start_time=$SECONDS

    tfsec_output=$(tfsec "${TF_ROOT}" --no-color --format=text --soft-fail 2>&1) || tfsec_rc=$?
    tfsec_rc=${tfsec_rc:-0}

    # tfsec returns 1 when findings exist (with --soft-fail it returns 0)
    # Count findings
    critical_count=$(echo "${tfsec_output}" | grep -c "CRITICAL" 2>/dev/null || echo "0")
    high_count=$(echo "${tfsec_output}" | grep -c "HIGH" 2>/dev/null || echo "0")
    medium_count=$(echo "${tfsec_output}" | grep -c "MEDIUM" 2>/dev/null || echo "0")
    low_count=$(echo "${tfsec_output}" | grep -c "LOW" 2>/dev/null || echo "0")

    total_findings=$((critical_count + high_count))

    if [[ ${total_findings} -gt 0 ]]; then
        record_result "tfsec: ${critical_count} critical, ${high_count} high, ${medium_count} medium, ${low_count} low" "fail" "$((SECONDS - start_time))" "${tfsec_output}"
    else
        record_result "tfsec: no critical/high findings" "pass" "$((SECONDS - start_time))"
    fi

    # Generate JUnit if requested
    if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
        mkdir -p "${REPORTS_DIR}"
        tfsec "${TF_ROOT}" --format=junit --soft-fail > "${REPORTS_DIR}/tfsec-results.xml" 2>/dev/null || true
        echo -e "  ${CYAN}tfsec JUnit report: ${REPORTS_DIR}/tfsec-results.xml${NC}"
    fi
fi

# Try trivy config scan as an alternative / supplement
if check_command trivy; then
    SECURITY_SCANNER_RAN=true
    start_time=$SECONDS

    trivy_output=$(trivy config "${TF_ROOT}" --severity HIGH,CRITICAL --exit-code 0 --format table 2>&1) || trivy_rc=$?
    trivy_rc=${trivy_rc:-0}

    trivy_findings=$(echo "${trivy_output}" | grep -cE "(HIGH|CRITICAL)" 2>/dev/null || echo "0")

    if [[ ${trivy_findings} -gt 0 ]]; then
        record_result "trivy config scan: ${trivy_findings} high/critical findings" "fail" "$((SECONDS - start_time))" "${trivy_output}"
    else
        record_result "trivy config scan: no high/critical findings" "pass" "$((SECONDS - start_time))"
    fi
fi

if [[ "${SECURITY_SCANNER_RAN}" == "false" ]]; then
    record_result "tfsec / trivy config scan" "skip"
    echo -e "  ${YELLOW}Install tfsec: brew install tfsec${NC}"
    echo -e "  ${YELLOW}Install trivy: brew install trivy${NC}"
fi

# =============================================================================
# CHECK 5: Checkov (Policy-as-Code)
# =============================================================================
log_section "5. Checkov (Policy-as-Code Scanning)"

if check_command checkov; then
    start_time=$SECONDS

    checkov_output=$(checkov -d "${TF_ROOT}" --framework terraform --quiet --compact --no-guide --soft-fail 2>&1) || checkov_rc=$?
    checkov_rc=${checkov_rc:-0}

    # Parse checkov summary
    passed_line=$(echo "${checkov_output}" | grep "Passed checks:" | tail -1)
    failed_line=$(echo "${checkov_output}" | grep "Failed checks:" | tail -1)

    if [[ -n "${failed_line}" ]]; then
        failed_num=$(echo "${failed_line}" | grep -oE '[0-9]+' | head -1)
        if [[ "${failed_num}" -gt 0 ]]; then
            record_result "checkov: ${passed_line}, ${failed_line}" "fail" "$((SECONDS - start_time))" "${checkov_output}"
        else
            record_result "checkov: ${passed_line}, ${failed_line}" "pass" "$((SECONDS - start_time))"
        fi
    else
        record_result "checkov: completed" "pass" "$((SECONDS - start_time))"
    fi

    # Generate JUnit if requested
    if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
        mkdir -p "${REPORTS_DIR}"
        checkov -d "${TF_ROOT}" --framework terraform --output junitxml --soft-fail > "${REPORTS_DIR}/checkov-results.xml" 2>/dev/null || true
        echo -e "  ${CYAN}Checkov JUnit report: ${REPORTS_DIR}/checkov-results.xml${NC}"
    fi
else
    record_result "checkov" "skip"
    echo -e "  ${YELLOW}Install: pip install checkov${NC}"
fi

# =============================================================================
# CHECK 6: Terrascan (Compliance Scanning)
# =============================================================================
log_section "6. Terrascan (Compliance Scanning)"

if check_command terrascan; then
    start_time=$SECONDS

    terrascan_output=$(terrascan scan -i terraform -d "${TF_ROOT}" --severity high --non-recursive=false --verbose 2>&1) || terrascan_rc=$?
    terrascan_rc=${terrascan_rc:-0}

    violation_count=$(echo "${terrascan_output}" | grep -c "Violation" 2>/dev/null || echo "0")

    if [[ ${violation_count} -gt 0 ]]; then
        record_result "terrascan: ${violation_count} violations found" "fail" "$((SECONDS - start_time))" "${terrascan_output}"
    else
        record_result "terrascan: no violations" "pass" "$((SECONDS - start_time))"
    fi

    # Generate JUnit if requested
    if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
        mkdir -p "${REPORTS_DIR}"
        terrascan scan -i terraform -d "${TF_ROOT}" --output junit-xml > "${REPORTS_DIR}/terrascan-results.xml" 2>/dev/null || true
        echo -e "  ${CYAN}Terrascan JUnit report: ${REPORTS_DIR}/terrascan-results.xml${NC}"
    fi
else
    record_result "terrascan" "skip"
    echo -e "  ${YELLOW}Install: brew install terrascan${NC}"
fi

# =============================================================================
# CHECK 7: Additional Static Analysis
# =============================================================================
log_section "7. Additional Checks"

# Check for sensitive values in .tf files
start_time=$SECONDS
sensitive_patterns=(
    'password\s*=\s*"[^"]*[^$]"'
    'secret\s*=\s*"[^"]*[^$]"'
    'api_key\s*=\s*"[^"]*[^$]"'
    'access_key\s*=\s*"[^"]*[^$]"'
    'private_key\s*=\s*"[^"]*[^$]"'
    'token\s*=\s*"[^"]*[^$]"'
)

hardcoded_secrets_found=false
secrets_output=""

for pattern in "${sensitive_patterns[@]}"; do
    matches=$(grep -rn --include="*.tf" -iE "${pattern}" "${TF_ROOT}" 2>/dev/null | grep -v "variable\|description\|#\|default\s*=\s*\"\"" || true)
    if [[ -n "${matches}" ]]; then
        hardcoded_secrets_found=true
        secrets_output+="${matches}"$'\n'
    fi
done

if [[ "${hardcoded_secrets_found}" == "true" ]]; then
    record_result "Hardcoded secrets check" "fail" "$((SECONDS - start_time))" "${secrets_output}"
else
    record_result "Hardcoded secrets check (no secrets found in .tf files)" "pass" "$((SECONDS - start_time))"
fi

# Check for missing variable descriptions
start_time=$SECONDS
vars_without_desc=$(grep -rn "^variable " "${TF_ROOT}" --include="*.tf" | while read -r line; do
    file=$(echo "${line}" | cut -d: -f1)
    lineno=$(echo "${line}" | cut -d: -f2)
    # Check if the next 5 lines contain a description
    has_desc=$(sed -n "$((lineno+1)),$((lineno+5))p" "${file}" | grep -c "description" || true)
    if [[ "${has_desc}" -eq 0 ]]; then
        echo "${line}"
    fi
done) || true

if [[ -n "${vars_without_desc}" ]]; then
    record_result "Variable descriptions check" "fail" "$((SECONDS - start_time))" "Variables missing descriptions:\n${vars_without_desc}"
else
    record_result "Variable descriptions check (all variables have descriptions)" "pass" "$((SECONDS - start_time))"
fi

# Check for missing output descriptions
start_time=$SECONDS
outputs_without_desc=$(grep -rn "^output " "${TF_ROOT}" --include="*.tf" | while read -r line; do
    file=$(echo "${line}" | cut -d: -f1)
    lineno=$(echo "${line}" | cut -d: -f2)
    has_desc=$(sed -n "$((lineno+1)),$((lineno+5))p" "${file}" | grep -c "description" || true)
    if [[ "${has_desc}" -eq 0 ]]; then
        echo "${line}"
    fi
done) || true

if [[ -n "${outputs_without_desc}" ]]; then
    record_result "Output descriptions check" "fail" "$((SECONDS - start_time))" "Outputs missing descriptions:\n${outputs_without_desc}"
else
    record_result "Output descriptions check (all outputs have descriptions)" "pass" "$((SECONDS - start_time))"
fi

# =============================================================================
# Summary
# =============================================================================
log_section "Validation Summary"

echo -e "  ${GREEN}Passed:${NC}  ${PASSED_CHECKS}"
echo -e "  ${RED}Failed:${NC}  ${FAILED_CHECKS}"
echo -e "  ${YELLOW}Skipped:${NC} ${SKIPPED_CHECKS}"
echo -e "  ${BOLD}Total:${NC}   ${TOTAL_CHECKS}"
echo ""

if [[ "${JUNIT_OUTPUT}" == "true" ]]; then
    write_junit_xml
fi

if [[ ${FAILED_CHECKS} -gt 0 ]]; then
    echo -e "${RED}${BOLD}Terraform validation FAILED with ${FAILED_CHECKS} failure(s).${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}Terraform validation PASSED.${NC}"
    exit 0
fi
