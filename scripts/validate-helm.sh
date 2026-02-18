#!/usr/bin/env bash
# =============================================================================
# Helm Chart Validation Script
# =============================================================================
#
# Runs comprehensive validation on all Helm charts and Kubernetes manifests:
#   1. helm lint         (chart linting for structural issues)
#   2. helm template     (render templates to verify they produce valid YAML)
#   3. kubeconform       (validate rendered manifests against K8s schemas)
#   4. kube-score        (check manifests for best practices)
#   5. Falco rules       (validate Falco rules YAML syntax)
#   6. Suricata rules    (validate Suricata IDS rule syntax)
#   7. YAML lint         (validate all YAML files for syntax)
#
# PREREQUISITES:
#   - helm >= 3.0
#   - kubeconform (https://github.com/yannh/kubeconform)
#   - kube-score (https://github.com/zegl/kube-score)
#   - yamllint (pip install yamllint)
#   - python3 (for Suricata rule checking)
#
# USAGE:
#   ./validate-helm.sh              # Run all checks
#   ./validate-helm.sh --junit      # Output JUnit XML to reports/
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELM_ROOT="${PROJECT_ROOT}/helm"
K8S_SECURITY_ROOT="${PROJECT_ROOT}/k8s-security"
REPORTS_DIR="${PROJECT_ROOT}/reports"
RENDERED_DIR="${PROJECT_ROOT}/.rendered-manifests"
JUNIT_OUTPUT=false

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
    command -v "$1" &>/dev/null
}

record_result() {
    local name="$1"
    local status="$2"
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
                echo -e "        ${message}" | head -30
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
                JUNIT_RESULTS+="    <testcase classname=\"helm\" name=\"${escaped_name}\" time=\"${duration}\"/>"$'\n'
                ;;
            fail)
                JUNIT_RESULTS+="    <testcase classname=\"helm\" name=\"${escaped_name}\" time=\"${duration}\">"$'\n'
                JUNIT_RESULTS+="      <failure message=\"Check failed\">${escaped_message}</failure>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
            skip)
                JUNIT_RESULTS+="    <testcase classname=\"helm\" name=\"${escaped_name}\" time=\"${duration}\">"$'\n'
                JUNIT_RESULTS+="      <skipped message=\"Tool not installed or chart not found\"/>"$'\n'
                JUNIT_RESULTS+="    </testcase>"$'\n'
                ;;
        esac
    fi
}

write_junit_xml() {
    mkdir -p "${REPORTS_DIR}"
    local output_file="${REPORTS_DIR}/helm-validation.xml"

    cat > "${output_file}" <<XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="helm-validation" tests="${TOTAL_CHECKS}" failures="${FAILED_CHECKS}" skipped="${SKIPPED_CHECKS}" time="0">
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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --junit    Output results in JUnit XML format to reports/"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}"
            exit 1
            ;;
    esac
done

echo -e "${BOLD}DevSecOps Project - Helm & Kubernetes Manifest Validation${NC}"
echo -e "Project root: ${PROJECT_ROOT}"
echo ""

# Create temp directory for rendered manifests
mkdir -p "${RENDERED_DIR}"
trap 'rm -rf "${RENDERED_DIR}"' EXIT

# =============================================================================
# CHECK 1: YAML Lint - All YAML files
# =============================================================================
log_section "1. YAML Lint (all YAML files)"

if check_command yamllint; then
    # Create a yamllint config that tolerates common Helm patterns
    YAMLLINT_CONFIG=$(mktemp)
    cat > "${YAMLLINT_CONFIG}" <<'YAMLLINTEOF'
---
extends: default
rules:
  line-length:
    max: 200
    allow-non-breakable-words: true
    allow-non-breakable-inline-mappings: true
  truthy:
    allowed-values: ['true', 'false', 'yes', 'no']
  comments:
    require-starting-space: true
    min-spaces-from-content: 1
  document-start: disable
  indentation:
    spaces: 2
    indent-sequences: whatever
  empty-lines:
    max: 2
YAMLLINTEOF

    yaml_files_checked=0
    yaml_files_failed=0

    while IFS= read -r yaml_file; do
        relative_path="${yaml_file#${PROJECT_ROOT}/}"
        start_time=$SECONDS

        lint_output=$(yamllint -c "${YAMLLINT_CONFIG}" "${yaml_file}" 2>&1) || lint_rc=$?
        lint_rc=${lint_rc:-0}

        yaml_files_checked=$((yaml_files_checked + 1))

        if [[ ${lint_rc} -ne 0 ]]; then
            yaml_files_failed=$((yaml_files_failed + 1))
            record_result "yamllint: ${relative_path}" "fail" "$((SECONDS - start_time))" "${lint_output}"
        fi
    done < <(find "${PROJECT_ROOT}" -name "*.yaml" -o -name "*.yml" | grep -v ".terraform" | grep -v "node_modules" | grep -v ".rendered-manifests" | sort)

    passed_yaml=$((yaml_files_checked - yaml_files_failed))
    if [[ ${yaml_files_failed} -eq 0 ]]; then
        record_result "yamllint: all ${yaml_files_checked} YAML files pass" "pass"
    else
        echo -e "  ${YELLOW}${passed_yaml}/${yaml_files_checked} files passed, ${yaml_files_failed} failed${NC}"
    fi

    rm -f "${YAMLLINT_CONFIG}"
else
    record_result "yamllint" "skip"
    echo -e "  ${YELLOW}Install: pip install yamllint${NC}"
fi

# =============================================================================
# CHECK 2: Helm Lint
# =============================================================================
log_section "2. Helm Lint"

if check_command helm; then
    # Find all Helm charts (directories containing Chart.yaml)
    helm_charts=()
    while IFS= read -r chart_yaml; do
        helm_charts+=("$(dirname "${chart_yaml}")")
    done < <(find "${HELM_ROOT}" -name "Chart.yaml" -type f 2>/dev/null || true)

    # Also check for values.yaml files without Chart.yaml (kustomize overlays, etc.)
    values_only=()
    while IFS= read -r values_file; do
        chart_dir=$(dirname "${values_file}")
        if [[ ! -f "${chart_dir}/Chart.yaml" ]]; then
            values_only+=("${chart_dir}")
        fi
    done < <(find "${HELM_ROOT}" -name "values.yaml" -type f 2>/dev/null || true)

    if [[ ${#helm_charts[@]} -gt 0 ]]; then
        for chart_dir in "${helm_charts[@]}"; do
            chart_name=$(basename "${chart_dir}")
            start_time=$SECONDS

            lint_output=$(helm lint "${chart_dir}" --strict 2>&1) || lint_rc=$?
            lint_rc=${lint_rc:-0}

            if [[ ${lint_rc} -eq 0 ]]; then
                record_result "helm lint: ${chart_name}" "pass" "$((SECONDS - start_time))"
            else
                record_result "helm lint: ${chart_name}" "fail" "$((SECONDS - start_time))" "${lint_output}"
            fi
        done
    else
        echo "  No Helm charts with Chart.yaml found in ${HELM_ROOT}."
        echo "  Checking values files for remote charts..."
    fi

    # Validate values.yaml files that belong to remote charts (e.g., trivy-operator)
    for values_dir in "${values_only[@]}"; do
        values_name=$(basename "${values_dir}")
        start_time=$SECONDS

        # Validate values.yaml is valid YAML
        if python3 -c "import yaml; yaml.safe_load(open('${values_dir}/values.yaml'))" 2>/dev/null; then
            record_result "values.yaml syntax: ${values_name}" "pass" "$((SECONDS - start_time))"
        else
            yaml_err=$(python3 -c "import yaml; yaml.safe_load(open('${values_dir}/values.yaml'))" 2>&1 || true)
            record_result "values.yaml syntax: ${values_name}" "fail" "$((SECONDS - start_time))" "${yaml_err}"
        fi
    done
else
    record_result "helm lint" "skip"
    echo -e "  ${YELLOW}Install: brew install helm${NC}"
fi

# =============================================================================
# CHECK 3: Helm Template Rendering
# =============================================================================
log_section "3. Helm Template Rendering"

if check_command helm; then
    # For charts that are remote (e.g., trivy-operator), we need the chart repo
    # We'll attempt to render what we can

    # Attempt to add common repos needed
    echo "Adding Helm repositories..."
    helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/ 2>/dev/null || true
    helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
    helm repo update 2>/dev/null || true

    # Render trivy-operator with local values
    TRIVY_VALUES="${HELM_ROOT}/trivy-operator/values.yaml"
    if [[ -f "${TRIVY_VALUES}" ]]; then
        start_time=$SECONDS
        render_output=$(helm template trivy-operator aquasecurity/trivy-operator \
            -n trivy-system \
            -f "${TRIVY_VALUES}" \
            --output-dir "${RENDERED_DIR}/trivy-operator" 2>&1) || render_rc=$?
        render_rc=${render_rc:-0}

        if [[ ${render_rc} -eq 0 ]]; then
            manifest_count=$(find "${RENDERED_DIR}/trivy-operator" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
            record_result "helm template: trivy-operator (${manifest_count} manifests rendered)" "pass" "$((SECONDS - start_time))"
        else
            record_result "helm template: trivy-operator" "fail" "$((SECONDS - start_time))" "${render_output}"
        fi
    fi

    # Render Falco if values exist
    FALCO_VALUES="${HELM_ROOT}/falco/values.yaml"
    if [[ -f "${FALCO_VALUES}" ]]; then
        start_time=$SECONDS
        render_output=$(helm template falco falcosecurity/falco \
            -n falco \
            -f "${FALCO_VALUES}" \
            --output-dir "${RENDERED_DIR}/falco" 2>&1) || render_rc=$?
        render_rc=${render_rc:-0}

        if [[ ${render_rc} -eq 0 ]]; then
            manifest_count=$(find "${RENDERED_DIR}/falco" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
            record_result "helm template: falco (${manifest_count} manifests rendered)" "pass" "$((SECONDS - start_time))"
        else
            record_result "helm template: falco" "fail" "$((SECONDS - start_time))" "${render_output}"
        fi
    else
        record_result "helm template: falco (no values.yaml found)" "skip"
    fi
else
    record_result "helm template" "skip"
fi

# =============================================================================
# CHECK 4: Kubeconform (Kubernetes Schema Validation)
# =============================================================================
log_section "4. Kubeconform (Kubernetes Schema Validation)"

if check_command kubeconform; then
    # Validate rendered templates
    rendered_yaml_count=$(find "${RENDERED_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${rendered_yaml_count} -gt 0 ]]; then
        start_time=$SECONDS
        conform_output=$(find "${RENDERED_DIR}" -name "*.yaml" -exec kubeconform \
            -kubernetes-version 1.27.0 \
            -schema-location default \
            -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
            -summary \
            -strict \
            -skip CustomResourceDefinition \
            {} + 2>&1) || conform_rc=$?
        conform_rc=${conform_rc:-0}

        if [[ ${conform_rc} -eq 0 ]]; then
            record_result "kubeconform: rendered templates (${rendered_yaml_count} files)" "pass" "$((SECONDS - start_time))"
        else
            record_result "kubeconform: rendered templates" "fail" "$((SECONDS - start_time))" "${conform_output}"
        fi
    else
        record_result "kubeconform: no rendered manifests to validate" "skip"
    fi

    # Validate k8s-security YAML files
    k8s_yaml_count=$(find "${K8S_SECURITY_ROOT}" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${k8s_yaml_count} -gt 0 ]]; then
        start_time=$SECONDS
        conform_output=$(find "${K8S_SECURITY_ROOT}" -name "*.yaml" -o -name "*.yml" | xargs kubeconform \
            -kubernetes-version 1.27.0 \
            -schema-location default \
            -summary \
            -skip CustomResourceDefinition \
            2>&1) || conform_rc=$?
        conform_rc=${conform_rc:-0}

        if [[ ${conform_rc} -eq 0 ]]; then
            record_result "kubeconform: k8s-security manifests (${k8s_yaml_count} files)" "pass" "$((SECONDS - start_time))"
        else
            record_result "kubeconform: k8s-security manifests" "fail" "$((SECONDS - start_time))" "${conform_output}"
        fi
    fi
else
    # Try kubeval as fallback
    if check_command kubeval; then
        rendered_yaml_count=$(find "${RENDERED_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
        if [[ ${rendered_yaml_count} -gt 0 ]]; then
            start_time=$SECONDS
            kubeval_output=$(find "${RENDERED_DIR}" -name "*.yaml" -exec kubeval \
                --kubernetes-version 1.27.0 \
                --strict \
                --skip-kinds CustomResourceDefinition \
                {} + 2>&1) || kubeval_rc=$?
            kubeval_rc=${kubeval_rc:-0}

            if [[ ${kubeval_rc} -eq 0 ]]; then
                record_result "kubeval: rendered templates" "pass" "$((SECONDS - start_time))"
            else
                record_result "kubeval: rendered templates" "fail" "$((SECONDS - start_time))" "${kubeval_output}"
            fi
        fi
    else
        record_result "kubeconform / kubeval" "skip"
        echo -e "  ${YELLOW}Install kubeconform: brew install kubeconform${NC}"
    fi
fi

# =============================================================================
# CHECK 5: Kube-Score (Best Practices)
# =============================================================================
log_section "5. Kube-Score (Best Practices)"

if check_command kube-score; then
    rendered_yaml_count=$(find "${RENDERED_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${rendered_yaml_count} -gt 0 ]]; then
        start_time=$SECONDS
        score_output=$(find "${RENDERED_DIR}" -name "*.yaml" -exec kube-score score \
            --output-format ci \
            {} + 2>&1) || score_rc=$?
        score_rc=${score_rc:-0}

        critical_count=$(echo "${score_output}" | grep -c "\[CRITICAL\]" 2>/dev/null || echo "0")
        warning_count=$(echo "${score_output}" | grep -c "\[WARNING\]" 2>/dev/null || echo "0")

        if [[ ${critical_count} -gt 0 ]]; then
            record_result "kube-score: ${critical_count} critical, ${warning_count} warnings" "fail" "$((SECONDS - start_time))" "${score_output}"
        else
            record_result "kube-score: ${warning_count} warnings, 0 critical" "pass" "$((SECONDS - start_time))"
        fi
    else
        record_result "kube-score: no rendered manifests to check" "skip"
    fi
else
    record_result "kube-score" "skip"
    echo -e "  ${YELLOW}Install: brew install kube-score${NC}"
fi

# =============================================================================
# CHECK 6: Falco Rules Validation
# =============================================================================
log_section "6. Falco Rules Validation"

FALCO_RULES_DIR="${HELM_ROOT}/falco"
falco_rules_found=false

# Look for Falco custom rules files
while IFS= read -r rules_file; do
    falco_rules_found=true
    relative_path="${rules_file#${PROJECT_ROOT}/}"
    start_time=$SECONDS

    # Validate YAML syntax
    if python3 -c "
import yaml, sys
try:
    with open('${rules_file}', 'r') as f:
        docs = list(yaml.safe_load_all(f))
    # Check each document for valid Falco rule structure
    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, list):
            for item in doc:
                if not isinstance(item, dict):
                    print(f'Invalid rule entry: expected dict, got {type(item).__name__}', file=sys.stderr)
                    sys.exit(1)
                valid_keys = {'rule', 'macro', 'list', 'desc', 'condition', 'output', 'priority', 'source', 'tags', 'enabled', 'exceptions', 'append', 'override', 'required_engine_version', 'items', 'name', 'values', 'fields'}
                for key in item:
                    if key not in valid_keys:
                        print(f'Warning: unknown key \"{key}\" in Falco rule', file=sys.stderr)
    print('Valid Falco rules YAML')
    sys.exit(0)
except yaml.YAMLError as e:
    print(f'YAML parse error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        record_result "Falco rules syntax: ${relative_path}" "pass" "$((SECONDS - start_time))"
    else
        falco_err=$(python3 -c "import yaml; yaml.safe_load(open('${rules_file}'))" 2>&1 || true)
        record_result "Falco rules syntax: ${relative_path}" "fail" "$((SECONDS - start_time))" "${falco_err}"
    fi
done < <(find "${FALCO_RULES_DIR}" -name "*rules*" -o -name "*falco*" | grep -E "\.(yaml|yml)$" 2>/dev/null || true)

# Also check values.yaml for customRules section
if [[ -f "${FALCO_RULES_DIR}/values.yaml" ]]; then
    start_time=$SECONDS
    if python3 -c "
import yaml
with open('${FALCO_RULES_DIR}/values.yaml', 'r') as f:
    values = yaml.safe_load(f)
if values and 'customRules' in values:
    for name, content in values['customRules'].items():
        rules = yaml.safe_load(content)
        print(f'  Custom rule file \"{name}\": {len(rules) if isinstance(rules, list) else 1} rule(s)')
    print('Custom rules syntax is valid')
else:
    print('No customRules found in values.yaml')
" 2>&1; then
        record_result "Falco customRules in values.yaml" "pass" "$((SECONDS - start_time))"
    else
        falco_custom_err=$(python3 -c "import yaml; yaml.safe_load(open('${FALCO_RULES_DIR}/values.yaml'))" 2>&1 || true)
        record_result "Falco customRules in values.yaml" "fail" "$((SECONDS - start_time))" "${falco_custom_err}"
    fi
fi

if [[ "${falco_rules_found}" == "false" ]] && [[ ! -f "${FALCO_RULES_DIR}/values.yaml" ]]; then
    record_result "Falco rules: no rules files found in ${FALCO_RULES_DIR}" "skip"
fi

# =============================================================================
# CHECK 7: Suricata Rules Validation
# =============================================================================
log_section "7. Suricata Rules Validation"

SURICATA_DIR="${HELM_ROOT}/suricata"
suricata_rules_found=false

# Look for Suricata .rules files
while IFS= read -r rules_file; do
    suricata_rules_found=true
    relative_path="${rules_file#${PROJECT_ROOT}/}"
    start_time=$SECONDS

    # Validate Suricata rule syntax using a basic regex check
    invalid_rules=0
    total_rules=0
    invalid_lines=""

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
        total_rules=$((total_rules + 1))

        # Basic Suricata rule format: action protocol src_ip src_port -> dst_ip dst_port (options)
        if ! echo "${line}" | grep -qE "^(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth|log)\s+(tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp)\s+"; then
            invalid_rules=$((invalid_rules + 1))
            invalid_lines+="  Line: ${line:0:80}..."$'\n'
        fi
    done < "${rules_file}"

    if [[ ${invalid_rules} -eq 0 ]]; then
        record_result "Suricata rules: ${relative_path} (${total_rules} rules)" "pass" "$((SECONDS - start_time))"
    else
        record_result "Suricata rules: ${relative_path} (${invalid_rules}/${total_rules} invalid)" "fail" "$((SECONDS - start_time))" "${invalid_lines}"
    fi
done < <(find "${SURICATA_DIR}" -name "*.rules" -type f 2>/dev/null || true)

# Also check for rules in values.yaml or ConfigMap files
while IFS= read -r yaml_file; do
    suricata_rules_found=true
    relative_path="${yaml_file#${PROJECT_ROOT}/}"
    start_time=$SECONDS

    if python3 -c "import yaml; yaml.safe_load(open('${yaml_file}'))" 2>/dev/null; then
        record_result "Suricata config YAML: ${relative_path}" "pass" "$((SECONDS - start_time))"
    else
        yaml_err=$(python3 -c "import yaml; yaml.safe_load(open('${yaml_file}'))" 2>&1 || true)
        record_result "Suricata config YAML: ${relative_path}" "fail" "$((SECONDS - start_time))" "${yaml_err}"
    fi
done < <(find "${SURICATA_DIR}" -name "*.yaml" -o -name "*.yml" 2>/dev/null | head -10 || true)

# Also look in ids-ips directory
IDS_DIR="${PROJECT_ROOT}/ids-ips"
while IFS= read -r rules_file; do
    suricata_rules_found=true
    relative_path="${rules_file#${PROJECT_ROOT}/}"
    start_time=$SECONDS

    total_rules=$(grep -cE "^(alert|pass|drop|reject|log)\s+" "${rules_file}" 2>/dev/null || echo "0")
    record_result "Suricata/IDS rules: ${relative_path} (${total_rules} rules)" "pass" "$((SECONDS - start_time))"
done < <(find "${IDS_DIR}" -name "*.rules" -type f 2>/dev/null || true)

if [[ "${suricata_rules_found}" == "false" ]]; then
    record_result "Suricata rules: no .rules files found" "skip"
fi

# =============================================================================
# CHECK 8: Kustomization Validation
# =============================================================================
log_section "8. Kustomization Validation"

while IFS= read -r kustomization_file; do
    relative_path="${kustomization_file#${PROJECT_ROOT}/}"
    kustomize_dir=$(dirname "${kustomization_file}")
    start_time=$SECONDS

    # Validate YAML syntax
    if python3 -c "import yaml; yaml.safe_load(open('${kustomization_file}'))" 2>/dev/null; then
        record_result "kustomization.yaml syntax: ${relative_path}" "pass" "$((SECONDS - start_time))"
    else
        yaml_err=$(python3 -c "import yaml; yaml.safe_load(open('${kustomization_file}'))" 2>&1 || true)
        record_result "kustomization.yaml syntax: ${relative_path}" "fail" "$((SECONDS - start_time))" "${yaml_err}"
    fi

    # Try kustomize build if available
    if check_command kustomize; then
        start_time=$SECONDS
        kustomize_output=$(kustomize build "${kustomize_dir}" 2>&1) || kustomize_rc=$?
        kustomize_rc=${kustomize_rc:-0}

        if [[ ${kustomize_rc} -eq 0 ]]; then
            resource_count=$(echo "${kustomize_output}" | grep -c "^kind:" 2>/dev/null || echo "0")
            record_result "kustomize build: ${relative_path} (${resource_count} resources)" "pass" "$((SECONDS - start_time))"
        else
            record_result "kustomize build: ${relative_path}" "fail" "$((SECONDS - start_time))" "${kustomize_output}"
        fi
    elif check_command kubectl; then
        start_time=$SECONDS
        kustomize_output=$(kubectl kustomize "${kustomize_dir}" 2>&1) || kustomize_rc=$?
        kustomize_rc=${kustomize_rc:-0}

        if [[ ${kustomize_rc} -eq 0 ]]; then
            record_result "kubectl kustomize: ${relative_path}" "pass" "$((SECONDS - start_time))"
        else
            record_result "kubectl kustomize: ${relative_path}" "fail" "$((SECONDS - start_time))" "${kustomize_output}"
        fi
    fi
done < <(find "${PROJECT_ROOT}" -name "kustomization.yaml" -o -name "kustomization.yml" 2>/dev/null | grep -v ".terraform" | sort || true)

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
    echo -e "${RED}${BOLD}Helm/K8s validation FAILED with ${FAILED_CHECKS} failure(s).${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}Helm/K8s validation PASSED.${NC}"
    exit 0
fi
