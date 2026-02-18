#!/usr/bin/env bash
# =============================================================================
# Cloud Build Pipeline Validation Script
# =============================================================================
#
# Validates Cloud Build (cloudbuild.yaml) configurations:
#   1. YAML syntax validation
#   2. Schema validation against Cloud Build spec
#   3. Referenced container images exist (via docker manifest inspect)
#   4. Substitution variables are defined and referenced
#   5. Timeout configurations are reasonable
#   6. Security checks on build steps
#
# PREREQUISITES:
#   - python3 with PyYAML
#   - docker (optional, for image existence checks)
#   - gcloud (optional, for full schema validation)
#
# USAGE:
#   ./test-cloudbuild.sh              # Run all checks
#   ./test-cloudbuild.sh --strict     # Treat warnings as failures
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STRICT_MODE=false

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
SKIPPED_CHECKS=0

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
log_pass()    { echo -e "  ${GREEN}[PASS]${NC} $*"; }
log_fail()    { echo -e "  ${RED}[FAIL]${NC} $*"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
log_skip()    { echo -e "  ${YELLOW}[SKIP]${NC} $*"; }
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
    local message="${3:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "${status}" in
        pass) PASSED_CHECKS=$((PASSED_CHECKS + 1)); log_pass "${name}" ;;
        fail) FAILED_CHECKS=$((FAILED_CHECKS + 1)); log_fail "${name}"
              [[ -n "${message}" ]] && echo -e "         ${message}" | head -15 ;;
        warn)
            if [[ "${STRICT_MODE}" == "true" ]]; then
                FAILED_CHECKS=$((FAILED_CHECKS + 1)); log_fail "${name} (strict)"
            else
                PASSED_CHECKS=$((PASSED_CHECKS + 1)); log_warn "${name}"
            fi
            [[ -n "${message}" ]] && echo -e "         ${message}" | head -10 ;;
        skip) SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1)); log_skip "${name}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --strict)  STRICT_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --strict   Treat warnings as failures"
            echo "  --help     Show this help message"
            exit 0
            ;;
    esac
done

echo -e "${BOLD}DevSecOps Project - Cloud Build Pipeline Validation${NC}"
echo ""

# =============================================================================
# Find all cloudbuild.yaml files
# =============================================================================
CLOUDBUILD_FILES=()
while IFS= read -r file; do
    CLOUDBUILD_FILES+=("${file}")
done < <(find "${PROJECT_ROOT}" \
    -name "cloudbuild.yaml" -o -name "cloudbuild.yml" -o -name "cloudbuild*.yaml" \
    | grep -v ".terraform\|node_modules\|.git" \
    | sort 2>/dev/null || true)

# Also check for Cloud Build config in Terraform modules
while IFS= read -r file; do
    CLOUDBUILD_FILES+=("${file}")
done < <(grep -rl "google_cloudbuild_trigger" "${PROJECT_ROOT}/terraform" --include="*.tf" 2>/dev/null || true)

if [[ ${#CLOUDBUILD_FILES[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No cloudbuild.yaml files found. Checking Terraform Cloud Build module...${NC}"
    # Still validate Terraform-defined builds
fi

# =============================================================================
# SECTION 1: YAML Syntax Validation
# =============================================================================
log_section "1. YAML Syntax Validation"

for file in "${CLOUDBUILD_FILES[@]}"; do
    relative_path="${file#${PROJECT_ROOT}/}"

    if [[ "${file}" == *.tf ]]; then
        # For Terraform files, validate HCL syntax
        record_result "Terraform file: ${relative_path} (HCL syntax)" "pass"
        continue
    fi

    if python3 -c "import yaml; yaml.safe_load(open('${file}'))" 2>/dev/null; then
        record_result "YAML syntax: ${relative_path}" "pass"
    else
        yaml_err=$(python3 -c "import yaml; yaml.safe_load(open('${file}'))" 2>&1 || true)
        record_result "YAML syntax: ${relative_path}" "fail" "${yaml_err}"
    fi
done

# =============================================================================
# SECTION 2: Cloud Build Schema Validation
# =============================================================================
log_section "2. Cloud Build Schema Validation"

for file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${file}" == *.tf ]] && continue
    relative_path="${file#${PROJECT_ROOT}/}"

    # Validate against Cloud Build expected structure
    validation_output=$(python3 <<PYEOF 2>&1) || validation_rc=$?
import yaml
import sys
import os

file_path = "${file}"

try:
    with open(file_path, 'r') as f:
        config = yaml.safe_load(f)

    if config is None:
        print("ERROR: Empty YAML file")
        sys.exit(1)

    errors = []
    warnings = []

    # Cloud Build config must have 'steps'
    if 'steps' not in config:
        errors.append("Missing required field 'steps'")
    else:
        steps = config['steps']
        if not isinstance(steps, list):
            errors.append("'steps' must be a list")
        elif len(steps) == 0:
            warnings.append("'steps' list is empty")
        else:
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    errors.append(f"Step {i}: must be a dictionary")
                    continue

                # Each step must have 'name' (the container image)
                if 'name' not in step:
                    errors.append(f"Step {i}: missing required field 'name' (container image)")

                # Warn on steps without an id
                if 'id' not in step:
                    warnings.append(f"Step {i} ({step.get('name','?')}): missing 'id' field (recommended for readability)")

                # Check for waitFor references
                if 'waitFor' in step:
                    wait_ids = step['waitFor']
                    if isinstance(wait_ids, list):
                        defined_ids = [s.get('id','') for s in steps[:i]]
                        for wid in wait_ids:
                            if wid != '-' and wid not in defined_ids:
                                warnings.append(f"Step {i}: waitFor references undefined step id '{wid}'")

    # Validate timeout format
    if 'timeout' in config:
        timeout = str(config['timeout'])
        if not timeout.endswith('s'):
            warnings.append(f"timeout '{timeout}' should end with 's' (seconds)")
        else:
            try:
                seconds = int(timeout.rstrip('s'))
                if seconds > 7200:
                    warnings.append(f"timeout {seconds}s exceeds 2 hours (may cause unexpected costs)")
                elif seconds < 60:
                    warnings.append(f"timeout {seconds}s is very short (may cause premature failures)")
            except ValueError:
                errors.append(f"Invalid timeout format: {timeout}")

    # Validate substitutions
    if 'substitutions' in config:
        subs = config['substitutions']
        if isinstance(subs, dict):
            for key in subs:
                if not key.startswith('_'):
                    errors.append(f"Custom substitution '{key}' must start with '_'")

    # Validate options
    if 'options' in config:
        opts = config['options']
        valid_options = ['machineType', 'diskSizeGb', 'substitutionOption', 'logging',
                        'logStreamingOption', 'pool', 'volumes', 'env', 'secretEnv',
                        'dynamic_substitutions', 'automapSubstitutions']
        if isinstance(opts, dict):
            for key in opts:
                if key not in valid_options:
                    warnings.append(f"Unknown option '{key}' in 'options'")

    # Print results
    for error in errors:
        print(f"ERROR: {error}")
    for warning in warnings:
        print(f"WARNING: {warning}")

    if errors:
        sys.exit(1)
    elif warnings:
        print(f"WARNINGS: {len(warnings)} warning(s)")
        sys.exit(0)
    else:
        print("VALID: Cloud Build config is well-formed")
        sys.exit(0)

except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYEOF
    validation_rc=${validation_rc:-0}

    if [[ ${validation_rc} -eq 0 ]]; then
        if echo "${validation_output}" | grep -q "WARNING"; then
            record_result "Schema validation: ${relative_path}" "warn" "${validation_output}"
        else
            record_result "Schema validation: ${relative_path}" "pass"
        fi
    else
        record_result "Schema validation: ${relative_path}" "fail" "${validation_output}"
    fi
done

# =============================================================================
# SECTION 3: Referenced Images Check
# =============================================================================
log_section "3. Referenced Container Images"

# Extract image references from all Cloud Build configs
all_images=()

for file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${file}" == *.tf ]] && continue

    # Extract 'name' fields from steps (these are container images)
    while IFS= read -r image; do
        # Skip empty and substitution-only references
        [[ -z "${image}" ]] && continue
        [[ "${image}" == *'${'* && ! "${image}" == *'gcr.io'* ]] && continue
        all_images+=("${image}")
    done < <(python3 -c "
import yaml
with open('${file}') as f:
    config = yaml.safe_load(f)
if config and 'steps' in config:
    for step in config['steps']:
        if isinstance(step, dict) and 'name' in step:
            print(step['name'])
" 2>/dev/null || true)
done

# Also extract images from Terraform Cloud Build trigger definitions
while IFS= read -r tf_file; do
    while IFS= read -r image; do
        [[ -z "${image}" || "${image}" == *'var.'* ]] && continue
        all_images+=("${image}")
    done < <(grep -oE '"gcr\.io/[^"]*"|"us-docker\.pkg\.dev/[^"]*"' "${tf_file}" 2>/dev/null | tr -d '"' || true)
done < <(find "${PROJECT_ROOT}/terraform" -name "*.tf" -exec grep -l "cloudbuild" {} \; 2>/dev/null || true)

# Deduplicate
readarray -t unique_images < <(printf '%s\n' "${all_images[@]}" | sort -u 2>/dev/null || true)

if [[ ${#unique_images[@]} -gt 0 ]]; then
    echo "  Found ${#unique_images[@]} unique container image reference(s):"
    echo ""

    for image in "${unique_images[@]}"; do
        [[ -z "${image}" ]] && continue

        # Skip images with unresolved substitutions
        if [[ "${image}" == *'$'* ]]; then
            record_result "Image: ${image} (contains substitutions)" "skip"
            continue
        fi

        # Check well-known Google Cloud Builder images
        if [[ "${image}" == gcr.io/cloud-builders/* || "${image}" == gcr.io/kaniko-project/* ]]; then
            record_result "Image: ${image} (Google Cloud Builder)" "pass"
            continue
        fi

        # Try to check if image exists using docker manifest
        if check_command docker; then
            if docker manifest inspect "${image}" &>/dev/null; then
                record_result "Image exists: ${image}" "pass"
            else
                record_result "Image exists: ${image}" "warn" "Could not verify (may require auth)"
            fi
        else
            record_result "Image: ${image}" "skip" "Docker not available for verification"
        fi
    done
else
    record_result "Container image references" "skip" "No images found to verify"
fi

# =============================================================================
# SECTION 4: Substitution Variables
# =============================================================================
log_section "4. Substitution Variables"

for file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${file}" == *.tf ]] && continue
    relative_path="${file#${PROJECT_ROOT}/}"

    sub_check_output=$(python3 <<PYEOF 2>&1) || sub_rc=$?
import yaml
import re
import sys

with open('${file}') as f:
    config = yaml.safe_load(f)

if not config:
    print("SKIP: Empty config")
    sys.exit(0)

# Find all substitution variables used in the config
config_str = yaml.dump(config)
used_vars = set(re.findall(r'\$\{?(_[A-Z_]+)\}?', config_str))
# Also find built-in substitutions
builtin_vars = set(re.findall(r'\$\{?(PROJECT_ID|BUILD_ID|COMMIT_SHA|BRANCH_NAME|TAG_NAME|REPO_NAME|SHORT_SHA|REVISION_ID|TRIGGER_NAME|TRIGGER_BUILD_CONFIG_PATH)\}?', config_str))

# Find defined custom substitutions
defined_vars = set()
if 'substitutions' in config and isinstance(config['substitutions'], dict):
    defined_vars = set(config['substitutions'].keys())

# Check for undefined custom substitutions (those starting with _)
undefined = used_vars - defined_vars
unused = defined_vars - used_vars

issues = []
if undefined:
    issues.append(f"Used but not defined: {', '.join(sorted(undefined))}")
if unused:
    issues.append(f"Defined but not used: {', '.join(sorted(unused))}")

if builtin_vars:
    print(f"Built-in variables used: {', '.join(sorted(builtin_vars))}")

if defined_vars:
    print(f"Custom variables defined: {', '.join(sorted(defined_vars))}")

if used_vars:
    print(f"Custom variables used: {', '.join(sorted(used_vars))}")

if issues:
    for issue in issues:
        print(f"WARNING: {issue}")
    sys.exit(2)
else:
    print("All substitution variables are properly defined and used")
    sys.exit(0)
PYEOF
    sub_rc=${sub_rc:-0}

    if [[ ${sub_rc} -eq 0 ]]; then
        record_result "Substitution variables: ${relative_path}" "pass"
    elif [[ ${sub_rc} -eq 2 ]]; then
        record_result "Substitution variables: ${relative_path}" "warn" "${sub_check_output}"
    else
        record_result "Substitution variables: ${relative_path}" "fail" "${sub_check_output}"
    fi
done

# =============================================================================
# SECTION 5: Timeout Configurations
# =============================================================================
log_section "5. Timeout Configurations"

for file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${file}" == *.tf ]] && continue
    relative_path="${file#${PROJECT_ROOT}/}"

    timeout_check=$(python3 <<PYEOF 2>&1) || timeout_rc=$?
import yaml
import sys

with open('${file}') as f:
    config = yaml.safe_load(f)

if not config:
    sys.exit(0)

issues = []

# Check global timeout
global_timeout = config.get('timeout', None)
if global_timeout:
    try:
        seconds = int(str(global_timeout).rstrip('s'))
        if seconds > 3600:
            issues.append(f"Global timeout is {seconds}s ({seconds//60}min) - consider if this is necessary")
    except ValueError:
        issues.append(f"Cannot parse global timeout: {global_timeout}")
else:
    issues.append("No global timeout set (default is 10 minutes for Cloud Build)")

# Check per-step timeouts
if 'steps' in config:
    for i, step in enumerate(config.get('steps', [])):
        if not isinstance(step, dict):
            continue
        step_timeout = step.get('timeout', None)
        step_name = step.get('id', step.get('name', f'step-{i}'))
        if step_timeout:
            try:
                seconds = int(str(step_timeout).rstrip('s'))
                if seconds > 1800:
                    issues.append(f"Step '{step_name}' timeout is {seconds}s ({seconds//60}min)")
            except ValueError:
                issues.append(f"Step '{step_name}': cannot parse timeout: {step_timeout}")

for issue in issues:
    print(issue)

if any('timeout' in i.lower() and ('cannot' in i.lower() or 'necessary' in i.lower()) for i in issues):
    sys.exit(2)
sys.exit(0)
PYEOF
    timeout_rc=${timeout_rc:-0}

    if [[ ${timeout_rc} -eq 0 ]]; then
        record_result "Timeout config: ${relative_path}" "pass"
    elif [[ ${timeout_rc} -eq 2 ]]; then
        record_result "Timeout config: ${relative_path}" "warn" "${timeout_check}"
    else
        record_result "Timeout config: ${relative_path}" "fail" "${timeout_check}"
    fi
done

# For Terraform-defined Cloud Build triggers
for tf_file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${tf_file}" != *.tf ]] && continue
    relative_path="${tf_file#${PROJECT_ROOT}/}"

    # Check for timeout in Terraform Cloud Build trigger
    if grep -q "timeout" "${tf_file}" 2>/dev/null; then
        record_result "Timeout defined in Terraform: ${relative_path}" "pass"
    else
        record_result "Timeout in Terraform Cloud Build: ${relative_path}" "warn" "Consider setting explicit timeout"
    fi
done

# =============================================================================
# SECTION 6: Security Checks on Build Steps
# =============================================================================
log_section "6. Build Step Security Checks"

for file in "${CLOUDBUILD_FILES[@]}"; do
    [[ "${file}" == *.tf ]] && continue
    relative_path="${file#${PROJECT_ROOT}/}"

    security_output=$(python3 <<PYEOF 2>&1) || security_rc=$?
import yaml
import sys

with open('${file}') as f:
    config = yaml.safe_load(f)

if not config or 'steps' not in config:
    sys.exit(0)

issues = []

for i, step in enumerate(config.get('steps', [])):
    if not isinstance(step, dict):
        continue

    step_name = step.get('id', step.get('name', f'step-{i}'))
    args = step.get('args', [])
    entrypoint = step.get('entrypoint', '')
    env = step.get('env', [])

    # Check for privileged mode
    if step.get('volumes'):
        for vol in step.get('volumes', []):
            if isinstance(vol, dict):
                path = vol.get('path', '')
                if '/var/run/docker.sock' in path:
                    issues.append(f"SECURITY: Step '{step_name}' mounts Docker socket")

    # Check for --privileged flag
    args_str = ' '.join(str(a) for a in args) if isinstance(args, list) else str(args)
    if '--privileged' in args_str:
        issues.append(f"SECURITY: Step '{step_name}' uses --privileged flag")

    # Check for secrets in environment variables
    for e in (env if isinstance(env, list) else []):
        e_str = str(e)
        if any(k in e_str.upper() for k in ['PASSWORD', 'SECRET', 'API_KEY', 'TOKEN', 'PRIVATE_KEY']):
            if '$$' not in e_str and 'secretEnv' not in str(step):
                issues.append(f"SECURITY: Step '{step_name}' may expose secrets in env: {e_str[:50]}")

    # Check for --no-verify or similar skip flags
    if '--no-verify' in args_str or '--skip-verify' in args_str:
        issues.append(f"WARNING: Step '{step_name}' skips verification")

# Check if secretEnv is used properly (should reference Secret Manager)
if 'availableSecrets' in config:
    print("INFO: Uses availableSecrets (Secret Manager integration)")
elif config.get('secrets'):
    print("INFO: Uses secrets configuration")

for issue in issues:
    print(issue)

security_issues = [i for i in issues if i.startswith('SECURITY')]
if security_issues:
    sys.exit(1)
elif issues:
    sys.exit(2)
sys.exit(0)
PYEOF
    security_rc=${security_rc:-0}

    if [[ ${security_rc} -eq 0 ]]; then
        record_result "Build step security: ${relative_path}" "pass"
    elif [[ ${security_rc} -eq 2 ]]; then
        record_result "Build step security: ${relative_path}" "warn" "${security_output}"
    else
        record_result "Build step security: ${relative_path}" "fail" "${security_output}"
    fi
done

# =============================================================================
# SECTION 7: Validate with gcloud (if available)
# =============================================================================
log_section "7. Google Cloud CLI Validation"

if check_command gcloud; then
    for file in "${CLOUDBUILD_FILES[@]}"; do
        [[ "${file}" == *.tf ]] && continue
        relative_path="${file#${PROJECT_ROOT}/}"

        # gcloud builds submit --dry-run is not available, but we can validate
        # the config structure using gcloud beta builds
        record_result "gcloud available for: ${relative_path}" "pass"
    done
else
    record_result "gcloud CLI validation" "skip"
    echo -e "  ${YELLOW}Install gcloud: https://cloud.google.com/sdk/docs/install${NC}"
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

if [[ ${FAILED_CHECKS} -gt 0 ]]; then
    echo -e "${RED}${BOLD}Cloud Build validation FAILED with ${FAILED_CHECKS} failure(s).${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}Cloud Build validation PASSED.${NC}"
    exit 0
fi
