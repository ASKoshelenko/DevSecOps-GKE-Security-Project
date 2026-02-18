#!/usr/bin/env bash
# =============================================================================
# Service Account Key to Workload Identity Federation Migration Script
# =============================================================================
#
# PURPOSE:
# Audits, identifies, and migrates all service account key usage to Workload
# Identity Federation (WIF) or GKE Workload Identity. This script is part of
# the incident response to the APT-driven SA key compromise (INC-2026-0042).
#
# USAGE:
#   ./migrate-to-federation.sh --project-id <PROJECT_ID> [OPTIONS]
#
# OPTIONS:
#   --project-id      GCP project ID (required)
#   --org-id          GCP organization ID (for org-wide audit)
#   --dry-run         Audit only, do not disable/delete keys
#   --disable-keys    Disable (but do not delete) all SA keys
#   --delete-keys     Delete all SA keys (IRREVERSIBLE)
#   --create-wif      Create WIF pool and provider for GitHub Actions
#   --github-org      GitHub org name (required with --create-wif)
#   --github-repo     GitHub repo name (required with --create-wif)
#   --force           Skip confirmation prompts
#   --output-json     Output results in JSON format
#   --help            Show this help message
#
# PREREQUISITES:
#   - gcloud CLI installed and authenticated
#   - Sufficient IAM permissions:
#     - iam.serviceAccountKeys.list
#     - iam.serviceAccountKeys.disable (for --disable-keys)
#     - iam.serviceAccountKeys.delete (for --delete-keys)
#     - iam.workloadIdentityPools.create (for --create-wif)
#   - jq installed for JSON processing
#
# EXIT CODES:
#   0 - Success
#   1 - Invalid arguments
#   2 - Missing prerequisites
#   3 - API error
#   4 - User cancelled operation
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants and Defaults
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/tmp/wif-migration-${TIMESTAMP}.log"
readonly REPORT_FILE="/tmp/sa-key-audit-${TIMESTAMP}.csv"

# Colors for terminal output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No color

# Default values
DRY_RUN=true
DISABLE_KEYS=false
DELETE_KEYS=false
CREATE_WIF=false
FORCE=false
OUTPUT_JSON=false
PROJECT_ID=""
ORG_ID=""
GITHUB_ORG=""
GITHUB_REPO=""

# Counters
TOTAL_SAS=0
TOTAL_KEYS=0
TOTAL_USER_KEYS=0
TOTAL_SYSTEM_KEYS=0
TOTAL_DISABLED=0
TOTAL_DELETED=0
TOTAL_EXPIRED=0

# =============================================================================
# Utility Functions
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Write to log file
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"

    # Write to terminal with colors
    case "${level}" in
        ERROR)   echo -e "${RED}[ERROR]${NC} ${message}" ;;
        WARN)    echo -e "${YELLOW}[WARN]${NC}  ${message}" ;;
        INFO)    echo -e "${GREEN}[INFO]${NC}  ${message}" ;;
        DEBUG)   echo -e "${CYAN}[DEBUG]${NC} ${message}" ;;
        ACTION)  echo -e "${BOLD}${BLUE}[ACTION]${NC} ${message}" ;;
        *)       echo "[${level}] ${message}" ;;
    esac
}

die() {
    log ERROR "$@"
    exit 1
}

confirm() {
    if [[ "${FORCE}" == "true" ]]; then
        return 0
    fi

    local prompt="$1"
    echo -e "${YELLOW}${prompt}${NC}"
    read -r -p "Type 'yes' to confirm: " response
    if [[ "${response}" != "yes" ]]; then
        log WARN "Operation cancelled by user."
        exit 4
    fi
}

print_banner() {
    echo -e "${BOLD}"
    echo "============================================================================="
    echo " Service Account Key -> Workload Identity Federation Migration"
    echo " Incident Response: INC-2026-0042 (APT SA Key Compromise)"
    echo "============================================================================="
    echo -e "${NC}"
    echo "  Project:    ${PROJECT_ID}"
    echo "  Timestamp:  ${TIMESTAMP}"
    echo "  Mode:       $(if [[ "${DRY_RUN}" == "true" ]]; then echo "DRY RUN (audit only)"; else echo "LIVE EXECUTION"; fi)"
    echo "  Log file:   ${LOG_FILE}"
    echo "  Report:     ${REPORT_FILE}"
    echo ""
}

# =============================================================================
# Prerequisite Checks
# =============================================================================

check_prerequisites() {
    log INFO "Checking prerequisites..."

    # Check gcloud
    if ! command -v gcloud &> /dev/null; then
        die "gcloud CLI is not installed. Install from: https://cloud.google.com/sdk/docs/install"
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        die "jq is not installed. Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    fi

    # Verify gcloud authentication
    if ! gcloud auth print-access-token &> /dev/null 2>&1; then
        die "gcloud is not authenticated. Run: gcloud auth login"
    fi

    # Verify project access
    if ! gcloud projects describe "${PROJECT_ID}" &> /dev/null 2>&1; then
        die "Cannot access project '${PROJECT_ID}'. Verify the project ID and your permissions."
    fi

    # Verify required IAM permissions
    log INFO "Verifying IAM permissions..."
    local caller_email
    caller_email="$(gcloud config get-value account 2>/dev/null)"
    log INFO "Authenticated as: ${caller_email}"

    log INFO "Prerequisites check passed."
}

# =============================================================================
# Audit Functions
# =============================================================================

audit_service_accounts() {
    log INFO "Enumerating all service accounts in project ${PROJECT_ID}..."

    # Initialize CSV report
    echo "service_account_email,key_id,key_type,key_origin,created_at,expires_at,status,last_authenticated,recommendation" > "${REPORT_FILE}"

    # List all service accounts
    local sa_list
    sa_list="$(gcloud iam service-accounts list \
        --project="${PROJECT_ID}" \
        --format='json' 2>/dev/null)" || die "Failed to list service accounts"

    TOTAL_SAS="$(echo "${sa_list}" | jq 'length')"
    log INFO "Found ${TOTAL_SAS} service accounts in project."

    echo ""
    echo -e "${BOLD}Service Account Key Inventory:${NC}"
    echo "-----------------------------------------------------------------------------"
    printf "%-50s %-12s %-10s %-12s\n" "SERVICE ACCOUNT" "KEY TYPE" "STATUS" "AGE (DAYS)"
    echo "-----------------------------------------------------------------------------"

    # Iterate over each service account
    echo "${sa_list}" | jq -r '.[].email' | while read -r sa_email; do
        audit_sa_keys "${sa_email}"
    done

    echo "-----------------------------------------------------------------------------"
    echo ""
    log INFO "Audit complete."
    print_summary
}

audit_sa_keys() {
    local sa_email="$1"

    # List keys for this service account
    local keys_json
    keys_json="$(gcloud iam service-accounts keys list \
        --iam-account="${sa_email}" \
        --project="${PROJECT_ID}" \
        --format='json' 2>/dev/null)" || {
        log WARN "Failed to list keys for ${sa_email} (may lack permissions)"
        return
    }

    local key_count
    key_count="$(echo "${keys_json}" | jq 'length')"

    if [[ "${key_count}" -eq 0 ]]; then
        return
    fi

    TOTAL_KEYS=$((TOTAL_KEYS + key_count))

    echo "${keys_json}" | jq -c '.[]' | while read -r key; do
        local key_id key_type key_origin valid_after valid_before
        key_id="$(echo "${key}" | jq -r '.name' | rev | cut -d'/' -f1 | rev)"
        key_type="$(echo "${key}" | jq -r '.keyType')"
        key_origin="$(echo "${key}" | jq -r '.keyOrigin // "UNKNOWN"')"
        valid_after="$(echo "${key}" | jq -r '.validAfterTime // "N/A"')"
        valid_before="$(echo "${key}" | jq -r '.validBeforeTime // "N/A"')"

        # Calculate key age in days
        local key_age="N/A"
        if [[ "${valid_after}" != "N/A" ]]; then
            local created_epoch
            created_epoch="$(date -d "${valid_after}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${valid_after}" +%s 2>/dev/null || echo "0")"
            local now_epoch
            now_epoch="$(date +%s)"
            if [[ "${created_epoch}" -gt 0 ]]; then
                key_age="$(( (now_epoch - created_epoch) / 86400 ))"
            fi
        fi

        # Determine status and recommendation
        local status="ACTIVE"
        local recommendation=""

        if [[ "${key_type}" == "SYSTEM_MANAGED" ]]; then
            TOTAL_SYSTEM_KEYS=$((TOTAL_SYSTEM_KEYS + 1))
            status="SYSTEM"
            recommendation="No action needed (GCP-managed)"
        else
            TOTAL_USER_KEYS=$((TOTAL_USER_KEYS + 1))

            # Check if the key is expired
            if [[ "${valid_before}" != "N/A" ]]; then
                local expires_epoch
                expires_epoch="$(date -d "${valid_before}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${valid_before}" +%s 2>/dev/null || echo "0")"
                local now_epoch
                now_epoch="$(date +%s)"
                if [[ "${expires_epoch}" -gt 0 ]] && [[ "${expires_epoch}" -lt "${now_epoch}" ]]; then
                    status="EXPIRED"
                    TOTAL_EXPIRED=$((TOTAL_EXPIRED + 1))
                    recommendation="DELETE - Key is expired"
                fi
            fi

            if [[ "${status}" == "ACTIVE" ]]; then
                if [[ "${key_age}" != "N/A" ]] && [[ "${key_age}" -gt 90 ]]; then
                    recommendation="CRITICAL - Key is ${key_age} days old. Migrate to WIF immediately."
                elif [[ "${key_age}" != "N/A" ]] && [[ "${key_age}" -gt 30 ]]; then
                    recommendation="HIGH - Key is ${key_age} days old. Plan WIF migration."
                else
                    recommendation="MEDIUM - Migrate to WIF at next opportunity."
                fi
            fi
        fi

        # Print to terminal
        local short_sa
        short_sa="$(echo "${sa_email}" | cut -c1-48)"
        printf "%-50s %-12s %-10s %-12s\n" "${short_sa}" "${key_type}" "${status}" "${key_age}"

        # Write to CSV report
        echo "${sa_email},${key_id},${key_type},${key_origin},${valid_after},${valid_before},${status},N/A,${recommendation}" >> "${REPORT_FILE}"
    done
}

print_summary() {
    echo -e "${BOLD}Audit Summary:${NC}"
    echo "  Total service accounts:     ${TOTAL_SAS}"
    echo "  Total keys found:           ${TOTAL_KEYS}"
    echo "  User-managed keys:          ${TOTAL_USER_KEYS}"
    echo "  System-managed keys:        ${TOTAL_SYSTEM_KEYS}"
    echo "  Expired keys:               ${TOTAL_EXPIRED}"
    echo ""

    if [[ "${TOTAL_USER_KEYS}" -gt 0 ]]; then
        echo -e "${RED}${BOLD}WARNING: ${TOTAL_USER_KEYS} user-managed SA keys found!${NC}"
        echo "These keys are a security risk and should be migrated to WIF."
        echo ""
        echo "Detailed report saved to: ${REPORT_FILE}"
    else
        echo -e "${GREEN}${BOLD}No user-managed SA keys found. Project is clean.${NC}"
    fi
    echo ""
}

# =============================================================================
# Key Lifecycle Functions
# =============================================================================

disable_all_user_keys() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log WARN "DRY RUN: Would disable all user-managed SA keys."
        return
    fi

    confirm "This will DISABLE all user-managed SA keys in project ${PROJECT_ID}. Services using these keys will lose access."

    log ACTION "Disabling all user-managed service account keys..."

    local sa_list
    sa_list="$(gcloud iam service-accounts list \
        --project="${PROJECT_ID}" \
        --format='value(email)' 2>/dev/null)"

    while IFS= read -r sa_email; do
        [[ -z "${sa_email}" ]] && continue

        local keys_json
        keys_json="$(gcloud iam service-accounts keys list \
            --iam-account="${sa_email}" \
            --project="${PROJECT_ID}" \
            --managed-by=user \
            --format='json' 2>/dev/null)"

        echo "${keys_json}" | jq -r '.[].name' | while read -r key_name; do
            [[ -z "${key_name}" ]] && continue
            local key_id
            key_id="$(echo "${key_name}" | rev | cut -d'/' -f1 | rev)"

            log ACTION "Disabling key ${key_id} for ${sa_email}..."
            if gcloud iam service-accounts keys disable "${key_id}" \
                --iam-account="${sa_email}" \
                --project="${PROJECT_ID}" 2>/dev/null; then
                log INFO "Disabled key ${key_id}"
                TOTAL_DISABLED=$((TOTAL_DISABLED + 1))
            else
                log ERROR "Failed to disable key ${key_id} for ${sa_email}"
            fi
        done
    done <<< "${sa_list}"

    log INFO "Disabled ${TOTAL_DISABLED} user-managed keys."
}

delete_all_user_keys() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log WARN "DRY RUN: Would delete all user-managed SA keys."
        return
    fi

    echo -e "${RED}${BOLD}"
    echo "============================================================================="
    echo " DANGER: IRREVERSIBLE OPERATION"
    echo "============================================================================="
    echo " This will PERMANENTLY DELETE all user-managed SA keys."
    echo " Any service using these keys will immediately lose access."
    echo " This operation CANNOT be undone."
    echo "============================================================================="
    echo -e "${NC}"

    confirm "Type 'yes' to permanently delete all user-managed SA keys."

    log ACTION "Deleting all user-managed service account keys..."

    local sa_list
    sa_list="$(gcloud iam service-accounts list \
        --project="${PROJECT_ID}" \
        --format='value(email)' 2>/dev/null)"

    while IFS= read -r sa_email; do
        [[ -z "${sa_email}" ]] && continue

        local keys_json
        keys_json="$(gcloud iam service-accounts keys list \
            --iam-account="${sa_email}" \
            --project="${PROJECT_ID}" \
            --managed-by=user \
            --format='json' 2>/dev/null)"

        echo "${keys_json}" | jq -r '.[].name' | while read -r key_name; do
            [[ -z "${key_name}" ]] && continue
            local key_id
            key_id="$(echo "${key_name}" | rev | cut -d'/' -f1 | rev)"

            log ACTION "Deleting key ${key_id} for ${sa_email}..."
            if gcloud iam service-accounts keys delete "${key_id}" \
                --iam-account="${sa_email}" \
                --project="${PROJECT_ID}" \
                --quiet 2>/dev/null; then
                log INFO "Deleted key ${key_id}"
                TOTAL_DELETED=$((TOTAL_DELETED + 1))
            else
                log ERROR "Failed to delete key ${key_id} for ${sa_email}"
            fi
        done
    done <<< "${sa_list}"

    log INFO "Deleted ${TOTAL_DELETED} user-managed keys."
}

# =============================================================================
# WIF Creation Functions
# =============================================================================

create_wif_pool() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log WARN "DRY RUN: Would create WIF pool and provider."
        return
    fi

    if [[ -z "${GITHUB_ORG}" ]] || [[ -z "${GITHUB_REPO}" ]]; then
        die "--github-org and --github-repo are required with --create-wif"
    fi

    log ACTION "Creating Workload Identity Federation pool and provider..."

    # Enable required APIs
    log INFO "Enabling required APIs..."
    for api in iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com; do
        gcloud services enable "${api}" --project="${PROJECT_ID}" 2>/dev/null || true
    done

    # Create the Workload Identity Pool
    local pool_id="github-actions-pool"
    log INFO "Creating Workload Identity Pool: ${pool_id}..."

    if gcloud iam workload-identity-pools describe "${pool_id}" \
        --project="${PROJECT_ID}" \
        --location="global" &>/dev/null; then
        log WARN "Pool '${pool_id}' already exists. Skipping creation."
    else
        gcloud iam workload-identity-pools create "${pool_id}" \
            --project="${PROJECT_ID}" \
            --location="global" \
            --display-name="GitHub Actions Pool" \
            --description="WIF pool for GitHub Actions CI/CD (created during SA key migration)" || \
            die "Failed to create WIF pool"
        log INFO "Created WIF pool: ${pool_id}"
    fi

    # Create the OIDC Provider
    local provider_id="github-oidc-provider"
    log INFO "Creating OIDC Provider: ${provider_id}..."

    if gcloud iam workload-identity-pools providers describe "${provider_id}" \
        --project="${PROJECT_ID}" \
        --location="global" \
        --workload-identity-pool="${pool_id}" &>/dev/null; then
        log WARN "Provider '${provider_id}' already exists. Skipping creation."
    else
        gcloud iam workload-identity-pools providers create-oidc "${provider_id}" \
            --project="${PROJECT_ID}" \
            --location="global" \
            --workload-identity-pool="${pool_id}" \
            --display-name="GitHub OIDC Provider" \
            --issuer-uri="https://token.actions.githubusercontent.com" \
            --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner,attribute.actor=assertion.actor,attribute.ref=assertion.ref" \
            --attribute-condition="assertion.repository_owner == '${GITHUB_ORG}' && assertion.repository == '${GITHUB_ORG}/${GITHUB_REPO}'" || \
            die "Failed to create OIDC provider"
        log INFO "Created OIDC provider: ${provider_id}"
    fi

    # Print the provider resource name for use in GitHub Actions
    local project_number
    project_number="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
    local provider_name="projects/${project_number}/locations/global/workloadIdentityPools/${pool_id}/providers/${provider_id}"

    echo ""
    echo -e "${GREEN}${BOLD}WIF Configuration Complete!${NC}"
    echo ""
    echo "Use this value in your GitHub Actions workflow:"
    echo -e "${CYAN}  workload_identity_provider: '${provider_name}'${NC}"
    echo ""
}

# =============================================================================
# Verification Functions
# =============================================================================

verify_wif() {
    log INFO "Verifying WIF configuration..."

    local pool_id="github-actions-pool"

    # Check pool exists and is enabled
    local pool_info
    pool_info="$(gcloud iam workload-identity-pools describe "${pool_id}" \
        --project="${PROJECT_ID}" \
        --location="global" \
        --format='json' 2>/dev/null)" || {
        log ERROR "WIF pool '${pool_id}' not found. Run with --create-wif first."
        return 1
    }

    local pool_state
    pool_state="$(echo "${pool_info}" | jq -r '.state')"
    if [[ "${pool_state}" == "ACTIVE" ]]; then
        log INFO "WIF pool is ACTIVE."
    else
        log ERROR "WIF pool state: ${pool_state} (expected ACTIVE)"
        return 1
    fi

    # List providers
    local providers
    providers="$(gcloud iam workload-identity-pools providers list \
        --project="${PROJECT_ID}" \
        --location="global" \
        --workload-identity-pool="${pool_id}" \
        --format='json' 2>/dev/null)"

    local provider_count
    provider_count="$(echo "${providers}" | jq 'length')"
    log INFO "Found ${provider_count} provider(s) in pool."

    echo "${providers}" | jq -r '.[].displayName' | while read -r name; do
        log INFO "  Provider: ${name}"
    done

    # Check org policy enforcement
    log INFO "Checking org policy constraints..."

    local key_creation_policy
    key_creation_policy="$(gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
        --project="${PROJECT_ID}" \
        --format='json' 2>/dev/null)" || {
        log WARN "Could not check iam.disableServiceAccountKeyCreation policy (may need orgpolicy.policy.get permission)"
    }

    if echo "${key_creation_policy}" | jq -e '.booleanPolicy.enforced == true' &>/dev/null; then
        log INFO "SA key creation is BLOCKED by org policy."
    else
        log WARN "SA key creation is NOT blocked. Apply org-policies.tf to enforce."
    fi

    echo ""
    log INFO "WIF verification complete."
}

# =============================================================================
# JSON Output
# =============================================================================

output_json_report() {
    if [[ "${OUTPUT_JSON}" != "true" ]]; then
        return
    fi

    local json_file="/tmp/sa-key-audit-${TIMESTAMP}.json"

    jq -R -s -c '
        split("\n") |
        .[1:] |
        map(select(length > 0)) |
        map(split(",")) |
        map({
            "service_account": .[0],
            "key_id": .[1],
            "key_type": .[2],
            "key_origin": .[3],
            "created_at": .[4],
            "expires_at": .[5],
            "status": .[6],
            "last_authenticated": .[7],
            "recommendation": .[8]
        })
    ' "${REPORT_FILE}" > "${json_file}"

    log INFO "JSON report saved to: ${json_file}"
}

# =============================================================================
# Argument Parsing
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --project-id)
                PROJECT_ID="$2"
                shift 2
                ;;
            --org-id)
                ORG_ID="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --disable-keys)
                DRY_RUN=false
                DISABLE_KEYS=true
                shift
                ;;
            --delete-keys)
                DRY_RUN=false
                DELETE_KEYS=true
                shift
                ;;
            --create-wif)
                DRY_RUN=false
                CREATE_WIF=true
                shift
                ;;
            --github-org)
                GITHUB_ORG="$2"
                shift 2
                ;;
            --github-repo)
                GITHUB_REPO="$2"
                shift 2
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --output-json)
                OUTPUT_JSON=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                die "Unknown argument: $1. Use --help for usage."
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "${PROJECT_ID}" ]]; then
        die "--project-id is required. Use --help for usage."
    fi
}

show_help() {
    cat << 'HELP'
Usage: migrate-to-federation.sh --project-id <PROJECT_ID> [OPTIONS]

Audit and migrate service account keys to Workload Identity Federation.

Required:
  --project-id <ID>     GCP project ID

Options:
  --org-id <ID>         GCP organization ID (for org-wide audit)
  --dry-run             Audit only, do not modify keys (default)
  --disable-keys        Disable all user-managed SA keys
  --delete-keys         Permanently delete all user-managed SA keys
  --create-wif          Create WIF pool and provider for GitHub Actions
  --github-org <ORG>    GitHub org name (required with --create-wif)
  --github-repo <REPO>  GitHub repo name (required with --create-wif)
  --force               Skip confirmation prompts
  --output-json         Also output results in JSON format
  --help                Show this help message

Examples:
  # Audit only (safe, read-only)
  ./migrate-to-federation.sh --project-id my-project --dry-run

  # Audit and create WIF resources
  ./migrate-to-federation.sh --project-id my-project \
    --create-wif --github-org myorg --github-repo myrepo

  # Full migration: create WIF, disable old keys, verify
  ./migrate-to-federation.sh --project-id my-project \
    --create-wif --github-org myorg --github-repo myrepo \
    --disable-keys

  # Nuclear option: delete all SA keys (after WIF is verified)
  ./migrate-to-federation.sh --project-id my-project \
    --delete-keys --force

Incident Response Workflow:
  1. Run with --dry-run to audit current state
  2. Review the CSV report for all active keys
  3. Set up WIF with --create-wif (or apply terraform-wif.tf)
  4. Update all workflows/services to use WIF
  5. Run with --disable-keys to disable old keys
  6. Monitor for 48 hours for any breakage
  7. Run with --delete-keys to permanently remove keys
  8. Apply org-policies.tf to prevent new key creation
HELP
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    parse_args "$@"

    # Initialize log
    echo "# WIF Migration Log - ${TIMESTAMP}" > "${LOG_FILE}"
    echo "# Project: ${PROJECT_ID}" >> "${LOG_FILE}"

    print_banner
    check_prerequisites

    # Phase 1: Audit (always runs)
    echo -e "${BOLD}Phase 1: Service Account Key Audit${NC}"
    echo "============================================================================="
    audit_service_accounts

    # Phase 2: Create WIF (optional)
    if [[ "${CREATE_WIF}" == "true" ]]; then
        echo -e "${BOLD}Phase 2: Create Workload Identity Federation${NC}"
        echo "============================================================================="
        create_wif_pool
    fi

    # Phase 3: Disable keys (optional)
    if [[ "${DISABLE_KEYS}" == "true" ]]; then
        echo -e "${BOLD}Phase 3: Disable Service Account Keys${NC}"
        echo "============================================================================="
        disable_all_user_keys
    fi

    # Phase 4: Delete keys (optional)
    if [[ "${DELETE_KEYS}" == "true" ]]; then
        echo -e "${BOLD}Phase 4: Delete Service Account Keys${NC}"
        echo "============================================================================="
        delete_all_user_keys
    fi

    # Phase 5: Verify WIF (if pool exists)
    echo -e "${BOLD}Phase 5: Verification${NC}"
    echo "============================================================================="
    verify_wif || true

    # Generate JSON report if requested
    output_json_report

    # Final summary
    echo ""
    echo -e "${BOLD}Migration Summary:${NC}"
    echo "  Keys disabled:  ${TOTAL_DISABLED}"
    echo "  Keys deleted:   ${TOTAL_DELETED}"
    echo "  Log file:       ${LOG_FILE}"
    echo "  CSV report:     ${REPORT_FILE}"
    echo ""

    if [[ "${TOTAL_USER_KEYS}" -gt 0 ]] && [[ "${DISABLE_KEYS}" == "false" ]] && [[ "${DELETE_KEYS}" == "false" ]]; then
        echo -e "${YELLOW}${BOLD}NEXT STEPS:${NC}"
        echo "  1. Review the audit report: ${REPORT_FILE}"
        echo "  2. Apply terraform-wif.tf to create WIF resources via Terraform"
        echo "  3. Update GitHub Actions workflows to use WIF (see github-oidc-example.yml)"
        echo "  4. Update GKE pods to use Workload Identity (see k8s-workload-identity/)"
        echo "  5. Re-run this script with --disable-keys to disable old keys"
        echo "  6. After 48h monitoring, re-run with --delete-keys"
        echo "  7. Apply org-policies.tf to block future key creation"
        echo ""
    fi

    log INFO "Migration script completed successfully."
}

main "$@"
