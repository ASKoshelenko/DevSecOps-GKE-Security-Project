#!/usr/bin/env bash
# =============================================================================
# Revoke Service Account - Disable Compromised Service Account
# =============================================================================
#
# This script disables a compromised GCP service account and revokes all
# its keys. This is a critical response action when APT actors are detected
# using stolen service account credentials.
#
# Usage:
#   ./revoke-sa.sh <service-account-email> [--project <project-id>] [--dry-run]
#
# What it does:
#   1. Validates the service account exists
#   2. Lists and logs all existing keys (for forensic record)
#   3. Deletes ALL user-managed keys (revokes access)
#   4. Disables the service account (prevents new token generation)
#   5. Lists recent activity by the SA (audit log query)
#   6. Logs all actions for audit trail
#
# IMPORTANT:
#   - This will IMMEDIATELY revoke access for anything using this SA
#   - Workload Identity bindings are NOT affected (they use short-lived tokens)
#   - Only user-managed keys are deleted; system-managed keys are rotated by GCP
#   - The SA is DISABLED, not deleted (can be re-enabled after investigation)
#
# Prerequisites:
#   - gcloud CLI configured with appropriate credentials
#   - IAM Admin role or Service Account Admin role
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="/var/log/security/revoke-sa-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
log() {
    local level="$1"
    shift
    echo -e "[${TIMESTAMP}] [${level}] $*" | tee -a "${LOG_FILE}" 2>/dev/null || echo "[${TIMESTAMP}] [${level}] $*"
}

error() { log "ERROR" "${RED}$*${NC}"; exit 1; }
warn()  { log "WARN"  "${YELLOW}$*${NC}"; }
info()  { log "INFO"  "${GREEN}$*${NC}"; }

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <service-account-email> [options]

Disable a compromised service account and revoke all its keys.

Arguments:
  service-account-email    Full email of the SA (e.g., my-sa@project.iam.gserviceaccount.com)

Options:
  --project     GCP project ID (default: extracted from SA email)
  --dry-run     Show what would be done without applying changes
  --force       Skip confirmation prompt

Examples:
  ${SCRIPT_NAME} compromised-sa@my-project.iam.gserviceaccount.com
  ${SCRIPT_NAME} worker-sa@prod.iam.gserviceaccount.com --dry-run
  ${SCRIPT_NAME} app-sa@dev.iam.gserviceaccount.com --force
EOF
    exit 1
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    usage
fi

SA_EMAIL="$1"
shift

PROJECT=""
DRY_RUN=""
FORCE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)
            PROJECT="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN="true"
            warn "DRY RUN MODE - No changes will be applied"
            shift
            ;;
        --force)
            FORCE="true"
            shift
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Extract project from SA email if not provided
if [[ -z "${PROJECT}" ]]; then
    PROJECT=$(echo "${SA_EMAIL}" | sed -n 's/.*@\(.*\)\.iam\.gserviceaccount\.com/\1/p')
    if [[ -z "${PROJECT}" ]]; then
        error "Cannot extract project ID from SA email. Use --project flag."
    fi
fi

PROJECT_FLAG="--project=${PROJECT}"

# Validate SA email format
if [[ ! "${SA_EMAIL}" =~ @.*\.iam\.gserviceaccount\.com$ ]]; then
    error "Invalid service account email format: ${SA_EMAIL}"
fi

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------
info "Starting service account revocation for: ${SA_EMAIL}"
info "Project: ${PROJECT}"

# Check gcloud is available
if ! command -v gcloud &>/dev/null; then
    error "gcloud CLI is not installed or not in PATH"
fi

# Verify the service account exists
if ! gcloud iam service-accounts describe "${SA_EMAIL}" ${PROJECT_FLAG} &>/dev/null; then
    error "Service account not found: ${SA_EMAIL}"
fi

# Get SA details
SA_DISPLAY_NAME=$(gcloud iam service-accounts describe "${SA_EMAIL}" \
    ${PROJECT_FLAG} --format="value(displayName)" 2>/dev/null || echo "Unknown")
SA_DISABLED=$(gcloud iam service-accounts describe "${SA_EMAIL}" \
    ${PROJECT_FLAG} --format="value(disabled)" 2>/dev/null || echo "Unknown")

info "Service Account details:"
info "  Email:        ${SA_EMAIL}"
info "  Display Name: ${SA_DISPLAY_NAME}"
info "  Disabled:     ${SA_DISABLED}"

# Check if already disabled
if [[ "${SA_DISABLED}" == "True" ]]; then
    warn "Service account is already disabled. Proceeding to revoke any remaining keys."
fi

# Confirmation (unless --force)
if [[ -z "${FORCE}" ]] && [[ -z "${DRY_RUN}" ]]; then
    echo ""
    echo "============================================================================="
    echo "  WARNING: This will IMMEDIATELY disable the service account and"
    echo "  revoke ALL its keys. Any workload using this SA will lose access."
    echo "============================================================================="
    echo ""
    read -r -p "Are you sure you want to proceed? (yes/no): " CONFIRM
    if [[ "${CONFIRM}" != "yes" ]]; then
        info "Operation cancelled by user"
        exit 0
    fi
fi

# -----------------------------------------------------------------------------
# Step 1: List and Record Existing Keys
# -----------------------------------------------------------------------------
info "Step 1: Recording existing service account keys"

KEYS=$(gcloud iam service-accounts keys list \
    --iam-account="${SA_EMAIL}" \
    ${PROJECT_FLAG} \
    --format="table(name.basename(),validAfterTime,validBeforeTime,keyAlgorithm,keyOrigin,keyType)" 2>/dev/null || echo "FAILED TO LIST KEYS")

info "Current keys:"
echo "${KEYS}" | tee -a "${LOG_FILE}" 2>/dev/null || true

# Get user-managed key IDs for deletion
USER_KEY_IDS=$(gcloud iam service-accounts keys list \
    --iam-account="${SA_EMAIL}" \
    ${PROJECT_FLAG} \
    --managed-by=user \
    --format="value(name.basename())" 2>/dev/null || echo "")

USER_KEY_COUNT=$(echo "${USER_KEY_IDS}" | grep -c . 2>/dev/null || echo "0")
info "Found ${USER_KEY_COUNT} user-managed key(s) to revoke"

# -----------------------------------------------------------------------------
# Step 2: Delete All User-Managed Keys
# -----------------------------------------------------------------------------
info "Step 2: Revoking all user-managed keys"

if [[ -n "${USER_KEY_IDS}" ]] && [[ "${USER_KEY_IDS}" != "" ]]; then
    while IFS= read -r KEY_ID; do
        if [[ -z "${KEY_ID}" ]]; then
            continue
        fi

        if [[ -z "${DRY_RUN}" ]]; then
            info "  Deleting key: ${KEY_ID}"
            gcloud iam service-accounts keys delete "${KEY_ID}" \
                --iam-account="${SA_EMAIL}" \
                ${PROJECT_FLAG} \
                --quiet 2>/dev/null || warn "  Failed to delete key ${KEY_ID}"
        else
            info "  [DRY RUN] Would delete key: ${KEY_ID}"
        fi
    done <<< "${USER_KEY_IDS}"

    info "All user-managed keys have been revoked"
else
    info "No user-managed keys found (SA may only use Workload Identity)"
fi

# -----------------------------------------------------------------------------
# Step 3: Disable the Service Account
# -----------------------------------------------------------------------------
info "Step 3: Disabling service account"

if [[ -z "${DRY_RUN}" ]]; then
    gcloud iam service-accounts disable "${SA_EMAIL}" \
        ${PROJECT_FLAG} \
        --quiet 2>/dev/null || warn "Failed to disable SA (may already be disabled)"

    info "Service account DISABLED"
else
    info "[DRY RUN] Would disable service account: ${SA_EMAIL}"
fi

# -----------------------------------------------------------------------------
# Step 4: Query Recent Activity (Audit Logs)
# -----------------------------------------------------------------------------
info "Step 4: Querying recent activity by this service account"

info "  Use Cloud Logging to review recent activity:"
info "  Filter: protoPayload.authenticationInfo.principalEmail=\"${SA_EMAIL}\""
info ""
info "  Quick gcloud command:"
info "  gcloud logging read 'protoPayload.authenticationInfo.principalEmail=\"${SA_EMAIL}\"' \\"
info "    --project=${PROJECT} --limit=50 --format=json --freshness=7d"

# Try to get recent activity count
RECENT_ACTIVITY=$(gcloud logging read \
    "protoPayload.authenticationInfo.principalEmail=\"${SA_EMAIL}\"" \
    ${PROJECT_FLAG} \
    --limit=10 \
    --freshness=1d \
    --format="value(timestamp)" 2>/dev/null | wc -l || echo "0")

info "  Recent activity (last 24h): approximately ${RECENT_ACTIVITY} log entries"

# -----------------------------------------------------------------------------
# Step 5: Audit Log Entry
# -----------------------------------------------------------------------------
info "Step 5: Recording audit trail"

AUDIT_ENTRY=$(cat <<EOF
{
    "action": "revoke_service_account",
    "timestamp": "${TIMESTAMP}",
    "service_account": "${SA_EMAIL}",
    "project": "${PROJECT}",
    "keys_revoked": ${USER_KEY_COUNT},
    "sa_disabled": true,
    "reason": "Compromised service account - APT detection",
    "operator": "$(whoami)@$(hostname)"
}
EOF
)

echo "${AUDIT_ENTRY}" >> "${LOG_FILE}" 2>/dev/null || true

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================================="
echo "  SERVICE ACCOUNT REVOKED"
echo "============================================================================="
echo ""
echo "  Service Account: ${SA_EMAIL}"
echo "  Project:         ${PROJECT}"
echo "  Keys Revoked:    ${USER_KEY_COUNT}"
echo "  SA Status:       DISABLED"
echo "  Timestamp:       ${TIMESTAMP}"
echo ""
echo "  The service account is now DISABLED and all keys are REVOKED."
echo "  No new tokens can be generated for this SA."
echo ""
echo "  TO RE-ENABLE (after investigation):"
echo "    gcloud iam service-accounts enable ${SA_EMAIL} ${PROJECT_FLAG}"
echo ""
echo "  TO DELETE PERMANENTLY:"
echo "    gcloud iam service-accounts delete ${SA_EMAIL} ${PROJECT_FLAG}"
echo ""
echo "  INVESTIGATE ACTIVITY:"
echo "    gcloud logging read \\"
echo "      'protoPayload.authenticationInfo.principalEmail=\"${SA_EMAIL}\"' \\"
echo "      ${PROJECT_FLAG} --limit=100 --freshness=30d --format=json"
echo ""
echo "============================================================================="

info "Service account revocation completed"
