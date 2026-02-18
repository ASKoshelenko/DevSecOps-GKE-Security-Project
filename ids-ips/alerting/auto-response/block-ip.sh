#!/usr/bin/env bash
# =============================================================================
# Block IP - Add Firewall Rule to Block C2 Server IP
# =============================================================================
#
# This script creates a GCP firewall rule to block egress traffic to a
# specified IP address (typically a C2 server identified by IDS). The
# rule is applied at the VPC level, blocking ALL GKE pods from reaching
# the malicious IP.
#
# Usage:
#   ./block-ip.sh <ip-address> [--network <vpc-name>] [--project <project-id>] [--dry-run]
#
# What it does:
#   1. Validates the IP address format
#   2. Checks if a firewall rule already exists for this IP
#   3. Creates a high-priority egress deny rule for the IP
#   4. Verifies the rule is applied
#   5. Logs the action for audit trail
#
# The firewall rule:
#   - Direction: EGRESS (outbound from our network)
#   - Action: DENY
#   - Priority: 100 (high priority, overrides allow rules)
#   - Protocols: ALL (TCP, UDP, ICMP)
#   - Target: ALL instances in the VPC
#
# Prerequisites:
#   - gcloud CLI configured with appropriate credentials
#   - Compute Admin or Security Admin role
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="/var/log/security/block-ip-$(date +%Y%m%d-%H%M%S).log"

# Defaults
DEFAULT_NETWORK="devsecops-vpc"
DEFAULT_PROJECT=""  # Uses gcloud default project

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
Usage: ${SCRIPT_NAME} <ip-address> [options]

Block egress traffic to a malicious IP by creating a GCP firewall rule.

Arguments:
  ip-address    IP address to block (e.g., 203.0.113.50)

Options:
  --network     VPC network name (default: ${DEFAULT_NETWORK})
  --project     GCP project ID (default: gcloud default)
  --dry-run     Show what would be done without applying changes

Examples:
  ${SCRIPT_NAME} 203.0.113.50
  ${SCRIPT_NAME} 198.51.100.0/24 --network production-vpc
  ${SCRIPT_NAME} 10.0.0.1 --dry-run
EOF
    exit 1
}

validate_ip() {
    local ip="$1"
    # Accept both single IPs and CIDR notation
    if [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    fi
    return 1
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    usage
fi

BLOCK_IP="$1"
shift

NETWORK="${DEFAULT_NETWORK}"
PROJECT="${DEFAULT_PROJECT}"
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --project)
            PROJECT="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN="true"
            warn "DRY RUN MODE - No changes will be applied"
            shift
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Add /32 if no CIDR specified (single host)
if [[ ! "${BLOCK_IP}" =~ / ]]; then
    BLOCK_IP_CIDR="${BLOCK_IP}/32"
else
    BLOCK_IP_CIDR="${BLOCK_IP}"
fi

# Validate IP format
if ! validate_ip "${BLOCK_IP}"; then
    error "Invalid IP address format: ${BLOCK_IP}"
fi

# Build project flag
PROJECT_FLAG=""
if [[ -n "${PROJECT}" ]]; then
    PROJECT_FLAG="--project=${PROJECT}"
else
    PROJECT=$(gcloud config get-value project 2>/dev/null)
fi

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------
info "Starting C2 IP blocking procedure for ${BLOCK_IP}"

# Check gcloud is available
if ! command -v gcloud &>/dev/null; then
    error "gcloud CLI is not installed or not in PATH"
fi

# Verify authentication
if ! gcloud auth print-identity-token &>/dev/null; then
    error "Not authenticated with gcloud. Run: gcloud auth login"
fi

# Generate unique firewall rule name
# Replace dots and slashes with dashes for valid rule name
RULE_NAME="block-c2-$(echo "${BLOCK_IP}" | tr './' '--')-$(date +%Y%m%d%H%M%S)"
# Ensure rule name is lowercase and valid
RULE_NAME=$(echo "${RULE_NAME}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')

# Check if a rule already exists for this IP
EXISTING_RULES=$(gcloud compute firewall-rules list \
    ${PROJECT_FLAG} \
    --filter="name~block-c2 AND direction=EGRESS" \
    --format="value(name,destinationRanges)" 2>/dev/null | grep -c "${BLOCK_IP}" || true)

if [[ "${EXISTING_RULES}" -gt 0 ]]; then
    warn "A firewall rule blocking ${BLOCK_IP} may already exist."
    warn "Proceeding to create an additional rule for completeness."
fi

# -----------------------------------------------------------------------------
# Step 1: Create Egress Deny Firewall Rule
# -----------------------------------------------------------------------------
info "Step 1: Creating egress deny firewall rule"
info "  Rule name:    ${RULE_NAME}"
info "  Network:      ${NETWORK}"
info "  Blocked IP:   ${BLOCK_IP_CIDR}"
info "  Direction:    EGRESS"
info "  Action:       DENY"
info "  Priority:     100"
info "  Protocols:    ALL"

if [[ -z "${DRY_RUN}" ]]; then
    gcloud compute firewall-rules create "${RULE_NAME}" \
        ${PROJECT_FLAG} \
        --network="${NETWORK}" \
        --direction=EGRESS \
        --action=DENY \
        --rules=all \
        --destination-ranges="${BLOCK_IP_CIDR}" \
        --priority=100 \
        --description="[AUTO-RESPONSE] Block C2 server ${BLOCK_IP} - detected at ${TIMESTAMP}" \
        --enable-logging \
        --quiet

    info "Firewall rule created successfully"
else
    info "[DRY RUN] Would create firewall rule: ${RULE_NAME}"
fi

# -----------------------------------------------------------------------------
# Step 2: Verify Rule Application
# -----------------------------------------------------------------------------
info "Step 2: Verifying firewall rule"

if [[ -z "${DRY_RUN}" ]]; then
    RULE_STATUS=$(gcloud compute firewall-rules describe "${RULE_NAME}" \
        ${PROJECT_FLAG} \
        --format="value(disabled)" 2>/dev/null || echo "UNKNOWN")

    if [[ "${RULE_STATUS}" == "False" ]]; then
        info "Firewall rule is ACTIVE and blocking traffic to ${BLOCK_IP}"
    else
        warn "Firewall rule status: ${RULE_STATUS} - manual verification recommended"
    fi
fi

# -----------------------------------------------------------------------------
# Step 3: Log the Action
# -----------------------------------------------------------------------------
info "Step 3: Recording audit log entry"

AUDIT_ENTRY=$(cat <<EOF
{
    "action": "block_c2_ip",
    "timestamp": "${TIMESTAMP}",
    "blocked_ip": "${BLOCK_IP}",
    "blocked_cidr": "${BLOCK_IP_CIDR}",
    "firewall_rule": "${RULE_NAME}",
    "network": "${NETWORK}",
    "project": "${PROJECT}",
    "reason": "C2 server detected by IDS/IPS",
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
echo "  C2 IP BLOCKED"
echo "============================================================================="
echo ""
echo "  Blocked IP:      ${BLOCK_IP_CIDR}"
echo "  Firewall Rule:   ${RULE_NAME}"
echo "  Network:         ${NETWORK}"
echo "  Project:         ${PROJECT}"
echo "  Priority:        100 (high - overrides lower-priority allow rules)"
echo "  Timestamp:       ${TIMESTAMP}"
echo ""
echo "  All egress traffic to ${BLOCK_IP} is now BLOCKED across the entire VPC."
echo ""
echo "  TO UNBLOCK (after investigation):"
echo "    gcloud compute firewall-rules delete ${RULE_NAME} ${PROJECT_FLAG}"
echo ""
echo "  TO LIST ALL C2 BLOCKS:"
echo "    gcloud compute firewall-rules list ${PROJECT_FLAG} --filter='name~block-c2'"
echo ""
echo "============================================================================="

info "C2 IP blocking procedure completed"
