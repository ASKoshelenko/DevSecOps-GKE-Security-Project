#!/usr/bin/env bash
# =============================================================================
# run_extraction.sh
# =============================================================================
# Wrapper script for the Trivy vulnerability extraction pipeline.
#
# This script handles environment setup, dependency verification, and
# execution of the extract_vulnerabilities.py script with configurable
# parameters.
#
# Usage:
#   ./run_extraction.sh                          # Use defaults from env vars
#   ./run_extraction.sh --dry-run                # Preview without writing
#   ./run_extraction.sh --start-date 2025-01-01  # Specific date range
#
# Environment variables:
#   GCP_PROJECT_ID   - (Required) GCP project ID
#   BQ_DATASET       - (Required) BigQuery dataset name
#   BQ_RAW_TABLE     - Raw logs table name (default: trivy_raw_logs)
#   BQ_VULN_TABLE    - Vulnerabilities table name (default: vulnerabilities)
#   BATCH_SIZE       - Insert batch size (default: 1000)
#   LOG_LEVEL        - Logging level (default: INFO)
#   VENV_DIR         - Virtual environment directory (default: .venv)
#   GOOGLE_APPLICATION_CREDENTIALS - Path to service account key (optional)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Required variables
GCP_PROJECT_ID="${GCP_PROJECT_ID:?'Error: GCP_PROJECT_ID environment variable is required'}"
BQ_DATASET="${BQ_DATASET:?'Error: BQ_DATASET environment variable is required'}"

# Optional variables with defaults
BQ_RAW_TABLE="${BQ_RAW_TABLE:-trivy_raw_logs}"
BQ_VULN_TABLE="${BQ_VULN_TABLE:-vulnerabilities}"
BATCH_SIZE="${BATCH_SIZE:-1000}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
VENV_DIR="${VENV_DIR:-${SCRIPT_DIR}/.venv}"

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------
log_info() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [INFO] $*"
}

log_error() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [ERROR] $*" >&2
}

log_warn() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [WARN] $*" >&2
}

check_prerequisites() {
    local missing=0

    if ! command -v python3 &>/dev/null; then
        log_error "python3 is not installed or not in PATH."
        missing=1
    fi

    if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
        log_error "pip is not installed or not in PATH."
        missing=1
    fi

    if [[ "${missing}" -ne 0 ]]; then
        log_error "Missing prerequisites. Please install the required tools."
        exit 1
    fi
}

setup_virtualenv() {
    if [[ ! -d "${VENV_DIR}" ]]; then
        log_info "Creating Python virtual environment at ${VENV_DIR} ..."
        python3 -m venv "${VENV_DIR}"
    fi

    log_info "Activating virtual environment ..."
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    log_info "Installing/upgrading dependencies ..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "${SCRIPT_DIR}/requirements.txt"
}

verify_gcp_auth() {
    if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
        if [[ ! -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]]; then
            log_error "GOOGLE_APPLICATION_CREDENTIALS points to a non-existent file: ${GOOGLE_APPLICATION_CREDENTIALS}"
            exit 1
        fi
        log_info "Using service account key: ${GOOGLE_APPLICATION_CREDENTIALS}"
    else
        # Check for Application Default Credentials
        if command -v gcloud &>/dev/null; then
            if ! gcloud auth application-default print-access-token &>/dev/null 2>&1; then
                log_warn "No Application Default Credentials found."
                log_warn "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS."
                log_warn "Proceeding anyway -- the script may fail if credentials are not available."
            else
                log_info "Using Application Default Credentials."
            fi
        else
            log_warn "gcloud CLI not found. Assuming credentials are provided via environment."
        fi
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_info "============================================================"
    log_info "Trivy Vulnerability Extraction Pipeline"
    log_info "============================================================"
    log_info "Project:     ${GCP_PROJECT_ID}"
    log_info "Dataset:     ${BQ_DATASET}"
    log_info "Raw table:   ${BQ_RAW_TABLE}"
    log_info "Vuln table:  ${BQ_VULN_TABLE}"
    log_info "Batch size:  ${BATCH_SIZE}"
    log_info "Log level:   ${LOG_LEVEL}"
    log_info "============================================================"

    check_prerequisites
    setup_virtualenv
    verify_gcp_auth

    # Build the argument list
    local args=(
        "--project-id" "${GCP_PROJECT_ID}"
        "--dataset"    "${BQ_DATASET}"
        "--raw-table"  "${BQ_RAW_TABLE}"
        "--vuln-table" "${BQ_VULN_TABLE}"
        "--batch-size" "${BATCH_SIZE}"
        "--log-level"  "${LOG_LEVEL}"
    )

    # Pass through any additional arguments (e.g., --dry-run, --start-date)
    args+=("$@")

    log_info "Starting extraction ..."
    log_info "Command: python3 ${SCRIPT_DIR}/extract_vulnerabilities.py ${args[*]}"

    python3 "${SCRIPT_DIR}/extract_vulnerabilities.py" "${args[@]}"
    local exit_code=$?

    if [[ ${exit_code} -eq 0 ]]; then
        log_info "Extraction pipeline completed successfully."
    else
        log_error "Extraction pipeline failed with exit code ${exit_code}."
    fi

    return ${exit_code}
}

main "$@"
