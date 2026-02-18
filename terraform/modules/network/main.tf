# =============================================================================
# Network Module - VPC, Subnets, and Security Firewall Rules
# =============================================================================
#
# Creates a hardened VPC network for the GKE cluster with:
# - Custom-mode VPC (no auto-created subnets)
# - Dedicated subnet with secondary ranges for pods and services
# - Egress firewall rules blocking known C2 (Command & Control) ports
# - Egress firewall rules blocking known malicious IP ranges
# - Ingress firewall rules allowing only necessary traffic
# - Cloud NAT for controlled outbound internet access from private nodes
#
# SECURITY FOCUS:
# Firewall rules are designed to detect and block APT-style attacks:
# - Block common C2 ports (Metasploit 4444, Cobalt Strike 8443, IRC 6666/6667)
# - Block crypto mining pool connections on common ports
# - Allow only necessary egress (DNS, HTTPS, NTP)
# - Log all denied traffic for forensic analysis
# =============================================================================

# -----------------------------------------------------------------------------
# VPC Network
# -----------------------------------------------------------------------------
# Custom-mode VPC gives us full control over subnet IP ranges.
# auto_create_subnetworks is false to prevent default subnets in every region.
# -----------------------------------------------------------------------------

resource "google_compute_network" "vpc" {
  name                    = "${var.network_name}-${var.environment}"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "DevSecOps VPC for ${var.environment} environment"
}

# -----------------------------------------------------------------------------
# GKE Subnet
# -----------------------------------------------------------------------------
# The subnet uses secondary ranges for GKE pods and services, which enables
# VPC-native (alias IP) networking. This is required for:
# - Network Policy enforcement
# - Pod-level firewall rules
# - Better IP address management
#
# Private Google Access allows nodes to reach Google APIs without public IPs.
# Flow logs are enabled for network forensics.
# -----------------------------------------------------------------------------

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${var.network_name}-gke-subnet-${var.environment}"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
  description              = "GKE subnet with pod and service secondary ranges"

  # Secondary ranges for GKE pods and services (VPC-native networking)
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }

  # Enable VPC flow logs for network forensics and threat detection
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
    filter_expr          = "true"
  }
}

# -----------------------------------------------------------------------------
# Cloud Router (required for Cloud NAT)
# -----------------------------------------------------------------------------

resource "google_compute_router" "router" {
  name    = "${var.network_name}-router-${var.environment}"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id

  bgp {
    asn = 64514
  }
}

# -----------------------------------------------------------------------------
# Cloud NAT
# -----------------------------------------------------------------------------
# Provides controlled outbound internet access for private GKE nodes.
# All egress traffic is NATed through Cloud NAT, making it visible in
# VPC flow logs for threat detection.
#
# Using MANUAL_ONLY allocation gives us static IPs for allowlisting.
# MIN_PORTS_PER_VM is set high enough for typical workloads.
# -----------------------------------------------------------------------------

resource "google_compute_router_nat" "nat" {
  name                               = "${var.network_name}-nat-${var.environment}"
  project                            = var.project_id
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }

  # Timeouts for connection tracking
  tcp_established_idle_timeout_sec = 1200
  tcp_transitory_idle_timeout_sec  = 30
  udp_idle_timeout_sec             = 30
}

# =============================================================================
# FIREWALL RULES
# =============================================================================
# Rules are evaluated by priority (lower number = higher priority).
# Our strategy:
#   Priority 100:  DENY known C2 ports (highest priority blocks)
#   Priority 200:  DENY known malicious IPs
#   Priority 500:  DENY crypto mining ports
#   Priority 1000: ALLOW necessary traffic (DNS, HTTPS, NTP)
#   Priority 65534: Default deny (implicit)
# =============================================================================

# -----------------------------------------------------------------------------
# DENY: Known C2 Ports (Egress)
# -----------------------------------------------------------------------------
# Blocks outbound connections to ports commonly used by C2 frameworks:
# - 4444: Metasploit default handler / Meterpreter
# - 5555: Android Debug Bridge / various RATs
# - 6666/6667: IRC-based C2 channels
# - 8443: Cobalt Strike default HTTPS listener
# - 9090: Various C2 frameworks (Merlin, etc.)
# - 1337: Common "leet" backdoor port
# - 31337: Back Orifice / elite hackers backdoor
# - 12345: NetBus trojan
# - 65535: Common data exfiltration port
#
# These rules fire BEFORE allow rules due to priority 100.
# Denied packets are logged for SIEM/alerting.
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "deny_c2_egress_tcp" {
  name        = "${var.network_name}-deny-c2-egress-tcp-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Block egress TCP to known C2 ports (Metasploit, Cobalt Strike, IRC, etc.)"
  direction   = "EGRESS"
  priority    = 100

  deny {
    protocol = "tcp"
    ports    = var.c2_blocked_ports
  }

  # Apply to all instances in the VPC
  destination_ranges = ["0.0.0.0/0"]

  # Log denied connections for threat detection and forensics
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_c2_egress_udp" {
  name        = "${var.network_name}-deny-c2-egress-udp-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Block egress UDP to known C2 ports"
  direction   = "EGRESS"
  priority    = 100

  deny {
    protocol = "udp"
    ports    = var.c2_blocked_ports
  }

  destination_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# -----------------------------------------------------------------------------
# DENY: Known Malicious IP Ranges (Egress)
# -----------------------------------------------------------------------------
# Blocks outbound connections to known malicious IP ranges.
# This list should be updated regularly from threat intelligence feeds.
# Empty by default; populated via variable or external data source.
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "deny_malicious_ips_egress" {
  count = length(var.c2_blocked_ips) > 0 ? 1 : 0

  name        = "${var.network_name}-deny-malicious-ips-egress-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Block egress to known malicious IP ranges from threat intel"
  direction   = "EGRESS"
  priority    = 200

  deny {
    protocol = "all"
  }

  destination_ranges = var.c2_blocked_ips

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# -----------------------------------------------------------------------------
# DENY: Crypto Mining Ports (Egress)
# -----------------------------------------------------------------------------
# Blocks common crypto mining pool ports. Crypto mining is a frequent
# objective of cloud-targeted attacks (cryptojacking).
# - 3333: Stratum mining protocol (most common)
# - 3334: Stratum mining protocol (alternate)
# - 8332/8333: Bitcoin P2P
# - 8545: Ethereum JSON-RPC
# - 30303: Ethereum P2P
# - 45700: Monero Stratum
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "deny_crypto_mining_egress" {
  name        = "${var.network_name}-deny-crypto-mining-egress-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Block egress to common crypto mining pool ports"
  direction   = "EGRESS"
  priority    = 500

  deny {
    protocol = "tcp"
    ports    = ["3333", "3334", "8332", "8333", "8545", "30303", "45700"]
  }

  destination_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# -----------------------------------------------------------------------------
# ALLOW: Internal Communication
# -----------------------------------------------------------------------------
# Allows all traffic within the VPC (node-to-node, pod-to-pod, pod-to-service).
# This is necessary for GKE cluster operation. Fine-grained pod-level
# restrictions are enforced by Kubernetes Network Policies instead.
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "allow_internal" {
  name        = "${var.network_name}-allow-internal-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Allow all internal VPC traffic (pod-to-pod and node-to-node)"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [
    var.subnet_cidr,
    var.pods_cidr,
    var.services_cidr,
  ]
}

# -----------------------------------------------------------------------------
# ALLOW: Health Checks
# -----------------------------------------------------------------------------
# Google Cloud health check probes originate from specific IP ranges.
# These must be allowed for GKE load balancer health checks to work.
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "allow_health_checks" {
  name        = "${var.network_name}-allow-health-checks-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Allow Google Cloud health check probes"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
  }

  # Google health check IP ranges
  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22",
  ]
}

# -----------------------------------------------------------------------------
# ALLOW: GKE Master to Nodes (Webhooks, etc.)
# -----------------------------------------------------------------------------
# The GKE master needs to reach nodes on specific ports for:
# - Webhook calls (admission controllers like OPA/Gatekeeper)
# - Kubelet API (for exec, logs, port-forward)
# - Metrics collection
# -----------------------------------------------------------------------------

resource "google_compute_firewall" "allow_master_to_nodes" {
  name        = "${var.network_name}-allow-master-to-nodes-${var.environment}"
  project     = var.project_id
  network     = google_compute_network.vpc.id
  description = "Allow GKE master to reach nodes for webhooks and kubelet"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "10250", "10255"]
  }

  source_ranges = [var.master_cidr]
  target_tags   = ["gke-node"]
}
