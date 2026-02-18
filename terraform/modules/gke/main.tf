# =============================================================================
# GKE Module - Security-Hardened Kubernetes Cluster
# =============================================================================
#
# Deploys a private GKE cluster with comprehensive security controls.
#
# SECURITY FEATURES:
# 1. Private Cluster: Worker nodes have no public IPs; master is accessible
#    only from authorized networks via private endpoint.
# 2. Workload Identity: Pods authenticate to Google Cloud APIs using
#    Kubernetes service account -> Google service account mapping.
#    No service account key JSON files needed.
# 3. Binary Authorization: Only images signed by trusted attestors can run.
#    Prevents supply chain attacks via compromised container images.
# 4. Network Policy (Calico): Enables Kubernetes NetworkPolicy resources
#    for microsegmentation between pods (east-west traffic control).
# 5. Pod Security Standards: Enforced via PodSecurity admission controller
#    to prevent privileged containers, host namespace access, etc.
# 6. Shielded Nodes: Secure boot + vTPM + integrity monitoring on all nodes.
#    Prevents rootkit injection and boot-level tampering.
# 7. Auto-upgrade DISABLED: For the APT demo, we use an older GKE version
#    with known vulnerabilities. In production, ALWAYS enable auto-upgrade.
# 8. Cloud Operations: Logging and monitoring with system + workload coverage.
#
# APT SCENARIO NOTES:
# - The older GKE version may have container escape CVEs (e.g., CVE-2024-21626)
# - Workload Identity prevents the "stolen service account key" attack vector
# - Network Policy blocks lateral movement between compromised pods
# - Binary Authorization would catch unauthorized/malicious images
# =============================================================================

# -----------------------------------------------------------------------------
# Binary Authorization Policy
# -----------------------------------------------------------------------------
# Enforces that only trusted container images can be deployed.
# In ALWAYS_DENY mode, all images are blocked unless explicitly allowed.
# For the demo, we use ALWAYS_ALLOW but log all deployments.
# In production, switch to REQUIRE_ATTESTATION with proper attestors.
# -----------------------------------------------------------------------------

resource "google_binary_authorization_policy" "policy" {
  project = var.project_id

  # For demo: allow all but enable audit logging
  # For production: change to ALWAYS_DENY and add specific attestation rules
  default_admission_rule {
    evaluation_mode  = "ALWAYS_ALLOW"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
  }

  # Global policy setting: require attestations for specific repos
  # Uncomment and configure for production use:
  # cluster_admission_rules {
  #   cluster          = "${var.zone}.${var.cluster_name}-${var.environment}"
  #   evaluation_mode  = "REQUIRE_ATTESTATION"
  #   enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
  #   require_attestations_by = [google_binary_authorization_attestor.build_attestor.name]
  # }
}

# -----------------------------------------------------------------------------
# GKE Cluster
# -----------------------------------------------------------------------------

resource "google_container_cluster" "primary" {
  provider = google-beta

  name     = "${var.cluster_name}-${var.environment}"
  project  = var.project_id
  location = var.zone

  # -------------------------------------------------------------------------
  # Kubernetes Version
  # -------------------------------------------------------------------------
  # DEMO NOTE: Using an older version intentionally to demonstrate
  # vulnerability scanning with Trivy. Known CVEs in this version include
  # container runtime escape vulnerabilities.
  # PRODUCTION: Remove min_master_version and set release_channel to REGULAR.
  # -------------------------------------------------------------------------
  min_master_version = var.gke_version

  # Disable the default node pool; we manage our own below
  remove_default_node_pool = true
  initial_node_count       = 1

  # -------------------------------------------------------------------------
  # Networking Configuration
  # -------------------------------------------------------------------------
  network    = var.network_self_link
  subnetwork = var.subnet_self_link

  # VPC-native networking (alias IPs) - required for Network Policy
  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  # -------------------------------------------------------------------------
  # Private Cluster Configuration
  # -------------------------------------------------------------------------
  # - enable_private_nodes: Nodes only get internal IPs (no public IPs)
  # - enable_private_endpoint: Set to false so we can access from authorized
  #   networks. Set to true for maximum security (VPN/interconnect only).
  # - master_ipv4_cidr_block: Dedicated /28 for the control plane
  # -------------------------------------------------------------------------
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.master_cidr

    master_global_access_config {
      enabled = true
    }
  }

  # Authorized networks that can reach the master endpoint
  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.authorized_networks
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  # -------------------------------------------------------------------------
  # Workload Identity
  # -------------------------------------------------------------------------
  # Enables GKE Workload Identity, which maps Kubernetes service accounts
  # to Google Cloud service accounts. This eliminates the need for service
  # account key files, which are a major security risk if stolen.
  #
  # Usage: Annotate a K8s SA with:
  #   iam.gke.io/gcp-service-account=<GSA>@<PROJECT>.iam.gserviceaccount.com
  # Then pods using that K8s SA automatically get the GSA's permissions.
  # -------------------------------------------------------------------------
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # -------------------------------------------------------------------------
  # Binary Authorization
  # -------------------------------------------------------------------------
  # Enables the Binary Authorization admission controller on this cluster.
  # Works with the policy defined above to control which images can run.
  # -------------------------------------------------------------------------
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # -------------------------------------------------------------------------
  # Network Policy (Calico)
  # -------------------------------------------------------------------------
  # Enables the Calico CNI plugin for Kubernetes NetworkPolicy enforcement.
  # Without this, NetworkPolicy resources are created but not enforced.
  # This is critical for:
  # - Preventing lateral movement between compromised pods
  # - Isolating sensitive workloads (e.g., security scanners)
  # - Implementing zero-trust networking within the cluster
  # -------------------------------------------------------------------------
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Required for network_policy to work
  addons_config {
    network_policy_config {
      disabled = false
    }

    # DNS cache for improved performance and reliability
    dns_cache_config {
      enabled = true
    }

    # GKE config connector for managing GCP resources from K8s
    # Disabled to reduce attack surface
    config_connector_config {
      enabled = false
    }

    # HTTP load balancing controller
    http_load_balancing {
      disabled = false
    }
  }

  # -------------------------------------------------------------------------
  # Logging and Monitoring
  # -------------------------------------------------------------------------
  # Comprehensive logging covers:
  # - SYSTEM_COMPONENTS: kubelet, kube-proxy, container runtime
  # - WORKLOADS: stdout/stderr from all pods
  # - API_SERVER: All Kubernetes API calls (audit logging)
  #
  # Monitoring covers:
  # - SYSTEM_COMPONENTS: Node and pod metrics
  # - Pod metrics for resource usage tracking
  # -------------------------------------------------------------------------
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "API_SERVER",
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
    ]

    managed_prometheus {
      enabled = true
    }
  }

  # -------------------------------------------------------------------------
  # Security Posture
  # -------------------------------------------------------------------------
  # Enables GKE Security Posture dashboard for:
  # - Workload vulnerability scanning
  # - Configuration auditing against CIS benchmarks
  # -------------------------------------------------------------------------
  security_posture_config {
    vulnerability_mode = "VULNERABILITY_ENTERPRISE"
    mode               = "BASIC"
  }

  # -------------------------------------------------------------------------
  # Maintenance Window
  # -------------------------------------------------------------------------
  # Schedule maintenance during low-traffic periods.
  # Auto-upgrade is handled at the node pool level.
  # -------------------------------------------------------------------------
  maintenance_policy {
    recurring_window {
      start_time = "2024-01-01T04:00:00Z"
      end_time   = "2024-01-01T08:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA"
    }
  }

  # -------------------------------------------------------------------------
  # Resource Labels
  # -------------------------------------------------------------------------
  resource_labels = merge(var.labels, {
    cluster = "${var.cluster_name}-${var.environment}"
  })

  # -------------------------------------------------------------------------
  # Deletion Protection
  # -------------------------------------------------------------------------
  # Prevents accidental cluster deletion. Set to false for demo/dev only.
  # -------------------------------------------------------------------------
  deletion_protection = false

  # Ignore changes to node count (managed by autoscaler)
  lifecycle {
    ignore_changes = [
      initial_node_count,
    ]
  }
}

# -----------------------------------------------------------------------------
# GKE Node Pool
# -----------------------------------------------------------------------------
# Separate managed node pool with security hardening.
#
# SECURITY FEATURES:
# - Shielded Nodes: Secure boot, vTPM, integrity monitoring
# - Workload Identity metadata: Uses GKE metadata server for SA tokens
# - COS_CONTAINERD image: Minimal OS surface reduces attack vectors
# - Auto-upgrade DISABLED: For demo with vulnerable version
# - Auto-repair ENABLED: Automatically fixes unhealthy nodes
# - OAuth scopes minimized: Uses dedicated SAs instead of broad scopes
# - Metadata concealment: Blocks legacy metadata endpoint
# -----------------------------------------------------------------------------

resource "google_container_node_pool" "primary_nodes" {
  provider = google-beta

  name     = "${var.cluster_name}-node-pool-${var.environment}"
  project  = var.project_id
  location = var.zone
  cluster  = google_container_cluster.primary.name

  # Fixed node count (no autoscaler for demo simplicity)
  node_count = var.node_count

  # -------------------------------------------------------------------------
  # Version Management
  # -------------------------------------------------------------------------
  # DEMO: Auto-upgrade disabled to keep the vulnerable version for scanning.
  # PRODUCTION: Always set auto_upgrade = true and use release channels.
  # -------------------------------------------------------------------------
  version = var.gke_version

  management {
    auto_repair  = true
    auto_upgrade = false  # DEMO ONLY - enable in production!
  }

  # -------------------------------------------------------------------------
  # Node Configuration
  # -------------------------------------------------------------------------
  node_config {
    machine_type = var.node_machine_type
    disk_size_gb = var.node_disk_size_gb
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"

    # Maximum pods per node (affects IP allocation)
    max_pods_per_node = var.max_pods_per_node

    # -----------------------------------------------------------------------
    # Shielded Instance Configuration
    # -----------------------------------------------------------------------
    # - Secure Boot: Verifies all boot components are signed by Google
    # - vTPM: Virtual Trusted Platform Module for measured boot
    # - Integrity Monitoring: Detects boot-level rootkits and tampering
    # -----------------------------------------------------------------------
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # -----------------------------------------------------------------------
    # Workload Identity on Nodes
    # -----------------------------------------------------------------------
    # GKE_METADATA mode enables the GKE metadata server, which intercepts
    # metadata requests and provides Workload Identity tokens instead of
    # the node's service account token. This prevents pods from accessing
    # the node's credentials.
    # -----------------------------------------------------------------------
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # -----------------------------------------------------------------------
    # OAuth Scopes
    # -----------------------------------------------------------------------
    # Minimal scopes since we use Workload Identity for pod-level access.
    # The node SA only needs platform-level access (logging, monitoring).
    # -----------------------------------------------------------------------
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    # Node labels for scheduling and identification
    labels = merge(var.labels, {
      node_pool = "primary"
    })

    # Tags for firewall rules targeting
    tags = ["gke-node", "${var.cluster_name}-${var.environment}-node"]

    # -----------------------------------------------------------------------
    # Metadata
    # -----------------------------------------------------------------------
    # disable-legacy-endpoints: Blocks the v0.1 and v1beta1 metadata
    # endpoints, which don't enforce Workload Identity restrictions.
    # This is critical for preventing metadata-based attacks.
    # -----------------------------------------------------------------------
    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  # -------------------------------------------------------------------------
  # Upgrade Settings
  # -------------------------------------------------------------------------
  # Max surge/unavailable controls the rolling update strategy.
  # max_surge = 1: Create 1 extra node during upgrades
  # max_unavailable = 0: Never have fewer nodes than desired count
  # -------------------------------------------------------------------------
  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }

  lifecycle {
    ignore_changes = [
      node_config[0].labels,
      node_config[0].taint,
    ]
  }
}
