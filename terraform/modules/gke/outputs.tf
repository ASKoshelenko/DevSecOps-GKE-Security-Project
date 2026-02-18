# =============================================================================
# GKE Module Outputs
# =============================================================================

output "cluster_name" {
  description = "The name of the GKE cluster"
  value       = google_container_cluster.primary.name
}

output "cluster_id" {
  description = "The unique ID of the GKE cluster"
  value       = google_container_cluster.primary.id
}

output "cluster_endpoint" {
  description = "The IP address of the cluster master endpoint"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "The base64-encoded public certificate of the cluster CA"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "cluster_location" {
  description = "The location (zone) of the cluster"
  value       = google_container_cluster.primary.location
}

output "cluster_master_version" {
  description = "The current master version of the cluster"
  value       = google_container_cluster.primary.master_version
}

output "cluster_node_version" {
  description = "The current node version of the cluster"
  value       = google_container_node_pool.primary_nodes.version
}

output "workload_identity_pool" {
  description = "The Workload Identity pool for this cluster"
  value       = "${var.project_id}.svc.id.goog"
}

output "node_pool_name" {
  description = "The name of the primary node pool"
  value       = google_container_node_pool.primary_nodes.name
}
