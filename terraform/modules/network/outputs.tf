# =============================================================================
# Network Module Outputs
# =============================================================================

output "network_name" {
  description = "The name of the VPC network"
  value       = google_compute_network.vpc.name
}

output "network_self_link" {
  description = "The self link of the VPC network"
  value       = google_compute_network.vpc.self_link
}

output "network_id" {
  description = "The ID of the VPC network"
  value       = google_compute_network.vpc.id
}

output "subnet_name" {
  description = "The name of the GKE subnet"
  value       = google_compute_subnetwork.gke_subnet.name
}

output "subnet_self_link" {
  description = "The self link of the GKE subnet"
  value       = google_compute_subnetwork.gke_subnet.self_link
}

output "subnet_id" {
  description = "The ID of the GKE subnet"
  value       = google_compute_subnetwork.gke_subnet.id
}

output "pods_range_name" {
  description = "The name of the secondary range for pods"
  value       = "pods"
}

output "services_range_name" {
  description = "The name of the secondary range for services"
  value       = "services"
}

output "router_name" {
  description = "The name of the Cloud Router"
  value       = google_compute_router.router.name
}

output "nat_name" {
  description = "The name of the Cloud NAT"
  value       = google_compute_router_nat.nat.name
}
