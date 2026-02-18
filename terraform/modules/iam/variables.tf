# =============================================================================
# IAM Module Variables
# =============================================================================

variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
}

variable "github_org" {
  description = "GitHub organization name for Workload Identity Federation"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name for Workload Identity Federation"
  type        = string
}

variable "dataset_id" {
  description = "BigQuery dataset ID for granting writer access"
  type        = string
}

variable "cluster_name" {
  description = "GKE cluster name (used for Workload Identity bindings)"
  type        = string
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}
