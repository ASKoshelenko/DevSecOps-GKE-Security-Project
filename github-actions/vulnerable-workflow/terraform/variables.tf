# =============================================================================
# Input Variables
# =============================================================================

variable "project_id" {
  description = "The GCP project ID where resources will be created"
  type        = string
  default     = "my-production-project"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, lowercase letters, digits, and hyphens."
  }
}

variable "region" {
  description = "The GCP region for resource deployment"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "app_service_account" {
  description = "Service account email for the application workload"
  type        = string
  default     = "app-workload@my-production-project.iam.gserviceaccount.com"
}

variable "monitoring_service_account" {
  description = "Service account email for monitoring and observability"
  type        = string
  default     = "monitoring@my-production-project.iam.gserviceaccount.com"
}
