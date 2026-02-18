# =============================================================================
# BigQuery Module Variables
# =============================================================================

variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
}

variable "dataset_id" {
  description = "ID for the BigQuery dataset"
  type        = string
}

variable "location" {
  description = "Location for the BigQuery dataset (e.g., US, EU)"
  type        = string
  default     = "US"
}

variable "log_retention_days" {
  description = "Number of days to retain raw vulnerability data"
  type        = number
  default     = 90
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}
