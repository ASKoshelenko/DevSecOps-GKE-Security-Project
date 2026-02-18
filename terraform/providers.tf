# =============================================================================
# Provider Configuration
# =============================================================================
# Configures the Google Cloud provider and required Terraform version.
# The google-beta provider is needed for features like Binary Authorization
# and Workload Identity Federation that are in beta or require beta APIs.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}

# -----------------------------------------------------------------------------
# Google Provider
# -----------------------------------------------------------------------------
# Primary provider for standard Google Cloud resources.
# Project and region are parameterized for multi-environment support.
# -----------------------------------------------------------------------------
provider "google" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# Google Beta Provider
# -----------------------------------------------------------------------------
# Beta provider for GKE features like Binary Authorization, Workload Identity,
# and advanced security configurations.
# -----------------------------------------------------------------------------
provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# Kubernetes Provider
# -----------------------------------------------------------------------------
# Configured using GKE cluster endpoint and credentials.
# Uses google_client_config for authentication rather than static tokens.
# This provider is used for deploying Kubernetes-native resources like
# Pod Security Standards and namespace configurations.
# -----------------------------------------------------------------------------
data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${module.gke.cluster_endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.cluster_ca_certificate)
}
