# =============================================================================
# DevSecOps Project - Root Makefile
# =============================================================================
#
# Orchestrates all validation, testing, linting, and security scanning
# for the entire DevSecOps infrastructure-as-code project.
#
# USAGE:
#   make help           Show all available targets
#   make validate       Run all validation checks
#   make test           Run all tests
#   make lint           Run all linters
#   make security-scan  Run security scanning
#   make all            Run everything
#
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ROOT := $(shell pwd)
SCRIPTS_DIR  := $(PROJECT_ROOT)/scripts
REPORTS_DIR  := $(PROJECT_ROOT)/reports
CLUSTER_NAME ?= devsecops-integration-test
KIND_CONFIG  := $(PROJECT_ROOT)/k8s-security/kind-config.yaml

# Colors for terminal output
GREEN  := \033[0;32m
RED    := \033[0;31m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
BOLD   := \033[1m
NC     := \033[0m

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: help all validate test lint security-scan \
        validate-terraform validate-helm validate-cloudbuild \
        test-python test-integration \
        lint-shell lint-yaml lint-python lint-terraform \
        security-audit security-secrets \
        setup-local teardown-local \
        demo-escape demo-crash \
        clean clean-reports clean-cluster \
        check-tools install-tools

# =============================================================================
# HELP
# =============================================================================

help: ## Show this help message
	@echo ""
	@echo -e "$(BOLD)DevSecOps Project - Available Targets$(NC)"
	@echo -e "$(BOLD)======================================$(NC)"
	@echo ""
	@echo -e "$(BLUE)Main Targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(BLUE)Usage Examples:$(NC)"
	@echo "  make validate          Run all validation checks"
	@echo "  make test              Run all tests (unit + integration)"
	@echo "  make lint              Run all linters"
	@echo "  make security-scan     Run security scanning"
	@echo "  make setup-local       Create local Kind cluster"
	@echo "  make all               Run everything"
	@echo ""

# =============================================================================
# AGGREGATE TARGETS
# =============================================================================

all: validate test lint security-scan ## Run all validation, tests, linting, and security scanning
	@echo ""
	@echo -e "$(GREEN)$(BOLD)All checks completed successfully.$(NC)"

validate: validate-terraform validate-helm validate-cloudbuild ## Run all validation checks
	@echo ""
	@echo -e "$(GREEN)$(BOLD)All validation checks completed.$(NC)"

test: test-python test-integration ## Run all tests (unit + integration)
	@echo ""
	@echo -e "$(GREEN)$(BOLD)All tests completed.$(NC)"

lint: lint-terraform lint-shell lint-yaml lint-python ## Run all linters
	@echo ""
	@echo -e "$(GREEN)$(BOLD)All linting completed.$(NC)"

security-scan: security-audit security-secrets ## Run all security scanning
	@echo ""
	@echo -e "$(GREEN)$(BOLD)All security scanning completed.$(NC)"

# =============================================================================
# VALIDATION TARGETS
# =============================================================================

validate-terraform: ## Validate Terraform code (fmt, validate, tflint, tfsec, checkov)
	@echo -e "$(BLUE)$(BOLD)Running Terraform validation...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-terraform.sh

validate-terraform-junit: ## Validate Terraform with JUnit XML output
	@echo -e "$(BLUE)$(BOLD)Running Terraform validation (JUnit output)...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-terraform.sh --junit

validate-terraform-fix: ## Validate and auto-fix Terraform formatting
	@echo -e "$(BLUE)$(BOLD)Running Terraform validation with auto-fix...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-terraform.sh --fix

validate-helm: ## Validate Helm charts (lint, template, kubeconform, kube-score)
	@echo -e "$(BLUE)$(BOLD)Running Helm chart validation...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-helm.sh

validate-helm-junit: ## Validate Helm charts with JUnit XML output
	@echo -e "$(BLUE)$(BOLD)Running Helm chart validation (JUnit output)...$(NC)"
	@bash $(SCRIPTS_DIR)/validate-helm.sh --junit

validate-cloudbuild: ## Validate Cloud Build pipeline configurations
	@echo -e "$(BLUE)$(BOLD)Running Cloud Build validation...$(NC)"
	@bash $(SCRIPTS_DIR)/test-cloudbuild.sh

# =============================================================================
# TEST TARGETS
# =============================================================================

test-python: ## Run Python unit tests (BigQuery extraction, vulnerability parsing)
	@echo -e "$(BLUE)$(BOLD)Running Python unit tests...$(NC)"
	@if command -v pytest &>/dev/null; then \
		python3 -m pytest $(SCRIPTS_DIR)/test_extract_vulnerabilities.py -v --tb=short; \
	else \
		python3 $(SCRIPTS_DIR)/test_extract_vulnerabilities.py; \
	fi

test-python-coverage: ## Run Python tests with coverage report
	@echo -e "$(BLUE)$(BOLD)Running Python tests with coverage...$(NC)"
	@python3 -m pytest $(SCRIPTS_DIR)/test_extract_vulnerabilities.py \
		-v --tb=short \
		--cov=$(SCRIPTS_DIR) \
		--cov-report=term-missing \
		--cov-report=html:$(REPORTS_DIR)/htmlcov

test-integration: ## Run end-to-end integration tests (requires Docker + Kind)
	@echo -e "$(BLUE)$(BOLD)Running integration tests...$(NC)"
	@echo -e "$(YELLOW)WARNING: This creates a Kind cluster and takes several minutes.$(NC)"
	@bash $(SCRIPTS_DIR)/integration-test.sh

test-integration-no-cleanup: ## Run integration tests without cleanup (for debugging)
	@echo -e "$(BLUE)$(BOLD)Running integration tests (no cleanup)...$(NC)"
	@bash $(SCRIPTS_DIR)/integration-test.sh --no-cleanup

# =============================================================================
# LINTING TARGETS
# =============================================================================

lint-terraform: ## Lint Terraform files (terraform fmt check)
	@echo -e "$(BLUE)$(BOLD)Linting Terraform files...$(NC)"
	@if command -v terraform &>/dev/null; then \
		terraform -chdir=$(PROJECT_ROOT)/terraform fmt -check -recursive -diff; \
	else \
		echo -e "$(YELLOW)terraform not installed, skipping$(NC)"; \
	fi

lint-shell: ## Lint shell scripts with shellcheck
	@echo -e "$(BLUE)$(BOLD)Linting shell scripts with shellcheck...$(NC)"
	@if command -v shellcheck &>/dev/null; then \
		find $(PROJECT_ROOT) -name "*.sh" -not -path "*/.terraform/*" -not -path "*/.git/*" \
			-exec shellcheck -x -S warning {} +; \
		echo -e "$(GREEN)shellcheck passed$(NC)"; \
	else \
		echo -e "$(YELLOW)shellcheck not installed (brew install shellcheck)$(NC)"; \
	fi

lint-yaml: ## Lint YAML files with yamllint
	@echo -e "$(BLUE)$(BOLD)Linting YAML files with yamllint...$(NC)"
	@if command -v yamllint &>/dev/null; then \
		find $(PROJECT_ROOT) -name "*.yaml" -o -name "*.yml" \
			| grep -v ".terraform\|node_modules\|.git\|.rendered" \
			| xargs yamllint -d '{extends: default, rules: {line-length: {max: 200}, document-start: disable, truthy: {allowed-values: ["true", "false", "yes", "no"]}}}'; \
		echo -e "$(GREEN)yamllint passed$(NC)"; \
	else \
		echo -e "$(YELLOW)yamllint not installed (pip install yamllint)$(NC)"; \
	fi

lint-python: ## Lint Python files with flake8 and optionally black
	@echo -e "$(BLUE)$(BOLD)Linting Python files...$(NC)"
	@if command -v flake8 &>/dev/null; then \
		find $(PROJECT_ROOT) -name "*.py" -not -path "*/.terraform/*" -not -path "*/.git/*" \
			-exec flake8 --max-line-length=120 --ignore=E501,W503 {} +; \
		echo -e "$(GREEN)flake8 passed$(NC)"; \
	else \
		echo -e "$(YELLOW)flake8 not installed (pip install flake8)$(NC)"; \
	fi
	@if command -v black &>/dev/null; then \
		find $(PROJECT_ROOT) -name "*.py" -not -path "*/.terraform/*" -not -path "*/.git/*" \
			-exec black --check --line-length=120 {} +; \
		echo -e "$(GREEN)black check passed$(NC)"; \
	else \
		echo -e "$(YELLOW)black not installed (pip install black)$(NC)"; \
	fi

# =============================================================================
# SECURITY SCANNING TARGETS
# =============================================================================

security-audit: ## Run comprehensive security audit
	@echo -e "$(BLUE)$(BOLD)Running security audit...$(NC)"
	@bash $(SCRIPTS_DIR)/security-audit.sh

security-audit-strict: ## Run security audit in strict mode (warnings are failures)
	@echo -e "$(BLUE)$(BOLD)Running security audit (strict mode)...$(NC)"
	@bash $(SCRIPTS_DIR)/security-audit.sh --strict

security-audit-junit: ## Run security audit with JUnit output
	@echo -e "$(BLUE)$(BOLD)Running security audit (JUnit output)...$(NC)"
	@bash $(SCRIPTS_DIR)/security-audit.sh --junit

security-secrets: ## Scan for hardcoded secrets with gitleaks
	@echo -e "$(BLUE)$(BOLD)Scanning for secrets...$(NC)"
	@if command -v gitleaks &>/dev/null; then \
		gitleaks detect --source=$(PROJECT_ROOT) --no-git --verbose; \
	else \
		echo -e "$(YELLOW)gitleaks not installed (brew install gitleaks)$(NC)"; \
		echo "Running basic regex-based secret scan instead..."; \
		grep -rn --include="*.tf" --include="*.yaml" --include="*.yml" --include="*.py" \
			-iE "(AKIA[0-9A-Z]{16}|password\s*=\s*\"[^\"]{8,}|private_key|aws_secret)" \
			$(PROJECT_ROOT) | grep -v "test\|example\|#\|description\|variable" || \
			echo -e "$(GREEN)No hardcoded secrets found$(NC)"; \
	fi

# =============================================================================
# LOCAL DEVELOPMENT ENVIRONMENT
# =============================================================================

setup-local: ## Setup local Kind cluster for development/testing
	@echo -e "$(BLUE)$(BOLD)Setting up local Kind cluster...$(NC)"
	@bash $(PROJECT_ROOT)/k8s-security/setup-vulnerable-cluster.sh create

teardown-local: ## Tear down local Kind cluster
	@echo -e "$(BLUE)$(BOLD)Tearing down local Kind cluster...$(NC)"
	@bash $(PROJECT_ROOT)/k8s-security/setup-vulnerable-cluster.sh delete

cluster-info: ## Show local cluster information
	@echo -e "$(BLUE)$(BOLD)Cluster Information:$(NC)"
	@bash $(PROJECT_ROOT)/k8s-security/setup-vulnerable-cluster.sh info

# =============================================================================
# DEMO TARGETS
# =============================================================================

demo-escape: ## Run container escape demonstration
	@echo -e "$(BLUE)$(BOLD)Running container escape demo...$(NC)"
	@if [[ -f "$(PROJECT_ROOT)/k8s-security/container-escape/escape-demo.sh" ]]; then \
		bash $(PROJECT_ROOT)/k8s-security/container-escape/escape-demo.sh; \
	else \
		echo -e "$(YELLOW)Container escape demo script not found.$(NC)"; \
		echo "Expected: k8s-security/container-escape/escape-demo.sh"; \
		echo ""; \
		echo "Quick manual demo:"; \
		echo "  1. make setup-local"; \
		echo "  2. kubectl run escape-pod --image=busybox --restart=Never -- sleep 3600"; \
		echo "  3. kubectl exec -it escape-pod -- /bin/sh"; \
		echo "  4. # Try to access host filesystem via /proc/1/root"; \
	fi

demo-crash: ## Run master plane crash demonstration
	@echo -e "$(BLUE)$(BOLD)Running master plane crash demo...$(NC)"
	@if [[ -f "$(PROJECT_ROOT)/k8s-security/master-plane-crash/api-server-dos.sh" ]]; then \
		bash $(PROJECT_ROOT)/k8s-security/master-plane-crash/api-server-dos.sh; \
	else \
		echo -e "$(YELLOW)Master plane crash demo script not found.$(NC)"; \
		echo "Expected: k8s-security/master-plane-crash/api-server-dos.sh"; \
		echo ""; \
		echo "Quick manual demo:"; \
		echo "  1. make setup-local"; \
		echo "  2. curl -s http://localhost:8080/api/v1/namespaces  # Anonymous API access"; \
		echo "  3. curl -s http://localhost:2379/v3/kv/range  # Direct etcd access"; \
	fi

# =============================================================================
# CLEANUP TARGETS
# =============================================================================

clean: clean-reports clean-cluster clean-rendered ## Clean up everything
	@echo -e "$(GREEN)$(BOLD)Cleanup complete.$(NC)"

clean-reports: ## Remove generated reports
	@echo -e "$(BLUE)Cleaning reports directory...$(NC)"
	@rm -rf $(REPORTS_DIR)
	@echo "  Removed $(REPORTS_DIR)"

clean-cluster: ## Delete Kind clusters created by this project
	@echo -e "$(BLUE)Cleaning up Kind clusters...$(NC)"
	@kind delete cluster --name $(CLUSTER_NAME) 2>/dev/null || true
	@kind delete cluster --name vuln-k8s-lab 2>/dev/null || true
	@echo "  Kind clusters deleted"

clean-rendered: ## Remove rendered manifests
	@echo -e "$(BLUE)Cleaning rendered manifests...$(NC)"
	@rm -rf $(PROJECT_ROOT)/.rendered-manifests
	@echo "  Removed .rendered-manifests"

clean-terraform: ## Clean Terraform temporary files
	@echo -e "$(BLUE)Cleaning Terraform temporary files...$(NC)"
	@find $(PROJECT_ROOT)/terraform -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@find $(PROJECT_ROOT)/terraform -name ".terraform.lock.hcl" -delete 2>/dev/null || true
	@echo "  Removed .terraform directories and lock files"

# =============================================================================
# TOOL MANAGEMENT
# =============================================================================

check-tools: ## Check which required tools are installed
	@echo -e "$(BOLD)Required Tools Status:$(NC)"
	@echo ""
	@echo -e "$(BLUE)Core Tools:$(NC)"
	@for tool in terraform kubectl helm kind docker; do \
		if command -v $$tool &>/dev/null; then \
			version=$$($$tool version 2>/dev/null | head -1 || echo "installed"); \
			echo -e "  $(GREEN)[OK]$(NC)   $$tool - $$version"; \
		else \
			echo -e "  $(RED)[MISS]$(NC) $$tool"; \
		fi \
	done
	@echo ""
	@echo -e "$(BLUE)Linting Tools:$(NC)"
	@for tool in tflint shellcheck yamllint flake8 black; do \
		if command -v $$tool &>/dev/null; then \
			echo -e "  $(GREEN)[OK]$(NC)   $$tool"; \
		else \
			echo -e "  $(YELLOW)[MISS]$(NC) $$tool (optional)"; \
		fi \
	done
	@echo ""
	@echo -e "$(BLUE)Security Tools:$(NC)"
	@for tool in tfsec trivy checkov terrascan gitleaks kubeconform kube-score; do \
		if command -v $$tool &>/dev/null; then \
			echo -e "  $(GREEN)[OK]$(NC)   $$tool"; \
		else \
			echo -e "  $(YELLOW)[MISS]$(NC) $$tool (optional)"; \
		fi \
	done
	@echo ""
	@echo -e "$(BLUE)Python:$(NC)"
	@for tool in python3 pytest; do \
		if command -v $$tool &>/dev/null; then \
			echo -e "  $(GREEN)[OK]$(NC)   $$tool"; \
		else \
			echo -e "  $(YELLOW)[MISS]$(NC) $$tool"; \
		fi \
	done

install-tools: ## Install required tools (macOS - Homebrew)
	@echo -e "$(BLUE)$(BOLD)Installing required tools via Homebrew...$(NC)"
	@echo ""
	@echo "Core tools:"
	brew install terraform kubectl helm kind 2>/dev/null || true
	@echo ""
	@echo "Linting tools:"
	brew install tflint shellcheck 2>/dev/null || true
	pip3 install yamllint flake8 black 2>/dev/null || true
	@echo ""
	@echo "Security tools:"
	brew install tfsec trivy terrascan gitleaks kubeconform kube-score 2>/dev/null || true
	pip3 install checkov 2>/dev/null || true
	@echo ""
	@echo "Python testing:"
	pip3 install pytest pytest-cov pyyaml 2>/dev/null || true
	@echo ""
	@echo "Pre-commit:"
	pip3 install pre-commit 2>/dev/null || true
	@echo ""
	@echo -e "$(GREEN)$(BOLD)Tool installation complete. Run 'make check-tools' to verify.$(NC)"

# =============================================================================
# PRE-COMMIT
# =============================================================================

pre-commit-install: ## Install pre-commit hooks
	@echo -e "$(BLUE)$(BOLD)Installing pre-commit hooks...$(NC)"
	@if command -v pre-commit &>/dev/null; then \
		pre-commit install; \
		echo -e "$(GREEN)Pre-commit hooks installed.$(NC)"; \
	else \
		echo -e "$(YELLOW)pre-commit not installed. Run: pip install pre-commit$(NC)"; \
	fi

pre-commit-run: ## Run all pre-commit hooks on all files
	@echo -e "$(BLUE)$(BOLD)Running pre-commit hooks on all files...$(NC)"
	@pre-commit run --all-files

# =============================================================================
# CI/CD TARGETS (for use in pipelines)
# =============================================================================

ci-validate: ## CI target: Run all validation with JUnit output
	@mkdir -p $(REPORTS_DIR)
	@bash $(SCRIPTS_DIR)/validate-terraform.sh --junit || true
	@bash $(SCRIPTS_DIR)/validate-helm.sh --junit || true
	@bash $(SCRIPTS_DIR)/test-cloudbuild.sh || true
	@bash $(SCRIPTS_DIR)/security-audit.sh --junit || true

ci-test: ## CI target: Run unit tests with XML output
	@mkdir -p $(REPORTS_DIR)
	@python3 -m pytest $(SCRIPTS_DIR)/test_extract_vulnerabilities.py \
		-v --tb=short \
		--junitxml=$(REPORTS_DIR)/python-tests.xml || true
