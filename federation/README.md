# Workload Identity Federation - Service Account Key Elimination

## Incident Context

A Russian APT group exfiltrated a high-privilege GCP service account key from a
compromised developer workstation. The stolen key (with `roles/editor` on the
production project) was used to:

- Access GKE clusters via `kubectl` with cluster-admin privileges
- Exfiltrate sensitive data from BigQuery datasets
- Deploy cryptominer pods through Cloud Build impersonation
- Establish persistence via additional service account creation

**Root cause**: The service account key was a long-lived JSON credential file
that had been created 14 months prior, never rotated, stored in plaintext on
a developer laptop, and accidentally committed to a private git repository.

This module eliminates the entire attack surface by:

1. **Blocking all SA key creation** via Organization Policy constraints
2. **Replacing key-based auth with Workload Identity Federation** for GitHub Actions
3. **Using GKE Workload Identity** for pod-level authentication
4. **Monitoring and alerting** on any SA key creation attempts

---

## Why Service Account Keys Are Dangerous

| Risk Factor | Service Account Key | Workload Identity Federation |
|---|---|---|
| **Credential lifetime** | Permanent (until manually deleted) | 1 hour (auto-expires) |
| **Rotation** | Manual, often neglected | Automatic, every request |
| **Storage** | File on disk (stealable) | In-memory only (ephemeral) |
| **Scope** | Full SA permissions, always | Same, but time-limited |
| **Revocation** | Must find and delete the key | Token expires naturally |
| **Exfiltration risk** | HIGH - file can be copied anywhere | NONE - token cannot leave runner |
| **Audit trail** | Key ID in logs (if you look) | Full OIDC claims in audit logs |
| **Blast radius** | Unlimited until key is revoked | Limited to 1-hour window |
| **Sharing** | Easy to share via Slack/email | Impossible to share |
| **Git exposure** | Often accidentally committed | Nothing to commit |

**Key insight**: With SA keys, the security model is "assume breach and try to
detect it." With WIF, the security model is "breach of the credential is
impossible because the credential does not exist."

---

## How Workload Identity Federation Works

### OIDC Token Exchange Flow (GitHub Actions)

```
+-------------------+     +---------------------+     +------------------+     +-------------------+
|  GitHub Actions   |     |  GitHub OIDC        |     |  GCP Security    |     |  GCP IAM          |
|  Workflow Runner  |     |  Identity Provider  |     |  Token Service   |     |  Credentials API  |
+--------+----------+     +----------+----------+     +--------+---------+     +---------+---------+
         |                           |                          |                         |
         | 1. Request OIDC token     |                          |                         |
         |   (with audience claim)   |                          |                         |
         |-------------------------->|                          |                         |
         |                           |                          |                         |
         | 2. Return signed JWT      |                          |                         |
         |   Claims:                 |                          |                         |
         |   - sub: repo:org/repo    |                          |                         |
         |   - repository: org/repo  |                          |                         |
         |   - actor: username       |                          |                         |
         |   - ref: refs/heads/main  |                          |                         |
         |   - workflow: deploy.yml  |                          |                         |
         |<--------------------------|                          |                         |
         |                           |                          |                         |
         | 3. Exchange JWT for       |                          |                         |
         |    federated token        |                          |                         |
         |-------------------------------------------------->|                         |
         |                           |                          |                         |
         |                           |  4. Validate JWT:        |                         |
         |                           |  - Verify signature      |                         |
         |                           |  - Check issuer          |                         |
         |                           |  - Check audience        |                         |
         |                           |  - Evaluate attribute    |                         |
         |                           |    conditions:           |                         |
         |                           |    * org matches?        |                         |
         |                           |    * repo matches?       |                         |
         |                           |    * runner is hosted?   |                         |
         |                           |                          |                         |
         | 5. Return federated       |                          |                         |
         |    access token           |                          |                         |
         |<--------------------------------------------------|                         |
         |                           |                          |                         |
         | 6. Exchange federated     |                          |                         |
         |    token for SA token     |                          |                         |
         |------------------------------------------------------------------------>|
         |                           |                          |                         |
         |                           |                          |  7. Validate:           |
         |                           |                          |  - SA has WIF binding?  |
         |                           |                          |  - IAM conditions met?  |
         |                           |                          |  - Branch restriction?  |
         |                           |                          |                         |
         | 8. Return short-lived     |                          |                         |
         |    SA access token        |                          |                         |
         |    (1 hour, non-renewable)|                          |                         |
         |<------------------------------------------------------------------------|
         |                           |                          |                         |
         | 9. Use token for GCP      |                          |                         |
         |    API calls (BigQuery,   |                          |                         |
         |    GKE, Artifact Registry)|                          |                         |
         |------------------------------------------------------------------------>|
```

### GKE Workload Identity Flow (Pod-Level)

```
+-------------------+     +---------------------+     +-------------------+
|  Pod              |     |  GKE Metadata       |     |  GCP IAM          |
|  (KSA: trivy-sa)  |     |  Server Proxy       |     |  Credentials API  |
+--------+----------+     +----------+----------+     +---------+---------+
         |                           |                          |
         | 1. GET /metadata/v1/...   |                          |
         |   service-accounts/       |                          |
         |   default/token           |                          |
         |-------------------------->|                          |
         |                           |                          |
         |                           | 2. Look up KSA annotation|
         |                           |    iam.gke.io/gcp-sa     |
         |                           |                          |
         |                           | 3. Request SA token      |
         |                           |------------------------->|
         |                           |                          |
         |                           |  4. Validate:            |
         |                           |  - KSA->GSA binding      |
         |                           |    exists?               |
         |                           |  - workloadIdentityUser  |
         |                           |    role granted?          |
         |                           |                          |
         |                           | 5. Return SA token       |
         |                           |<-------------------------|
         |                           |                          |
         | 6. Return token to pod    |                          |
         |<--------------------------|                          |
         |                           |                          |
         | 7. Use token for GCP APIs |                          |
         |-------------------------------------------------->|
```

---

## File Structure

```
federation/
|-- terraform-wif.tf                    # WIF pool, OIDC provider, SA bindings
|-- terraform-gke-wi.tf                 # GKE Workload Identity (KSA->GSA)
|-- org-policies.tf                     # Org policies to block SA keys
|-- migrate-to-federation.sh            # Migration audit and execution script
|-- github-oidc-example.yml             # GitHub Actions workflow with WIF
|-- k8s-workload-identity/
|   |-- service-account.yaml            # KSA definitions with GSA annotations
|   |-- deployment.yaml                 # Security-hardened deployment example
|   |-- test-access.sh                  # Verification script for WIF in pods
|-- monitoring/
|   |-- alert-sa-key-usage.tf           # Alert on SA key authentication
|   |-- alert-sa-key-creation.tf        # Alert on SA key creation attempts
|   |-- log-filter.txt                  # Cloud Logging filters for SA keys
|-- README.md                           # This file
```

---

## Deployment Guide

### Step 1: Audit Current SA Keys

```bash
# Run the migration script in audit-only mode
./migrate-to-federation.sh --project-id YOUR_PROJECT_ID --dry-run

# Review the generated CSV report
cat /tmp/sa-key-audit-*.csv
```

### Step 2: Deploy WIF Infrastructure

```bash
# Initialize Terraform
cd federation
terraform init

# Review the plan
terraform plan \
  -var="project_id=YOUR_PROJECT_ID" \
  -var="github_org=YOUR_ORG" \
  -var="github_repo=YOUR_REPO"

# Apply
terraform apply \
  -var="project_id=YOUR_PROJECT_ID" \
  -var="github_org=YOUR_ORG" \
  -var="github_repo=YOUR_REPO"
```

### Step 3: Update GitHub Actions

1. Set these GitHub Actions variables (Settings > Secrets and variables > Actions > Variables):
   - `WIF_PROVIDER`: Copy from Terraform output `wif_provider_resource_name`
   - `WIF_DEPLOYER_SA`: Copy from Terraform output `github_deployer_sa_email`
   - `WIF_READER_SA`: Copy from Terraform output `github_reader_sa_email`
   - `WIF_SCANNER_SA`: Copy from Terraform output `github_scanner_sa_email`
   - `GCP_PROJECT_ID`: Your GCP project ID
   - `GKE_CLUSTER`: Your GKE cluster name
   - `GKE_ZONE`: Your GKE cluster zone

2. Copy the workflow file:
   ```bash
   cp github-oidc-example.yml .github/workflows/devsecops-pipeline.yml
   ```

3. Remove all `GOOGLE_CREDENTIALS` secrets from GitHub Actions.

### Step 4: Deploy GKE Workload Identity

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s-workload-identity/service-account.yaml
kubectl apply -f k8s-workload-identity/deployment.yaml

# Verify Workload Identity works
chmod +x k8s-workload-identity/test-access.sh
./k8s-workload-identity/test-access.sh --project-id YOUR_PROJECT_ID
```

### Step 5: Disable Old SA Keys

```bash
# Disable all user-managed keys (services will lose access)
./migrate-to-federation.sh --project-id YOUR_PROJECT_ID --disable-keys

# Monitor for 48 hours for any breakage
# Check Cloud Logging for authentication failures
```

### Step 6: Delete Old SA Keys

```bash
# After confirming no breakage, permanently delete keys
./migrate-to-federation.sh --project-id YOUR_PROJECT_ID --delete-keys --force
```

### Step 7: Enforce Organization Policies

```bash
# Apply org policies to prevent new key creation
terraform apply -target=google_project_organization_policy.disable_sa_key_creation
terraform apply -target=google_project_organization_policy.disable_sa_key_upload
```

### Step 8: Deploy Monitoring

```bash
# Apply monitoring and alerting
terraform apply -target=module.monitoring
```

---

## Incident Response: Compromised SA Key

If a service account key is suspected to be compromised, follow this runbook:

### Immediate Actions (Within 15 Minutes)

1. **Disable the key** (does not delete, allows re-enable if false positive):
   ```bash
   gcloud iam service-accounts keys disable KEY_ID \
     --iam-account=SA_EMAIL \
     --project=PROJECT_ID
   ```

2. **Check for active sessions** using the compromised key:
   ```bash
   gcloud logging read \
     'protoPayload.authenticationInfo.serviceAccountKeyName="//iam.googleapis.com/projects/PROJECT_ID/serviceAccounts/SA_EMAIL/keys/KEY_ID"' \
     --project=PROJECT_ID \
     --freshness=24h \
     --format=json
   ```

3. **Revoke all active sessions** for the service account:
   ```bash
   gcloud iam service-accounts disable SA_EMAIL \
     --project=PROJECT_ID
   ```

### Investigation (Within 1 Hour)

4. **Audit all actions** taken by the compromised SA:
   ```bash
   gcloud logging read \
     'protoPayload.authenticationInfo.principalEmail="SA_EMAIL"' \
     --project=PROJECT_ID \
     --freshness=7d \
     --format='table(timestamp, protoPayload.methodName, protoPayload.resourceName)'
   ```

5. **Check for persistence mechanisms**:
   - New service accounts created by the compromised SA
   - New IAM bindings granted by the compromised SA
   - New SA keys created by the compromised SA
   - New resources (VMs, Cloud Functions) that could maintain access

6. **Check for data exfiltration**:
   - BigQuery job history (data export queries)
   - Cloud Storage access logs
   - VPC flow logs for unusual egress

### Remediation (Within 4 Hours)

7. **Delete the compromised key**:
   ```bash
   gcloud iam service-accounts keys delete KEY_ID \
     --iam-account=SA_EMAIL \
     --project=PROJECT_ID
   ```

8. **Remove any persistence** found in step 5.

9. **Re-enable the service account** (if it was legitimately needed):
   ```bash
   gcloud iam service-accounts enable SA_EMAIL --project=PROJECT_ID
   ```

10. **Migrate to WIF** to prevent recurrence:
    ```bash
    ./migrate-to-federation.sh --project-id PROJECT_ID \
      --create-wif --github-org ORG --github-repo REPO
    ```

### Post-Incident (Within 24 Hours)

11. Apply `org-policies.tf` to block future key creation.
12. Deploy monitoring alerts (`monitoring/` directory).
13. Conduct a post-incident review.
14. Update threat model documentation.

---

## Security Best Practices for WIF

1. **Always restrict attribute conditions**: Never create a WIF provider without
   `attribute_condition`. An unrestricted provider allows ANY GitHub repo to
   authenticate.

2. **Use branch restrictions for deployment SAs**: The deployer SA should only
   be impersonable from protected branches (main/master). This prevents feature
   branches from deploying to production.

3. **Prefer `principalSet` over `principal`**: Use `principalSet` with attribute
   filters for more granular control. Use `principal` only when you need to
   match a specific subject claim.

4. **Enforce runner environment**: Add `assertion.runner_environment == 'github-hosted'`
   to attribute conditions. Self-hosted runners could be compromised and used
   to steal tokens.

5. **Audit WIF usage**: Enable Cloud Audit Logs for IAM Credentials API and
   STS API. Every token exchange is logged with full context.

6. **Rotate WIF pools periodically**: While not strictly necessary (there are no
   secrets to rotate), recreating pools periodically tests your disaster recovery
   procedures.

7. **Use separate SAs per function**: Create dedicated service accounts for
   deployment, reading, and scanning. Never use a single SA for everything.

8. **Set token lifetime**: Use the minimum token lifetime needed. For GitHub
   Actions, 3600s (1 hour) is usually sufficient.

9. **Monitor for SA key creation attempts**: Even with org policies, set up
   alerts for key creation attempts. These indicate either misconfiguration
   or an attacker probing for weaknesses.

10. **Document your WIF architecture**: Maintain a map of which repos can
    impersonate which SAs. This is critical for access reviews and incident
    response.

---

## Troubleshooting

### "Permission 'iam.serviceAccounts.getAccessToken' denied"

The WIF identity cannot impersonate the target service account. Check:
- The `roles/iam.workloadIdentityUser` binding exists on the SA
- The `member` in the binding matches the WIF pool/attribute filter
- The attribute conditions in the WIF provider allow the current token claims
- For branch-restricted SAs, verify the workflow is running from an allowed branch

### "Unable to acquire credentials from the metadata server"

GKE Workload Identity is not working. Check:
- Workload Identity is enabled on the GKE cluster
- The node pool has the GKE metadata server enabled
- The KSA has the `iam.gke.io/gcp-service-account` annotation
- The annotation email matches the GSA email exactly
- The `roles/iam.workloadIdentityUser` binding exists on the GSA

### "Organization policy constraint violated"

The SA key creation org policy is blocking the operation. This is expected
behavior after applying `org-policies.tf`. If you legitimately need to create
a key (migration period), add a temporary exception.

### "OIDC token audience mismatch"

The `audience` in the GitHub Actions auth step does not match the
`allowed_audiences` in the WIF provider. Either:
- Remove the custom audience from the auth step (uses provider URL as default)
- Add the custom audience to the provider's `allowed_audiences` list
