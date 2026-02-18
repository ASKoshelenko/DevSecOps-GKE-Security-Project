# GitHub Actions CI/CD Security: Terraform Plan Token Theft

> **DISCLAIMER**: This repository contains intentionally vulnerable configurations
> and exploit demonstrations for **authorized security testing and educational
> purposes only**. Do not use these techniques against systems you do not own or
> have explicit written authorization to test. Unauthorized access to computer
> systems is a criminal offense in most jurisdictions.

## Overview

This module demonstrates a critical vulnerability class in GitHub Actions CI/CD
pipelines that perform Terraform operations on pull requests. The attack exploits
the interaction between GitHub Actions trigger types, Workload Identity Federation,
and Terraform's execution model to steal cloud credentials and compromise
infrastructure.

### The Core Vulnerability

Many organizations use GitHub Actions to run `terraform plan` on pull requests to
preview infrastructure changes before merging. A common but dangerous pattern is:

```yaml
on:
  pull_request_target:  # Runs with elevated privileges
    types: [opened, synchronize]

jobs:
  plan:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out UNTRUSTED code

      - uses: google-github-actions/auth@v2  # Authenticates to GCP
        with:
          workload_identity_provider: "..."
          service_account: "..."

      - run: terraform plan  # Executes attacker's code with GCP token
```

This gives an attacker who can open a pull request the ability to execute arbitrary
code with a valid GCP access token.

## Directory Structure

```
github-actions/
├── README.md                          # This file
├── vulnerable-workflow/
│   ├── .github/workflows/
│   │   └── terraform-plan.yml         # The vulnerable workflow
│   ├── ATTACK.md                      # Detailed attack walkthrough
│   ├── exploits/
│   │   ├── malicious-provider.tf      # External data source token theft
│   │   ├── malicious-backend-config.tf # Backend hijacking attack
│   │   ├── steal-token.sh             # Post-exploitation demonstration
│   │   ├── modified-workflow.yml      # Workflow modification attack
│   │   └── poisoned-module/
│   │       └── main.tf                # Supply chain module attack
│   └── terraform/
│       ├── main.tf                    # Legitimate infrastructure code
│       ├── backend.tf                 # GCS backend configuration
│       ├── variables.tf               # Input variables
│       └── outputs.tf                 # Output values
└── secure-workflow/
    └── .github/workflows/
        └── terraform-plan.yml         # The secure workflow pattern
```

## Vulnerability Classes Demonstrated

### 1. Pwn Request (CICD-SEC-4)

**OWASP CI/CD Risk**: [Poisoned Pipeline Execution (PPE)](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)

The `pull_request_target` trigger runs the workflow with the permissions and secrets
of the base branch, but if the workflow checks out the PR's code, untrusted code
executes with elevated privileges. This is known as a "pwn request."

**GitHub's Security Lab advisory**: [Keeping your GitHub Actions and workflows
secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

### 2. Terraform Plan Code Execution

`terraform plan` is widely misunderstood as a read-only operation. In reality, it
executes code through:

| Vector | Execution Phase | Stealth Level |
|--------|----------------|---------------|
| `external` data source | Plan | High - looks like validation |
| `http` data source | Plan | Medium - makes HTTP requests |
| Custom/malicious provider | Init + Plan | High - arbitrary Go code |
| `local-exec` provisioner | Apply (some plan) | Low - obvious in code |
| Module source override | Init | High - downloaded from attacker |
| Backend configuration | Init | Medium - changes state location |

### 3. Workload Identity Federation Token Theft

While Workload Identity Federation (WIF) is significantly more secure than static
service account keys, the access token obtained through the OIDC exchange is still
a bearer token that can be stolen and reused:

| Aspect | SA Key | Workload Identity |
|--------|--------|-------------------|
| Token lifetime | Permanent (until rotated) | Short-lived (1 hour default) |
| Scope of theft | Full SA access forever | Temporary access |
| Detection | Key usage from unexpected IP | Token usage after workflow ends |
| Revocation | Delete the key | Token expires automatically |
| Attack window | Unlimited | ~1 hour |

WIF makes attacks harder and limits the blast radius, but does not prevent
token theft if the attacker has code execution during the workflow.

### 4. State Manipulation

Terraform state is the source of truth for managed infrastructure. An attacker
with write access to the state backend (GCS bucket) can:

- **Inject resources**: Add IAM bindings or service accounts that Terraform "manages"
- **Remove resources**: Delete resources from state so Terraform ignores them
- **Modify attributes**: Change resource configurations in state
- **Extract secrets**: State often contains passwords, keys, and connection strings

## Real-World Incidents

### GitHub Actions Vulnerabilities

- **2021 - GitHub Actions `pull_request_target` advisory**: GitHub published a
  security advisory warning about the `pull_request_target` misuse pattern after
  multiple repositories were found vulnerable. ([GitHub Blog](https://github.blog/2021-04-22-github-actions-update-helping-maintainers-combat-bad-actors/))

- **2022 - AWS Terraform Provider vulnerability**: Researchers demonstrated that
  malicious Terraform providers could execute arbitrary code during `terraform init`
  and `terraform plan`. ([HashiCorp Advisory](https://discuss.hashicorp.com/t/hcsec-2022-13-multiple-vulnerabilities-in-terraform-enterprise/40553))

### Supply Chain Attacks (Relevant Patterns)

- **2021 - Codecov Bash Uploader**: Attackers modified the Codecov bash uploader
  script to exfiltrate environment variables (including CI tokens and secrets)
  from CI/CD pipelines. The compromised script ran in thousands of CI environments
  for months. ([Codecov Disclosure](https://about.codecov.io/security-update/))

- **2021 - ua-parser-js npm compromise**: A popular npm package was compromised
  to include a cryptominer and credential stealer. Packages pulled during CI/CD
  would execute malicious code in the build environment. ([GitHub Advisory](https://github.com/advisories/GHSA-pjwm-rvh2-c87w))

- **2022 - GitHub Actions `actions/checkout` research**: Security researchers
  demonstrated that many open-source repositories had vulnerable GitHub Actions
  workflows that could be exploited by forking the repo and opening a malicious PR.

- **2024 - tj-actions/changed-files compromise**: The widely-used `tj-actions/changed-files`
  GitHub Action was compromised via a stolen PAT. Attackers injected code that
  exfiltrated CI secrets from any workflow that used the action. This affected
  thousands of repositories. ([Wiz Research](https://www.wiz.io/blog/new-github-action-supply-chain-attack-reviewdog-action-setup))

## OWASP Top 10 CI/CD Security Risks

This demonstration covers several OWASP CI/CD security risks:

| Risk | ID | Relevance |
|------|-----|-----------|
| Insufficient Flow Control Mechanisms | CICD-SEC-1 | No approval gates on plan |
| Inadequate Identity and Access Management | CICD-SEC-2 | Overprivileged CI service account |
| Dependency Chain Abuse | CICD-SEC-3 | Malicious Terraform modules |
| Poisoned Pipeline Execution | CICD-SEC-4 | Core vulnerability demonstrated |
| Insufficient PBAC | CICD-SEC-5 | PR code runs with production creds |
| Insufficient Credential Hygiene | CICD-SEC-6 | Token accessible to all steps |
| Insecure System Configuration | CICD-SEC-7 | Missing environment protections |
| Ungoverned Usage of 3rd Party Services | CICD-SEC-8 | Unpinned action versions |
| Improper Artifact Integrity Validation | CICD-SEC-9 | No plan output verification |
| Insufficient Logging and Visibility | CICD-SEC-10 | Limited detection capabilities |

Reference: [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

## Secure Pattern: Key Mitigations

The `secure-workflow/` directory demonstrates the correct approach. Key mitigations:

### 1. Use `pull_request` Instead of `pull_request_target`

```yaml
on:
  pull_request:  # Safe: fork PRs have no secrets, no OIDC, no write token
    types: [opened, synchronize]
```

For fork PRs, `pull_request` runs without access to secrets or OIDC tokens,
making it safe even if the PR code is malicious.

### 2. Two-Job Architecture

```
Job 1 (plan): pull_request trigger, runs untrusted code, no secrets
     │
     ▼ (artifact)
Job 2 (comment): workflow_run trigger, has write token, runs only base code
```

### 3. Read-Only Plan Service Account

```yaml
service_account: "terraform-plan-readonly@project.iam.gserviceaccount.com"
# This SA has ONLY:
#   - roles/storage.objectViewer on state bucket
#   - roles/viewer on the project
# It CANNOT:
#   - Create/modify resources
#   - Create service account keys
#   - Modify IAM policies
```

### 4. Pin Action Versions by SHA

```yaml
# Bad: mutable tag, can be changed by the action maintainer
- uses: actions/checkout@v4

# Good: immutable SHA, content cannot change
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
```

### 5. Environment Protection Rules

```yaml
jobs:
  plan:
    environment: terraform-plan  # Requires approval from designated reviewers
```

### 6. Restrict Workload Identity Federation

```yaml
# In GCP, restrict the WIF provider to specific repos and branches:
attribute_condition: |
  assertion.repository == "org/repo" &&
  assertion.ref == "refs/heads/main" &&
  assertion.event_name != "pull_request_target"
```

### 7. Network Egress Restrictions

Deploy GitHub Actions runners in a VPC with egress filtering to prevent
data exfiltration via HTTP/DNS to attacker-controlled servers.

### 8. Terraform Policy as Code

Use [OPA/Conftest](https://www.conftest.dev/) or [Sentinel](https://www.hashicorp.com/sentinel)
to validate Terraform configurations before plan execution:

```bash
# Deny external data sources
conftest test --policy policies/ terraform/

# Policy example (Rego):
# deny[msg] {
#   input.resource_changes[_].type == "external"
#   msg := "External data sources are not allowed"
# }
```

## Further Reading

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [Google Cloud: Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [HashiCorp: Security in Terraform](https://developer.hashicorp.com/terraform/cloud-docs/architectural-details/security-model)
- [OWASP CI/CD Security](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Cycode: Why Terraform Plan Is Not Harmless](https://cycode.com/blog/terraform-plan-is-not-harmless/)
- [Praetorian: Attacking Terraform](https://www.praetorian.com/blog/attacking-and-defending-terraform/)
- [Bridgecrew: Terraform Security Best Practices](https://www.checkov.io/)
