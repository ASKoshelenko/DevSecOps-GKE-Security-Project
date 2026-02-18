# =============================================================================
# Cloud Armor WAF Rules - APT Protection
# =============================================================================
#
# Google Cloud Armor provides WAF (Web Application Firewall) and DDoS
# protection for applications behind GCP load balancers. These policies
# protect GKE-hosted services from:
#
#   - Known malicious IP ranges (threat intelligence-based blocking)
#   - OWASP Top 10 attacks (SQL injection, XSS, RFI, etc.)
#   - Geographic restrictions (block traffic from high-risk countries)
#   - Rate limiting to prevent brute force and credential stuffing
#   - Custom rules for APT-specific attack patterns
#
# These policies are attached to backend services of GKE Ingress resources.
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "blocked_countries" {
  description = <<-EOT
    ISO 3166-1 alpha-2 country codes to block.
    Default blocks countries commonly associated with APT infrastructure.
    Adjust based on your organization's threat model and business requirements.
  EOT
  type    = list(string)
  default = ["KP"]  # Only block North Korea by default; add others as needed
}

variable "rate_limit_threshold" {
  description = "Maximum requests per minute from a single IP before rate limiting"
  type        = number
  default     = 1000
}

# -----------------------------------------------------------------------------
# Cloud Armor Security Policy - APT Protection
# -----------------------------------------------------------------------------
resource "google_compute_security_policy" "apt_protection" {
  project     = var.project_id
  name        = "apt-protection-policy-${var.environment}"
  description = "Cloud Armor WAF policy for protecting GKE services against APT-related web attacks"

  # -------------------------------------------------------------------------
  # Rule 1: Block known malicious IPs (highest priority)
  # -------------------------------------------------------------------------
  # Block IP ranges identified from threat intelligence feeds.
  # This list should be updated regularly from CTI sources.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 100
    description = "Block known malicious IP ranges from threat intelligence feeds"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-known-malicious-ips')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 2: Block TOR exit nodes
  # -------------------------------------------------------------------------
  # APT groups frequently use TOR to anonymize their origin.
  # Block all known TOR exit nodes from accessing our services.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 200
    description = "Block TOR exit nodes - commonly used by APT groups for anonymization"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-tor-exit-nodes')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 3: Block crypto mining pool IPs
  # -------------------------------------------------------------------------
  # Prevent compromised pods from being accessed by mining pool infrastructure
  # (reverse connections from pools to check miner status).
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 300
    description = "Block known crypto mining pool IP ranges"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-crypto-miners')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 4: Geographic blocking
  # -------------------------------------------------------------------------
  # Block traffic from countries with high APT activity.
  # Note: Legitimate users may use VPNs, so this should be tuned carefully.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 400
    description = "Block traffic from high-risk geographic regions"

    match {
      expr {
        expression = "origin.region_code in ${jsonencode(var.blocked_countries)}"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 5: OWASP Top 10 - SQL Injection Protection
  # -------------------------------------------------------------------------
  # Detect and block SQL injection attempts in HTTP requests.
  # Uses Cloud Armor's pre-configured WAF rules (ModSecurity CRS).
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1000
    description = "Block SQL injection attacks (OWASP A03:2021)"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 6: OWASP Top 10 - Cross-Site Scripting (XSS) Protection
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1100
    description = "Block cross-site scripting (XSS) attacks (OWASP A07:2017)"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 7: OWASP Top 10 - Remote File Inclusion (RFI) Protection
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1200
    description = "Block remote file inclusion (RFI) attacks"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 8: OWASP Top 10 - Local File Inclusion (LFI) Protection
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1300
    description = "Block local file inclusion (LFI) and path traversal attacks"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 9: Remote Code Execution (RCE) Protection
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1400
    description = "Block remote code execution attempts"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 10: Protocol Attack Protection
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1500
    description = "Block protocol-level attacks (HTTP request smuggling, header injection)"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 11: Scanner / Reconnaissance Detection
  # -------------------------------------------------------------------------
  # Block known vulnerability scanners and reconnaissance tools.
  # APTs often use automated scanners before targeted exploitation.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 1600
    description = "Block automated vulnerability scanners and reconnaissance tools"

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 12: Rate Limiting - Brute Force Prevention
  # -------------------------------------------------------------------------
  # Throttle excessive requests from a single IP to prevent brute force
  # attacks, credential stuffing, and API abuse.
  # -------------------------------------------------------------------------
  rule {
    action   = "throttle"
    priority = 2000
    description = "Rate limit excessive requests to prevent brute force attacks"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      rate_limit_threshold {
        count        = var.rate_limit_threshold
        interval_sec = 60
      }
      enforce_on_key = "IP"
    }
  }

  # -------------------------------------------------------------------------
  # Rule 13: Custom - Block Suspicious User Agents
  # -------------------------------------------------------------------------
  # Block requests with user agents commonly used by malware, C2 frameworks,
  # and exploitation tools.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 2100
    description = "Block suspicious user agents associated with malware and C2 tools"

    match {
      expr {
        expression = <<-EXPR
          request.headers['user-agent'].matches('(?i).*(cobalt|metasploit|meterpreter|empire|covenant|sliver|havoc|brute|nikto|sqlmap|nmap|masscan|dirbuster|gobuster).*')
        EXPR
      }
    }
  }

  # -------------------------------------------------------------------------
  # Rule 14: Custom - Block Web Shell Access Patterns
  # -------------------------------------------------------------------------
  # Detect and block common web shell access patterns in URLs.
  # -------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 2200
    description = "Block web shell access patterns in URLs"

    match {
      expr {
        expression = <<-EXPR
          request.path.matches('(?i).*(cmd|shell|exec|system|passthru|eval|base64_decode|phpinfo).*\\.php.*') ||
          request.query.matches('(?i).*(cmd=|exec=|system=|passthru=|eval=).*')
        EXPR
      }
    }
  }

  # -------------------------------------------------------------------------
  # Default Rule: Allow all other traffic
  # -------------------------------------------------------------------------
  rule {
    action   = "allow"
    priority = 2147483647
    description = "Default rule - allow traffic that passes all security checks"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  # Adaptive Protection - ML-based anomaly detection
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
      # Automatically deploy rules when L7 DDoS is detected
      rule_visibility = "STANDARD"
    }
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "cloud_armor_policy_id" {
  description = "Cloud Armor security policy ID for attaching to backend services"
  value       = google_compute_security_policy.apt_protection.id
}

output "cloud_armor_policy_self_link" {
  description = "Cloud Armor security policy self link"
  value       = google_compute_security_policy.apt_protection.self_link
}
