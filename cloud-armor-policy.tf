##################################################################################
# Cloud Armor Policy to protect against OWASP 10 and another one custom rules
##################################################################################

##################################################################################
# VARIABLES
##################################################################################

variable "project"          {}
variable "company_name"     {}
variable "business_unit"    {}
variable "environment_tag"  {}
variable "admin_path"       {}
variable "ip_blacklist"     {} 


##################################################################################
# CLOUD ARMOR POLICY
##################################################################################

resource "random_integer" "rand" {
  min = 10000
  max = 99999
}

resource "google_compute_security_policy" "owasp_10_policy" {
  name          = local.policy_name
  description   = "Policy for external users."

  rule {
    action   = "allow"
    priority = "3000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["${local.ifconfig_co_json.ip}/32"]
      }
    }
    description = "Whitelist Rule to allow known source IP addresses."
  }

  rule {
    action   = "deny(404)"
    priority = "3500"
    match {
        expr {
          expression = "request.path.matches('${var.admin_path}') && !inIpRange(origin.ip, '${local.ifconfig_co_json.ip}/32')"
        }
    }
    description = "Allow only admins to manage the website."
  }

  rule {
    action   = "deny(404)"
    priority = "4900"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = [var.ip_blacklist]
      }
    }
    description = "Blacklist Rule to block known source IP addresses."
  }

  rule {
    action   = "deny(404)"
    priority = "5900"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('xss-stable')"
        }
    }
    description = "Protect against Cross-site scripting."
  }

  rule {
    action   = "deny(404)"
    priority = "5800"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('sqli-stable')"
        }
    }
    description = "Protect against SQL Injection."
  }

  rule {
    action   = "deny(404)"
    priority = "5700"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('lfi-stable')"
        }
    }
    description = "Protect against Local file inclusion."
  }

  rule {
    action   = "deny(404)"
    priority = "5600"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('rfi-stable')"
        }
    }
    description = "Protect against Remote file inclusion."
  }

  rule {
    action   = "deny(404)"
    priority = "5500"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('rce-stable')"
        }
    }
    description = "Protect against Remote code execution."
  }

  rule {
    action   = "deny(404)"
    priority = "5400"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('scannerdetection-stable')"
        }
    }
    description = "Protect against Scanner detection."
  }

  rule {
    action   = "deny(404)"
    priority = "5300"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('protocolattack-stable')"
        }
    }
    description = "Protect against Protocol attack."
  }

  rule {
    action   = "deny(404)"
    priority = "5200"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('php-stable')"
        }
    }
    description = "Protect against PHP Injection."
  }

  rule {
    action   = "deny(404)"
    priority = "5100"
    match {
        expr {
          expression = "evaluatePreconfiguredExpr('sessionfixation-stable')"
        }
    }
    description = "Protect against Session Fixation."
  }

  rule {
    action   = "deny(404)"
    priority = "6900"
    match {
        expr {
          expression = "origin.region_code == 'CN' || origin.region_code == 'RU' || origin.region_code == 'AF' || origin.region_code == 'CD' || origin.region_code == 'CG'"
        }
    }
    description = "Block traffic from known malicious countries."
  }

  rule {
    action   = "deny(404)"
    priority = "6899"
    match {
        expr {
          expression = "origin.region_code == 'CZ' || origin.region_code == 'HK' || origin.region_code == 'IR' || origin.region_code == 'IQ'"
        }
    }
    description = "Block traffic from known malicious countries."
  }

  rule {
    action   = "deny(404)"
    priority = "6898"
    match {
        expr {
          expression = "origin.region_code == 'KZ' || origin.region_code == 'KP' || origin.region_code == 'SO'"
        }
    }
    description = "Block traffic from known malicious countries."
  }

  rule {
    action   = "allow"
    priority = "10000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["0.0.0.0/0"]
      }
    }
    description = "Allow traffic from internet."
  }

  rule {
    action   = "deny(404)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default rule, higher priority overrides it."
  }
}
