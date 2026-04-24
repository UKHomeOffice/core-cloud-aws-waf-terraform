variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "slot" {
  type = string
}

# tenant is null for default policies
variable "tenant" {
  type    = string
  default = null
}

variable "include_account_ids" {
  description = "Account IDs to scope this FMS policy to. Mutually exclusive with exclude_account_ids."
  type        = list(string)
  default     = []
}

variable "exclude_account_ids" {
  description = "Account IDs to exclude from this FMS policy."
  type        = list(string)
  default     = []
}

############################################################
# WAF Logging
############################################################
variable "waf_log_destination_arn" {
  description = "Kinesis Firehose delivery stream ARN used for WAF logging (must exist in the account where the WebACL is created)."
  type        = string
  default     = null
}

############################################################
# Policy selector
#
# - "default"         => catch-all EXCLUDE mode (blue)
# - "default_include" => include-only default (green)
# - "tenant"          => include-only tenant policy
############################################################
variable "policy_selector" {
  type = string

  validation {
    condition     = contains(["default", "default_include", "tenant"], var.policy_selector)
    error_message = "policy_selector must be one of: default, default_include, tenant."
  }
}

############################################################
# Rule group ARNs
############################################################
variable "essential_rule_group_arn" {
  type = string
}

variable "tenant_rule_group_arn" {
  type    = string
  default = null
}

# Platform emergency rule groups (optional)
variable "platform_emergency_first_rule_group_arn" {
  type    = string
  default = null
}

variable "platform_emergency_last_rule_group_arn" {
  type    = string
  default = null
}

# Platform baseline rule group (optional)
variable "platform_baseline_rule_group_arn" {
  description = "Platform baseline rule group ARN (trusted labels + platform blocks). Runs in PRE."
  type        = string
  default     = null
}

############################################################
# Managed rule toggles
############################################################
variable "enable_core_rule_set" {
  type    = bool
  default = true
}

variable "enable_ip_reputation" {
  type    = bool
  default = true
}

variable "enable_anonymous_ip" {
  type    = bool
  default = true
}

variable "enable_bot_control" {
  type    = bool
  default = false
}

variable "enable_layer7_ddos" {
  type    = bool
  default = true
}

variable "antiddos_sensitivity_to_block" {
  type    = string
  default = "LOW"
}

variable "antiddos_challenge_usage" {
  type    = string
  default = "DISABLED"
}

############################################################
# FMS tagging / scoping
############################################################
variable "fms_tag_key" {
  description = "Tag key used to mark resources as managed by FMS (used for include-only policies)."
  type        = string
  default     = "fms-managed"
}

# Optional override.
# IMPORTANT:
# - If policy_selector == "default" (exclude-mode), this map is treated as EXCLUSION tags.
# - If policy_selector != "default" (include-only), this map is treated as INCLUSION tags.
variable "resource_tags" {
  description = "Resource tags used by FMS to include/exclude resources. Overrides module defaults."
  type        = map(string)
  default     = null
}

############################################################
# Tags
############################################################
variable "tags" {
  type    = map(string)
  default = {}
}

variable "resource_type_list" {
  description = "Resource types this FMS policy applies to."
  type        = list(string)
  default     = [
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ApiGateway::Stage",
  ]
}
variable "bot_control_rules" {
  description = "Map of Bot Control rule name to action override. Values: COUNT, BLOCK, ALLOW, NONE (NONE removes any override)."
  type        = map(string)
  default     = {}
}

variable "bot_control_inspection_level" {
  description = "Bot Control inspection level. COMMON includes only common bot rules. TARGETED additionally enables TGT_ rules."
  type        = string
  default     = "TARGETED"

  validation {
    condition     = contains(["COMMON", "TARGETED"], var.bot_control_inspection_level)
    error_message = "Must be COMMON or TARGETED."
  }
}