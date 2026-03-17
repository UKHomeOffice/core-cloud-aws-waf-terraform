variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "fms_tag_key" {
  type    = string
  default = "fms-managed"
}

variable "slots" {
  type = list(string)
}

variable "slot_config" {
  type    = map(any)
  default = {}
}

############################################################
# Managed rule toggles (global defaults)
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

variable "default_catch_all_slot" {
  type    = string
  default = "blue"
}

variable "enable_waf_logging" {
  type    = bool
  default = false
}

variable "waf_log_destination_arn_by_slot" {
  description = "Map of slot => Firehose delivery stream ARN for WAF logging (streams must be named aws-waf-logs-*)."
  type        = map(string)
  default     = {}
}

variable "platform_exclude_account_ids" {
  description = "Account IDs to exclude from platform default FMS policies. Platform controlled."
  type        = list(string)
  default     = []
}

variable "tenant_exclude_account_ids" {
  description = "Account IDs to exclude from all tenant FMS policies. Platform controlled."
  type        = list(string)
  default     = []
}

############################################################
# Platform controls (Emergency + Baseline)
############################################################
variable "platform" {
  type = object({
    emergency = optional(object({
      block_ip_sets   = optional(any, {}) # global + per-slot keys
      block_countries = optional(any, {}) # global + per-slot keys
    }), {})

    baseline = optional(object({
      # TRUSTED (label-only -> platform:trusted)
      trusted_ip_sets    = optional(any, {}) # global + per-slot keys; uses "allowlist" list
      trusted_countries  = optional(any, {}) # global + per-slot keys; list(string)

      # BLOCKS
      block_ip_sets      = optional(any, {}) # global + per-slot keys; uses "blocklist" list
      block_countries    = optional(any, {}) # global + per-slot keys; list(string)
    }), {})
  })

  default = {}
}

############################################################
# Tenants (ip_sets + geo per slot)
############################################################
variable "tenants" {
  type = map(object({
    enabled            = optional(bool, true)
    slots              = optional(list(string))
    enable_bot_control = optional(bool, false)

    ip_sets = optional(map(object({
      allowlist = optional(list(string), [])
      blocklist = optional(list(string), [])
    })), {})

    geo = optional(map(object({
      allow = optional(list(string), [])
      block = optional(list(string), [])
    })), {})
  }))

  default = {}
}