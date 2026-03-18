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
  description = "Map of tenant configurations."
  type = map(object({
    enabled             = bool
    enable_bot_control  = bool
    tags                = map(string)
    include_account_ids = optional(list(string), [])
    exclude_account_ids = optional(list(string), [])
    ip_sets = object({
      blue  = object({ allowlist = list(string), blocklist = list(string) })
      green = object({ allowlist = list(string), blocklist = list(string) })
    })
    geo = object({
      blue  = object({ allow = list(string), block = list(string) })
      green = object({ allow = list(string), block = list(string) })
    })
  }))
}