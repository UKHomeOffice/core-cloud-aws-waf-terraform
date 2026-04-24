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
      trusted_ip_sets   = optional(any, {}) # global + per-slot keys; uses "allowlist" list
      trusted_countries = optional(any, {}) # global + per-slot keys; list(string)

      # GENERIC TRUSTED REQUEST RULES
      # - global rules act as defaults
      # - slot rules with the same name override global rules for that slot
      trusted_request_rules = optional(map(list(object({
        name   = string
        action = string           # allow | count | block
        label  = optional(string) # used when action = count

        match = object({
          methods = optional(list(string), [])

          uri = optional(object({
            exact = optional(list(string), [])
            regex = optional(list(string), [])
          }), {})

          headers = optional(object({
            host = optional(object({
              exact = optional(list(string), [])
              regex = optional(list(string), [])
            }), {})

            required = optional(list(string), [])
          }), {})

          source = optional(object({
            ipv4_cidrs = optional(list(string), [])
          }), {})
        })
      }))), {})

      # CAPACITY
      capacity = optional(any, {})

      # BOT CONTROL RULE OVERRIDES
      # global key applies to all slots; per-slot keys override global values
      # Values: COUNT | BLOCK | ALLOW | NONE
      bot_control_rules = optional(any, {})

      # COMMON = only COMMON rules active
      # TARGETED = COMMON + TGT_ rules active (default)
      bot_control_inspection_level = optional(string, "TARGETED")

      # BLOCKS
      block_ip_sets   = optional(any, {}) # global + per-slot keys; uses "blocklist" list
      block_countries = optional(any, {}) # global + per-slot keys; list(string)

      # OPERATIONAL ALLOW RULES
      operational_allow = optional(object({
        healthcheck_ip_sets = optional(any, {}) # global + per-slot keys; uses "allowlist"
        curl_ip_sets        = optional(any, {}) # global + per-slot keys; uses "allowlist"
      }), {})
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

    slots = optional(list(string), [])

    ip_sets = optional(map(object({
      allowlist = list(string)
      blocklist = list(string)
    })), {})

    geo = optional(map(object({
      allow = list(string)
      block = list(string)
    })), {})
  }))
}