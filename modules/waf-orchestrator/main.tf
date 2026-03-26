locals {

  tenant_defined_exclusions = distinct(flatten([
    for tenant_name, tenant in var.tenants :
    try(tenant.exclude_account_ids, [])
  ]))

  tenant_included_accounts = distinct(flatten([
    for tenant_name, tenant in var.tenants :
    try(tenant.include_account_ids, [])
  ]))

  effective_platform_exclude = distinct(concat(
    var.platform_exclude_account_ids,
    local.tenant_defined_exclusions,
    local.tenant_included_accounts
  ))

  ############################################################
  # Slots per tenant:
  # - if tenant.slots set -> use it
  # - else -> fall back to var.slots
  ############################################################
  tenant_slots = {
    for tenant_name, tenant in var.tenants :
    tenant_name => (
      try(length(tenant.slots), 0) > 0
      ? tenant.slots
      : distinct(concat(
      [
        for slot, cfg in try(tenant.ip_sets, {}) : slot
        if length(try(cfg.allowlist, [])) > 0 || length(try(cfg.blocklist, [])) > 0
      ],
      [
        for slot, cfg in try(tenant.geo, {}) : slot
        if length(try(cfg.allow, [])) > 0 || length(try(cfg.block, [])) > 0
      ]
    ))
    )
  }

  ############################################################
  # Build <tenant>-<slot> matrix and attach ip_sets/geo per slot
  ############################################################
  tenant_slot_matrix = {
    for item in flatten([
      for tenant_name, tenant in var.tenants : (
        try(tenant.enabled, true) ? [
        for slot in local.tenant_slots[tenant_name] : {
          key    = "${tenant_name}-${slot}"
          tenant = tenant_name
          slot   = slot

          ip_sets = lookup(try(tenant.ip_sets, {}), slot, {
            allowlist = []
            blocklist = []
          })

          geo = lookup(try(tenant.geo, {}), slot, {
            allow = []
            block = []
          })
        }
      ] : []
      )
    ]) : item.key => item
  }

  ############################################################
  # Platform emergency per-slot (merge global + slot-specific)
  ############################################################
  platform_emergency_by_slot = {
    for slot in var.slots : slot => {
      block_ips = distinct(concat(
        try(var.platform.emergency.block_ip_sets.global.blocklist, []),
        try(var.platform.emergency.block_ip_sets[slot].blocklist, [])
      ))

      block_countries = distinct(concat(
        try(var.platform.emergency.block_countries.global, []),
        try(var.platform.emergency.block_countries[slot], [])
      ))
    }
  }

  ############################################################
  # Platform baseline per-slot (merge global + slot-specific)
  # TRUSTED = label-only (platform:trusted)
  ############################################################
  platform_baseline_by_slot = {
    for slot in var.slots : slot => {
      trusted_ips = distinct(concat(
        try(var.platform.baseline.trusted_ip_sets.global.allowlist, []),
        try(var.platform.baseline.trusted_ip_sets[slot].allowlist, [])
      ))

      block_ips = distinct(concat(
        try(var.platform.baseline.block_ip_sets.global.blocklist, []),
        try(var.platform.baseline.block_ip_sets[slot].blocklist, [])
      ))

      block_countries = distinct(concat(
        try(var.platform.baseline.block_countries.global, []),
        try(var.platform.baseline.block_countries[slot], [])
      ))
    }
  }
}

############################################################
# TENANT ACCOUNT VALIDATION
# Ensures all enabled tenants have include_account_ids set
# Prevents accidental org-wide tenant policies
############################################################
resource "terraform_data" "tenant_account_validation" {
  for_each = {
    for tenant_name, tenant in var.tenants :
    tenant_name => tenant
    if try(tenant.enabled, true) && length(try(tenant.include_account_ids, [])) == 0
  }

  lifecycle {
    precondition {
      condition     = length(each.key) == 0  # always false — each.key is never empty
      error_message = "Tenant '${each.key}' must have include_account_ids set. Tenant policies cannot be org-wide — this prevents unintended WAF attachment across all accounts."
    }
  }
}

############################################################
# ESSENTIAL RULE GROUPS
############################################################
module "essential_rule_groups" {
  source = "../waf-rule-group-essential"

  for_each = toset(var.slots)

  name_prefix = var.name_prefix
  environment = var.environment
  slot        = each.value
  tags        = var.tags
}

############################################################
# PLATFORM BASELINE - TRUSTED IP SET (label-only)
############################################################
resource "aws_wafv2_ip_set" "platform_baseline_trusted" {
  for_each = {
    for slot, v in local.platform_baseline_by_slot :
    slot => v if length(v.trusted_ips) > 0
  }

  name               = "${var.name_prefix}-platform-baseline-trusted-${each.key}"
  description        = "Platform baseline trusted set label-only for slot ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.trusted_ips

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = each.key
    "waf:type"   = "baseline-trusted"
  })

  lifecycle {
    create_before_destroy = true
  }
}

############################################################
# PLATFORM BASELINE - BLOCK IP SET
############################################################
resource "aws_wafv2_ip_set" "platform_baseline_block" {
  for_each = {
    for slot, v in local.platform_baseline_by_slot :
    slot => v if length(v.block_ips) > 0
  }

  name               = "${var.name_prefix}-platform-baseline-block-${each.key}"
  description        = "Platform baseline blocklist for slot ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.block_ips

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = each.key
    "waf:type"   = "baseline-blocklist"
  })

  lifecycle {
    create_before_destroy = true
  }
}

############################################################
# PLATFORM BASELINE RULE GROUP
############################################################
module "platform_baseline" {
  source = "../waf-rule-group-platform-baseline"

  for_each = local.platform_baseline_by_slot

  name_prefix = var.name_prefix
  environment = var.environment
  slot        = each.key

  trusted_ipset_arn = try(aws_wafv2_ip_set.platform_baseline_trusted[each.key].arn, null)

  block_ipset_arn = try(aws_wafv2_ip_set.platform_baseline_block[each.key].arn, null)
  block_countries = each.value.block_countries

  healthcheck_allow_ipset_arn = try(aws_wafv2_ip_set.platform_healthcheck_allow[each.key].arn, null)
  curl_allow_ipset_arn        = try(aws_wafv2_ip_set.platform_curl_allow[each.key].arn, null)

  tags = var.tags
}

############################################################
# PLATFORM EMERGENCY IP SETS (block only)
############################################################
resource "aws_wafv2_ip_set" "platform_emergency_block" {
  for_each = {
    for slot, v in local.platform_emergency_by_slot :
    slot => v
    if length(v.block_ips) > 0
  }

  name               = "${var.name_prefix}-platform-emergency-block-${each.key}"
  description        = "Platform emergency blocklist for slot ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.block_ips

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = each.key
    "waf:type"   = "emergency-blocklist"
  })

  lifecycle {
    create_before_destroy = true
  }
}

############################################################
# PLATFORM EMERGENCY RULE GROUPS (FIRST + LAST)
############################################################
module "platform_emergency_first" {
  source = "../waf-rule-group-platform-emergency"

  for_each = local.platform_emergency_by_slot

  name_prefix = var.name_prefix
  environment = var.environment
  slot        = each.key
  kind        = "first"

  block_ipset_arn = try(aws_wafv2_ip_set.platform_emergency_block[each.key].arn, null)
  block_countries = each.value.block_countries

  tags = var.tags
}

module "platform_emergency_last" {
  source = "../waf-rule-group-platform-emergency"

  for_each = local.platform_emergency_by_slot

  name_prefix = var.name_prefix
  environment = var.environment
  slot        = each.key
  kind        = "last"

  block_ipset_arn = try(aws_wafv2_ip_set.platform_emergency_block[each.key].arn, null)
  block_countries = each.value.block_countries

  tags = var.tags
}

############################################################
# TENANT IP SETS
############################################################
resource "aws_wafv2_ip_set" "tenant_allow" {
  for_each = {
    for k, v in local.tenant_slot_matrix :
    k => v
    if length(v.ip_sets.allowlist) > 0
  }

  name               = "${var.name_prefix}-allow-${each.value.tenant}-${each.value.slot}"
  description        = "Allowlist for ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.ip_sets.allowlist

  tags = merge(var.tags, {
    "waf:tenant" = each.value.tenant
    "waf:slot"   = each.value.slot
    "waf:type"   = "allowlist"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_ip_set" "tenant_block" {
  for_each = {
    for k, v in local.tenant_slot_matrix :
    k => v
    if length(v.ip_sets.blocklist) > 0
  }

  name               = "${var.name_prefix}-block-${each.value.tenant}-${each.value.slot}"
  description        = "Blocklist for ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.ip_sets.blocklist

  tags = merge(var.tags, {
    "waf:tenant" = each.value.tenant
    "waf:slot"   = each.value.slot
    "waf:type"   = "blocklist"
  })

  lifecycle {
    create_before_destroy = true
  }
}

############################################################
# TENANT RULE GROUPS (IP sets + geo)
############################################################
module "tenant_rule_groups" {
  source = "../waf-rule-group-tenant-custom"

  for_each = local.tenant_slot_matrix

  name_prefix = var.name_prefix
  tenant      = each.value.tenant
  slot        = each.value.slot

  allow_ipset_arn = try(aws_wafv2_ip_set.tenant_allow[each.key].arn, null)
  block_ipset_arn = try(aws_wafv2_ip_set.tenant_block[each.key].arn, null)

  allow_countries = try(each.value.geo.allow, [])
  block_countries = try(each.value.geo.block, [])

  tags = var.tags
}

############################################################
# DEFAULT POLICIES
############################################################
module "default_policies" {
  source = "../waf-fms-policy"

  for_each = toset(var.slots)

  name_prefix = var.name_prefix
  environment = var.environment
  slot        = each.value

  essential_rule_group_arn = module.essential_rule_groups[each.value].rule_group_arn

  tenant_rule_group_arn = null
  tenant                = null

  exclude_account_ids = local.effective_platform_exclude

  policy_selector = try(var.slot_config[each.value].policy_selector, "default_include")

  resource_type_list = try(
    var.slot_config[each.value].resource_type_list,
    [
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "AWS::ApiGateway::Stage",
    ]
  )

  enable_core_rule_set = try(var.slot_config[each.value].enable_core_rule_set, var.enable_core_rule_set)
  enable_ip_reputation = try(var.slot_config[each.value].enable_ip_reputation, var.enable_ip_reputation)
  enable_anonymous_ip  = try(var.slot_config[each.value].enable_anonymous_ip, var.enable_anonymous_ip)
  enable_bot_control   = try(var.slot_config[each.value].enable_bot_control, var.enable_bot_control)
  enable_layer7_ddos   = try(var.slot_config[each.value].enable_layer7_ddos, var.enable_layer7_ddos)

  antiddos_sensitivity_to_block = var.antiddos_sensitivity_to_block
  antiddos_challenge_usage      = var.antiddos_challenge_usage

  fms_tag_key = var.fms_tag_key

  platform_baseline_rule_group_arn        = try(module.platform_baseline[each.value].rule_group_arn, null)
  platform_emergency_first_rule_group_arn = try(module.platform_emergency_first[each.value].rule_group_arn, null)
  platform_emergency_last_rule_group_arn  = try(module.platform_emergency_last[each.value].rule_group_arn, null)

  waf_log_destination_arn = try(var.waf_log_destination_arn_by_slot[each.value], null)

  tags = var.tags
}

############################################################
# TENANT POLICIES
############################################################
module "tenant_policies" {
  source = "../waf-fms-policy"

  for_each = local.tenant_slot_matrix

  depends_on = [
    module.default_policies
  ]

  name_prefix     = var.name_prefix
  environment     = var.environment
  tenant          = each.value.tenant
  slot            = each.value.slot
  policy_selector = "tenant"

  essential_rule_group_arn = module.essential_rule_groups[each.value.slot].rule_group_arn
  tenant_rule_group_arn    = module.tenant_rule_groups[each.key].rule_group_arn

  include_account_ids = try(var.tenants[each.value.tenant].include_account_ids, [])

  resource_type_list = try(
    var.slot_config[each.value.slot].resource_type_list,
    [
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "AWS::ApiGateway::Stage",
    ]
  )

  enable_core_rule_set = try(var.slot_config[each.value.slot].enable_core_rule_set, var.enable_core_rule_set)
  enable_ip_reputation = try(var.slot_config[each.value.slot].enable_ip_reputation, var.enable_ip_reputation)
  enable_anonymous_ip  = try(var.slot_config[each.value.slot].enable_anonymous_ip, var.enable_anonymous_ip)
  enable_layer7_ddos   = try(var.slot_config[each.value.slot].enable_layer7_ddos, var.enable_layer7_ddos)

  enable_bot_control = try(
    var.tenants[each.value.tenant].enable_bot_control,
    try(var.slot_config[each.value.slot].enable_bot_control, var.enable_bot_control)
  )

  antiddos_sensitivity_to_block = var.antiddos_sensitivity_to_block
  antiddos_challenge_usage      = var.antiddos_challenge_usage

  fms_tag_key = var.fms_tag_key

  platform_baseline_rule_group_arn        = try(module.platform_baseline[each.value.slot].rule_group_arn, null)
  platform_emergency_first_rule_group_arn = try(module.platform_emergency_first[each.value.slot].rule_group_arn, null)
  platform_emergency_last_rule_group_arn  = try(module.platform_emergency_last[each.value.slot].rule_group_arn, null)

  waf_log_destination_arn = try(var.waf_log_destination_arn_by_slot[each.value.slot], null)

  tags = var.tags
}

resource "aws_wafv2_ip_set" "platform_healthcheck_allow" {
  for_each = {
    for slot in var.slots : slot => distinct(concat(
      try(var.platform.baseline.operational_allow.healthcheck_ip_sets.global.allowlist, []),
      try(var.platform.baseline.operational_allow.healthcheck_ip_sets[slot].allowlist, [])
    ))
    if length(distinct(concat(
      try(var.platform.baseline.operational_allow.healthcheck_ip_sets.global.allowlist, []),
      try(var.platform.baseline.operational_allow.healthcheck_ip_sets[slot].allowlist, [])
    ))) > 0
  }

  name               = "${var.name_prefix}-healthcheck-${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value

  tags = merge(var.tags, {
    "waf:slot" = each.key
  })
}

resource "aws_wafv2_ip_set" "platform_curl_allow" {
  for_each = {
    for slot in var.slots : slot => distinct(concat(
      try(var.platform.baseline.operational_allow.curl_ip_sets.global.allowlist, []),
      try(var.platform.baseline.operational_allow.curl_ip_sets[slot].allowlist, [])
    ))
    if length(distinct(concat(
      try(var.platform.baseline.operational_allow.curl_ip_sets.global.allowlist, []),
      try(var.platform.baseline.operational_allow.curl_ip_sets[slot].allowlist, [])
    ))) > 0
  }

  name               = "${var.name_prefix}-curl-${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value

  tags = merge(var.tags, {
    "waf:slot" = each.key
  })
}
