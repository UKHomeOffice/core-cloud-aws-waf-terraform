locals {
  logging_config = (
    var.waf_log_destination_arn != null
    ? {
    loggingConfiguration = {
      logDestinationConfigs = [var.waf_log_destination_arn]
      redactedFields        = []
      loggingFilterConfigs  = null
    }
  }
    : {}
  )

  ############################################################
  # 1) Platform Emergency Rule Groups (optional)
  ############################################################
  rg_platform_emergency_first = var.platform_emergency_first_rule_group_arn == null ? null : {
    ruleGroupType              = "RuleGroup"
    ruleGroupArn               = var.platform_emergency_first_rule_group_arn
    overrideAction             = { type = "NONE" }
    managedRuleGroupIdentifier = null
    sampledRequestsEnabled     = true
    excludeRules               = []
  }

  rg_platform_emergency_last = var.platform_emergency_last_rule_group_arn == null ? null : {
    ruleGroupType              = "RuleGroup"
    ruleGroupArn               = var.platform_emergency_last_rule_group_arn
    overrideAction             = { type = "NONE" }
    managedRuleGroupIdentifier = null
    sampledRequestsEnabled     = true
    excludeRules               = []
  }

  ############################################################
  # 1b) Platform Baseline Rule Group (optional)
  ############################################################
  rg_platform_baseline = var.platform_baseline_rule_group_arn == null ? null : {
    ruleGroupType              = "RuleGroup"
    ruleGroupArn               = var.platform_baseline_rule_group_arn
    overrideAction             = { type = "NONE" }
    managedRuleGroupIdentifier = null
    sampledRequestsEnabled     = true
    excludeRules               = []
  }

  ############################################################
  # 2) Essential Rule Groups
  ############################################################
  rg_essential = {
    ruleGroupType              = "RuleGroup"
    ruleGroupArn               = var.essential_rule_group_arn
    overrideAction             = { type = "NONE" }
    managedRuleGroupIdentifier = null
    sampledRequestsEnabled     = true
    excludeRules               = []
  }

  rg_tenant = var.tenant_rule_group_arn == null ? null : {
    ruleGroupType              = "RuleGroup"
    ruleGroupArn               = var.tenant_rule_group_arn
    overrideAction             = { type = "NONE" }
    managedRuleGroupIdentifier = null
    sampledRequestsEnabled     = true
    excludeRules               = []
  }

  ############################################################
  # 3) AWS managed rule groups
  ############################################################
  rg_antiddos = var.enable_layer7_ddos ? {
    ruleGroupType          = "ManagedRuleGroup"
    ruleGroupArn           = null
    overrideAction         = { type = "NONE" }
    sampledRequestsEnabled = true
    excludeRules           = []
    managedRuleGroupIdentifier = {
      versionEnabled       = null
      version              = null
      vendorName           = "AWS"
      managedRuleGroupName = "AWSManagedRulesAntiDDoSRuleSet"
      managedRuleGroupConfigs = [
        {
          awsmanagedRulesAntiDDoSRuleSet = {
            sensitivityToBlock = var.antiddos_sensitivity_to_block
            clientSideActionConfig = {
              challenge = {
                usageOfAction = var.antiddos_challenge_usage
              }
            }
          }
        }
      ]
    }
  } : null

  managed_groups = [
      var.enable_core_rule_set ? {
      ruleGroupType          = "ManagedRuleGroup"
      ruleGroupArn           = null
      overrideAction         = { type = "NONE" }
      sampledRequestsEnabled = true
      excludeRules           = []
      managedRuleGroupIdentifier = {
        versionEnabled       = null
        version              = null
        vendorName           = "AWS"
        managedRuleGroupName = "AWSManagedRulesCommonRuleSet"
      }
    } : null,

      var.enable_ip_reputation ? {
      ruleGroupType          = "ManagedRuleGroup"
      ruleGroupArn           = null
      overrideAction         = { type = "NONE" }
      sampledRequestsEnabled = true
      excludeRules           = []
      managedRuleGroupIdentifier = {
        versionEnabled       = null
        version              = null
        vendorName           = "AWS"
        managedRuleGroupName = "AWSManagedRulesAmazonIpReputationList"
      }
    } : null,

      var.enable_anonymous_ip ? {
      ruleGroupType          = "ManagedRuleGroup"
      ruleGroupArn           = null
      overrideAction         = { type = "NONE" }
      sampledRequestsEnabled = true
      excludeRules           = []
      managedRuleGroupIdentifier = {
        versionEnabled       = null
        version              = null
        vendorName           = "AWS"
        managedRuleGroupName = "AWSManagedRulesAnonymousIpList"
      }
    } : null,

      var.enable_bot_control ? {
      ruleGroupType          = "ManagedRuleGroup"
      ruleGroupArn           = null
      overrideAction         = { type = "NONE" }
      sampledRequestsEnabled = true
      excludeRules           = []
      managedRuleGroupIdentifier = {
        versionEnabled       = null
        version              = null
        vendorName           = "AWS"
        managedRuleGroupName = "AWSManagedRulesBotControlRuleSet"
      }
    } : null,

    local.rg_antiddos
  ]

  ############################################################
  # 4) Rule ordering (layered, deterministic)
  ############################################################
  pre_rules = [
    for rg in concat(
        var.platform_emergency_first_rule_group_arn != null ? [local.rg_platform_emergency_first] : [],
        var.platform_baseline_rule_group_arn != null ? [local.rg_platform_baseline] : [],
      [local.rg_essential],
      local.managed_groups,
        var.tenant_rule_group_arn != null ? [local.rg_tenant] : []
    ) : rg if rg != null
  ]

  post_rules = [
    for rg in concat(
        var.platform_emergency_last_rule_group_arn != null ? [local.rg_platform_emergency_last] : []
    ) : rg if rg != null
  ]

  managed_service_data = jsonencode(
    merge(
      {
        type                                    = "WAFV2"
        preProcessRuleGroups                    = local.pre_rules
        postProcessRuleGroups                   = local.post_rules
        defaultAction                           = { type = "ALLOW" }
        customRequestHandling                   = null
        customResponse                          = null
        overrideCustomerWebACLAssociation       = false
        sampledRequestsEnabledForDefaultActions = true
      },
      local.logging_config
    )
  )

  ############################################################
  # 5) Policy name
  ############################################################
  policy_name = (
    var.tenant != null
    ? "${var.name_prefix}-tenant-${var.tenant}-waf-policy-${var.slot}"
    : "${var.name_prefix}-platform-waf-policy-${var.slot}"
  )

  ############################################################
  # 6) FMS resource scoping (SELECTOR-DRIVEN MODEL)
  ############################################################
  tenant_match_tags = merge(
    {
      (var.fms_tag_key) = "true"
      "waf:selector"    = "tenant"
      "waf:slot"        = var.slot
    },
      var.tenant != null ? { "waf:tenant" = var.tenant } : {}
  )

  default_include_match_tags = {
    (var.fms_tag_key) = "true"
    "waf:selector"    = "default_include"
    "waf:slot"        = var.slot
  }

  default_exclusion_tags = {
    (var.fms_tag_key) = "true"
  }

  exclude_mode = (var.policy_selector == "default")

  effective_include_tags = (
    var.resource_tags != null
    ? var.resource_tags
    : (
    var.policy_selector == "tenant"
    ? local.tenant_match_tags
    : local.default_include_match_tags
  )
  )

  effective_resource_tags = local.exclude_mode ? local.default_exclusion_tags : local.effective_include_tags

  policy_tags = merge(
    var.tags,
    {
      "waf:env"      = var.environment
      "waf:slot"     = var.slot
      "waf:selector" = var.policy_selector
    },
      var.tenant != null ? { "waf:tenant" = var.tenant } : {}
  )
}

resource "aws_fms_policy" "this" {
  name                = local.policy_name
  remediation_enabled = true
  resource_type_list = [
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ApiGateway::Stage",
  ]

  dynamic "include_map" {
    for_each = length(var.include_account_ids) > 0 ? [1] : []
    content {
      account = var.include_account_ids
    }
  }

  dynamic "exclude_map" {
    for_each = length(var.exclude_account_ids) > 0 ? [1] : []
    content {
      account = var.exclude_account_ids
    }
  }

  resource_tags         = local.effective_resource_tags
  exclude_resource_tags = local.exclude_mode

  delete_unused_fm_managed_resources = true
  delete_all_policy_resources        = true

  security_service_policy_data {
    type                 = "WAFV2"
    managed_service_data = local.managed_service_data
  }

  tags = local.policy_tags

  lifecycle {
    precondition {
      condition     = var.policy_selector != "tenant" || length(var.include_account_ids) > 0
      error_message = "Tenant policies must have include_account_ids set — tenant policies cannot be org-wide."
    }
    precondition {
      condition     = var.policy_selector != "tenant" || (var.tenant != null && var.tenant_rule_group_arn != null)
      error_message = "When policy_selector=tenant, you must set tenant and tenant_rule_group_arn."
    }
    precondition {
      condition     = var.policy_selector == "tenant" || var.tenant == null
      error_message = "tenant must be null unless policy_selector=tenant."
    }
    precondition {
      condition     = !(length(var.include_account_ids) > 0 && length(var.exclude_account_ids) > 0)
      error_message = "include_account_ids and exclude_account_ids are mutually exclusive."
    }
  }
}