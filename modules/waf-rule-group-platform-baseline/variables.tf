variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "slot" {
  type = string
}

############################################################
# TRUSTED (LABEL ONLY)
############################################################

# Optional platform trusted IP set ARN (labels platform:trusted)
variable "trusted_ipset_arn" {
  type    = string
  default = null
}

############################################################
# BLOCKS
############################################################

# Optional platform blocklist IP set ARN
variable "block_ipset_arn" {
  type    = string
  default = null
}

# Optional geo block list
variable "block_countries" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "healthcheck_allow_ipset_arn" {
  type    = string
  default = null
}

variable "curl_allow_ipset_arn" {
  type    = string
  default = null
}