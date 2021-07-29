##################################################################################
# LOCALS
##################################################################################

# Grabbing the Public IP of our Cloud Architect ;)
data "http" "my_public_ip" {
  url = "https://ifconfig.co/json"
  request_headers = {
    Accept = "application/json"
  }
}

locals {
  ifconfig_co_json = jsondecode(data.http.my_public_ip.body)
}

locals {
  env_name          =   lower(terraform.workspace)
  co_name           =   lower(var.company_name)
  biz_name          =   lower(var.business_unit)

  policy_name       =   "${local.co_name}-${local.biz_name}-${local.env_name}-policy-${random_integer.rand.result}"

}
