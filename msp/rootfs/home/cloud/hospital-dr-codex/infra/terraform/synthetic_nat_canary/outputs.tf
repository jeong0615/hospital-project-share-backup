output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" { value = data.aws_region.current.name }
output "run_id" { value = var.run_id }
output "synthetic_ami_id" { value = var.synthetic_ami_id }
output "synthetic_ami_owner_id" { value = try(data.aws_ami.synthetic[0].owner_id, "") }
output "root_volume_size_gib" { value = var.root_volume_size_gib }
output "vpc_id" { value = try(aws_vpc.canary[0].id, "") }
output "vpc_cidr" { value = var.vpc_cidr }
output "public_subnet_id" { value = try(aws_subnet.public[0].id, "") }
output "public_subnet_cidr" { value = var.public_subnet_cidr }
output "private_subnet_id" { value = try(aws_subnet.private[0].id, "") }
output "private_subnet_cidr" { value = var.private_subnet_cidr }
output "web_instance_id" { value = try(aws_instance.web[0].id, "") }
output "web_eni_id" { value = try(aws_network_interface.web[0].id, "") }
output "web_private_ip" { value = var.web_private_ip }
output "web_eip" { value = try(aws_eip.web[0].public_ip, "") }
output "web_eip_allocation_id" { value = try(aws_eip.web[0].id, "") }
output "emr_instance_id" { value = try(aws_instance.emr[0].id, "") }
output "emr_eni_id" { value = try(aws_network_interface.emr[0].id, "") }
output "emr_private_ip" { value = var.emr_private_ip }
output "web_sg_id" { value = try(aws_security_group.web[0].id, "") }
output "emr_sg_id" { value = try(aws_security_group.emr[0].id, "") }
output "ssm_endpoint_sg_id" { value = try(aws_security_group.ssm_endpoint[0].id, "") }
output "default_sg_id" { value = try(aws_default_security_group.canary[0].id, "") }
output "ssm_endpoint_ids" { value = { for service, endpoint in aws_vpc_endpoint.ssm : service => endpoint.id } }
output "ssm_endpoint_eni_ids" { value = { for service, endpoint in aws_vpc_endpoint.ssm : service => one(endpoint.network_interface_ids) } }
output "public_route_table_id" { value = try(aws_route_table.public[0].id, "") }
output "private_route_table_id" { value = try(aws_route_table.private[0].id, "") }
output "default_route_table_id" { value = try(aws_default_route_table.canary[0].id, "") }
output "web_network_acl_id" { value = try(aws_network_acl.web[0].id, "") }
output "emr_network_acl_id" { value = try(aws_network_acl.emr[0].id, "") }
output "default_network_acl_id" { value = try(aws_default_network_acl.canary[0].id, "") }
output "internet_gateway_id" { value = try(aws_internet_gateway.canary[0].id, "") }
output "firewall_rule_group_id" { value = try(aws_route53_resolver_firewall_rule_group.canary[0].id, "") }
output "firewall_allow_domain_list_id" { value = try(aws_route53_resolver_firewall_domain_list.allow[0].id, "") }
output "firewall_block_domain_list_id" { value = try(aws_route53_resolver_firewall_domain_list.block_all[0].id, "") }
output "firewall_association_id" { value = try(aws_route53_resolver_firewall_rule_group_association.canary[0].id, "") }
output "ssm_role_name" { value = try(aws_iam_role.ssm[0].name, "") }
output "ssm_instance_profile_name" { value = try(aws_iam_instance_profile.ssm[0].name, "") }
output "probe_ipv4" { value = var.probe_ipv4 }
output "probe_domain" { value = var.probe_domain }
