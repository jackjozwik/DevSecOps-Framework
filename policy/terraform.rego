package main

# Enforce encryption for S3 buckets
deny_s3_bucket_encryption[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_s3_bucket"
  not resource.values.server_side_encryption_configuration
  msg = sprintf("S3 bucket %s must have server-side encryption enabled.", [resource.address])
}

# Restrict public access to SSH (22) and RDP (3389)
deny_security_group_ssh[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.values.ingress[_].from_port == 22
  resource.values.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg = sprintf("Security group %s allows unrestricted SSH access.", [resource.address])
}

deny_security_group_rdp[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.values.ingress[_].from_port == 3389
  resource.values.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg = sprintf("Security group %s allows unrestricted RDP access.", [resource.address])
}

# Enforce instance type restrictions to prevent using t2.micro
deny_instance_type[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_instance"
  resource.values.instance_type == "t2.micro"
  msg = sprintf("Instance type t2.micro is not allowed for resource %s.", [resource.address])
}

# Ensure EC2 instances are launched in private subnets
deny_private_subnet[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_instance"
  private_subnet_ids := {"subnet-12345678", "subnet-87654321"}
  not private_subnet_ids[resource.values.subnet_id]
  msg = sprintf("EC2 instance %s must be launched in a private subnet.", [resource.address])
}

# Enforce IAM roles with least privilege
deny_iam_least_privilege[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_iam_role"
  assume_role_actions := [action | 
    statement := resource.values.assume_role_policy_statement[_]; 
    action := statement.actions[_]; 
    action == "sts:AssumeRole"
  ]
  count(assume_role_actions) > 1
  msg = sprintf("IAM role %s grants more than one AssumeRole action, violating the principle of least privilege.", [resource.address])
}

# Restrict overly open ports for ingress
deny_security_group_ingress_port_range[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.values.ingress[_].from_port == 0
  resource.values.ingress[_].to_port == 65535
  msg = sprintf("Security group %s has an overly open ingress port range.", [resource.address])
}

# Restrict overly open ports for egress
deny_security_group_egress_port_range[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.values.egress[_].from_port == 0
  resource.values.egress[_].to_port == 65535
  msg = sprintf("Security group %s has an overly open egress port range.", [resource.address])
}

# Warning for missing tags
warn_missing_tags[msg] {
  resource := input.planned_values.root_module.resources[_]
  not resource.values.tags
  msg = sprintf("Resource %s does not have tags defined.", [resource.address])
}
