// ==============================================================================
// CloudSentinel Zero-Trust Cedar Policy Suite
// Enforces zero-trust guardrails across AWS Infrastructure-as-Code resources.
// ==============================================================================

// Baseline permit: allows deployment of compliant resources by default
permit (
    principal,
    action,
    resource
);

// Rule 1: Forbid IAM roles with AdministratorAccess or wildcard actions
@id("iam-no-admin-or-wildcard")
@severity("CRITICAL")
@reason("IAM role grants AdministratorAccess or wildcard actions ('*'), violating least-privilege principles")
@recommendation("Remove AdministratorAccess policy and replace wildcard actions ('*') with granular, least-privilege IAM permissions scoped to specific resources")
forbid (
    principal,
    action,
    resource
)
when {
    (
        (resource has resource_type && (resource.resource_type == "AWS::IAM::Role" || resource.resource_type == "aws_iam_role")) ||
        (resource has type && (resource.type == "AWS::IAM::Role" || resource.type == "aws_iam_role"))
    ) && (
        (resource has has_admin_access && resource.has_admin_access == true) ||
        (resource has has_wildcard_action && resource.has_wildcard_action == true) ||
        (resource has managed_policies && resource.managed_policies.contains("arn:aws:iam::aws:policy/AdministratorAccess")) ||
        (resource has managed_policies && resource.managed_policies.contains("AdministratorAccess")) ||
        (resource has actions && resource.actions.contains("*")) ||
        (resource has action && resource.action == "*")
    )
};

// Rule 2: Forbid S3 buckets without server-side encryption or with public access enabled
@id("s3-no-unencrypted-or-public-buckets")
@severity("HIGH")
@reason("S3 bucket lacks server-side encryption or has public access enabled")
@recommendation("Enable default server-side encryption (AES256 or aws:kms) and configure PublicAccessBlockConfiguration to block all public access")
forbid (
    principal,
    action,
    resource
)
when {
    (
        (resource has resource_type && (resource.resource_type == "AWS::S3::Bucket" || resource.resource_type == "aws_s3_bucket")) ||
        (resource has type && (resource.type == "AWS::S3::Bucket" || resource.type == "aws_s3_bucket"))
    ) && (
        (resource has encryption_enabled && resource.encryption_enabled == false) ||
        (resource has encrypted && resource.encrypted == false) ||
        (resource has public_access_enabled && resource.public_access_enabled == true) ||
        (resource has public_access_block && resource.public_access_block == false) ||
        (resource has is_public && resource.is_public == true) ||
        (resource has acl && (
            resource.acl == "public-read" ||
            resource.acl == "public-read-write" ||
            resource.acl == "PublicRead" ||
            resource.acl == "PublicReadWrite"
        ))
    )
};

// Rule 3: Forbid Security groups with open 0.0.0.0/0 ingress
@id("security-group-no-open-ingress")
@severity("HIGH")
@reason("Security group allows open ingress traffic from 0.0.0.0/0")
@recommendation("Restrict ingress CIDR blocks to specific authorized IP ranges or VPC private subnets")
forbid (
    principal,
    action,
    resource
)
when {
    (
        (resource has resource_type && (resource.resource_type == "AWS::EC2::SecurityGroup" || resource.resource_type == "aws_security_group")) ||
        (resource has type && (resource.type == "AWS::EC2::SecurityGroup" || resource.type == "aws_security_group"))
    ) && (
        (resource has has_open_ingress && resource.has_open_ingress == true) ||
        (resource has open_ingress && resource.open_ingress == true) ||
        (resource has cidr_ip && resource.cidr_ip == "0.0.0.0/0") ||
        (resource has cidr_blocks && resource.cidr_blocks.contains("0.0.0.0/0")) ||
        (resource has ingress_cidrs && resource.ingress_cidrs.contains("0.0.0.0/0"))
    )
};

// Rule 4: Flag unattached/orphaned EBS volumes as cost waste
@id("ebs-cost-waste-unattached-volume")
@severity("MEDIUM")
@reason("EBS volume is unattached or orphaned, leading to unnecessary cloud cost waste")
@recommendation("Attach the EBS volume to an active EC2 instance or snapshot and decommission the volume")
forbid (
    principal,
    action,
    resource
)
when {
    (
        (resource has resource_type && (resource.resource_type == "AWS::EC2::Volume" || resource.resource_type == "aws_ebs_volume")) ||
        (resource has type && (resource.type == "AWS::EC2::Volume" || resource.type == "aws_ebs_volume"))
    ) && (
        (resource has is_unattached && resource.is_unattached == true) ||
        (resource has is_orphaned && resource.is_orphaned == true) ||
        (resource has attached && resource.attached == false) ||
        (resource has attachment_state && (resource.attachment_state == "unattached" || resource.attachment_state == "available"))
    )
};
