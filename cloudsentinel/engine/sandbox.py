"""
CloudSentinel Local In-Memory Sandbox Engine.

Provides safe, zero-cost, local-only simulation of Infrastructure-as-Code resources
using Moto and Boto3. Simulates IAM roles, S3 buckets, EC2 Security Groups, and
estimates monthly cost savings from orphaned or wasteful resources without ever
making live AWS network calls.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import boto3
from moto import mock_aws

from cloudsentinel.engine.evaluator import IaCParser, _extract_string_value
from cloudsentinel.models import IaCFormat, SandboxResult

# Default monthly cost estimation metrics (AWS us-east-1 baseline)
# Standard gp3/gp2 block storage is ~$0.10 per GB/month
EBS_GB_MONTHLY_RATE = 0.10


class LocalSandboxEngine:
    """
    100% in-memory AWS sandbox engine powered by Moto.
    Verifies infrastructure synthesizability, applies security configurations,
    and calculates cost savings for orphaned cloud resources.
    """

    MOCK_AWS_ENV = {
        "AWS_ACCESS_KEY_ID": "testing-mock-access-key",
        "AWS_SECRET_ACCESS_KEY": "testing-mock-secret-key",
        "AWS_SECURITY_TOKEN": "testing-mock-token",
        "AWS_SESSION_TOKEN": "testing-mock-token",
        "AWS_DEFAULT_REGION": "us-east-1",
    }

    def __init__(self, region_name: str = "us-east-1") -> None:
        self.region_name = region_name

    def simulate_patch(self, template_content: str, iac_format: Optional[IaCFormat] = None) -> SandboxResult:
        """
        Simulate deployment of an IaC template completely in-memory using Moto.

        Args:
            template_content: Raw IaC template (CloudFormation, SAM, or Terraform JSON).
            iac_format: Explicit IaCFormat or None to auto-detect.

        Returns:
            SandboxResult with success status, simulated resources, cost savings, and diagnostics.
        """
        simulated_resources: List[str] = []
        diagnostics: List[str] = []
        total_monthly_savings = 0.0

        detected_format = iac_format or IaCParser.detect_format(template_content)

        # Apply mock AWS credentials environment to avoid any accidental external egress
        with patch.dict(os.environ, self.MOCK_AWS_ENV):
            with mock_aws():
                try:
                    data, _ = IaCParser.parse_template(template_content, detected_format)
                    resources = data.get("Resources", {}) if detected_format != IaCFormat.TERRAFORM else data.get("resource", {})

                    if detected_format == IaCFormat.TERRAFORM:
                        simulated_resources, total_monthly_savings, diagnostics = self._simulate_terraform(
                            resources
                        )
                    else:
                        simulated_resources, total_monthly_savings, diagnostics = self._simulate_cloudformation(
                            resources
                        )

                    success = True
                    diag_summary = "\n".join(diagnostics)

                except Exception as exc:
                    success = False
                    diag_summary = f"Sandbox simulation error: {type(exc).__name__}: {str(exc)}"

        return SandboxResult(
            success=success,
            simulated_resources=simulated_resources,
            cost_savings_monthly=round(total_monthly_savings, 2),
            diagnostics=diag_summary,
        )

    def _simulate_cloudformation(
        self, resources: Dict[str, Any]
    ) -> Tuple[List[str], float, List[str]]:
        """Simulate CloudFormation / SAM resources in Moto."""
        simulated: List[str] = []
        diagnostics: List[str] = []
        monthly_savings = 0.0

        if not isinstance(resources, dict):
            return simulated, monthly_savings, diagnostics

        # Find attached volumes in template
        attached_volume_ids: set[str] = set()
        for _, res_data in resources.items():
            if isinstance(res_data, dict) and res_data.get("Type") == "AWS::EC2::VolumeAttachment":
                props = res_data.get("Properties", {})
                vol_ref = _extract_string_value(props.get("VolumeId"))
                if vol_ref:
                    attached_volume_ids.add(vol_ref)

        s3_client = boto3.client("s3", region_name=self.region_name)
        iam_client = boto3.client("iam", region_name=self.region_name)
        ec2_client = boto3.client("ec2", region_name=self.region_name)

        # Ensure default mock VPC exists for security group bindings
        vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
        if not vpcs:
            vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
            default_vpc_id = vpc["Vpc"]["VpcId"]
        else:
            default_vpc_id = vpcs[0]["VpcId"]

        for logical_id, res_data in resources.items():
            if not isinstance(res_data, dict):
                continue

            res_type = res_data.get("Type", "")
            props = res_data.get("Properties", {})
            if not isinstance(props, dict):
                props = {}

            # -------------------------------------------------------------
            # S3 Bucket Simulation
            # -------------------------------------------------------------
            if res_type == "AWS::S3::Bucket":
                bucket_name = _extract_string_value(props.get("BucketName") or f"cloudsentinel-{logical_id}").lower()
                bucket_name = bucket_name.replace("_", "-")

                s3_client.create_bucket(Bucket=bucket_name)

                # Simulate encryption configuration
                enc_config = props.get("BucketEncryption", {})
                if enc_config and isinstance(enc_config, dict):
                    sse_rules = enc_config.get("ServerSideEncryptionConfiguration", [])
                    if sse_rules:
                        boto_rules = []
                        for rule in sse_rules:
                            if isinstance(rule, dict):
                                default_enc = (
                                    rule.get("ServerSideEncryptionByDefault")
                                    or rule.get("ApplyServerSideEncryptionByDefault")
                                    or {}
                                )
                                rule_entry: Dict[str, Any] = {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": default_enc.get("SSEAlgorithm", "AES256")
                                    }
                                }
                                if "KMSMasterKeyId" in default_enc:
                                    rule_entry["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyId"] = default_enc["KMSMasterKeyId"]
                                boto_rules.append(rule_entry)

                        if boto_rules:
                            s3_client.put_bucket_encryption(
                                Bucket=bucket_name,
                                ServerSideEncryptionConfiguration={"Rules": boto_rules},
                            )
                            diagnostics.append(f"[S3] Verified server-side encryption for '{logical_id}' ({bucket_name}).")
                else:
                    diagnostics.append(f"[S3] Notice: Bucket '{logical_id}' simulated without server-side encryption.")

                # Simulate Public Access Block Configuration
                pab_config = props.get("PublicAccessBlockConfiguration", {})
                if pab_config and isinstance(pab_config, dict):
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": pab_config.get("BlockPublicAcls", True),
                            "IgnorePublicAcls": pab_config.get("IgnorePublicAcls", True),
                            "BlockPublicPolicy": pab_config.get("BlockPublicPolicy", True),
                            "RestrictPublicBuckets": pab_config.get("RestrictPublicBuckets", True),
                        },
                    )
                    diagnostics.append(f"[S3] Applied PublicAccessBlockConfiguration to '{logical_id}'.")
                else:
                    diagnostics.append(f"[S3] Notice: No PublicAccessBlock applied to '{logical_id}'.")

                simulated.append(logical_id)

            # -------------------------------------------------------------
            # IAM Role Simulation
            # -------------------------------------------------------------
            elif res_type == "AWS::IAM::Role":
                role_name = _extract_string_value(props.get("RoleName") or f"CloudSentinel-Role-{logical_id}")
                assume_role_doc = props.get("AssumeRolePolicyDocument") or {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                }
                if isinstance(assume_role_doc, dict):
                    assume_role_doc = json.dumps(assume_role_doc)

                iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=str(assume_role_doc),
                )

                # Attach managed policies
                managed_arns = props.get("ManagedPolicyArns", [])
                if isinstance(managed_arns, list):
                    for arn in managed_arns:
                        arn_str = _extract_string_value(arn)
                        if "AdministratorAccess" in arn_str:
                            diagnostics.append(f"[IAM] Warning: Attached AdministratorAccess to role '{logical_id}'.")
                        # In Moto, ensure mock policy exists before attaching
                        pol_name = arn_str.split("/")[-1]
                        try:
                            created_p = iam_client.create_policy(
                                PolicyName=f"MockPolicy-{pol_name}-{logical_id}",
                                PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
                            )
                            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=created_p["Policy"]["Arn"])
                        except Exception:
                            pass

                # Put inline policies
                inline_pols = props.get("Policies", [])
                if isinstance(inline_pols, list):
                    for p in inline_pols:
                        if isinstance(p, dict):
                            p_name = _extract_string_value(p.get("PolicyName", "InlinePolicy"))
                            p_doc = p.get("PolicyDocument", {})
                            doc_str = json.dumps(p_doc) if isinstance(p_doc, dict) else str(p_doc)
                            iam_client.put_role_policy(
                                RoleName=role_name,
                                PolicyName=p_name,
                                PolicyDocument=doc_str,
                            )
                            if '"Action": "*"' in doc_str or "'Action': '*'" in doc_str:
                                diagnostics.append(f"[IAM] Warning: Inline policy '{p_name}' contains wildcard actions.")

                diagnostics.append(f"[IAM] Successfully simulated role '{logical_id}' ({role_name}).")
                simulated.append(logical_id)

            # -------------------------------------------------------------
            # Security Group Simulation
            # -------------------------------------------------------------
            elif res_type == "AWS::EC2::SecurityGroup":
                sg_name = f"CloudSentinel-SG-{logical_id}"
                desc = _extract_string_value(props.get("GroupDescription", "Simulated security group"))
                sg = ec2_client.create_security_group(
                    GroupName=sg_name,
                    Description=desc,
                    VpcId=default_vpc_id,
                )
                sg_id = sg["GroupId"]

                ingress_rules = props.get("SecurityGroupIngress", [])
                if isinstance(ingress_rules, list):
                    for rule in ingress_rules:
                        if isinstance(rule, dict):
                            protocol = _extract_string_value(rule.get("IpProtocol", "tcp"))
                            from_port = int(rule.get("FromPort", 80)) if rule.get("FromPort") is not None else 80
                            to_port = int(rule.get("ToPort", 80)) if rule.get("ToPort") is not None else 80
                            cidr_ip = _extract_string_value(rule.get("CidrIp", ""))

                            ip_permission = {
                                "IpProtocol": protocol,
                                "FromPort": from_port,
                                "ToPort": to_port,
                            }
                            if cidr_ip:
                                ip_permission["IpRanges"] = [{"CidrIp": cidr_ip}]

                            try:
                                ec2_client.authorize_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[ip_permission],
                                )
                            except Exception:
                                pass

                            if cidr_ip == "0.0.0.0/0":
                                diagnostics.append(f"[EC2] Warning: SG '{logical_id}' allows open 0.0.0.0/0 ingress on port {from_port}-{to_port}.")

                diagnostics.append(f"[EC2] Simulated Security Group '{logical_id}' ({sg_id}).")
                simulated.append(logical_id)

            # -------------------------------------------------------------
            # EBS Volume Simulation & Cost Waste Analysis
            # -------------------------------------------------------------
            elif res_type == "AWS::EC2::Volume":
                size = int(props.get("Size", 100))
                vol_type = _extract_string_value(props.get("VolumeType", "gp3"))
                az = _extract_string_value(props.get("AvailabilityZone", f"{self.region_name}a"))

                vol = ec2_client.create_volume(
                    AvailabilityZone=az,
                    Size=size,
                    VolumeType=vol_type,
                )
                vol_id = vol["VolumeId"]

                is_attached = logical_id in attached_volume_ids
                if not is_attached:
                    savings = size * EBS_GB_MONTHLY_RATE
                    monthly_savings += savings
                    diagnostics.append(
                        f"[Cost Waste] Identified orphaned EBS volume '{logical_id}' ({vol_id}, {size} GB). "
                        f"Projected monthly savings: ${savings:.2f}."
                    )
                else:
                    diagnostics.append(f"[EBS] Simulated attached volume '{logical_id}' ({vol_id}, {size} GB).")

                simulated.append(logical_id)

            else:
                simulated.append(logical_id)
                diagnostics.append(f"[Generic] Simulated resource '{logical_id}' of type '{res_type}'.")

        return simulated, monthly_savings, diagnostics

    def _simulate_terraform(
        self, resources: Dict[str, Any]
    ) -> Tuple[List[str], float, List[str]]:
        """Simulate Terraform JSON resources in Moto."""
        simulated: List[str] = []
        diagnostics: List[str] = []
        monthly_savings = 0.0

        if not isinstance(resources, dict):
            return simulated, monthly_savings, diagnostics

        s3_client = boto3.client("s3", region_name=self.region_name)
        ec2_client = boto3.client("ec2", region_name=self.region_name)

        # Track volume attachments
        attached_volume_ids: set[str] = set()
        vol_attachments = resources.get("aws_volume_attachment", {})
        if isinstance(vol_attachments, dict):
            for _, attach_props in vol_attachments.items():
                if isinstance(attach_props, dict):
                    vol_id = _extract_string_value(attach_props.get("volume_id", ""))
                    if vol_id:
                        attached_volume_ids.add(vol_id)

        for tf_type, tf_items in resources.items():
            if not isinstance(tf_items, dict):
                continue

            for res_name, props in tf_items.items():
                if not isinstance(props, dict):
                    props = {}

                if tf_type == "aws_s3_bucket":
                    bucket_name = _extract_string_value(props.get("bucket") or f"tf-{res_name}").lower().replace("_", "-")
                    s3_client.create_bucket(Bucket=bucket_name)
                    enc = bool(props.get("server_side_encryption_configuration"))
                    if enc:
                        diagnostics.append(f"[S3] Verified server-side encryption for '{res_name}' ({bucket_name}).")
                    else:
                        diagnostics.append(f"[S3] Notice: Bucket '{res_name}' simulated without server-side encryption.")
                    simulated.append(res_name)

                elif tf_type == "aws_ebs_volume":
                    size = int(props.get("size", 100))
                    vol_type = _extract_string_value(props.get("type", "gp3"))
                    vol = ec2_client.create_volume(
                        AvailabilityZone=f"{self.region_name}a",
                        Size=size,
                        VolumeType=vol_type,
                    )
                    is_attached = res_name in attached_volume_ids
                    if not is_attached:
                        savings = size * EBS_GB_MONTHLY_RATE
                        monthly_savings += savings
                        diagnostics.append(
                            f"[Cost Waste] Identified orphaned Terraform EBS volume '{res_name}' ({vol['VolumeId']}). "
                            f"Projected monthly savings: ${savings:.2f}."
                        )
                    simulated.append(res_name)

                else:
                    simulated.append(res_name)
                    diagnostics.append(f"[Generic] Simulated Terraform resource '{res_name}' of type '{tf_type}'.")

        return simulated, monthly_savings, diagnostics


__all__ = [
    "LocalSandboxEngine",
    "EBS_GB_MONTHLY_RATE",
]
