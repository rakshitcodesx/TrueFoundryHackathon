"""
CloudSentinel Policy Evaluation Engine.

Provides AST parsing for CloudFormation/SAM YAML and Terraform JSON,
normalization to AWS Cedar entity representations, and formal verification
against zero-trust Cedar policies.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import cedarpy
import yaml

from cloudsentinel.models import (
    IaCFormat,
    PolicyViolation,
    ScanResult,
    Severity,
)

# Default path to zero-trust Cedar policy
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "zerotrust.cedar"


# -----------------------------------------------------------------------------
# Custom PyYAML Loader for CloudFormation / SAM Intrinsic Functions
# -----------------------------------------------------------------------------

class CloudFormationYamlLoader(yaml.SafeLoader):
    """Safe PyYAML loader capable of resolving CloudFormation / SAM intrinsic tags."""
    pass


def _cfn_tag_constructor(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
    """Fallback constructor for CloudFormation intrinsic function tags (e.g. !Ref, !Sub)."""
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node)}
    return {tag_suffix: None}


# Register catch-all multi-constructor for all '!' prefixed CloudFormation tags
CloudFormationYamlLoader.add_multi_constructor("!", _cfn_tag_constructor)


# -----------------------------------------------------------------------------
# Helper String Extraction Utilities
# -----------------------------------------------------------------------------

def _extract_string_value(val: Any) -> str:
    """Extract raw string representation from scalars or intrinsic dicts."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        for sub_val in val.values():
            if isinstance(sub_val, str):
                return sub_val
    return str(val) if val is not None else ""


# -----------------------------------------------------------------------------
# IaC Parser & Entity Normalizer
# -----------------------------------------------------------------------------

class IaCParser:
    """
    Parser and normalizer for Infrastructure-as-Code templates.
    Supports CloudFormation YAML, SAM YAML, and Terraform JSON.
    """

    @staticmethod
    def detect_format(content: str) -> IaCFormat:
        """Detect the IaC format (CloudFormation, SAM, or Terraform) from content."""
        trimmed = content.strip()
        # Attempt JSON parsing first
        if trimmed.startswith("{"):
            try:
                parsed_json = json.loads(content)
                if isinstance(parsed_json, dict):
                    if "resource" in parsed_json or "terraform" in parsed_json or "provider" in parsed_json:
                        return IaCFormat.TERRAFORM
                    if "Transform" in parsed_json and "Serverless" in str(parsed_json.get("Transform")):
                        return IaCFormat.SAM
                    if "AWSTemplateFormatVersion" in parsed_json or "Resources" in parsed_json:
                        return IaCFormat.CLOUDFORMATION
            except Exception:
                pass

        # Parse with CloudFormation YAML loader
        try:
            parsed_yaml = yaml.load(content, Loader=CloudFormationYamlLoader)
            if isinstance(parsed_yaml, dict):
                if "Transform" in parsed_yaml and "Serverless" in str(parsed_yaml.get("Transform")):
                    return IaCFormat.SAM
                if "resource" in parsed_yaml and "Resources" not in parsed_yaml:
                    return IaCFormat.TERRAFORM
                return IaCFormat.CLOUDFORMATION
        except Exception:
            pass

        return IaCFormat.CLOUDFORMATION

    @classmethod
    def parse_template(cls, content: str, iac_format: Optional[IaCFormat] = None) -> Tuple[Dict[str, Any], IaCFormat]:
        """Parse raw template content into a structured dictionary and detected format."""
        format_detected = iac_format or cls.detect_format(content)

        if format_detected == IaCFormat.TERRAFORM:
            try:
                data = json.loads(content)
            except Exception:
                data = yaml.load(content, Loader=CloudFormationYamlLoader) or {}
        else:
            data = yaml.load(content, Loader=CloudFormationYamlLoader) or {}

        if not isinstance(data, dict):
            data = {}

        return data, format_detected

    @classmethod
    def normalize_to_cedar_entities(cls, content: str, iac_format: Optional[IaCFormat] = None) -> List[Dict[str, Any]]:
        """
        Parse and transform IaC template resources into Cedar entity specifications.
        Each entity dict adheres to: {"uid": {"type": "Resource", "id": <str>}, "attrs": <dict>, "parents": []}
        """
        data, detected_format = cls.parse_template(content, iac_format)
        entities: List[Dict[str, Any]] = []

        if detected_format == IaCFormat.TERRAFORM:
            entities = cls._normalize_terraform(data)
        else:
            entities = cls._normalize_cloudformation(data)

        return entities

    @classmethod
    def _normalize_cloudformation(cls, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize CloudFormation / SAM resources into Cedar entities."""
        resources = data.get("Resources", {})
        if not isinstance(resources, dict):
            return []

        # Track volume attachments across template
        attached_volume_ids: set[str] = set()
        for res_id, res_data in resources.items():
            if not isinstance(res_data, dict):
                continue
            res_type = res_data.get("Type", "")
            props = res_data.get("Properties", {})
            if res_type == "AWS::EC2::VolumeAttachment" and isinstance(props, dict):
                vol_ref = _extract_string_value(props.get("VolumeId"))
                if vol_ref:
                    attached_volume_ids.add(vol_ref)

        entities: List[Dict[str, Any]] = []

        for logical_id, res_data in resources.items():
            if not isinstance(res_data, dict):
                continue

            res_type = res_data.get("Type", "")
            props = res_data.get("Properties", {})
            if not isinstance(props, dict):
                props = {}

            attrs: Dict[str, Any] = {
                "resource_type": res_type,
                "type": res_type,
            }

            # -------------------------------------------------------------
            # IAM Role Normalization
            # -------------------------------------------------------------
            if res_type == "AWS::IAM::Role":
                managed_policies_raw = props.get("ManagedPolicyArns", [])
                managed_policies: List[str] = []
                has_admin = False

                if isinstance(managed_policies_raw, list):
                    for p in managed_policies_raw:
                        p_str = _extract_string_value(p)
                        managed_policies.append(p_str)
                        if "AdministratorAccess" in p_str:
                            has_admin = True

                has_wildcard = False
                actions: List[str] = []

                policies = props.get("Policies", [])
                if isinstance(policies, list):
                    for pol in policies:
                        if isinstance(pol, dict):
                            doc = pol.get("PolicyDocument", {})
                            statements = doc.get("Statement", []) if isinstance(doc, dict) else []
                            if isinstance(statements, dict):
                                statements = [statements]
                            for stmt in statements:
                                if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                                    action_spec = stmt.get("Action", [])
                                    if isinstance(action_spec, str):
                                        actions.append(action_spec)
                                        if action_spec == "*":
                                            has_wildcard = True
                                    elif isinstance(action_spec, list):
                                        for a in action_spec:
                                            a_str = _extract_string_value(a)
                                            actions.append(a_str)
                                            if a_str == "*":
                                                has_wildcard = True

                attrs.update({
                    "has_admin_access": has_admin,
                    "has_wildcard_action": has_wildcard,
                    "managed_policies": managed_policies,
                    "actions": actions,
                })

            # -------------------------------------------------------------
            # S3 Bucket Normalization
            # -------------------------------------------------------------
            elif res_type == "AWS::S3::Bucket":
                # Check server-side encryption
                bucket_enc = props.get("BucketEncryption", {})
                sse_config = bucket_enc.get("ServerSideEncryptionConfiguration", []) if isinstance(bucket_enc, dict) else []
                encryption_enabled = bool(sse_config and len(sse_config) > 0)

                # Check public access block
                pab = props.get("PublicAccessBlockConfiguration", {})
                acl = _extract_string_value(props.get("AccessControl", ""))

                is_public = False
                pab_enabled = False

                if acl in ["public-read", "public-read-write", "PublicRead", "PublicReadWrite"]:
                    is_public = True

                if isinstance(pab, dict) and pab:
                    block_acls = pab.get("BlockPublicAcls") is True
                    ignore_acls = pab.get("IgnorePublicAcls") is True
                    block_policy = pab.get("BlockPublicPolicy") is True
                    restrict_buckets = pab.get("RestrictPublicBuckets") is True
                    if block_acls and ignore_acls and block_policy and restrict_buckets and not is_public:
                        pab_enabled = True
                    else:
                        is_public = True
                else:
                    is_public = True

                attrs.update({
                    "encryption_enabled": encryption_enabled,
                    "encrypted": encryption_enabled,
                    "public_access_enabled": is_public,
                    "public_access_block": pab_enabled,
                    "is_public": is_public,
                    "acl": acl,
                })

            # -------------------------------------------------------------
            # Security Group Normalization
            # -------------------------------------------------------------
            elif res_type == "AWS::EC2::SecurityGroup":
                ingress_rules = props.get("SecurityGroupIngress", [])
                ingress_cidrs: List[str] = []
                has_open_ingress = False

                if isinstance(ingress_rules, list):
                    for rule in ingress_rules:
                        if isinstance(rule, dict):
                            cidr_ip = _extract_string_value(rule.get("CidrIp", ""))
                            cidr_ipv6 = _extract_string_value(rule.get("CidrIpv6", ""))
                            if cidr_ip:
                                ingress_cidrs.append(cidr_ip)
                                if cidr_ip == "0.0.0.0/0":
                                    has_open_ingress = True
                            if cidr_ipv6:
                                ingress_cidrs.append(cidr_ipv6)
                                if cidr_ipv6 in ["::/0", "0000:0000:0000:0000:0000:0000:0000:0000/0"]:
                                    has_open_ingress = True

                primary_cidr = "0.0.0.0/0" if has_open_ingress else (ingress_cidrs[0] if ingress_cidrs else "")

                attrs.update({
                    "has_open_ingress": has_open_ingress,
                    "open_ingress": has_open_ingress,
                    "cidr_ip": primary_cidr,
                    "cidr_blocks": ingress_cidrs,
                    "ingress_cidrs": ingress_cidrs,
                })

            # -------------------------------------------------------------
            # EBS Volume Normalization
            # -------------------------------------------------------------
            elif res_type == "AWS::EC2::Volume":
                is_attached = logical_id in attached_volume_ids
                attrs.update({
                    "is_unattached": not is_attached,
                    "is_orphaned": not is_attached,
                    "attached": is_attached,
                    "attachment_state": "attached" if is_attached else "unattached",
                })

            entities.append({
                "uid": {"type": "Resource", "id": logical_id},
                "attrs": attrs,
                "parents": [],
            })

        return entities

    @classmethod
    def _normalize_terraform(cls, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Terraform JSON resources into Cedar entities."""
        resources = data.get("resource", {})
        if not isinstance(resources, dict):
            return []

        # Find any aws_volume_attachment
        attached_volume_ids: set[str] = set()
        vol_attachments = resources.get("aws_volume_attachment", {})
        if isinstance(vol_attachments, dict):
            for _, attach_props in vol_attachments.items():
                if isinstance(attach_props, dict):
                    vol_id = _extract_string_value(attach_props.get("volume_id", ""))
                    if vol_id:
                        attached_volume_ids.add(vol_id)

        entities: List[Dict[str, Any]] = []

        for tf_type, tf_blocks in resources.items():
            if not isinstance(tf_blocks, dict):
                continue

            for res_name, props in tf_blocks.items():
                if not isinstance(props, dict):
                    props = {}

                attrs: Dict[str, Any] = {
                    "resource_type": tf_type,
                    "type": tf_type,
                }

                if tf_type == "aws_iam_role":
                    managed_policies = props.get("managed_policy_arns", [])
                    has_admin = False
                    if isinstance(managed_policies, list):
                        for p in managed_policies:
                            p_str = _extract_string_value(p)
                            if "AdministratorAccess" in p_str:
                                has_admin = True

                    actions: List[str] = []
                    has_wildcard = False
                    policy_str = _extract_string_value(props.get("inline_policy", ""))
                    if '"Action": "*"' in policy_str or "'Action': '*'" in policy_str:
                        has_wildcard = True
                        actions.append("*")

                    attrs.update({
                        "has_admin_access": has_admin,
                        "has_wildcard_action": has_wildcard,
                        "managed_policies": managed_policies if isinstance(managed_policies, list) else [],
                        "actions": actions,
                    })

                elif tf_type == "aws_s3_bucket":
                    enc = bool(props.get("server_side_encryption_configuration"))
                    acl = _extract_string_value(props.get("acl", ""))
                    is_public = acl in ["public-read", "public-read-write"] or not props.get("public_access_block", True)

                    attrs.update({
                        "encryption_enabled": enc,
                        "encrypted": enc,
                        "public_access_enabled": is_public,
                        "public_access_block": not is_public,
                        "is_public": is_public,
                        "acl": acl,
                    })

                elif tf_type == "aws_security_group":
                    ingress_rules = props.get("ingress", [])
                    has_open = False
                    ingress_cidrs: List[str] = []
                    if isinstance(ingress_rules, list):
                        for r in ingress_rules:
                            if isinstance(r, dict):
                                c_blocks = r.get("cidr_blocks", [])
                                if isinstance(c_blocks, list):
                                    for c in c_blocks:
                                        c_str = _extract_string_value(c)
                                        ingress_cidrs.append(c_str)
                                        if c_str == "0.0.0.0/0":
                                            has_open = True

                    attrs.update({
                        "has_open_ingress": has_open,
                        "open_ingress": has_open,
                        "cidr_ip": "0.0.0.0/0" if has_open else (ingress_cidrs[0] if ingress_cidrs else ""),
                        "cidr_blocks": ingress_cidrs,
                        "ingress_cidrs": ingress_cidrs,
                    })

                elif tf_type == "aws_ebs_volume":
                    is_attached = res_name in attached_volume_ids
                    attrs.update({
                        "is_unattached": not is_attached,
                        "is_orphaned": not is_attached,
                        "attached": is_attached,
                        "attachment_state": "attached" if is_attached else "unattached",
                    })

                entities.append({
                    "uid": {"type": "Resource", "id": res_name},
                    "attrs": attrs,
                    "parents": [],
                })

        return entities


# -----------------------------------------------------------------------------
# Cedar Policy Evaluator
# -----------------------------------------------------------------------------

# Static metadata mapping for standard CloudSentinel zero-trust rules
DEFAULT_RULE_METADATA: Dict[str, Dict[str, Any]] = {
    "iam-no-admin-or-wildcard": {
        "severity": Severity.CRITICAL,
        "reason": "IAM role grants AdministratorAccess or wildcard actions ('*'), violating least-privilege principles.",
        "recommendation": "Remove AdministratorAccess and replace wildcard actions ('*') with scoped, least-privilege permissions.",
    },
    "s3-no-unencrypted-or-public-buckets": {
        "severity": Severity.HIGH,
        "reason": "S3 bucket lacks server-side encryption or has public access enabled.",
        "recommendation": "Enable default server-side encryption (AES256 or aws:kms) and configure PublicAccessBlockConfiguration.",
    },
    "security-group-no-open-ingress": {
        "severity": Severity.HIGH,
        "reason": "Security group allows open ingress traffic from 0.0.0.0/0.",
        "recommendation": "Restrict ingress CIDR blocks to specific authorized IP ranges or VPC private subnets.",
    },
    "ebs-cost-waste-unattached-volume": {
        "severity": Severity.MEDIUM,
        "reason": "EBS volume is unattached or orphaned, leading to unnecessary cloud cost waste.",
        "recommendation": "Attach the EBS volume to an active EC2 instance or snapshot and decommission the volume.",
    },
}


class CedarEvaluator:
    """
    Zero-Trust evaluation engine using AWS Cedar policy execution via cedarpy.
    """

    def __init__(self, policy_path: Optional[Union[Path, str]] = None) -> None:
        self.policy_path = Path(policy_path or DEFAULT_POLICY_PATH).resolve()
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Cedar policy file not found at: {self.policy_path}")

        self.policy_content = self.policy_path.read_text(encoding="utf-8")
        self.rule_metadata = self._extract_rule_metadata(self.policy_content)

    def _extract_rule_metadata(self, policy_content: str) -> Dict[str, Dict[str, Any]]:
        """Parse @id, @severity, @reason, and @recommendation annotations from policy text."""
        metadata: Dict[str, Dict[str, Any]] = dict(DEFAULT_RULE_METADATA)

        # Regex to locate policy blocks with annotations
        blocks = policy_content.split("forbid")
        for block in blocks[:-1]:
            id_match = re.search(r'@id\("([^"]+)"\)', block)
            if not id_match:
                continue
            rule_id = id_match.group(1)

            sev_match = re.search(r'@severity\("([^"]+)"\)', block)
            reason_match = re.search(r'@reason\("([^"]+)"\)', block)
            rec_match = re.search(r'@recommendation\("([^"]+)"\)', block)

            severity = Severity.HIGH
            if sev_match:
                try:
                    severity = Severity(sev_match.group(1).upper())
                except ValueError:
                    pass

            metadata[rule_id] = {
                "severity": severity,
                "reason": reason_match.group(1) if reason_match else f"Zero-trust violation: {rule_id}",
                "recommendation": rec_match.group(1) if rec_match else "Remediate according to zero-trust architecture guidelines.",
            }

        return metadata

    def evaluate_entities(self, entities: List[Dict[str, Any]]) -> ScanResult:
        """
        Evaluate a list of normalized Cedar entities against the loaded policy suite.
        Returns a ScanResult containing violations and timing metrics.
        """
        start_time = time.perf_counter()
        violations: List[PolicyViolation] = []

        principal_uid = {"type": "Principal", "id": "deployment-pipeline"}
        action_uid = {"type": "Action", "id": "deploy"}

        # Base principal and action entities
        base_entities = [
            {"uid": principal_uid, "attrs": {}, "parents": []},
            {"uid": action_uid, "attrs": {}, "parents": []},
        ]

        for entity in entities:
            eval_entities = base_entities + [entity]
            resource_uid = entity["uid"]
            resource_id = resource_uid.get("id", "UnknownResource")

            authz_result = cedarpy.is_authorized(
                request={
                    "principal": principal_uid,
                    "action": action_uid,
                    "resource": resource_uid,
                    "context": {},
                },
                policies=self.policy_content,
                entities=eval_entities,
            )

            if not authz_result.allowed:
                # Map reason annotations
                diagnostics = authz_result.diagnostics
                reasons = diagnostics.reasons if diagnostics else []
                id_map = diagnostics.id_annotations_by_reason if diagnostics else {}

                matched_rule_ids: List[str] = []
                for r in reasons:
                    rule_id = id_map.get(r, r)
                    if rule_id not in matched_rule_ids:
                        matched_rule_ids.append(rule_id)

                if not matched_rule_ids and reasons:
                    matched_rule_ids = reasons

                for rule_id in matched_rule_ids:
                    meta = self.rule_metadata.get(rule_id, {
                        "severity": Severity.HIGH,
                        "reason": f"Resource '{resource_id}' violated Zero-Trust policy '{rule_id}'.",
                        "recommendation": "Review resource configuration and align with zero-trust security standards.",
                    })

                    violations.append(
                        PolicyViolation(
                            rule_id=rule_id,
                            resource_id=resource_id,
                            severity=meta["severity"],
                            reason=meta["reason"],
                            recommendation=meta["recommendation"],
                        )
                    )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResult(
            compliant=(len(violations) == 0),
            violations_count=len(violations),
            execution_time_ms=elapsed_ms,
            violations=violations,
        )

    def evaluate(self, template_content: str, iac_format: Optional[IaCFormat] = None) -> ScanResult:
        """
        Parse and evaluate an IaC template string against Cedar zero-trust policies.
        """
        entities = IaCParser.normalize_to_cedar_entities(template_content, iac_format)
        return self.evaluate_entities(entities)


__all__ = [
    "IaCParser",
    "CedarEvaluator",
    "CloudFormationYamlLoader",
    "DEFAULT_POLICY_PATH",
]
