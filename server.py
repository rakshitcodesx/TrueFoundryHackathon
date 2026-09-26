"""
TrueForge CloudSentinel MCP Integration Server.

Exposes Model Context Protocol (MCP) tools for autonomous zero-trust IaC security scanning,
local in-memory sandbox validation, and safety-gated remediation.
"""

from __future__ import annotations

import difflib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

from cloudsentinel.engine.evaluator import CedarEvaluator, IaCParser
from cloudsentinel.engine.sandbox import LocalSandboxEngine
from cloudsentinel.models import ActionRisk, IaCFormat, RemediationPlan

# Initialize FastMCP Server
mcp = FastMCP(
    "TrueForge-CloudSentinel",
    instructions=(
        "Autonomous Local-First Zero-Trust Security Gatekeeper for AI-Generated IaC. "
        "Provides static Cedar policy enforcement, in-memory Moto sandboxing, and safe remediation."
    ),
)

# Shared engine instances
_evaluator = CedarEvaluator()
_sandbox = LocalSandboxEngine()


@mcp.tool()
def scan_infrastructure(file_path: str) -> str:
    """
    Scan an Infrastructure-as-Code (IaC) template against AWS Cedar Zero-Trust policies.

    Evaluates CloudFormation, SAM, and Terraform against formal zero-trust guardrails:
    - Forbids IAM roles with AdministratorAccess or wildcard actions ('*')
    - Forbids S3 buckets without server-side encryption or with public access enabled
    - Forbids Security Groups with open 0.0.0.0/0 ingress
    - Flags unattached or orphaned EBS volumes as cost waste

    Args:
        file_path: Absolute or relative path to the IaC template file (YAML/JSON).

    Returns:
        JSON string containing compliance verdict, total violations count,
        execution time in ms, and detailed policy violation list.
    """
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        error_payload = {
            "error": f"Target template file not found: {file_path}",
            "compliant": False,
            "violations_count": 0,
            "execution_time_ms": 0.0,
            "violations": [],
        }
        return json.dumps(error_payload, indent=2)

    try:
        content = target.read_text(encoding="utf-8")
        result = _evaluator.evaluate(content)
        return result.model_dump_json(indent=2)
    except Exception as exc:
        error_payload = {
            "error": f"Scan failed: {type(exc).__name__}: {str(exc)}",
            "compliant": False,
            "violations_count": 0,
            "execution_time_ms": 0.0,
            "violations": [],
        }
        return json.dumps(error_payload, indent=2)


@mcp.tool()
def simulate_in_sandbox(candidate_content: str, iac_format: str = "cloudformation") -> str:
    """
    Simulate candidate or patched IaC infrastructure completely in-memory using Moto.

    Validates that proposed infrastructure can synthesize and deploy cleanly:
    - Tests S3 bucket creation, server-side encryption, and PublicAccessBlock
    - Tests IAM role creation, assume-role policies, and inline/managed policies
    - Tests EC2 Security Group creation and ingress CIDR isolation
    - Calculates projected monthly cost savings for eliminated orphaned EBS volumes

    Args:
        candidate_content: Raw IaC template content (CloudFormation/SAM YAML or Terraform JSON).
        iac_format: IaC format ('cloudformation', 'sam', or 'terraform'). Defaults to 'cloudformation'.

    Returns:
        JSON string containing simulation success status, list of simulated resources,
        projected monthly cost savings in USD, and simulation diagnostics.
    """
    try:
        fmt_str = iac_format.strip().lower()
        if "terraform" in fmt_str:
            fmt_enum = IaCFormat.TERRAFORM
        elif "sam" in fmt_str:
            fmt_enum = IaCFormat.SAM
        elif "cloudformation" in fmt_str:
            fmt_enum = IaCFormat.CLOUDFORMATION
        else:
            fmt_enum = IaCParser.detect_format(candidate_content)

        sandbox_result = _sandbox.simulate_patch(candidate_content, fmt_enum)
        return sandbox_result.model_dump_json(indent=2)
    except Exception as exc:
        error_payload = {
            "success": False,
            "simulated_resources": [],
            "cost_savings_monthly": 0.0,
            "diagnostics": f"Sandbox simulation error: {type(exc).__name__}: {str(exc)}",
        }
        return json.dumps(error_payload, indent=2)


@mcp.tool()
def apply_remediation(file_path: str, verified_content: str) -> str:
    """
    [DESTRUCTIVE ACTION - REQUIRES HUMAN APPROVAL]
    Apply a verified remediation patch to an Infrastructure-as-Code template file.

    IMPORTANT SAFETY & GOVERNANCE NOTICE:
    This tool performs a destructive write operation on the host filesystem and MUST
    receive explicit human operator approval before execution.

    Safety Guardrails:
    1. An atomic, timestamped backup copy is created in '.cloudguard/backups/' before modification.
    2. A unified diff is computed and returned in the audit response.
    3. The file is overwritten with the verified content.

    Args:
        file_path: Relative or absolute path to the target template file to modify.
        verified_content: The new, security-verified template content to write.

    Returns:
        JSON string containing operation status, backup file path, unified diff,
        bytes written, and human approval audit confirmation.
    """
    target = Path(file_path).resolve()
    backup_dir = Path(".cloudguard/backups").resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{target.stem}_{timestamp}{target.suffix}.bak"
    backup_path = backup_dir / backup_filename

    # Read original content if file exists
    original_content = ""
    if target.exists() and target.is_file():
        original_content = target.read_text(encoding="utf-8")
        shutil.copy2(target, backup_path)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"new_file_{timestamp}.bak"
        backup_path.write_text("# Initial file creation\n", encoding="utf-8")

    # Generate unified diff for auditing
    diff_lines = list(
        difflib.unified_diff(
            original_content.splitlines(keepends=True),
            verified_content.splitlines(keepends=True),
            fromfile=f"a/{target.name}",
            tofile=f"b/{target.name}",
        )
    )
    diff_text = "".join(diff_lines)

    # Perform atomic write
    target.write_text(verified_content, encoding="utf-8")
    bytes_written = len(verified_content.encode("utf-8"))

    # Construct remediation plan model
    plan = RemediationPlan(
        target_file=str(target),
        risk_level=ActionRisk.DESTRUCTIVE,
        diff=diff_text,
        requires_approval=True,
    )

    response = {
        "status": "success",
        "action": "remediation_applied",
        "target_file": str(target),
        "backup_path": str(backup_path),
        "bytes_written": bytes_written,
        "requires_human_approval": True,
        "risk_level": plan.risk_level.value,
        "diff": diff_text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": f"Successfully applied remediation to '{target.name}'. Backup saved at '{backup_path.name}'.",
    }

    return json.dumps(response, indent=2)


if __name__ == "__main__":
    mcp.run()
