"""
Unit and Integration Tests for TrueForge CloudSentinel FastMCP Server.

Verifies that all three FastMCP tools:
1. scan_infrastructure
2. simulate_in_sandbox
3. apply_remediation
execute cleanly via standard Python calls and return correct JSON structures.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
import sys

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import pytest

from server import apply_remediation, scan_infrastructure, simulate_in_sandbox


def test_scan_infrastructure_insecure():
    """Verify scan_infrastructure identifies all policy violations in insecure template."""
    insecure_path = Path("examples/insecure_template.yaml")
    assert insecure_path.exists(), "examples/insecure_template.yaml is missing"

    result_json = scan_infrastructure(str(insecure_path))
    data = json.loads(result_json)

    assert data["compliant"] is False
    assert data["violations_count"] == 4
    assert data["execution_time_ms"] >= 0.0
    assert len(data["violations"]) == 4

    rule_ids = {v["rule_id"] for v in data["violations"]}
    assert "iam-no-admin-or-wildcard" in rule_ids
    assert "s3-no-unencrypted-or-public-buckets" in rule_ids
    assert "security-group-no-open-ingress" in rule_ids
    assert "ebs-cost-waste-unattached-volume" in rule_ids


def test_scan_infrastructure_compliant():
    """Verify scan_infrastructure approves compliant zero-trust template."""
    compliant_path = Path("examples/compliant_template.yaml")
    assert compliant_path.exists(), "examples/compliant_template.yaml is missing"

    result_json = scan_infrastructure(str(compliant_path))
    data = json.loads(result_json)

    assert data["compliant"] is True
    assert data["violations_count"] == 0
    assert len(data["violations"]) == 0
    assert data["execution_time_ms"] >= 0.0


def test_scan_infrastructure_file_not_found():
    """Verify scan_infrastructure gracefully handles non-existent file paths."""
    result_json = scan_infrastructure("non_existent_template_xyz123.yaml")
    data = json.loads(result_json)

    assert data["compliant"] is False
    assert "error" in data
    assert "not found" in data["error"].lower()


def test_simulate_in_sandbox_insecure():
    """Verify simulate_in_sandbox runs in Moto and computes cost savings for orphaned EBS."""
    insecure_content = Path("examples/insecure_template.yaml").read_text(encoding="utf-8")
    result_json = simulate_in_sandbox(insecure_content, iac_format="cloudformation")
    data = json.loads(result_json)

    assert data["success"] is True
    assert len(data["simulated_resources"]) == 4
    assert "InsecureDataBucket" in data["simulated_resources"]
    assert "OrphanedStorageVolume" in data["simulated_resources"]
    assert data["cost_savings_monthly"] == 10.0  # 100 GB * $0.10/GB
    assert "diagnostics" in data
    assert "orphaned EBS volume" in data["diagnostics"].lower() or "orphaned ebs volume" in data["diagnostics"].lower()


def test_simulate_in_sandbox_compliant():
    """Verify simulate_in_sandbox runs clean simulation for compliant template."""
    compliant_content = Path("examples/compliant_template.yaml").read_text(encoding="utf-8")
    result_json = simulate_in_sandbox(compliant_content, iac_format="cloudformation")
    data = json.loads(result_json)

    assert data["success"] is True
    assert len(data["simulated_resources"]) > 0
    assert "SecureDataBucket" in data["simulated_resources"]
    assert data["cost_savings_monthly"] == 0.0
    assert "Verified server-side encryption" in data["diagnostics"]


def test_apply_remediation_lifecycle():
    """Verify apply_remediation creates backup, overwrites target, and records audit trail."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = Path(tmp_dir) / "infra_target.yaml"
        initial_content = "AWSTemplateFormatVersion: '2010-09-09'\n# Initial Insecure Content\n"
        test_file.write_text(initial_content, encoding="utf-8")

        verified_remediation = "AWSTemplateFormatVersion: '2010-09-09'\n# Hardened Zero-Trust Content\n"

        result_json = apply_remediation(str(test_file), verified_remediation)
        data = json.loads(result_json)

        # 1. Verify response structure and safety properties
        assert data["status"] == "success"
        assert data["action"] == "remediation_applied"
        assert data["requires_human_approval"] is True
        assert data["risk_level"] == "DESTRUCTIVE"
        assert "backup_path" in data
        assert "diff" in data

        # 2. Verify target file was updated
        updated_content = test_file.read_text(encoding="utf-8")
        assert updated_content == verified_remediation

        # 3. Verify backup file was created and preserved original content
        backup_path = Path(data["backup_path"])
        assert backup_path.exists(), f"Backup file {backup_path} does not exist"
        backup_content = backup_path.read_text(encoding="utf-8")
        assert backup_content == initial_content

        # Cleanup backup test artifact
        try:
            backup_path.unlink()
        except Exception:
            pass


def test_apply_remediation_new_file():
    """Verify apply_remediation creates the target file and directory if it does not yet exist."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        new_file = Path(tmp_dir) / "sub_dir" / "new_infra.yaml"
        content = "AWSTemplateFormatVersion: '2010-09-09'\n# New File\n"

        result_json = apply_remediation(str(new_file), content)
        data = json.loads(result_json)

        assert data["status"] == "success"
        assert new_file.exists()
        assert new_file.read_text(encoding="utf-8") == content

        # Cleanup created backup
        backup_path = Path(data["backup_path"])
        if backup_path.exists():
            backup_path.unlink()
