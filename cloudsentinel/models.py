"""
CloudSentinel Domain Models.

Defines core enums and Pydantic models for Infrastructure-as-Code (IaC) scanning,
Zero-Trust policy violations, sandbox simulation results, and remediation planning.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class IaCFormat(str, Enum):
    """Supported Infrastructure-as-Code formats."""
    CLOUDFORMATION = "cloudformation"
    SAM = "sam"
    TERRAFORM = "terraform"


class Severity(str, Enum):
    """Severity classification for policy violations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ActionRisk(str, Enum):
    """Operational risk level associated with automated remediation actions."""
    READ_ONLY = "READ_ONLY"
    SIMULATED = "SIMULATED"
    DESTRUCTIVE = "DESTRUCTIVE"


class PolicyViolation(BaseModel):
    """Represents a specific zero-trust policy violation detected on an IaC resource."""
    rule_id: str
    resource_id: str
    severity: Severity
    reason: str
    recommendation: str

    model_config = ConfigDict(use_enum_values=False)


class ScanResult(BaseModel):
    """Static analysis scan result evaluated against Cedar zero-trust policies."""
    compliant: bool
    violations_count: int
    execution_time_ms: float
    violations: List[PolicyViolation] = Field(default_factory=list)

    model_config = ConfigDict(use_enum_values=False)


class SandboxResult(BaseModel):
    """Result of safe local sandbox resource synthesis and cost simulation."""
    success: bool
    simulated_resources: List[str] = Field(default_factory=list)
    cost_savings_monthly: float = 0.0
    diagnostics: str = ""

    model_config = ConfigDict(use_enum_values=False)


class RemediationPlan(BaseModel):
    """Remediation plan detailing proposed code modifications and approval requirements."""
    target_file: str
    risk_level: ActionRisk
    diff: str
    requires_approval: bool = False

    model_config = ConfigDict(use_enum_values=False)


__all__ = [
    "IaCFormat",
    "Severity",
    "ActionRisk",
    "PolicyViolation",
    "ScanResult",
    "SandboxResult",
    "RemediationPlan",
]
