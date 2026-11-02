"""Data models shared across the policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    """Return the ordinal rank of a severity, unknown severities rank lowest."""
    normalized = (severity or "UNKNOWN").upper()
    try:
        return SEVERITY_ORDER.index(normalized)
    except ValueError:
        return 0


@dataclass
class Vulnerability:
    id: str
    package: str
    severity: str
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None


@dataclass
class SbomComponent:
    name: str
    version: Optional[str] = None
    licenses: List[str] = field(default_factory=list)


@dataclass
class SecretFinding:
    file: str
    rule_id: str
    line: Optional[int] = None
    description: Optional[str] = None


@dataclass
class PolicyConfig:
    max_severity: str = "HIGH"
    fail_on_secrets: bool = True
    denied_licenses: List[str] = field(default_factory=list)
    ignore_cves: List[str] = field(default_factory=list)


@dataclass
class PolicyViolation:
    category: str
    message: str
    severity: Optional[str] = None


@dataclass
class PolicyResult:
    violations: List[PolicyViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations
