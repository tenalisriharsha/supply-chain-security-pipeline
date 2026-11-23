"""Parsers that turn raw scanner JSON into policy_engine data models."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .errors import PolicyEngineError
from .models import SbomComponent, SecretFinding, Vulnerability

_SPDX_EXPRESSION_SPLIT_RE = re.compile(r"\s+(?:AND|OR)\s+|[()]")


def _split_spdx_expression(expression: str) -> List[str]:
    """Split an SPDX license expression (e.g. "GPL-3.0 OR MIT") into its
    constituent license IDs so each one can be checked individually against
    a denylist.
    """
    return [
        token.strip()
        for token in _SPDX_EXPRESSION_SPLIT_RE.split(expression)
        if token.strip()
    ]


def parse_trivy_results(data: Dict[str, Any]) -> List[Vulnerability]:
    """Parse a Trivy JSON report (image/filesystem scan) into Vulnerability records."""
    if not isinstance(data, dict):
        raise PolicyEngineError(
            f"trivy scan report must be a JSON object, not a {type(data).__name__}"
        )
    vulnerabilities: List[Vulnerability] = []
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vulnerabilities.append(
                Vulnerability(
                    id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    package=vuln.get("PkgName", "unknown"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                )
            )
    return vulnerabilities


def parse_syft_sbom(data: Dict[str, Any]) -> List[SbomComponent]:
    """Parse a Syft CycloneDX JSON SBOM into SbomComponent records."""
    if not isinstance(data, dict):
        raise PolicyEngineError(
            f"syft SBOM report must be a JSON object, not a {type(data).__name__}"
        )
    components: List[SbomComponent] = []
    for component in data.get("components") or []:
        licenses: List[str] = []
        for license_entry in component.get("licenses") or []:
            license_obj = license_entry.get("license") or {}
            license_id = license_obj.get("id") or license_obj.get("name")
            if license_id:
                licenses.append(license_id)
                continue
            expression = license_entry.get("expression")
            if expression:
                licenses.extend(_split_spdx_expression(expression))
        components.append(
            SbomComponent(
                name=component.get("name", "unknown"),
                version=component.get("version"),
                licenses=licenses,
            )
        )
    return components


def parse_gitleaks_findings(data: List[Dict[str, Any]]) -> List[SecretFinding]:
    """Parse a gitleaks JSON report into SecretFinding records."""
    if data is not None and not isinstance(data, list):
        raise PolicyEngineError(
            f"gitleaks report must be a JSON array, not a {type(data).__name__}"
        )
    findings: List[SecretFinding] = []
    for finding in data or []:
        findings.append(
            SecretFinding(
                file=finding.get("File", "unknown"),
                rule_id=finding.get("RuleID", "unknown"),
                line=finding.get("StartLine"),
                description=finding.get("Description"),
            )
        )
    return findings
