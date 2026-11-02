"""Parsers that turn raw scanner JSON into policy_engine data models."""

from __future__ import annotations

from typing import Any, Dict, List

from .models import SbomComponent, SecretFinding, Vulnerability


def parse_trivy_results(data: Dict[str, Any]) -> List[Vulnerability]:
    """Parse a Trivy JSON report (image/filesystem scan) into Vulnerability records."""
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
    components: List[SbomComponent] = []
    for component in data.get("components") or []:
        licenses: List[str] = []
        for license_entry in component.get("licenses") or []:
            license_obj = license_entry.get("license") or {}
            license_id = license_obj.get("id") or license_obj.get("name")
            if license_id:
                licenses.append(license_id)
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
