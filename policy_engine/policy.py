"""Policy loading and evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import List, Union

import yaml

from .models import (
    PolicyConfig,
    PolicyResult,
    PolicyViolation,
    SbomComponent,
    SecretFinding,
    Vulnerability,
    severity_rank,
)


def load_policy(path: Union[str, Path]) -> PolicyConfig:
    """Load a PolicyConfig from a YAML file."""
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return PolicyConfig(
        max_severity=str(raw.get("max_severity", "HIGH")).upper(),
        fail_on_secrets=bool(raw.get("fail_on_secrets", True)),
        denied_licenses=list(raw.get("denied_licenses", [])),
        ignore_cves=list(raw.get("ignore_cves", [])),
    )


def evaluate_vulnerabilities(
    vulnerabilities: List[Vulnerability], config: PolicyConfig
) -> List[PolicyViolation]:
    threshold = severity_rank(config.max_severity)
    violations: List[PolicyViolation] = []
    for vuln in vulnerabilities:
        if vuln.id in config.ignore_cves:
            continue
        if severity_rank(vuln.severity) >= threshold:
            violations.append(
                PolicyViolation(
                    category="vulnerability",
                    message=(
                        f"{vuln.id} in {vuln.package} is {vuln.severity} "
                        f"(exceeds max_severity={config.max_severity})"
                    ),
                    severity=vuln.severity,
                )
            )
    return violations


def evaluate_licenses(
    components: List[SbomComponent], config: PolicyConfig
) -> List[PolicyViolation]:
    denied = {license_id.upper() for license_id in config.denied_licenses}
    violations: List[PolicyViolation] = []
    if not denied:
        return violations
    for component in components:
        for license_id in component.licenses:
            if license_id.upper() in denied:
                violations.append(
                    PolicyViolation(
                        category="license",
                        message=(
                            f"{component.name}@{component.version} uses denied "
                            f"license {license_id}"
                        ),
                    )
                )
    return violations


def evaluate_secrets(
    findings: List[SecretFinding], config: PolicyConfig
) -> List[PolicyViolation]:
    violations: List[PolicyViolation] = []
    if not config.fail_on_secrets:
        return violations
    for finding in findings:
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file
        violations.append(
            PolicyViolation(
                category="secret",
                message=f"potential secret ({finding.rule_id}) found in {location}",
            )
        )
    return violations


def evaluate(
    vulnerabilities: List[Vulnerability],
    components: List[SbomComponent],
    secrets: List[SecretFinding],
    config: PolicyConfig,
) -> PolicyResult:
    violations: List[PolicyViolation] = []
    violations.extend(evaluate_vulnerabilities(vulnerabilities, config))
    violations.extend(evaluate_licenses(components, config))
    violations.extend(evaluate_secrets(secrets, config))
    return PolicyResult(violations=violations)
