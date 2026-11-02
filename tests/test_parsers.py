import json
from pathlib import Path

from policy_engine.parsers import (
    parse_gitleaks_findings,
    parse_syft_sbom,
    parse_trivy_results,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    with open(FIXTURES / name, "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_parse_trivy_results_extracts_all_vulnerabilities():
    data = load_fixture("trivy-critical.json")
    vulnerabilities = parse_trivy_results(data)

    assert len(vulnerabilities) == 3
    ids = {v.id for v in vulnerabilities}
    assert ids == {"CVE-2023-4863", "CVE-2023-5678", "CVE-2021-0002"}

    critical = next(v for v in vulnerabilities if v.id == "CVE-2023-4863")
    assert critical.package == "libwebp"
    assert critical.severity == "CRITICAL"
    assert critical.fixed_version == "1.3.2"


def test_parse_trivy_results_handles_empty_results():
    assert parse_trivy_results({"Results": []}) == []
    assert parse_trivy_results({}) == []


def test_parse_syft_sbom_extracts_components_and_licenses():
    data = load_fixture("syft-sbom-clean.json")
    components = parse_syft_sbom(data)

    assert len(components) == 2
    flask = next(c for c in components if c.name == "flask")
    assert flask.version == "3.0.0"
    assert flask.licenses == ["BSD-3-Clause"]


def test_parse_syft_sbom_handles_missing_components():
    assert parse_syft_sbom({}) == []


def test_parse_gitleaks_findings_extracts_records():
    data = load_fixture("gitleaks-findings.json")
    findings = parse_gitleaks_findings(data)

    assert len(findings) == 1
    assert findings[0].file == "demo-app/config.py"
    assert findings[0].rule_id == "generic-api-key"
    assert findings[0].line == 12


def test_parse_gitleaks_findings_handles_empty_list():
    assert parse_gitleaks_findings([]) == []
