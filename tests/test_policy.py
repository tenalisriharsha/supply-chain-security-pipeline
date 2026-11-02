from pathlib import Path

from policy_engine.models import (
    PolicyConfig,
    SbomComponent,
    SecretFinding,
    Vulnerability,
)
from policy_engine.policy import (
    evaluate,
    evaluate_licenses,
    evaluate_secrets,
    evaluate_vulnerabilities,
    load_policy,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_policy_reads_fields():
    config = load_policy(FIXTURES / "policy-default.yaml")

    assert config.max_severity == "HIGH"
    assert config.fail_on_secrets is True
    assert "GPL-3.0" in config.denied_licenses


def test_load_policy_defaults_when_file_is_sparse(tmp_path):
    sparse = tmp_path / "sparse.yaml"
    sparse.write_text("max_severity: CRITICAL\n")

    config = load_policy(sparse)

    assert config.max_severity == "CRITICAL"
    assert config.fail_on_secrets is True
    assert config.denied_licenses == []


def test_evaluate_vulnerabilities_flags_at_or_above_threshold():
    config = PolicyConfig(max_severity="HIGH")
    vulnerabilities = [
        Vulnerability(id="CVE-1", package="a", severity="CRITICAL"),
        Vulnerability(id="CVE-2", package="b", severity="HIGH"),
        Vulnerability(id="CVE-3", package="c", severity="MEDIUM"),
    ]

    violations = evaluate_vulnerabilities(vulnerabilities, config)

    assert {v.message.split()[0] for v in violations} == {"CVE-1", "CVE-2"}


def test_evaluate_vulnerabilities_respects_ignore_list():
    config = PolicyConfig(max_severity="HIGH", ignore_cves=["CVE-1"])
    vulnerabilities = [Vulnerability(id="CVE-1", package="a", severity="CRITICAL")]

    assert evaluate_vulnerabilities(vulnerabilities, config) == []


def test_evaluate_licenses_flags_denied_license():
    config = PolicyConfig(denied_licenses=["GPL-3.0"])
    components = [
        SbomComponent(name="ok-lib", version="1.0", licenses=["MIT"]),
        SbomComponent(name="bad-lib", version="2.0", licenses=["GPL-3.0"]),
    ]

    violations = evaluate_licenses(components, config)

    assert len(violations) == 1
    assert "bad-lib" in violations[0].message


def test_evaluate_licenses_noop_when_denylist_empty():
    config = PolicyConfig(denied_licenses=[])
    components = [SbomComponent(name="bad-lib", licenses=["GPL-3.0"])]

    assert evaluate_licenses(components, config) == []


def test_evaluate_secrets_flags_each_finding_when_enabled():
    config = PolicyConfig(fail_on_secrets=True)
    findings = [SecretFinding(file="a.py", rule_id="aws-key", line=3)]

    violations = evaluate_secrets(findings, config)

    assert len(violations) == 1
    assert "a.py:3" in violations[0].message


def test_evaluate_secrets_noop_when_disabled():
    config = PolicyConfig(fail_on_secrets=False)
    findings = [SecretFinding(file="a.py", rule_id="aws-key", line=3)]

    assert evaluate_secrets(findings, config) == []


def test_evaluate_combines_all_categories_and_fails():
    config = PolicyConfig(max_severity="HIGH", fail_on_secrets=True, denied_licenses=["GPL-3.0"])
    result = evaluate(
        vulnerabilities=[Vulnerability(id="CVE-1", package="a", severity="CRITICAL")],
        components=[SbomComponent(name="bad-lib", licenses=["GPL-3.0"])],
        secrets=[SecretFinding(file="a.py", rule_id="aws-key")],
        config=config,
    )

    assert result.passed is False
    assert len(result.violations) == 3


def test_evaluate_passes_with_clean_inputs():
    config = PolicyConfig(max_severity="HIGH", fail_on_secrets=True, denied_licenses=["GPL-3.0"])
    result = evaluate(
        vulnerabilities=[Vulnerability(id="CVE-1", package="a", severity="LOW")],
        components=[SbomComponent(name="ok-lib", licenses=["MIT"])],
        secrets=[],
        config=config,
    )

    assert result.passed is True
    assert result.violations == []
