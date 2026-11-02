from pathlib import Path

from policy_engine.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_check_passes_on_clean_reports(capsys):
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(FIXTURES / "trivy-clean.json"),
            "--sbom",
            str(FIXTURES / "syft-sbom-clean.json"),
            "--secrets",
            str(FIXTURES / "gitleaks-clean.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "RESULT: PASS" in captured.out
    assert "VIOLATIONS (0)" in captured.out


def test_check_fails_on_critical_vulnerability(capsys):
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(FIXTURES / "trivy-critical.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RESULT: FAIL" in captured.out
    assert "CVE-2023-4863" in captured.out
    assert "CVE-2023-5678" in captured.out


def test_check_fails_on_secret_finding(capsys):
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--secrets",
            str(FIXTURES / "gitleaks-findings.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RESULT: FAIL" in captured.out
    assert "generic-api-key" in captured.out


def test_check_fails_on_denied_license(capsys):
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--sbom",
            str(FIXTURES / "syft-sbom-denied-license.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "copyleft-lib" in captured.out


def test_check_with_lenient_policy_passes_despite_findings(capsys):
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-lenient.yaml"),
            "--scan",
            str(FIXTURES / "trivy-critical.json"),
            "--secrets",
            str(FIXTURES / "gitleaks-findings.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "RESULT: PASS" in captured.out
