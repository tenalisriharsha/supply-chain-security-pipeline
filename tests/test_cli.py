import subprocess
import sys
from pathlib import Path

import pytest

from policy_engine.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parent.parent


def test_check_help_documents_all_flags(capsys):
    """README's "Running the policy engine directly" section promises
    `python -m policy_engine.cli check --help` as the full flag reference.
    """
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--help"])

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    for flag in ("--policy", "--scan", "--sbom", "--secrets"):
        assert flag in captured.out


def test_missing_required_policy_flag_errors_with_nonzero_exit(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--scan", str(FIXTURES / "trivy-clean.json")])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "--policy" in captured.err


def test_cli_runs_end_to_end_as_a_subprocess():
    """Exercises the real module as CI invokes it: `python -m policy_engine.cli check ...`."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "policy_engine.cli",
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(FIXTURES / "trivy-clean.json"),
            "--sbom",
            str(FIXTURES / "syft-sbom-clean.json"),
            "--secrets",
            str(FIXTURES / "gitleaks-clean.json"),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "RESULT: PASS" in result.stdout


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
