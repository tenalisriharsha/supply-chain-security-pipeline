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


def test_check_fails_on_denied_license_expressed_as_spdx_expression(capsys):
    """Real Syft output reports many licenses as `{"expression": "..."}`
    rather than the `{"license": {"id": ...}}` object form. A denied license
    expressed this way must still be caught, not silently passed.
    """
    exit_code = main(
        [
            "check",
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--sbom",
            str(FIXTURES / "syft-sbom-expression-license.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RESULT: FAIL" in captured.out
    assert "copyleft-expr-lib" in captured.out


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "policy_engine.cli", "check", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_check_with_missing_scan_file_errors_cleanly_instead_of_traceback():
    """A mistyped --scan path (or a report that failed to generate) must not
    dump a raw Python traceback; it should fail with a short message.
    """
    result = _run_cli(
        [
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(FIXTURES / "does-not-exist.json"),
            "--sbom",
            str(FIXTURES / "syft-sbom-clean.json"),
            "--secrets",
            str(FIXTURES / "gitleaks-clean.json"),
        ]
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "RESULT:" not in result.stdout


def test_check_with_missing_policy_file_errors_cleanly_instead_of_traceback():
    result = _run_cli(
        [
            "--policy",
            str(FIXTURES / "does-not-exist.yaml"),
            "--scan",
            str(FIXTURES / "trivy-clean.json"),
        ]
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "RESULT:" not in result.stdout


def test_check_with_malformed_scan_json_errors_cleanly_instead_of_traceback(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("not json", encoding="utf-8")

    result = _run_cli(
        [
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(bad_json),
        ]
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "RESULT:" not in result.stdout


def test_check_with_wrongly_shaped_scan_json_errors_cleanly_instead_of_traceback(tmp_path):
    """A syntactically valid but wrongly-shaped report (e.g. a top-level JSON
    list instead of the expected object) must not crash the parser.
    """
    list_json = tmp_path / "list.json"
    list_json.write_text("[]", encoding="utf-8")

    result = _run_cli(
        [
            "--policy",
            str(FIXTURES / "policy-default.yaml"),
            "--scan",
            str(list_json),
        ]
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "RESULT:" not in result.stdout


def test_check_with_typo_max_severity_errors_cleanly_instead_of_silently_failing(tmp_path):
    """A typo'd max_severity (e.g. "HIGHH" instead of "HIGH") must be reported
    as a config error, not silently ranked as the lowest severity -- which
    would make every finding, including a LOW one, "exceed" the threshold.
    """
    typo_policy = tmp_path / "policy-typo.yaml"
    typo_policy.write_text(
        "max_severity: HIGHH\n"
        "fail_on_secrets: true\n"
        "denied_licenses: []\n"
        "ignore_cves: []\n"
    )

    result = _run_cli(
        [
            "--policy",
            str(typo_policy),
            "--scan",
            str(FIXTURES / "trivy-clean.json"),
            "--sbom",
            str(FIXTURES / "syft-sbom-clean.json"),
            "--secrets",
            str(FIXTURES / "gitleaks-clean.json"),
        ]
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "RESULT:" not in result.stdout
    assert "HIGHH" in result.stderr


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
