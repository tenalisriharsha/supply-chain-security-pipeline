"""Tests for scripts/generate_provenance.py.

This script is not part of the policy_engine package (it has no __init__.py
and is never pip-installed), so it is loaded directly from its file path.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_provenance.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_provenance", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def provenance_module():
    return _load_module()


@pytest.fixture(autouse=True)
def _clear_github_env(monkeypatch):
    for name in (
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SERVER_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_build_provenance_shape(provenance_module):
    predicate = provenance_module.build_provenance(
        repository="tenalisriharsha/supply-chain-security-pipeline",
        commit_sha="abc123",
        ref="refs/heads/main",
        run_id="42",
        run_attempt="1",
    )

    assert predicate["builder"]["id"] == (
        "https://github.com/tenalisriharsha/supply-chain-security-pipeline"
        "/.github/workflows/ci.yml@refs/heads/main"
    )
    assert predicate["buildType"] == "https://github.com/actions/runs"
    assert predicate["invocation"]["configSource"] == {
        "uri": "git+https://github.com/tenalisriharsha/supply-chain-security-pipeline@refs/heads/main",
        "digest": {"sha1": "abc123"},
        "entryPoint": ".github/workflows/ci.yml",
    }
    assert predicate["invocation"]["environment"] == {
        "github_run_id": "42",
        "github_run_attempt": "1",
    }
    assert predicate["metadata"]["buildInvocationId"] == "42-1"
    assert predicate["metadata"]["reproducible"] is False
    assert predicate["materials"] == [
        {
            "uri": "git+https://github.com/tenalisriharsha/supply-chain-security-pipeline@refs/heads/main",
            "digest": {"sha1": "abc123"},
        }
    ]


def test_build_provenance_honors_custom_server_url(provenance_module):
    predicate = provenance_module.build_provenance(
        repository="acme/widget",
        commit_sha="deadbeef",
        ref="refs/heads/main",
        run_id="1",
        run_attempt="1",
        server_url="https://github.acme.internal",
    )

    assert predicate["builder"]["id"].startswith("https://github.acme.internal/acme/widget")
    assert predicate["invocation"]["configSource"]["uri"].startswith(
        "git+https://github.acme.internal/acme/widget"
    )


def test_build_provenance_honors_custom_workflow_path(provenance_module):
    predicate = provenance_module.build_provenance(
        repository="acme/widget",
        commit_sha="deadbeef",
        ref="refs/heads/main",
        run_id="1",
        run_attempt="1",
        workflow_path=".github/workflows/release.yml",
    )

    assert predicate["invocation"]["configSource"]["entryPoint"] == (
        ".github/workflows/release.yml"
    )
    assert predicate["builder"]["id"].endswith(
        "/.github/workflows/release.yml@refs/heads/main"
    )


def test_main_writes_predicate_json_from_argv(tmp_path, provenance_module):
    output = tmp_path / "provenance.json"
    exit_code = provenance_module.main(
        [
            "--repository",
            "tenalisriharsha/supply-chain-security-pipeline",
            "--commit-sha",
            "abc123",
            "--ref",
            "refs/heads/main",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.exists()
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["invocation"]["configSource"]["digest"]["sha1"] == "abc123"
    assert output.read_text(encoding="utf-8").endswith("\n")


def test_main_falls_back_to_github_actions_env_vars(tmp_path, monkeypatch, provenance_module):
    monkeypatch.setenv("GITHUB_REPOSITORY", "tenalisriharsha/supply-chain-security-pipeline")
    monkeypatch.setenv("GITHUB_SHA", "envsha")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_RUN_ID", "99")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")

    output = tmp_path / "provenance.json"
    exit_code = provenance_module.main(["--output", str(output)])

    assert exit_code == 0
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["invocation"]["configSource"]["digest"]["sha1"] == "envsha"
    assert written["metadata"]["buildInvocationId"] == "99-2"


def test_main_errors_when_required_values_are_missing(tmp_path, capsys, provenance_module):
    output = tmp_path / "provenance.json"

    with pytest.raises(SystemExit) as excinfo:
        provenance_module.main(["--output", str(output)])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "missing required values" in captured.err
    assert not output.exists()


def test_main_reports_each_missing_field_by_name(tmp_path, capsys, provenance_module):
    output = tmp_path / "provenance.json"

    with pytest.raises(SystemExit):
        provenance_module.main(
            [
                "--repository",
                "tenalisriharsha/supply-chain-security-pipeline",
                "--commit-sha",
                "abc123",
                "--output",
                str(output),
            ]
        )

    captured = capsys.readouterr()
    assert "missing required values:" in captured.err
    missing_section = captured.err.split("missing required values:", 1)[1]
    assert "ref" in missing_section
    assert "run_id" in missing_section
    assert "run_attempt" in missing_section
    assert "repository" not in missing_section
    assert "commit_sha" not in missing_section


def test_script_runs_end_to_end_as_a_subprocess(tmp_path):
    """Exercises the real file as CI invokes it: `python scripts/generate_provenance.py ...`."""
    output = tmp_path / "provenance.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--repository",
            "tenalisriharsha/supply-chain-security-pipeline",
            "--commit-sha",
            "cafef00d",
            "--ref",
            "refs/heads/main",
            "--run-id",
            "7",
            "--run-attempt",
            "1",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "Wrote SLSA provenance predicate" in result.stdout
    predicate = json.loads(output.read_text(encoding="utf-8"))
    assert predicate["invocation"]["configSource"]["digest"]["sha1"] == "cafef00d"
