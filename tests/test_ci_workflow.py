"""Structural checks on the CI workflow and the fixtures it depends on.

These don't run the real syft/trivy/gitleaks CLIs (that only happens on a
GitHub Actions runner with Docker and network access) but they do catch the
most common way this kind of workflow silently breaks: a typo in a job name,
a step that stops writing the file the next step reads, or a referenced
fixture that got renamed or deleted.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def load_workflow():
    with open(WORKFLOW_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_workflow_is_valid_yaml_with_expected_jobs():
    workflow = load_workflow()
    assert set(workflow["jobs"]) == {
        "test",
        "supply-chain-scan",
        "vulnerable-fixture-demo",
    }


def test_scan_jobs_depend_on_test_job():
    workflow = load_workflow()
    assert workflow["jobs"]["supply-chain-scan"]["needs"] == "test"
    assert workflow["jobs"]["vulnerable-fixture-demo"]["needs"] == "test"


def test_scan_jobs_run_the_three_real_scanners():
    workflow = load_workflow()
    for job_name in ("supply-chain-scan", "vulnerable-fixture-demo"):
        steps = workflow["jobs"][job_name]["steps"]
        uses = [step.get("uses", "") for step in steps]
        runs = " ".join(step.get("run", "") for step in steps)
        assert any(u.startswith("anchore/sbom-action") for u in uses)
        assert any(u.startswith("aquasecurity/trivy-action") for u in uses)
        assert "gitleaks detect" in runs
        assert "policy_engine.cli check" in runs


def test_vulnerable_fixture_demo_expects_the_gate_to_fail():
    workflow = load_workflow()
    steps = workflow["jobs"]["vulnerable-fixture-demo"]["steps"]
    gate_step = next(step for step in steps if step.get("id") == "gate")
    assert gate_step["continue-on-error"] is True


def test_vulnerable_dockerfile_exists_and_uses_an_eol_base_image():
    dockerfile = REPO_ROOT / "demo-app" / "Dockerfile.vulnerable"
    assert dockerfile.exists()
    contents = dockerfile.read_text(encoding="utf-8")
    assert "FROM debian:9" in contents


def test_secrets_sample_fixture_exists():
    fixture = REPO_ROOT / "tests" / "fixtures" / "secrets-sample" / "leaky_config.py"
    assert fixture.exists()
    contents = fixture.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" in contents
