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
        "publish",
    }


def test_scan_jobs_depend_on_test_job():
    workflow = load_workflow()
    assert workflow["jobs"]["supply-chain-scan"]["needs"] == "test"
    assert workflow["jobs"]["vulnerable-fixture-demo"]["needs"] == "test"


def test_publish_job_depends_on_both_scan_jobs():
    workflow = load_workflow()
    needs = workflow["jobs"]["publish"]["needs"]
    assert set(needs) == {"supply-chain-scan", "vulnerable-fixture-demo"}


def test_publish_job_only_runs_on_push_to_main():
    workflow = load_workflow()
    condition = workflow["jobs"]["publish"]["if"]
    assert "github.event_name == 'push'" in condition
    assert "github.ref == 'refs/heads/main'" in condition


def test_publish_job_has_oidc_and_registry_permissions():
    workflow = load_workflow()
    permissions = workflow["jobs"]["publish"]["permissions"]
    assert permissions["id-token"] == "write"
    assert permissions["packages"] == "write"


def test_publish_job_pushes_signs_and_attests():
    workflow = load_workflow()
    steps = workflow["jobs"]["publish"]["steps"]
    uses = [step.get("uses", "") for step in steps]
    runs = "\n".join(step.get("run", "") for step in steps)

    assert any(u.startswith("docker/login-action") for u in uses)
    assert any(u.startswith("sigstore/cosign-installer") for u in uses)
    assert "ghcr.io/" in runs
    assert "docker push" in runs
    assert "cosign sign --yes" in runs
    assert "scripts/generate_provenance.py" in runs
    assert "cosign attest --yes" in runs
    assert "--type slsaprovenance" in runs


def test_publish_job_tags_image_latest_and_sha():
    workflow = load_workflow()
    steps = workflow["jobs"]["publish"]["steps"]
    runs = "\n".join(step.get("run", "") for step in steps)
    assert ":latest" in runs
    assert "${{ github.sha }}" in runs


def test_scan_jobs_ignore_unfixed_cves_in_trivy():
    """Both Trivy scans must set ignore-unfixed, per PROGRESS.md's "CI
    incident" writeup and the README's "Unfixed vulnerabilities don't gate
    the build" section: base-image OS packages routinely carry freshly
    disclosed CVEs with no vendor patch, and gating on those would block
    every build regardless of what this repo changes.
    """
    workflow = load_workflow()
    for job_name in ("supply-chain-scan", "vulnerable-fixture-demo"):
        steps = workflow["jobs"][job_name]["steps"]
        trivy_steps = [
            step for step in steps if step.get("uses", "").startswith("aquasecurity/trivy-action")
        ]
        assert trivy_steps, f"{job_name} is expected to run aquasecurity/trivy-action"
        for step in trivy_steps:
            value = step.get("with", {}).get("ignore-unfixed")
            assert str(value).lower() == "true", (
                f"{job_name}'s Trivy step must set ignore-unfixed: true, got {value!r}"
            )


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


def test_verify_image_script_exists_and_is_executable():
    script = REPO_ROOT / "scripts" / "verify_image.sh"
    assert script.exists()
    assert script.stat().st_mode & 0o111, "verify_image.sh must be executable"


def test_generate_provenance_script_referenced_by_publish_job_exists():
    workflow = load_workflow()
    runs = "\n".join(step.get("run", "") for step in workflow["jobs"]["publish"]["steps"])
    assert "scripts/generate_provenance.py" in runs
    script = REPO_ROOT / "scripts" / "generate_provenance.py"
    assert script.exists()
