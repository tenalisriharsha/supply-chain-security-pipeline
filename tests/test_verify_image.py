"""Tests for scripts/verify_image.sh.

Real cosign calls require a published image and network access, neither of
which exist in this environment, so the real cosign binary in paths that
exercise it is replaced with a small recorder script that stands in for the
external cosign CLI (the "thing outside this project" the mock rules allow)
while the actual bash script under test — argument parsing, usage/error
handling, and the exact cosign invocations it builds — runs unmodified and
unmocked. The no-cosign-installed path below needs no mock at all: cosign is
genuinely absent from this machine, so it exercises the real error path.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_image.sh"

DEFAULT_IDENTITY_REGEXP = (
    "^https://github.com/tenalisriharsha/supply-chain-security-pipeline"
    "/.github/workflows/ci.yml@refs/heads/main$"
)
ISSUER = "https://token.actions.githubusercontent.com"


def _run(args, env=None):
    return subprocess.run(
        ["bash", str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def test_usage_error_when_no_image_ref_given():
    result = _run([])
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_fails_clearly_when_cosign_is_not_installed():
    env = dict(os.environ)
    env["PATH"] = "/usr/bin:/bin"  # a PATH with no cosign on this machine
    result = _run(["ghcr.io/tenalisriharsha/demo-app:latest"], env=env)
    assert result.returncode == 2
    assert "cosign is required" in result.stderr


@pytest.fixture()
def fake_cosign_dir(tmp_path):
    """A PATH entry containing a recorder script standing in for cosign."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_path = tmp_path / "cosign-calls.log"
    recorder = bin_dir / "cosign"
    recorder.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$@" >> "{log_path}"\n'
        'if [ "$1" = "verify" ] && [ "${FAKE_COSIGN_VERIFY_FAILS:-}" = "1" ]; then\n'
        "  exit 1\n"
        "fi\n"
        'echo "fake cosign: $1 ok"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    recorder.chmod(recorder.stat().st_mode | stat.S_IEXEC)
    return bin_dir, log_path


def test_verify_and_verify_attestation_use_matching_identity_and_issuer(fake_cosign_dir):
    bin_dir, log_path = fake_cosign_dir
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"

    result = _run(["ghcr.io/tenalisriharsha/demo-app:latest"], env=env)

    assert result.returncode == 0, result.stderr
    calls = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(calls) == 2

    verify_call, attest_call = calls
    assert verify_call.startswith("verify ")
    assert attest_call.startswith("verify-attestation ")
    assert "--type slsaprovenance" in attest_call
    for call in (verify_call, attest_call):
        assert f"--certificate-identity-regexp {DEFAULT_IDENTITY_REGEXP}" in call
        assert f"--certificate-oidc-issuer {ISSUER}" in call
    assert calls[0].rstrip().endswith("ghcr.io/tenalisriharsha/demo-app:latest")
    assert calls[1].rstrip().endswith("ghcr.io/tenalisriharsha/demo-app:latest")
    assert "OK: ghcr.io/tenalisriharsha/demo-app:latest is signed" in result.stdout


def test_verify_repo_env_override_changes_identity_regexp(fake_cosign_dir):
    bin_dir, log_path = fake_cosign_dir
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
    env["VERIFY_REPO"] = "someorg/somerepo"

    result = _run(["ghcr.io/someorg/demo-app:latest"], env=env)

    assert result.returncode == 0, result.stderr
    calls = log_path.read_text(encoding="utf-8")
    assert (
        "^https://github.com/someorg/somerepo/.github/workflows/ci.yml@refs/heads/main$"
        in calls
    )
    assert "tenalisriharsha/supply-chain-security-pipeline" not in calls


def test_stops_and_does_not_print_ok_if_signature_verification_fails(fake_cosign_dir):
    bin_dir, log_path = fake_cosign_dir
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
    env["FAKE_COSIGN_VERIFY_FAILS"] = "1"

    result = _run(["ghcr.io/tenalisriharsha/demo-app:latest"], env=env)

    assert result.returncode != 0
    calls = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(calls) == 1, "verify-attestation must not run once signature verification fails"
    assert "OK:" not in result.stdout
