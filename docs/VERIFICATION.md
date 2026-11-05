# Verification report

Performed in a fresh `git clone` of this repository (branch
`night/2026-11-03`, commit `21971c9`) into a temporary directory, outside
the working copy, on 2026-11-05.

## First-use check

Followed the README "Quick start" section word for word, in order, without
fixing anything along the way.

```
python3 -m pip --version
```
Expected: the README's warning applies if this is older than pip 21.3.
Observed: `pip 21.2.4 ... (python 3.9)` — the exact old-pip scenario the
quick start calls out.

```
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
```
Expected: pip upgrades inside the venv. Observed: upgraded cleanly from
21.2.4 to 26.0.1.

```
pip install -e . -r requirements-dev.txt
```
Expected: dependencies install and the package becomes importable.
Observed: installed cleanly — `PyYAML`, `pytest`, `pytest-cov`, and
`policy-engine` (editable) — no errors.

```
python -m pytest tests demo-app -v
```
Expected: 58 tests passing. Observed: `58 passed in 1.33s`, zero failures.

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-clean.json \
  --sbom tests/fixtures/syft-sbom-clean.json \
  --secrets tests/fixtures/gitleaks-clean.json
```
Expected: `RESULT: PASS`, exit 0. Observed: exactly that —
`Vulnerabilities scanned: 1`, `VIOLATIONS (0)`, `RESULT: PASS`, exit 0.

Every command ran exactly as written, in order, with no undocumented step
and no deviation from the stated expected behavior. The pip-upgrade step
that the quick start now includes specifically covers the old-system-pip
case this machine's `python3` resolves to.

Result: PASS

## Headline feature run

Ran the policy engine CLI — the project's core deliverable — against the
real fixtures shipped in the repo, covering both the pass and every
documented fail path:

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-critical.json \
  --sbom tests/fixtures/syft-sbom-denied-license.json \
  --secrets tests/fixtures/gitleaks-findings.json
```
Expected: fail on all three violation categories at once. Observed:
`VIOLATIONS (4)` — `CVE-2023-4863` (CRITICAL), `CVE-2023-5678` (HIGH),
`copyleft-lib@9.9.9 uses denied license GPL-3.0`, and
`potential secret (generic-api-key) found in demo-app/config.py:12` —
`RESULT: FAIL`, exit 1.

```
python -m policy_engine.cli check --help
```
Expected: full flag reference. Observed: usage text documenting
`--policy`, `--scan`, `--sbom`, `--secrets`, matching the README.

Also ran `scripts/generate_provenance.py`, the pure-Python, no-network SLSA
predicate generator the `publish` job uses:
```
python scripts/generate_provenance.py \
  --repository tenalisriharsha/supply-chain-security-pipeline \
  --commit-sha <head-sha> --ref refs/heads/main \
  --run-id 999999 --run-attempt 1 --output /tmp/provenance.json
```
Expected: a SLSA v0.2 predicate JSON file. Observed: exactly that, with
`builder.id`, `invocation.configSource.digest.sha1`, and
`metadata.buildInvocationId` populated from the supplied values.

The signing/verification half of the headline feature —
`scripts/verify_image.sh ghcr.io/.../demo-app:latest`, which calls real
`cosign` to verify a keyless signature and SLSA attestation on a published
image — could not be run for real: it needs `cosign` installed (not
present on this machine) and a real image already published to GHCR by a
GitHub Actions run (no such run exists from this local environment, and
pushing one is outside the scope of a local check). Ran the script anyway:
with no arguments it printed `Usage: scripts/verify_image.sh <image-ref>`
and exited 2; with an image ref it failed clearly and immediately with
`cosign is required: https://docs.sigstore.dev/system_config/installation/`,
exit 2 — the exact behavior the test suite expects
(`test_fails_clearly_when_cosign_is_not_installed`), so the script's own
error handling is confirmed even though the full verification path isn't.

Likewise the real `syft`/`trivy`/`gitleaks` CI job (`supply-chain-scan`)
and the `vulnerable-fixture-demo` job both require Docker to build an
image; the Docker daemon is not running here, and `syft`/`trivy`/`gitleaks`
are not installed locally, so that half of the pipeline could not be
exercised directly. The policy engine itself — the part that decides
pass/fail — was exercised directly above against fixtures that are the
committed, versioned test inputs for exactly this scan pipeline.

Result: NOT_POSSIBLE - full image build/scan/sign/verify requires Docker
(daemon not running here), `syft`/`trivy`/`gitleaks`/`cosign` (none
installed), and a real image already published to GHCR by GitHub Actions;
the policy-engine gate logic itself, which is this project's actual
deliverable, was run for real above against both passing and failing
fixture inputs with correct results, and the provenance generator and
verify script's own error paths were exercised for real too.

## Test suite with development tools

The project documents exactly one dev dependency set
(`requirements-dev.txt`: `pytest`, `pytest-cov`) and runs no linter or type
checker in CI (`.github/workflows/ci.yml`'s `test` job only runs pytest);
there is no `ruff`, `mypy`, `flake8`, or similar configuration anywhere in
the repository.

```
pip install -e . -r requirements-dev.txt
python -m pytest tests demo-app -v
```
Expected: all tests pass (README's "Development" section documents this
exact command). Observed: `58 passed in 1.33s`, zero failures, zero
skips, covering the policy engine, CLI, CI-workflow-shape checks, SLSA
provenance generation, `verify_image.sh`'s own test suite, and the
demo app.

Also ran with the installed `pytest-cov`, since it's a declared dev
dependency even though the README doesn't give an explicit coverage
command:
```
python -m pytest tests demo-app -v --cov=policy_engine --cov-report=term-missing
```
Observed: `58 passed`, 97% statement coverage on `policy_engine`
(172 statements, 6 missed).

Result: PASS
