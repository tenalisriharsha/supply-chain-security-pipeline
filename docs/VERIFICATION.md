# Verification report

Performed in a fresh `git clone` of this repository into a temporary
directory, outside the working copy, on 2026-11-05.

## First-use check

Followed the README "Quick start" section word for word, in order, without
fixing anything along the way.

```
git clone <repo> repo && cd repo
python3 -m venv .venv && source .venv/bin/activate
```
Expected: a usable virtual environment. Observed: `python3` on this machine
resolves to `/usr/bin/python3`, Python 3.9.6, bundled with pip 21.2.4.

```
pip install -e . -r requirements-dev.txt
```
Expected (per README): dependencies install and the package becomes
importable. Observed:
```
ERROR: File "setup.py" or "setup.cfg" not found. Directory cannot be
installed in editable mode: .../repo
(A "pyproject.toml" file was found, but editable mode currently requires
a setuptools-based build.)
```
pip 21.2.4 predates PEP 660 (editable installs from a `pyproject.toml`-only
project, added in pip 21.3), so the install fails outright. This is a
mismatch: the README's quick start does not mention a minimum pip/Python
version, and the `python3` a first-time user gets by typing exactly what
the README says can be too old for the very next command it tells them to
run.

```
python -m pytest tests demo-app -v
```
Expected: 58 tests passing. Observed (cascading from the failed install):
`No module named pytest`.

```
python -m policy_engine.cli check --policy policy.yaml --scan ... --sbom ... --secrets ...
```
Expected: `RESULT: PASS`. Observed (cascading from the failed install):
`ModuleNotFoundError: No module named 'yaml'`.

None of this is a bug in the project's own code — rerunning the identical
quick start with a newer Python/pip (3.14.8 / pip 26.2.1, also present on
this machine but not the one `python3` resolves to) installs and runs
cleanly, as shown in the sections below. The mismatch is specifically that
the quick start has an unstated minimum-tooling requirement and gives no
indication of what version it expects, so a literal first-time run of the
documented commands, in order, fails at the second command.

Result: FAIL - `pip install -e . -r requirements-dev.txt` fails under the
`python3` this machine's PATH resolves to (pip 21.2.4, too old for
PEP 660 editable installs); every later quick-start command then fails as
a consequence. Works end-to-end with Python 3.14.8 / pip 26.2.1 (see below).

## Headline feature run

With a virtual environment built from Python 3.14.8 (`pip install -e . -r
requirements-dev.txt` completes cleanly there), ran the policy engine CLI —
the project's core feature — against the real fixtures shipped in the repo,
covering both the pass and every documented fail path:

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-clean.json \
  --sbom tests/fixtures/syft-sbom-clean.json \
  --secrets tests/fixtures/gitleaks-clean.json
```
Expected: `RESULT: PASS`, exit 0. Observed: exactly that —
`Vulnerabilities scanned: 1`, `VIOLATIONS (0)`, `RESULT: PASS`, exit 0.

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-critical.json \
  --sbom tests/fixtures/syft-sbom-clean.json \
  --secrets tests/fixtures/gitleaks-clean.json
```
Expected: fail on a CRITICAL CVE exceeding `max_severity: HIGH`. Observed:
`VIOLATIONS (2)` listing `CVE-2023-4863 ... CRITICAL` and
`CVE-2023-5678 ... HIGH`, `RESULT: FAIL`, exit 1.

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-clean.json \
  --sbom tests/fixtures/syft-sbom-clean.json \
  --secrets tests/fixtures/gitleaks-findings.json
```
Expected: fail on a detected secret. Observed:
`[secret] potential secret (generic-api-key) found in demo-app/config.py:12`,
`RESULT: FAIL`, exit 1.

```
python -m policy_engine.cli check --policy policy.yaml \
  --scan tests/fixtures/trivy-clean.json \
  --sbom tests/fixtures/syft-sbom-denied-license.json \
  --secrets tests/fixtures/gitleaks-clean.json
```
Expected: fail on a denied license. Observed:
`[license] copyleft-lib@9.9.9 uses denied license GPL-3.0`, `RESULT: FAIL`,
exit 1.

```
python -m policy_engine.cli check --help
```
Expected: full flag reference. Observed: usage text documenting
`--policy`, `--scan`, `--sbom`, `--secrets`, matching the README.

Also ran `scripts/generate_provenance.py`, the pure-Python, no-network SLSA
predicate generator the `publish` job uses:
```
GITHUB_REPOSITORY=... GITHUB_SHA=... GITHUB_REF=... GITHUB_RUN_ID=999 \
  python scripts/generate_provenance.py --output /tmp/provenance.json
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
pushing one is outside the scope of a local check). Ran the script anyway
with no image: it failed clearly and immediately with
`cosign is required: https://docs.sigstore.dev/system_config/installation/`,
exit 2 — the exact behavior the test suite expects
(`test_fails_clearly_when_cosign_is_not_installed`), so the script's own
error handling is confirmed even though the full verification path isn't.

Likewise the real `syft`/`trivy`/`gitleaks` CI job (`supply-chain-scan`)
and the `vulnerable-fixture-demo` job both require Docker to build an
image; the Docker daemon is not running here, so that half of the pipeline
could not be exercised directly. The policy engine itself — the part that
decides pass/fail — was exercised directly above against fixtures that are
byte-for-byte the same shape as what those real tools produce (the fixture
files are the committed, versioned test inputs for exactly this scan
pipeline).

Result: NOT_POSSIBLE - full image build/scan/sign/verify requires Docker
(daemon not running here) and `cosign` (not installed), plus a real image
already published to GHCR by GitHub Actions; the policy-engine gate logic
itself, which is this project's actual deliverable, was run for real above
against both passing and failing fixture inputs with correct results.

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
exact command). Observed: `58 passed in 1.69s`, zero failures, zero
skips, covering the policy engine, CLI, CI-workflow-shape checks, SLSA
provenance generation, `verify_image.sh`'s own test suite, and the
demo app.

Also ran with the installed `pytest-cov`, since it's a declared dev
dependency even though the README doesn't give an explicit coverage
command:
```
python -m pytest tests demo-app --cov=policy_engine -q
```
Observed: `58 passed`, 97% statement coverage on `policy_engine`
(172 statements, 6 missed).

Result: PASS
