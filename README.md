# supply-chain-security-pipeline

[![CI](https://github.com/tenalisriharsha/supply-chain-security-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/tenalisriharsha/supply-chain-security-pipeline/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A GitHub Actions pipeline that builds a container image, generates a
Software Bill of Materials (SBOM) with [Syft](https://github.com/anchore/syft),
scans it for known CVEs with [Trivy](https://github.com/aquasecurity/trivy)
and for leaked secrets with [gitleaks](https://github.com/gitleaks/gitleaks),
signs the resulting image with [cosign](https://github.com/sigstore/cosign),
and attaches [SLSA](https://slsa.dev/) provenance so consumers can verify
where and how an image was built. A policy violation — a vulnerability above
the configured severity, a denied license, or a detected secret — fails the
build instead of shipping silently.

> **Project status:** Phase 1 of 4 complete. See [PROGRESS.md](PROGRESS.md)
> for the architecture, the full phased build plan, and exactly where work
> resumes next.

## Preview

The pipeline's policy engine is the piece under active development right
now. These are real, unedited runs of its test suite and CLI against this
repository.

**Repository layout**
![Repository structure](docs/screenshots/01-repo-structure.png)

**Test suite**
![Test suite passing](docs/screenshots/02-test-suite.png)

**CLI help**
![Policy engine CLI help](docs/screenshots/03-cli-help.png)

**Policy check against a clean artifact**
![Policy check pass](docs/screenshots/04-policy-check-pass.png)

**Policy check against a vulnerable artifact**
![Policy check fail](docs/screenshots/05-policy-check-fail.png)

**Commit history**
![Commit history](docs/screenshots/06-commit-history.png)

## Quick start

```bash
git clone https://github.com/tenalisriharsha/supply-chain-security-pipeline.git
cd supply-chain-security-pipeline

python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements-dev.txt

# Run the test suite
python -m pytest tests demo-app -v

# Check a clean artifact against the default policy
python -m policy_engine.cli check \
  --policy policy.yaml \
  --scan tests/fixtures/trivy-clean.json \
  --sbom tests/fixtures/syft-sbom-clean.json \
  --secrets tests/fixtures/gitleaks-clean.json
```

## How it works

```
push/PR -> build image -> Syft SBOM -> Trivy scan -----v
                       \-> gitleaks scan -------------> policy engine gate -> cosign sign -> SLSA provenance
```

The **policy engine** (`policy_engine/`) is the core of the pipeline. It
parses Trivy, Syft, and gitleaks JSON reports into a common model and
evaluates them against a declarative `policy.yaml`, independently of any
specific CI provider. The GitHub Actions workflow in
`.github/workflows/ci.yml` orchestrates it. Full architecture diagram and
rationale are in [PROGRESS.md](PROGRESS.md).

## Policy configuration

`policy.yaml` at the repository root controls what fails the build:

```yaml
max_severity: HIGH       # fail on vulnerabilities at or above this severity
fail_on_secrets: true    # fail if gitleaks finds anything
denied_licenses:         # fail if any SBOM component uses one of these
  - GPL-3.0
  - AGPL-3.0
ignore_cves: []          # known false positives / accepted risk, by CVE ID
```

## Repository layout

```
policy_engine/   core policy evaluation library + CLI
demo-app/        minimal HTTP service used as the sample build artifact
tests/           unit tests and scanner-output fixtures for the policy engine
.github/         CI workflow
```

## Development

```bash
python -m pytest tests demo-app -v
```

## Status

Phase 1 (project scaffold and the policy engine core) is complete and
tested. The full phase-by-phase build plan, architecture, and the exact
resume point for the next phase live in [PROGRESS.md](PROGRESS.md).

## License

MIT — see [LICENSE](LICENSE).
