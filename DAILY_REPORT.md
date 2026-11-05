# Daily Report

Summary of what was built across the life of this project, for anyone
picking it up cold. Build history by phase is in [PROGRESS.md](PROGRESS.md);
this file is the higher-level summary plus test results, limitations, and
ideas for continuing it.

## What was built

A GitHub Actions pipeline, backed by a standalone, CI-provider-agnostic
policy engine, that:

1. Builds a minimal demo container image.
2. Generates a CycloneDX SBOM for it with Syft.
3. Scans the image for known CVEs with Trivy.
4. Scans the source tree for leaked secrets with gitleaks.
5. Feeds all three real tool outputs into a policy engine
   (`policy_engine/`) that evaluates them against a declarative
   `policy.yaml` and fails the build on any violation — a vulnerability at
   or above a configured severity with a fix available, a denied license,
   or any detected secret.
6. On push to `main`, publishes the image to GHCR, signs it keylessly with
   cosign (backed by the job's GitHub Actions OIDC token, no stored signing
   key), and attaches a SLSA v0.2 provenance attestation describing exactly
   which commit, ref, and workflow run produced it.
7. Ships a verification script (`scripts/verify_image.sh`) so a consumer of
   the published image can check both the signature and the provenance
   attestation with `cosign`.

A second CI job, `vulnerable-fixture-demo`, proves the gate isn't a no-op:
it builds a deliberately outdated image (`demo-app/Dockerfile.vulnerable`,
an EOL `debian:9` base) and scans a fixture containing a known-example
AWS key, then asserts the policy gate actually failed on both.

## Test results

54 tests pass (`python -m pytest tests demo-app -v`): policy engine model,
parser, and evaluation unit tests; CLI behavior tests; provenance-generation
and image-verification script tests; structural checks on the CI workflow
YAML (job graph, permissions, trigger conditions); and the demo app's own
tests. The full suite runs in about 2 seconds with no external dependencies
(Docker, network, or live scanners) — it uses recorded Trivy/Syft/gitleaks
JSON fixtures under `tests/fixtures/`, independent of the real scanners the
CI workflow also exercises on every push and pull request.

## Known limitations

- **The `publish` job is validated piece by piece, not end-to-end.** It only
  runs on a push to `main` with a real GitHub Actions OIDC token, which
  can't be exercised from a sandbox with no Docker, no cosign, and no push
  access to `main`. Its individual pieces were validated separately: the
  workflow YAML and job graph are covered by `tests/test_ci_workflow.py`,
  and `scripts/generate_provenance.py` and `scripts/verify_image.sh` were
  both run for real locally (see `docs/screenshots/07-provenance-generation.png`
  and `docs/screenshots/08-verify-image.png`). The first real signature and
  attestation will be produced the first time this branch's commits land on
  `main`.
- **Trivy runs with `ignore-unfixed: true`.** Base-image OS packages
  routinely carry freshly-disclosed CVEs with no vendor patch yet; without
  this flag, the "clean" demo-app build would fail nondeterministically as
  the Debian advisory database updates, regardless of what this repository
  changes. Only vulnerabilities with an available upgrade path gate the
  build. See the README's "Unfixed vulnerabilities don't gate the build"
  section for the full rationale and how to opt out of it.
- **The demo app is intentionally minimal** — a single-endpoint HTTP
  service — since it exists to be a believable build artifact for the
  pipeline, not a product in its own right.
- **No license allowlist mode.** `denied_licenses` is a blocklist; there's
  no complementary "only these licenses are allowed" mode, which some
  organizations prefer.

## Ideas for continuing this project

- Add a license *allowlist* mode to `policy.yaml` as an alternative to the
  current denylist, for organizations that want to default-deny anything
  not explicitly approved.
- Support multiple policy files evaluated together (e.g. a shared baseline
  plus a per-repository override), rather than a single `--policy` path.
- Add a `--format json` output mode to `policy-engine check` so the gate's
  result can be consumed by other tooling (a PR comment bot, a dashboard)
  without scraping the human-readable report.
- Rebuild `docs/screenshots/` periodically (`python scripts/capture_screenshots.py`)
  as a pre-release step so the preview images never drift from actual CLI
  output.
- Track Debian security-tracker status directly (rather than relying solely
  on `ignore-unfixed`) to distinguish "no fix yet" from "will not fix",
  which Trivy's output doesn't currently separate.
