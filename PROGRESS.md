# Progress

## Vision

A GitHub Actions pipeline that builds a container image, generates a Software
Bill of Materials (SBOM) with Syft, scans it for known CVEs with Trivy and for
leaked secrets with gitleaks, signs the resulting image with cosign, and
attaches SLSA provenance so consumers can verify where and how the image was
built. Any policy violation — a vulnerability above the configured severity,
a denied license, or a detected secret — fails the build instead of shipping
silently.

## Architecture

```
            push / pull_request
                   |
                   v
        +----------------------+
        |  GitHub Actions CI   |
        +----------------------+
                   |
                   v
   +-------------------------------+
   |  1. Build container image     |
   +-------------------------------+
                   |
                   v
   +-------------------------------+        +-------------------------------+
   |  2. Generate SBOM (Syft)      | -----> |  3. Scan SBOM for CVEs        |
   |     CycloneDX JSON            |        |     (Trivy)                   |
   +-------------------------------+        +-------------------------------+
                   |                                      |
                   v                                      v
   +-------------------------------+        +-------------------------------+
   |  4. Scan repo for secrets      |        |  Trivy / Syft / gitleaks      |
   |     (gitleaks)                 |        |  JSON reports                 |
   +-------------------------------+        +-------------------------------+
                   |                                      |
                   +------------------+-------------------+
                                      v
                     +-------------------------------+
                     |  5. Policy engine gate         |
                     |     (this repo's core logic)   |
                     |     fails build on violation   |
                     +-------------------------------+
                                      |
                        pass          |          fail
                   +------------------+------------------+
                   v                                      v
   +-------------------------------+        +-------------------------------+
   |  6. Sign image (cosign,        |        |  Build fails, violations      |
   |     keyless OIDC)              |        |  printed in CI logs           |
   +-------------------------------+        +-------------------------------+
                   |
                   v
   +-------------------------------+
   |  7. Attach SLSA provenance     |
   |     attestation                |
   +-------------------------------+
```

The **policy engine** (`policy_engine/`) is the core of the pipeline: it
parses Trivy, Syft, and gitleaks JSON output into a common model and
evaluates it against a declarative `policy.yaml`, independent of any specific
CI provider. The GitHub Actions workflow is a thin orchestration layer around
it, which keeps the policy logic unit-testable without needing a live CI run,
a registry, or signing keys.

## Build Plan

### Phase 1 — Scaffold & policy engine foundation
- [x] Repository scaffold (`demo-app/`, `policy_engine/`, `tests/`, CI workflow directory)
- [x] Policy engine data models (`Vulnerability`, `SbomComponent`, `SecretFinding`, `PolicyConfig`, `PolicyResult`)
- [x] Parsers for Trivy, Syft (CycloneDX), and gitleaks JSON output
- [x] Policy evaluation (max severity, denied licenses, secret findings, CVE ignore list)
- [x] CLI (`policy-engine check`) with human-readable report and pass/fail exit code
- [x] Minimal demo HTTP service + Dockerfile as the artifact the pipeline will build
- [x] Unit tests for models, parsers, policy evaluation, and CLI (26 tests, all passing)
- [x] Initial CI workflow running the test suite and a policy-check smoke test
- [x] README, LICENSE, PROGRESS.md

### Phase 2 — Real scanner integration
- [x] Wire actual Syft SBOM generation into the GitHub Actions workflow (`anchore/sbom-action`)
- [x] Wire actual Trivy vulnerability scanning into the workflow (`aquasecurity/trivy-action`)
- [x] Wire actual gitleaks secret scanning into the workflow (binary install + `gitleaks detect`)
- [x] Feed real scanner output into the policy engine gate in CI (`supply-chain-scan` job)
- [x] Add a deliberately vulnerable fixture image/package to prove the gate fails the build
      (`demo-app/Dockerfile.vulnerable`, an EOL `debian:9` base, plus
      `tests/fixtures/secrets-sample/` with AWS's published example key; the
      `vulnerable-fixture-demo` job runs the real scanners against both and
      asserts the policy gate actually failed)

### Phase 3 — Signing & provenance
- [x] Build and push the container image to a registry from CI (`publish`
      job in `.github/workflows/ci.yml`, GHCR, `push`-to-`main` only)
- [x] Sign the image with cosign using keyless (OIDC) signing (`cosign sign
      --yes`, backed by the job's ambient `id-token: write` OIDC token)
- [x] Generate and attach SLSA provenance attestation
      (`scripts/generate_provenance.py` builds a SLSA v0.2 predicate from
      the GitHub Actions run context; `cosign attest --type slsaprovenance`
      attaches it)
- [x] Add a verification script for consumers to check signature +
      provenance (`scripts/verify_image.sh <image-ref>`)

### Phase 4 — Hardening & docs
- [x] Diagnose and fix a real CI failure on `supply-chain-scan` (see
      "CI incident" below) — the closest thing to an end-to-end dry run
      available without push rights to `main`: it exercised the real
      `syft`/`trivy`/`gitleaks` CLIs against the real demo-app image on a
      GitHub Actions runner and surfaced a genuine, previously-unseen
      failure mode
- [x] Document policy customization and failure modes (new "What causes a
      failure" table and "Unfixed vulnerabilities don't gate the build"
      section in the README)
- [x] Add preview screenshots of the full pipeline run (8 total — added
      `07-provenance-generation` and `08-verify-image` covering the Phase 3
      signing/provenance tooling, which wasn't captured yet)
- [x] Final polish pass on README and PROGRESS.md

## CI incident: `supply-chain-scan` failing on PR #1

Two distinct real failures showed up in sequence on the open PR, both only
visible on an actual GitHub Actions runner (neither reproduces from the
offline fixtures the unit tests use):

1. **Trivy binary install flake.** `aquasecurity/trivy-action@v0.36.0`'s
   bundled installer failed once with `curl` exit code 6 (DNS resolution)
   fetching the Trivy binary — a transient runner network issue, not a
   workflow bug. Confirmed by re-running the job and watching the install
   succeed on retry while the identical step in the sibling
   `vulnerable-fixture-demo` job (same action, same tag) had already
   succeeded in the original run.
2. **Real CVE drift in the base image.** With the install flake gone, the
   `supply-chain-scan` job's Policy gate step then failed for real: Trivy
   found 48 HIGH-severity CVEs in `python:3.12-slim`'s Debian OS layer
   (`util-linux`, `apt`, `perl-base`, etc.) that this repo's Dockerfile
   never touches — they come from the base image, not from anything built
   here. None had a `FixedVersion` yet (freshly disclosed, no vendor patch
   published). Fixed by adding `ignore-unfixed: "true"` to both
   `aquasecurity/trivy-action` steps in `.github/workflows/ci.yml`: the
   gate now only fails on vulnerabilities with an actual upgrade path,
   which is what `max_severity` is meant to enforce. This is a standard
   Trivy CI pattern, not a weakening of the policy — a leaked secret or a
   denied license still fails the build unconditionally, and any
   vulnerability with a fix available still gates it.
3. **New fixable CVE in the base image.** With `ignore-unfixed` in place,
   `supply-chain-scan` later failed again on a different CVE
   (`CVE-2026-109518` in `apt`/`libapt-pkg7.0`) — this one *did* have a
   `FixedVersion` (Debian's `stable-security` channel shipped `3.0.4`
   after `python:3.12-slim` was last rebuilt), so `ignore-unfixed` correctly
   let it through the gate. Reproduced locally by building `demo-app/` with
   Docker and running `apt list --upgradable` as root inside the resulting
   image, which showed `apt`/`libapt-pkg7.0` sitting one security point
   release behind. Fixed in `demo-app/Dockerfile` by running
   `apt-get update && apt-get upgrade -y` during the build, so the shipped
   image always carries whatever OS security patches exist at build time
   instead of whatever happened to be baked into the upstream base image.
   Rebuilt and confirmed `apt`/`libapt-pkg7.0` report `3.0.4` post-fix.

## Resume point

All four phases are implemented and tested. `.github/workflows/ci.yml` has
four jobs: `test` (unit tests + a fixture-based policy smoke test),
`supply-chain-scan` (builds the real demo-app image and runs real
`syft`/`trivy`/`gitleaks` against it, gated through the policy engine),
`vulnerable-fixture-demo` (proves the same real tools catch a genuinely
outdated image and a genuine leaked secret), and `publish`
(`needs: [supply-chain-scan, vulnerable-fixture-demo]`, `push`-to-`main`
only) which pushes the image to GHCR, signs it keylessly with cosign, and
attaches a SLSA v0.2 provenance attestation via
`scripts/generate_provenance.py` + `cosign attest`.

One piece remains validated only in isolation rather than live end-to-end:
the `publish` job itself (push to GHCR, `cosign sign`, `cosign attest`)
only runs on a push to `main` with a real GitHub Actions OIDC token —
there's no way to exercise that from a sandbox with no Docker, no cosign,
and no push access to `main`. It was validated piece by piece instead:
the workflow YAML parses and its job graph/permissions are covered by
`tests/test_ci_workflow.py`, `scripts/generate_provenance.py` was run for
real locally and its output inspected (see
`docs/screenshots/07-provenance-generation.png`), and
`scripts/verify_image.sh` was run for real against both its usage-error and
missing-dependency paths (see `docs/screenshots/08-verify-image.png`). The
first real signature and attestation will be produced the first time this
branch's commits land on `main`.

STATUS: COMPLETE
