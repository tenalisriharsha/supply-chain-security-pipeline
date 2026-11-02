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
- [ ] Wire actual Syft SBOM generation into the GitHub Actions workflow
- [ ] Wire actual Trivy vulnerability scanning into the workflow
- [ ] Wire actual gitleaks secret scanning into the workflow
- [ ] Feed real scanner output into the policy engine gate in CI
- [ ] Add a deliberately vulnerable fixture image/package to prove the gate fails the build

### Phase 3 — Signing & provenance
- [ ] Build and push the container image to a registry from CI
- [ ] Sign the image with cosign using keyless (OIDC) signing
- [ ] Generate and attach SLSA provenance attestation
- [ ] Add a verification script/command for consumers to check signature + provenance

### Phase 4 — Hardening & docs
- [ ] End-to-end dry run of the full pipeline on a real push
- [ ] Document policy customization and failure modes
- [ ] Add preview screenshots of the full pipeline run
- [ ] Final polish pass on README and PROGRESS.md

## Resume point for next session

Start Phase 2: wire real `syft`, `trivy`, and `gitleaks` CLI invocations into
`.github/workflows/ci.yml` as new steps that run after the image build, write
their JSON reports to disk, and pass those report paths to
`policy-engine check` instead of the test fixtures. Add a second, deliberately
vulnerable fixture (e.g. an old base image or a package with a known CVE) to
prove in CI that the pipeline actually fails the build, not just that the
policy engine can fail in unit tests.

STATUS: IN_PROGRESS
