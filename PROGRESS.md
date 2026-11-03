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

Start Phase 3: the `.github/workflows/ci.yml` `supply-chain-scan` and
`vulnerable-fixture-demo` jobs build the demo image, run real `syft`,
`trivy`, and `gitleaks`, and gate on their actual JSON output — but neither
job pushes an image anywhere or signs anything yet. Add a `publish` job
(triggered on push to `main` only, after `supply-chain-scan` passes) that:

1. Pushes `demo-app:ci` to GHCR (`ghcr.io/<owner>/demo-app`) using the
   built-in `GITHUB_TOKEN`.
2. Signs the pushed image with `cosign` using keyless OIDC
   (`cosign sign --yes` with the `id-token: write` permission set on the
   job).
3. Generates a SLSA provenance attestation (`slsa-framework/slsa-github-generator`
   or `cosign attest` with an in-toto predicate) and attaches it to the image.
4. Add a `scripts/verify_image.sh` (or a `policy-engine verify` subcommand)
   that a consumer can run to check both the cosign signature and the
   provenance attestation against the published image.

Note in the PR description / commit that signing and provenance require a
real GHCR push, which only happens on `main`, not on PRs from forks — keep
that job scoped to `push` on `main` so PR runs from this pipeline don't fail
for lack of registry credentials.

STATUS: IN_PROGRESS
