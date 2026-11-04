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
- [ ] End-to-end dry run of the full pipeline on a real push
- [ ] Document policy customization and failure modes
- [ ] Add preview screenshots of the full pipeline run
- [ ] Final polish pass on README and PROGRESS.md

## Resume point for next session

Phase 3 is done: `.github/workflows/ci.yml` has a `publish` job
(`needs: [supply-chain-scan, vulnerable-fixture-demo]`, gated on
`github.event_name == 'push' && github.ref == 'refs/heads/main'`) that
builds the demo image, pushes it to `ghcr.io/<owner>/demo-app` tagged
`:latest` and `:<commit-sha>`, signs it keylessly with cosign, generates a
SLSA v0.2 provenance predicate via `scripts/generate_provenance.py`, and
attaches it with `cosign attest`. `scripts/verify_image.sh <image-ref>`
lets a consumer check both. This can't be exercised end-to-end locally
(no Docker/cosign in this environment, and keyless signing needs a real
GitHub Actions OIDC token) — it was validated by checking the workflow
YAML parses, running `scripts/generate_provenance.py` standalone and
inspecting its output, and running `scripts/verify_image.sh` with no
args to confirm its usage/error path. The real validation happens on the
first push to `main` after this merges.

Known test conflict: `tests/test_ci_workflow.py::test_workflow_is_valid_yaml_with_expected_jobs`
hardcodes the job set to `{test, supply-chain-scan, vulnerable-fixture-demo}`
and now fails because `publish` was added as this phase's plan required.
Logged in the disputes file rather than edited — see
`/Users/tenalisriharsha/kimi-daily/state/split/supply-chain-security-pipeline/disputes.md`.

Start Phase 4 next:
- [ ] End-to-end dry run of the full pipeline on a real push to `main`
      (confirm `publish` actually signs and attests against GHCR)
- [ ] Document policy customization and failure modes in more depth
- [ ] Add preview screenshots of the full pipeline run
- [ ] Final polish pass on README and PROGRESS.md, then mark COMPLETE

STATUS: IN_PROGRESS
