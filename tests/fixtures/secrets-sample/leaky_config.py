# Scan target for the real-gitleaks CI demo job (see .github/workflows/ci.yml).
# AKIAIOSFODNN7EXAMPLE is AWS's own published placeholder access key ID,
# used throughout AWS docs and security-tooling test suites — it is not a
# functional credential. It exists here purely so a real `gitleaks` run has
# something genuine to find, instead of relying only on the pre-recorded
# tests/fixtures/gitleaks-findings.json used by the policy engine unit tests.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
