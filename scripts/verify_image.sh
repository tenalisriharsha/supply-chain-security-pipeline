#!/usr/bin/env bash
# Verify that a published demo-app image was signed by this repository's CI
# and carries a SLSA provenance attestation for the same build.
#
# Usage: scripts/verify_image.sh <image-ref>
#   scripts/verify_image.sh ghcr.io/tenalisriharsha/demo-app:latest
#
# Requires: cosign (https://docs.sigstore.dev/system_config/installation/)
set -euo pipefail

IMAGE_REF="${1:-}"
REPO="${VERIFY_REPO:-tenalisriharsha/supply-chain-security-pipeline}"

if [ -z "$IMAGE_REF" ]; then
  echo "Usage: $0 <image-ref>" >&2
  exit 2
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required: https://docs.sigstore.dev/system_config/installation/" >&2
  exit 2
fi

ISSUER="https://token.actions.githubusercontent.com"
IDENTITY_REGEXP="^https://github.com/${REPO}/.github/workflows/ci.yml@refs/heads/main$"

echo "Verifying signature on ${IMAGE_REF} ..."
cosign verify \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE_REF"

echo
echo "Verifying SLSA provenance attestation on ${IMAGE_REF} ..."
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE_REF"

echo
echo "OK: ${IMAGE_REF} is signed by ${REPO}'s CI and carries a matching SLSA provenance attestation."
