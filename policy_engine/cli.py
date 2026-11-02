"""Command-line entrypoint for the policy engine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .models import SbomComponent, SecretFinding, Vulnerability
from .parsers import parse_gitleaks_findings, parse_syft_sbom, parse_trivy_results
from .policy import evaluate, load_policy


def _load_json(path: Optional[str]):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="policy-engine",
        description="Evaluate SBOM, vulnerability, and secret-scan reports against policy.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Run a policy check against scan reports.")
    check.add_argument("--policy", required=True, help="Path to policy YAML file.")
    check.add_argument("--scan", help="Path to a Trivy JSON vulnerability report.")
    check.add_argument("--sbom", help="Path to a Syft CycloneDX JSON SBOM.")
    check.add_argument("--secrets", help="Path to a gitleaks JSON report.")
    return parser


def run_check(args: argparse.Namespace) -> int:
    config = load_policy(args.policy)

    vulnerabilities: List[Vulnerability] = []
    if args.scan:
        vulnerabilities = parse_trivy_results(_load_json(args.scan))

    components: List[SbomComponent] = []
    if args.sbom:
        components = parse_syft_sbom(_load_json(args.sbom))

    secrets: List[SecretFinding] = []
    if args.secrets:
        secrets = parse_gitleaks_findings(_load_json(args.secrets))

    result = evaluate(vulnerabilities, components, secrets, config)

    print("Supply-chain policy check")
    print(
        f"  policy: {args.policy} "
        f"(max_severity={config.max_severity}, fail_on_secrets={config.fail_on_secrets})"
    )
    print()
    print(f"Vulnerabilities scanned: {len(vulnerabilities)}")
    print(f"SBOM components scanned: {len(components)}")
    print(f"Secret findings scanned: {len(secrets)}")
    print()

    if result.violations:
        print(f"VIOLATIONS ({len(result.violations)}):")
        for violation in result.violations:
            print(f"  [{violation.category}] {violation.message}")
    else:
        print("VIOLATIONS (0)")

    print()
    print(f"RESULT: {'PASS' if result.passed else 'FAIL'}")

    return 0 if result.passed else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return run_check(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
