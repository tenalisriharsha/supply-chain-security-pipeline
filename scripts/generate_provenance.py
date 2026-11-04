"""Build a SLSA v0.2 provenance predicate for the image built in CI.

Produces the *predicate* object only (not the full in-toto statement) —
``cosign attest --type slsaprovenance`` wraps it into a statement and fills
in the subject (image digest) itself.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional


def build_provenance(
    *,
    repository: str,
    commit_sha: str,
    ref: str,
    run_id: str,
    run_attempt: str,
    workflow_path: str = ".github/workflows/ci.yml",
    server_url: str = "https://github.com",
) -> dict:
    """Return a SLSA v0.2 provenance predicate for a GitHub Actions build.

    ``repository`` is ``owner/name`` (``GITHUB_REPOSITORY``), ``commit_sha``
    is the built commit (``GITHUB_SHA``), ``ref`` is the git ref that
    triggered the build (``GITHUB_REF``), and ``run_id``/``run_attempt``
    identify the specific workflow run (``GITHUB_RUN_ID``/
    ``GITHUB_RUN_ATTEMPT``).
    """
    repo_uri = f"git+{server_url}/{repository}@{ref}"
    builder_id = f"{server_url}/{repository}/{workflow_path}@{ref}"

    return {
        "builder": {"id": builder_id},
        "buildType": "https://github.com/actions/runs",
        "invocation": {
            "configSource": {
                "uri": repo_uri,
                "digest": {"sha1": commit_sha},
                "entryPoint": workflow_path,
            },
            "environment": {
                "github_run_id": run_id,
                "github_run_attempt": run_attempt,
            },
        },
        "metadata": {
            "buildInvocationId": f"{run_id}-{run_attempt}",
            "completeness": {
                "parameters": True,
                "environment": False,
                "materials": True,
            },
            "reproducible": False,
        },
        "materials": [
            {
                "uri": repo_uri,
                "digest": {"sha1": commit_sha},
            }
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a SLSA v0.2 provenance predicate for a GitHub Actions build.",
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    parser.add_argument("--workflow-path", default=".github/workflows/ci.yml")
    parser.add_argument("--server-url", default=os.environ.get("GITHUB_SERVER_URL", "https://github.com"))
    parser.add_argument("--output", required=True, help="Path to write the predicate JSON to.")
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    missing = [
        name
        for name in ("repository", "commit_sha", "ref", "run_id", "run_attempt")
        if not getattr(args, name)
    ]
    if missing:
        parser.error(f"missing required values: {', '.join(missing)}")

    predicate = build_provenance(
        repository=args.repository,
        commit_sha=args.commit_sha,
        ref=args.ref,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        workflow_path=args.workflow_path,
        server_url=args.server_url,
    )

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(predicate, handle, indent=2)
        handle.write("\n")

    print(f"Wrote SLSA provenance predicate to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
