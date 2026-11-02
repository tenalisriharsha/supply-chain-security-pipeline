"""Run real commands against this repo and screenshot their actual output.

Each command listed below is executed for real with subprocess; the captured
stdout/stderr and exit code are rendered verbatim into a terminal-style HTML
page, which is then screenshotted with Playwright. Nothing here hand-writes
or edits command output.
"""

from __future__ import annotations

import html
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "docs" / "screenshots"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{
    margin: 0;
    background: #1e1e2e;
    display: flex;
    justify-content: center;
    padding: 40px;
  }}
  .window {{
    width: 980px;
    background: #181825;
    border-radius: 10px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    overflow: hidden;
    font-family: "SF Mono", "Menlo", "Consolas", monospace;
  }}
  .titlebar {{
    background: #11111b;
    padding: 10px 14px;
    display: flex;
    align-items: center;
  }}
  .dot {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-right: 8px;
  }}
  .dot.red {{ background: #f38ba8; }}
  .dot.yellow {{ background: #f9e2af; }}
  .dot.green {{ background: #a6e3a1; }}
  .title {{
    color: #a6adc8;
    font-size: 13px;
    margin-left: 12px;
  }}
  .body {{
    padding: 20px 22px 26px;
    color: #cdd6f4;
    font-size: 14px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  .prompt {{
    color: #a6e3a1;
  }}
  .cmd {{
    color: #cdd6f4;
  }}
</style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <div class="dot red"></div>
      <div class="dot yellow"></div>
      <div class="dot green"></div>
      <div class="title">{title}</div>
    </div>
    <div class="body">{body}</div>
  </div>
</body>
</html>
"""


def run(cmd, cwd=REPO_ROOT, env=None):
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, env=env
    )
    return result.stdout + result.stderr, result.returncode


def render_block(display_cmd: str, output: str, exit_code: int) -> str:
    lines = [f'<span class="prompt">$</span> <span class="cmd">{html.escape(display_cmd)}</span>']
    if output:
        lines.append(html.escape(output.rstrip("\n")))
    lines.append(f"\n[exit code: {exit_code}]")
    return "\n".join(lines)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    python = str(VENV_PYTHON)

    panels = []

    # 1. Repository structure
    find_cmd = [
        "find", ".", "-type", "f",
        "-not", "-path", "./.git/*",
        "-not", "-path", "./.venv/*",
        "-not", "-path", "*/__pycache__/*",
        "-not", "-path", "./.pytest_cache/*",
        "-not", "-path", "*.egg-info/*",
    ]
    out, code = run(find_cmd)
    sorted_out = "\n".join(sorted(out.strip().splitlines()))
    panels.append((
        "01-repo-structure",
        "supply-chain-security-pipeline — repository layout",
        render_block("find . -type f | sort", sorted_out, code),
    ))

    # 2. Full test suite
    cmd = [python, "-m", "pytest", "tests", "demo-app", "-v"]
    out, code = run(cmd)
    panels.append((
        "02-test-suite",
        "supply-chain-security-pipeline — pytest",
        render_block("python -m pytest tests demo-app -v", out, code),
    ))

    # 3. CLI help
    out1, code1 = run([python, "-m", "policy_engine.cli", "--help"])
    out2, code2 = run([python, "-m", "policy_engine.cli", "check", "--help"])
    combined = (
        render_block("python -m policy_engine.cli --help", out1, code1)
        + "\n\n"
        + render_block("python -m policy_engine.cli check --help", out2, code2)
    )
    panels.append((
        "03-cli-help",
        "supply-chain-security-pipeline — policy-engine CLI",
        combined,
    ))

    # 4. Clean policy check (PASS)
    cmd = [
        python, "-m", "policy_engine.cli", "check",
        "--policy", "policy.yaml",
        "--scan", "tests/fixtures/trivy-clean.json",
        "--sbom", "tests/fixtures/syft-sbom-clean.json",
        "--secrets", "tests/fixtures/gitleaks-clean.json",
    ]
    out, code = run(cmd)
    display = (
        "python -m policy_engine.cli check --policy policy.yaml "
        "--scan tests/fixtures/trivy-clean.json "
        "--sbom tests/fixtures/syft-sbom-clean.json "
        "--secrets tests/fixtures/gitleaks-clean.json"
    )
    panels.append((
        "04-policy-check-pass",
        "supply-chain-security-pipeline — policy check (clean artifact)",
        render_block(display, out, code),
    ))

    # 5. Violating policy check (FAIL) + exit code
    cmd = [
        python, "-m", "policy_engine.cli", "check",
        "--policy", "policy.yaml",
        "--scan", "tests/fixtures/trivy-critical.json",
        "--sbom", "tests/fixtures/syft-sbom-denied-license.json",
        "--secrets", "tests/fixtures/gitleaks-findings.json",
    ]
    out, code = run(cmd)
    display = (
        "python -m policy_engine.cli check --policy policy.yaml "
        "--scan tests/fixtures/trivy-critical.json "
        "--sbom tests/fixtures/syft-sbom-denied-license.json "
        "--secrets tests/fixtures/gitleaks-findings.json"
    )
    block = render_block(display, out, code)
    panels.append((
        "05-policy-check-fail",
        "supply-chain-security-pipeline — policy check (vulnerable artifact)",
        block,
    ))

    # 6. Commit history
    out, code = run(["git", "log", "--oneline", "--no-decorate"])
    panels.append((
        "06-commit-history",
        "supply-chain-security-pipeline — git log",
        render_block("git log --oneline --no-decorate", out, code),
    ))

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1100, "height": 900})
        for filename, title, body in panels:
            html_content = TEMPLATE.format(title=html.escape(title), body=body)
            tmp_html = OUT_DIR / f"_{filename}.html"
            tmp_html.write_text(html_content, encoding="utf-8")
            page.goto(f"file://{tmp_html}")
            page.wait_for_timeout(100)
            target = OUT_DIR / f"{filename}.png"
            page.locator(".window").screenshot(path=str(target))
            tmp_html.unlink()
            print(f"wrote {target}")
        browser.close()


if __name__ == "__main__":
    sys.exit(main())
