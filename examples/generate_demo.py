#!/usr/bin/env python3
"""
Basilisk Demo Report Generator — Client-Ready Sample Report Script.

Loads a mock scan session JSON file and generates executive HTML and
Markdown reports for sales and marketing demonstrations.

Usage:
  python3 examples/generate_demo.py [--report-type executive]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure root directory is on sys.path so basilisk can be imported
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from basilisk.core.config import BasiliskConfig
from basilisk.core.finding import Finding
from basilisk.core.profile import BasiliskProfile
from basilisk.core.session import ScanSession
from basilisk.report.generator import _write_markdown_report
from basilisk.report.html import generate_html


def load_mock_session(json_path: Path, report_type: str = "executive") -> ScanSession:
    """Load session data from a mock JSON file and instantiate ScanSession."""
    if not json_path.exists():
        raise FileNotFoundError(f"Mock session file not found at: {json_path}")

    data = json.loads(json_path.read_text(encoding="utf-8"))

    # Load configuration
    config_dict = data.get("config", {})
    config = BasiliskConfig.from_dict(config_dict)
    config.output.report_type = report_type
    config.output.include_raw_content = True
    config.output.include_conversations = True
    config.output.output_dir = str(SCRIPT_DIR)

    # Instantiate ScanSession
    session_id = data.get("id", "demo-session-2026")
    session = ScanSession(config, session_id=session_id)

    if data.get("status"):
        session.status = data["status"]
    if data.get("started_at"):
        session.started_at = datetime.fromisoformat(data["started_at"])
    if data.get("finished_at"):
        session.finished_at = datetime.fromisoformat(data["finished_at"])

    # Load profile
    if data.get("profile"):
        session.profile = BasiliskProfile.from_dict(data["profile"])

    # Load findings
    for finding_dict in data.get("findings", []):
        finding = Finding.from_dict(finding_dict)
        session.findings.append(finding)

    return session


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate client-ready sample reports from mock session data."
    )
    parser.add_argument(
        "--report-type",
        default="executive",
        choices=["executive", "standard"],
        help="Report style layout (default: executive)",
    )
    parser.add_argument(
        "--input",
        default=str(SCRIPT_DIR / "mock_session.json"),
        help="Path to mock session JSON file",
    )
    args = parser.parse_args()

    mock_json_path = Path(args.input).resolve()
    print(f"Loading mock session from {mock_json_path}...")

    session = load_mock_session(mock_json_path, report_type=args.report_type)

    # Output paths required by specifications
    html_output_path = SCRIPT_DIR / "sample_executive_report.html"
    md_output_path = SCRIPT_DIR / "sample_executive_report.md"

    print(f"Generating HTML report ({args.report_type} mode)...")
    generate_html(
        session,
        html_output_path,
        include_raw_content=True,
        include_conversations=True,
    )
    print(f"✓ HTML report generated: {html_output_path}")

    print(f"Generating Markdown report ({args.report_type} mode)...")
    _write_markdown_report(
        session,
        md_output_path,
        include_raw=True,
        include_conversations=True,
    )
    print(f"✓ Markdown report generated: {md_output_path}")

    print("\nSample client reports generated successfully!")


if __name__ == "__main__":
    main()
