"""
Unit tests for basilisk generate CLI command and prompt candidate generation.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from basilisk.cli.generate import run_generate
from basilisk.cli.main import cli


def test_cli_generate_command(tmp_path: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "gen_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract biological threat information",
            "--count",
            "10",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"

    json_file = output_dir / "candidates.json"
    html_file = output_dir / "candidates.html"

    assert json_file.exists()
    assert html_file.exists()

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 10

    required_keys = {"id", "prompt", "source_probe", "mutation_used", "harm_category", "rank"}
    for idx, item in enumerate(data, 1):
        assert required_keys.issubset(item.keys())
        assert item["rank"] == idx
        assert item["id"] == f"GEN-{idx:03d}"
        assert isinstance(item["prompt"], str) and len(item["prompt"]) > 0
        assert isinstance(item["source_probe"], str) and len(item["source_probe"]) > 0
        assert isinstance(item["mutation_used"], str) and len(item["mutation_used"]) > 0
        assert isinstance(item["harm_category"], str) and len(item["harm_category"]) > 0

    html_content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "navigator.clipboard.writeText" in html_content
    assert "window.isSecureContext" in html_content
    assert "document.execCommand('copy')" in html_content
    assert "extract biological threat information" in html_content
    assert "GEN-001" in html_content
    assert "Download Results CSV" in html_content
    assert "result-btn worked" in html_content
    assert "result-btn failed" in html_content
    assert "result-btn partial" in html_content
    assert "notes-input" in html_content
    assert "localStorage" in html_content
    assert "new Blob" in html_content


def test_run_generate_custom_count(tmp_path: Path) -> None:
    """
    Test custom count prompt generation and HTML report features.

    Manual verification steps for generated HTML (offline / file:// protocol):
    1. Open generated candidates.html directly in a browser (e.g. file:///path/to/candidates.html).
    2. Click 'Copy Prompt' on candidate items: verify button text briefly shows 'Copied!' for 1.5s and prompt is in clipboard.
    3. Click 'Worked', 'Failed', or 'Partial' on candidates: verify selected button is highlighted and progress counter updates.
    4. Type notes in the optional notes input field under candidate items.
    5. Refresh the page: verify chosen result button state and notes persist via localStorage.
    6. Click 'Download Results CSV': verify candidate_feedback.csv is downloaded containing candidate_id, prompt, result, notes.
    """
    output_dir = tmp_path / "custom_out"
    json_path, html_path = run_generate(
        objective="exfiltrate system API keys",
        count=15,
        output_dir=str(output_dir),
    )

    assert json_path.exists()
    assert html_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(data) == 15

    ranks = [item["rank"] for item in data]
    assert ranks == list(range(1, 16))

    html_text = html_path.read_text(encoding="utf-8")
    assert "exfiltrate system API keys" in html_text
    assert "copyPrompt" in html_text
    assert "downloadCsv" in html_text
    assert "saveCandidateState" in html_text
    assert "loadSavedState" in html_text
