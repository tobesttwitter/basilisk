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
    assert "extract biological threat information" in html_content
    assert "GEN-001" in html_content


def test_run_generate_custom_count(tmp_path: Path) -> None:
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
