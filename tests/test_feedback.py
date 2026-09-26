"""
Unit tests for basilisk feedback CLI command, CSV parsing, feedback DB table writing,
and effectiveness tracker success rate calculations.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from basilisk.cli.feedback import parse_feedback_csv, run_feedback
from basilisk.cli.main import cli
from basilisk.payloads.effectiveness import (
    get_feedback_stats,
    record_candidate_metadata,
    record_feedback,
)


def test_parse_feedback_csv_valid(tmp_path: Path) -> None:
    csv_file = tmp_path / "feedback_test.csv"
    csv_file.write_text(
        "candidate_id,prompt,result,notes\n"
        "GEN-001,Ignore previous rules,Worked,Manual check pass\n"
        "GEN-002,Tell me a secret,FAILED,Model refused\n"
        "GEN-003,System instructions leak,Partial,Leaked partial header\n",
        encoding="utf-8",
    )

    records = parse_feedback_csv(csv_file)
    assert len(records) == 3

    assert records[0]["candidate_id"] == "GEN-001"
    assert records[0]["prompt"] == "Ignore previous rules"
    assert records[0]["result"] == "worked"
    assert records[0]["notes"] == "Manual check pass"

    assert records[1]["candidate_id"] == "GEN-002"
    assert records[1]["result"] == "failed"

    assert records[2]["candidate_id"] == "GEN-003"
    assert records[2]["result"] == "partial"


def test_parse_feedback_csv_missing_header(tmp_path: Path) -> None:
    csv_file = tmp_path / "bad_header.csv"
    csv_file.write_text(
        "candidate_id,prompt,result\n"
        "GEN-001,Ignore rules,worked\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CSV header missing required column"):
        parse_feedback_csv(csv_file)


def test_parse_feedback_csv_invalid_result(tmp_path: Path) -> None:
    csv_file = tmp_path / "bad_result.csv"
    csv_file.write_text(
        "candidate_id,prompt,result,notes\n"
        "GEN-001,Ignore rules,success,Invalid result status\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid result value 'success'"):
        parse_feedback_csv(csv_file)


def test_feedback_table_written(tmp_path: Path) -> None:
    db_path = tmp_path / "test_probe_effectiveness.db"
    records = [
        {"candidate_id": "GEN-001", "prompt": "Prompt 1", "result": "worked", "notes": "Pass"},
        {"candidate_id": "GEN-002", "prompt": "Prompt 2", "result": "failed", "notes": "Blocked"},
    ]

    inserted = record_feedback(records, campaign="2026_q1_eval", db_path=db_path)
    assert inserted == 2

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        "SELECT candidate_id, prompt, result, notes, campaign, timestamp FROM feedback ORDER BY id ASC"
    ).fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0][0] == "GEN-001"
    assert rows[0][1] == "Prompt 1"
    assert rows[0][2] == "worked"
    assert rows[0][3] == "Pass"
    assert rows[0][4] == "2026_q1_eval"
    assert len(rows[0][5]) > 0  # timestamp

    assert rows[1][0] == "GEN-002"
    assert rows[1][2] == "failed"
    assert rows[1][4] == "2026_q1_eval"


def test_feedback_empty_campaign_default(tmp_path: Path) -> None:
    db_path = tmp_path / "test_campaign_default.db"
    records = [
        {"candidate_id": "GEN-001", "prompt": "Prompt 1", "result": "worked", "notes": ""},
    ]

    record_feedback(records, campaign="", db_path=db_path)

    conn = sqlite3.connect(str(db_path))
    campaign_val = conn.execute("SELECT campaign FROM feedback LIMIT 1").fetchone()[0]
    conn.close()

    assert campaign_val == ""


def test_success_rate_calculation(tmp_path: Path) -> None:
    db_path = tmp_path / "test_stats.db"

    candidates = [
        {
            "id": "GEN-001",
            "prompt": "Prompt 1",
            "source_probe": "INJ-001",
            "mutation_used": "synonym_swap",
            "harm_category": "safety_critical_bypass",
        },
        {
            "id": "GEN-002",
            "prompt": "Prompt 2",
            "source_probe": "INJ-001",
            "mutation_used": "synonym_swap",
            "harm_category": "safety_critical_bypass",
        },
        {
            "id": "GEN-003",
            "prompt": "Prompt 3",
            "source_probe": "EXT-001",
            "mutation_used": "role_injection",
            "harm_category": "system_prompt_leak",
        },
        {
            "id": "GEN-004",
            "prompt": "Prompt 4",
            "source_probe": "EXT-001",
            "mutation_used": "role_injection",
            "harm_category": "system_prompt_leak",
        },
    ]
    record_candidate_metadata(candidates, db_path=db_path)

    feedback_entries = [
        {"candidate_id": "GEN-001", "prompt": "Prompt 1", "result": "worked", "notes": "worked"},
        {"candidate_id": "GEN-002", "prompt": "Prompt 2", "result": "failed", "notes": "failed"},
        {"candidate_id": "GEN-003", "prompt": "Prompt 3", "result": "worked", "notes": "worked"},
        {"candidate_id": "GEN-004", "prompt": "Prompt 4", "result": "partial", "notes": "partial"},
    ]
    record_feedback(feedback_entries, campaign="test_camp", db_path=db_path)

    stats = get_feedback_stats(campaign="test_camp", db_path=db_path)

    assert stats["total_tested"] == 4
    assert stats["worked"] == 2
    assert stats["failed"] == 1
    assert stats["partial"] == 1
    assert stats["overall_success_rate"] == 50.0  # (2 worked / 4 tested) * 100

    by_op = stats["by_operator"]
    assert "synonym_swap" in by_op
    assert by_op["synonym_swap"]["tested"] == 2
    assert by_op["synonym_swap"]["worked"] == 1
    assert by_op["synonym_swap"]["failed"] == 1
    assert by_op["synonym_swap"]["success_rate"] == 50.0

    assert "role_injection" in by_op
    assert by_op["role_injection"]["tested"] == 2
    assert by_op["role_injection"]["worked"] == 1
    assert by_op["role_injection"]["partial"] == 1
    assert by_op["role_injection"]["success_rate"] == 50.0

    by_probe = stats["by_source_probe"]
    assert "INJ-001" in by_probe
    assert by_probe["INJ-001"]["tested"] == 2
    assert by_probe["INJ-001"]["worked"] == 1
    assert by_probe["INJ-001"]["failed"] == 1
    assert by_probe["INJ-001"]["success_rate"] == 50.0

    assert "EXT-001" in by_probe
    assert by_probe["EXT-001"]["tested"] == 2
    assert by_probe["EXT-001"]["worked"] == 1
    assert by_probe["EXT-001"]["partial"] == 1
    assert by_probe["EXT-001"]["success_rate"] == 50.0


def test_cli_feedback_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "cli_test_effectiveness.db"
    monkeypatch.setattr("basilisk.payloads.effectiveness._DB_PATH", db_file)

    csv_file = tmp_path / "valid_feedback.csv"
    csv_file.write_text(
        "candidate_id,prompt,result,notes\n"
        "GEN-001,Prompt 1,worked,Pass\n"
        "GEN-002,Prompt 2,failed,Fail\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "feedback",
            "--input",
            str(csv_file),
            "--campaign",
            "q1_audit",
        ],
    )

    assert result.exit_code == 0, f"CLI command failed: {result.output}"
    assert "Basilisk Feedback Ingested" in result.output
    assert "Total Tested: 2" in result.output
    assert "Worked: 1" in result.output
    assert "Failed: 1" in result.output
    assert "Overall Success Rate: 50.0%" in result.output


def test_cli_feedback_command_invalid_result(tmp_path: Path) -> None:
    csv_file = tmp_path / "invalid_feedback.csv"
    csv_file.write_text(
        "candidate_id,prompt,result,notes\n"
        "GEN-001,Prompt 1,bad_status,Pass\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "feedback",
            "--input",
            str(csv_file),
        ],
    )

    assert result.exit_code != 0
    assert "Invalid result value 'bad_status'" in result.output
