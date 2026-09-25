"""
Tests for Baseline Regression Detection Engine and CLI integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from basilisk.core.config import BasiliskConfig
from basilisk.core.finding import AttackCategory, Finding, Severity
from basilisk.core.session import ScanSession
from basilisk.runtime.baseline import (
    BaselineDiff,
    BaselineFinding,
    compare_baseline,
    load_baseline_report,
    normalize_current_findings,
    print_baseline_diff_summary,
)


def _make_finding(id_suffix: str, module: str, title: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"BSLK-2026-{id_suffix}",
        title=title,
        severity=severity,
        category=AttackCategory.PROMPT_INJECTION,
        attack_module=module,
        payload="test payload",
        response="test response",
    )


def test_load_baseline_json_report(tmp_path: Path):
    baseline_file = tmp_path / "baseline_report.json"
    data = {
        "findings": [
            {
                "id": "BSLK-2026-001",
                "title": "Prompt Injection in Chat",
                "severity": "high",
                "category": "prompt_injection",
                "attack_module": "basilisk.attacks.injection.direct",
                "payload": "disregard rules",
            },
            {
                "id": "BSLK-2026-002",
                "title": "System Prompt Leakage",
                "severity": "medium",
                "category": "prompt_injection",
                "attack_module": "basilisk.attacks.extraction.system_prompt",
                "payload": "print prompt",
            },
        ]
    }
    baseline_file.write_text(json.dumps(data), encoding="utf-8")

    findings = load_baseline_report(baseline_file)
    assert len(findings) == 2
    assert findings[0].identity == "basilisk.attacks.injection.direct:Prompt Injection in Chat"
    assert findings[1].identity == "basilisk.attacks.extraction.system_prompt:System Prompt Leakage"


def test_load_baseline_sarif_report(tmp_path: Path):
    sarif_file = tmp_path / "baseline.sarif"
    data = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "BSLK/injection/direct",
                        "message": {"text": "Direct Prompt Injection\n\nDetails..."},
                        "properties": {
                            "attack_module": "basilisk.attacks.injection.direct",
                            "severity": "high",
                            "category": "prompt_injection",
                        },
                        "fingerprints": {
                            "basilisk/v1": "basilisk.attacks.injection.direct:Direct Prompt Injection",
                        },
                    }
                ]
            }
        ],
    }
    sarif_file.write_text(json.dumps(data), encoding="utf-8")

    findings = load_baseline_report(sarif_file)
    assert len(findings) == 1
    assert findings[0].identity == "basilisk.attacks.injection.direct:Direct Prompt Injection"
    assert findings[0].title == "Direct Prompt Injection"


def test_baseline_diff_new_and_resolved(tmp_path: Path):
    baseline_file = tmp_path / "baseline.json"
    data = {
        "findings": [
            {
                "id": "BSLK-2026-001",
                "title": "Old Finding A",
                "severity": "high",
                "attack_module": "basilisk.attacks.mod_a",
            },
            {
                "id": "BSLK-2026-002",
                "title": "Shared Finding B",
                "severity": "medium",
                "attack_module": "basilisk.attacks.mod_b",
            },
        ]
    }
    baseline_file.write_text(json.dumps(data), encoding="utf-8")

    current_findings = [
        _make_finding("002", "basilisk.attacks.mod_b", "Shared Finding B", Severity.MEDIUM),
        _make_finding("003", "basilisk.attacks.mod_c", "New Finding C", Severity.HIGH),
    ]

    diff = compare_baseline(current_findings, baseline_file)
    assert diff.has_regressions is True
    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].title == "New Finding C"

    assert len(diff.resolved_findings) == 1
    assert diff.resolved_findings[0].title == "Old Finding A"

    assert len(diff.unchanged_findings) == 1
    assert diff.unchanged_findings[0].title == "Shared Finding B"


def test_baseline_diff_no_regressions(tmp_path: Path):
    baseline_file = tmp_path / "baseline.json"
    data = {
        "findings": [
            {
                "id": "BSLK-2026-001",
                "title": "Shared Finding A",
                "severity": "high",
                "attack_module": "basilisk.attacks.mod_a",
            },
            {
                "id": "BSLK-2026-002",
                "title": "Shared Finding B",
                "severity": "medium",
                "attack_module": "basilisk.attacks.mod_b",
            },
        ]
    }
    baseline_file.write_text(json.dumps(data), encoding="utf-8")

    current_findings = [
        _make_finding("001", "basilisk.attacks.mod_a", "Shared Finding A", Severity.HIGH),
    ]

    diff = compare_baseline(current_findings, baseline_file)
    assert diff.has_regressions is False
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 1
    assert len(diff.unchanged_findings) == 1


def test_print_baseline_diff_summary(capsys):
    diff = BaselineDiff(
        new_findings=[
            BaselineFinding(
                identity="mod1:New Finding",
                title="New Finding",
                severity="high",
                category="prompt_injection",
                attack_module="mod1",
            )
        ],
        resolved_findings=[
            BaselineFinding(
                identity="mod2:Fixed Finding",
                title="Fixed Finding",
                severity="medium",
                category="prompt_injection",
                attack_module="mod2",
            )
        ],
        unchanged_findings=[],
        baseline_path="baseline.json",
        total_baseline=1,
        total_current=1,
    )

    print_baseline_diff_summary(diff)
    captured = capsys.readouterr().out
    assert "REGRESSION DETECTED" in captured
    assert "New Finding" in captured
    assert "Fixed Finding" in captured


@pytest.mark.asyncio
async def test_run_scan_with_baseline_regression(tmp_path: Path):
    from basilisk.cli.scan import run_scan

    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"findings": []}), encoding="utf-8")

    cfg = BasiliskConfig.from_cli_args(
        target="http://localhost/chat", provider="mock", output_dir=str(tmp_path)
    )

    with (
        patch("basilisk.cli.scan.BasiliskConfig.from_cli_args", return_value=cfg),
        patch("basilisk.cli.scan.execute_scan", new_callable=AsyncMock) as mock_exec,
        patch("basilisk.report.generator.generate_report", new_callable=AsyncMock, return_value=str(tmp_path / "report.json")),
    ):
        async def fake_execute(cfg, session, **kwargs):
            await session.add_finding(_make_finding("100", "mod_new", "Regression Finding"))

        mock_exec.side_effect = fake_execute

        exit_code = await run_scan(
            target="http://localhost/chat",
            provider="mock",
            output_dir=str(tmp_path),
            baseline=str(baseline_file),
        )

        assert exit_code == 1


@pytest.mark.asyncio
async def test_run_scan_with_baseline_no_regression(tmp_path: Path):
    from basilisk.cli.scan import run_scan

    baseline_file = tmp_path / "baseline.json"
    baseline_data = {
        "findings": [
            {
                "id": "BSLK-2026-100",
                "title": "Known Finding",
                "severity": "high",
                "attack_module": "mod_known",
            }
        ]
    }
    baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

    cfg = BasiliskConfig.from_cli_args(
        target="http://localhost/chat", provider="mock", output_dir=str(tmp_path)
    )

    with (
        patch("basilisk.cli.scan.BasiliskConfig.from_cli_args", return_value=cfg),
        patch("basilisk.cli.scan.execute_scan", new_callable=AsyncMock) as mock_exec,
        patch("basilisk.report.generator.generate_report", new_callable=AsyncMock, return_value=str(tmp_path / "report.json")),
    ):
        async def fake_execute(cfg, session, **kwargs):
            await session.add_finding(_make_finding("100", "mod_known", "Known Finding"))

        mock_exec.side_effect = fake_execute

        exit_code = await run_scan(
            target="http://localhost/chat",
            provider="mock",
            output_dir=str(tmp_path),
            baseline=str(baseline_file),
        )

        assert exit_code == 0
