"""
Unit tests for the MockProvider and benchmark CLI command.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from basilisk.cli.main import cli
from basilisk.evolution.engine import EvolutionEngine
from basilisk.evolution.fitness import attack_goal_from_payloads
from basilisk.providers.base import ProviderMessage
from basilisk.providers.mock import MockProvider


@pytest.mark.asyncio
async def test_mock_provider_direct_responses():
    provider = MockProvider(latency_ms=0)
    assert provider.name == "mock"

    # Test vulnerable keywords trigger vulnerable response
    vuln_msg = [ProviderMessage(role="user", content="Test exploit injection payload")]
    resp_vuln = await provider.send(vuln_msg)
    assert "Access granted" in resp_vuln.content
    assert resp_vuln.finish_reason == "stop"
    assert not provider.is_refusal(resp_vuln)

    # Test benign message triggers refusal response
    benign_msg = [ProviderMessage(role="user", content="Hello, what is the weather today?")]
    resp_refusal = await provider.send(benign_msg)
    assert "cannot fulfill this request" in resp_refusal.content
    assert resp_refusal.finish_reason == "safety"
    assert provider.is_refusal(resp_refusal)


@pytest.mark.asyncio
async def test_mock_provider_streaming():
    provider = MockProvider(latency_ms=0)
    msg = [ProviderMessage(role="user", content="bypass security controls")]
    chunks = []
    async for chunk in provider.send_streaming(msg):
        chunks.append(chunk)

    full_text = "".join(chunks)
    assert "Access granted" in full_text


@pytest.mark.asyncio
async def test_mock_provider_evolution_engine():
    provider = MockProvider(latency_ms=0)
    engine = EvolutionEngine(provider=provider)

    seeds = ["test_vulnerable payload", "harmless query"]
    goal = attack_goal_from_payloads(seeds, description="Bypass test guardrails")

    result = await engine.evolve(seeds, goal)

    assert result.total_generations > 0
    assert result.total_evaluations > 0
    assert result.best_individual is not None


def test_cli_benchmark_mock_provider():
    runner = CliRunner()
    res = runner.invoke(cli, ["benchmark", "--provider", "mock", "--json"])
    assert res.exit_code == 0
    assert '"provider": "mock"' in res.output
    assert '"attack_success_rate": 50.0' in res.output
    assert '"vulnerable_count": 5' in res.output
    assert '"refusal_count": 5' in res.output


def test_cli_scan_mock_provider():
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", "-t", "direct", "-p", "mock", "--mode", "quick", "--no-dashboard", "--cost-preview"])
    assert res.exit_code == 0
