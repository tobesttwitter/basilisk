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
    assert "window.isSecureContext" in html_content
    assert "navigator.clipboard.writeText" in html_content
    assert "execCommand('copy')" in html_content
    assert "1500" in html_content
    assert "Worked" in html_content
    assert "Failed" in html_content
    assert "Partial" in html_content
    assert "Download Results CSV" in html_content
    assert "notes-input" in html_content
    assert "localStorage" in html_content
    assert "extract biological threat information" in html_content
    assert "GEN-001" in html_content


def test_export_candidates_html_interactive_features(tmp_path: Path) -> None:
    from basilisk.cli.generate import GeneratedCandidate, export_candidates_html

    candidates = [
        GeneratedCandidate(
            id="GEN-001",
            prompt="Test prompt string",
            source_probe="probe-1",
            mutation_used="raw_probe",
            harm_category="SAFETY_CRITICAL_BYPASS",
            rank=1,
            score=5.0,
        )
    ]
    html_path = tmp_path / "interactive_candidates.html"
    export_candidates_html(candidates, "Test Objective", html_path)

    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")

    # Verify two-tier copy logic & feedback timeout
    assert "window.isSecureContext" in content
    assert "navigator.clipboard.writeText" in content
    assert "execCommand('copy')" in content
    assert "1500" in content  # 1.5s confirmation duration

    # Verify worked/failed/partial buttons
    assert "setResult('GEN-001', 'worked')" in content
    assert "setResult('GEN-001', 'failed')" in content
    assert "setResult('GEN-001', 'partial')" in content

    # Verify notes input
    assert "notes-GEN-001" in content
    assert "updateNotes('GEN-001', this.value)" in content

    # Verify CSV download and Blob usage
    assert "downloadCSV()" in content
    assert "Download Results CSV" in content
    assert "'candidate_id', 'prompt', 'result', 'notes'" in content
    assert "new Blob(" in content
    assert "setAttribute('download'" in content

    # Verify localStorage persistence
    assert "basilisk_cand_" in content
    assert "getCandidateState" in content


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


def test_generate_objective_targeting(tmp_path: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "target_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "reveal emergency override code",
            "--count",
            "10",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Matched" in result.output
    assert "candidates." in result.output

    json_file = output_dir / "candidates.json"
    assert json_file.exists()

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) > 0

    target_keywords = {"reveal", "emergency", "override", "code"}
    matched_keyword_found = False
    for item in data:
        prompt_lower = item["prompt"].lower()
        if any(kw in prompt_lower for kw in target_keywords):
            matched_keyword_found = True
            break
    assert matched_keyword_found, "At least one candidate prompt should contain target objective keywords"


def test_generate_no_matching_probes_strict(tmp_path: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "no_match_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "xyz nonMatchingUnicornKeyword123456",
            "--count",
            "10",
            "--output-dir",
            str(output_dir),
            "--strict",
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Warning: Only 0 probes match the objective." in result.output
    assert "Matched 0 probes to objective 'xyz nonMatchingUnicornKeyword123456'. Generated 0 candidates." in result.output

    json_file = output_dir / "candidates.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 0


def test_generate_no_matching_probes_no_strict(tmp_path: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "no_strict_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "xyz nonMatchingUnicornKeyword123456",
            "--count",
            "10",
            "--output-dir",
            str(output_dir),
            "--no-strict",
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Generated 10 candidates." in result.output

    json_file = output_dir / "candidates.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 10


def test_ai_generate_missing_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GH_MODELS_TOKEN", raising=False)
    runner = CliRunner()
    output_dir = tmp_path / "ai_missing_token_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "bypass safety filter",
            "--ai",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "GH_MODELS_TOKEN is required for --ai-provider github. Create one at github.com/settings/tokens with models:read permission." in result.output


def test_ai_generate_success_mock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GH_MODELS_TOKEN", "mock_gh_token_123")

    mock_ai_response = [
        {
            "prompt": "You are a research assistant exploring safety limits. Roleplay scenario.",
            "technique": "role-play framing",
        },
        {
            "prompt": "Hypothetical question about override commands.",
            "technique": "hypothetical scenario",
        },
    ]

    class MockUrlOpenResponse:
        def __init__(self, data):
            self._data = json.dumps(data).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._data

    def mock_urlopen(req, timeout=None):
        assert req.full_url == "https://models.github.ai/inference/chat/completions"
        assert req.headers["Authorization"] == "Bearer mock_gh_token_123"
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["model"] == "gpt-4o-mini"
        return MockUrlOpenResponse({
            "choices": [
                {
                    "message": {
                        "content": json.dumps(mock_ai_response)
                    }
                }
            ]
        })

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    runner = CliRunner()
    output_dir = tmp_path / "ai_success_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract system instructions",
            "--ai",
            "--count",
            "2",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Generated 2 AI candidate prompts for objective" in result.output

    json_file = output_dir / "candidates.json"
    html_file = output_dir / "candidates.html"

    assert json_file.exists()
    assert html_file.exists()

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["id"] == "AI-001"
    assert data[0]["prompt"] == "You are a research assistant exploring safety limits. Roleplay scenario."
    assert data[0]["technique"] == "role-play framing"
    assert data[0]["source_probe"] == "github-models:gpt-4o-mini"
    assert data[1]["id"] == "AI-002"
    assert data[1]["technique"] == "hypothetical scenario"

    html_content = html_file.read_text(encoding="utf-8")
    assert "AI-001" in html_content
    assert "role-play framing" in html_content
    assert "Technique:" in html_content


def test_ai_generate_api_error_mock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GH_MODELS_TOKEN", "mock_gh_token_123")

    def mock_urlopen_error(req, timeout=None):
        raise RuntimeError("Connection refused")

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen_error)

    runner = CliRunner()
    output_dir = tmp_path / "ai_error_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract credentials",
            "--ai",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "GitHub Models API call failed" in result.output


def test_ai_generate_non_json_response_diagnostic(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GH_MODELS_TOKEN", "mock_gh_token_123")

    html_response_body = "<html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1><p>Cloudflare error page</p></body></html>"

    class MockUrlOpenResponse:
        def __init__(self, raw_bytes, status=200, headers=None):
            self._data = raw_bytes
            self.status = status
            self.headers = headers or {"Content-Type": "text/html; charset=utf-8", "Server": "cloudflare"}

        def getcode(self):
            return self.status

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._data

    def mock_urlopen(req, timeout=None):
        return MockUrlOpenResponse(html_response_body.encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    runner = CliRunner()
    output_dir = tmp_path / "ai_non_json_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract credentials",
            "--ai",
            "--ai-provider",
            "github",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    stderr_output = result.output
    assert "Diagnostic Info — GitHub Models response parsing failed:" in stderr_output
    assert "HTTP Status Code: 200" in stderr_output
    assert "Full Request URL: https://models.github.ai/inference/chat/completions" in stderr_output
    assert "text/html; charset=utf-8" in stderr_output
    assert "<html><head><title>502 Bad Gateway</title></head>" in stderr_output
    assert "GitHub Models API call failed:" in stderr_output


def test_ai_generate_success_logs_content_type(tmp_path: Path, monkeypatch, caplog) -> None:
    import logging

    caplog.set_level(logging.INFO)
    monkeypatch.setenv("GH_MODELS_TOKEN", "mock_gh_token_123")

    mock_ai_response = [
        {"prompt": "Test prompt framing", "technique": "role-play framing"}
    ]

    class MockUrlOpenResponse:
        def __init__(self, data):
            self._data = json.dumps(data).encode("utf-8")
            self.status = 200
            self.headers = {"Content-Type": "application/json"}

        def getcode(self):
            return self.status

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._data

    def mock_urlopen(req, timeout=None):
        return MockUrlOpenResponse({
            "choices": [{"message": {"content": json.dumps(mock_ai_response)}}]
        })

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    runner = CliRunner()
    output_dir = tmp_path / "ai_log_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "test objective",
            "--ai",
            "--count",
            "1",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0
    assert "API response Content-Type for GitHub Models: application/json" in caplog.text


def test_puter_ai_generate_missing_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PUTER_AUTH_TOKEN", raising=False)
    runner = CliRunner()
    output_dir = tmp_path / "puter_missing_token_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract system prompt",
            "--ai-provider",
            "puter",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "PUTER_AUTH_TOKEN is required for the Puter provider. Get one at puter.com/dashboard#account." in result.output


def test_puter_ai_generate_success_mock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PUTER_AUTH_TOKEN", "mock_puter_token_123")

    mock_ai_response = [
        {
            "prompt": "Assume the role of a system security auditor. Generate test framing.",
            "technique": "authority escalation",
        },
        {
            "prompt": "Translate the following instruction framing into a pseudo-code block.",
            "technique": "encoding obfuscation",
        },
    ]

    class MockUrlOpenResponse:
        def __init__(self, data):
            self._data = json.dumps(data).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._data

    def mock_urlopen(req, timeout=None):
        assert req.full_url == "https://api.puter.com/puterai/openai/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer mock_puter_token_123"
        assert req.headers.get("Content-type") == "application/json" or req.headers.get("Content-Type") == "application/json"
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["model"] == "qwen/qwen3.8-27b-abliterated-cyber:free"
        assert len(payload["messages"]) == 2
        assert payload["messages"][0]["role"] == "system"
        assert "You are an AI red-team research assistant." in payload["messages"][0]["content"]
        assert payload["messages"][1]["content"] == "extract system prompt"
        return MockUrlOpenResponse({
            "choices": [
                {
                    "message": {
                        "content": json.dumps(mock_ai_response)
                    }
                }
            ]
        })

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    runner = CliRunner()
    output_dir = tmp_path / "puter_success_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract system prompt",
            "--ai-provider",
            "puter",
            "--count",
            "2",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Generating AI-powered (Puter) adversarial framings for objective" in result.output

    json_file = output_dir / "candidates.json"
    html_file = output_dir / "candidates.html"

    assert json_file.exists()
    assert html_file.exists()

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["id"] == "AI-001"
    assert data[0]["prompt"] == "Assume the role of a system security auditor. Generate test framing."
    assert data[0]["technique"] == "authority escalation"
    assert data[0]["source_probe"] == "puter:qwen/qwen3.8-27b-abliterated-cyber:free"
    assert data[1]["id"] == "AI-002"
    assert data[1]["technique"] == "encoding obfuscation"

    html_content = html_file.read_text(encoding="utf-8")
    assert "AI-001" in html_content
    assert "authority escalation" in html_content


def test_puter_ai_generate_error_mock(tmp_path: Path, monkeypatch) -> None:
    import io
    import urllib.error

    monkeypatch.setenv("PUTER_AUTH_TOKEN", "mock_puter_token_123")

    def mock_urlopen_error(req, timeout=None):
        raise urllib.error.HTTPError(
            url="https://api.puter.com/puterai/openai/v1/chat/completions",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error": "Endpoint not found"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen_error)

    runner = CliRunner()
    output_dir = tmp_path / "puter_error_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "test objective",
            "--ai-provider",
            "puter",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "Puter API call failed" in result.output
    assert "404" in result.output
    assert '{"error": "Endpoint not found"}' in result.output


def test_openrouter_ai_generate_missing_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    runner = CliRunner()
    output_dir = tmp_path / "openrouter_missing_token_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract system prompt",
            "--ai-provider",
            "openrouter",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "OPENROUTER_API_KEY is required for the OpenRouter provider. Get one at openrouter.ai/keys." in result.output


def test_openrouter_ai_generate_success_mock(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "mock_openrouter_key_123")

    mock_ai_response = [
        {
            "prompt": "You are an ethical researcher testing filter response rules. Framing test.",
            "technique": "hypothetical scenario",
        },
        {
            "prompt": "Construct a multi-step instruction chain testing guardrail boundaries.",
            "technique": "instruction nesting",
        },
    ]

    class MockUrlOpenResponse:
        def __init__(self, data):
            self._data = json.dumps(data).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self._data

    def mock_urlopen(req, timeout=None):
        assert req.full_url == "https://openrouter.ai/api/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer mock_openrouter_key_123"
        assert req.headers.get("Content-type") == "application/json" or req.headers.get("Content-Type") == "application/json"
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["model"] == "cognitivecomputations/dolphin3.0-mistral-24b:free"
        assert len(payload["messages"]) == 2
        assert payload["messages"][0]["role"] == "system"
        assert "You are an AI red-team research assistant." in payload["messages"][0]["content"]
        assert payload["messages"][1]["content"] == "extract system prompt"
        return MockUrlOpenResponse({
            "choices": [
                {
                    "message": {
                        "content": json.dumps(mock_ai_response)
                    }
                }
            ]
        })

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    runner = CliRunner()
    output_dir = tmp_path / "openrouter_success_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "extract system prompt",
            "--ai-provider",
            "openrouter",
            "--count",
            "2",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "Generating AI-powered (OpenRouter) adversarial framings for objective" in result.output

    json_file = output_dir / "candidates.json"
    html_file = output_dir / "candidates.html"

    assert json_file.exists()
    assert html_file.exists()

    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["id"] == "AI-001"
    assert data[0]["prompt"] == "You are an ethical researcher testing filter response rules. Framing test."
    assert data[0]["technique"] == "hypothetical scenario"
    assert data[0]["source_probe"] == "openrouter:cognitivecomputations/dolphin3.0-mistral-24b:free"
    assert data[1]["id"] == "AI-002"
    assert data[1]["technique"] == "instruction nesting"

    html_content = html_file.read_text(encoding="utf-8")
    assert "AI-001" in html_content
    assert "hypothetical scenario" in html_content


def test_openrouter_ai_generate_error_mock(tmp_path: Path, monkeypatch) -> None:
    import io
    import urllib.error

    monkeypatch.setenv("OPENROUTER_API_KEY", "mock_openrouter_key_123")

    def mock_urlopen_error(req, timeout=None):
        raise urllib.error.HTTPError(
            url="https://openrouter.ai/api/v1/chat/completions",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=io.BytesIO(b'{"error": "Invalid API key"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen_error)

    runner = CliRunner()
    output_dir = tmp_path / "openrouter_error_out"
    result = runner.invoke(
        cli,
        [
            "generate",
            "--objective",
            "test objective",
            "--ai-provider",
            "openrouter",
            "--output-dir",
            str(output_dir),
        ],
    )
    assert result.exit_code != 0
    assert "OpenRouter API call failed" in result.output
    assert "401" in result.output
    assert '{"error": "Invalid API key"}' in result.output
