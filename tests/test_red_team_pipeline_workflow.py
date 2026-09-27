from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_red_team_pipeline_workflow_file_exists_and_valid() -> None:
    workflow_path = ROOT / ".github/workflows/red-team-pipeline.yml"
    assert workflow_path.exists(), "red-team-pipeline.yml workflow file must exist"

    text = workflow_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    assert data["name"] == "Offline Red-Teaming Pipeline"
    on_block = data.get("on") or data.get(True)
    assert "workflow_dispatch" in on_block

    inputs = on_block["workflow_dispatch"]["inputs"]
    assert "command" in inputs
    assert inputs["command"]["required"] is True
    assert inputs["command"]["type"] == "choice"
    assert set(inputs["command"]["options"]) == {"generate", "feedback", "evolve", "report"}

    assert "objective" in inputs
    assert "campaign" in inputs
    assert "count" in inputs
    assert inputs["count"]["default"] == "50"
    assert "report_format" in inputs
    assert inputs["report_format"]["default"] == "markdown"

    assert 'basilisk generate --objective "${{ inputs.objective }}" --count ${{ inputs.count }} --output-dir generate_output' in text
    assert 'basilisk feedback --input feedback/${{ inputs.campaign }}.csv --campaign ${{ inputs.campaign }}' in text
    assert 'basilisk evolve-interactive --campaign ${{ inputs.campaign }} --count ${{ inputs.count }} --output-dir generate_output' in text
    assert 'basilisk report --campaign ${{ inputs.campaign }} --format ${{ inputs.report_format }} --output-dir reports' in text

    assert 'if: always()' in text
    assert 'generate_output/' in text
    assert 'reports/' in text


def test_feedback_directory_structure_and_readme() -> None:
    feedback_dir = ROOT / "feedback"
    assert feedback_dir.is_dir(), "feedback directory must exist"

    gitkeep = feedback_dir / ".gitkeep"
    assert gitkeep.exists(), "feedback/.gitkeep must exist"

    readme = feedback_dir / "README.md"
    assert readme.exists(), "feedback/README.md must exist"

    text = readme.read_text(encoding="utf-8")
    assert "candidate_id,prompt,result,notes" in text
    assert "worked" in text
    assert "failed" in text
    assert "partial" in text


def test_readme_documents_offline_red_teaming_pipeline() -> None:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")

    assert "## Running Offline Red-Teaming Pipeline" in text
    assert "generate" in text
    assert "feedback" in text
    assert "evolve" in text
    assert "report" in text
    assert "candidate_id,prompt,result,notes" in text
