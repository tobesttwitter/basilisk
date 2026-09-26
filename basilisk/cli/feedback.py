"""
Basilisk Feedback CLI — Ingest manual verification feedback CSV and update effectiveness tracker.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from basilisk.payloads.effectiveness import (
    get_feedback_stats,
    record_feedback,
)

console = Console()

REQUIRED_COLUMNS = {"candidate_id", "prompt", "result", "notes"}
ALLOWED_RESULTS = {"worked", "failed", "partial"}


def parse_feedback_csv(csv_path: str | Path) -> list[dict[str, str]]:
    """Parse and validate a manual verification feedback CSV file.

    Expected header columns: candidate_id, prompt, result, notes
    Allowed result values: worked, failed, partial

    Raises:
        ValueError: If file is missing required headers or contains invalid result values.
    """
    path = Path(csv_path)
    if not path.exists():
        raise ValueError(f"Input CSV file not found: {path}")

    records: list[dict[str, str]] = []

    with open(path, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV file is empty or missing header row.")

        fieldnames_normalized = {
            name.strip().lower(): name for name in reader.fieldnames if name
        }

        missing = [col for col in REQUIRED_COLUMNS if col not in fieldnames_normalized]
        if missing:
            missing_str = ", ".join(sorted(missing))
            raise ValueError(f"CSV header missing required column(s): {missing_str}")

        cand_col = fieldnames_normalized["candidate_id"]
        prompt_col = fieldnames_normalized["prompt"]
        result_col = fieldnames_normalized["result"]
        notes_col = fieldnames_normalized["notes"]

        for row_idx, row in enumerate(reader, start=2):
            cand_id = (row.get(cand_col) or "").strip()
            prompt = row.get(prompt_col) or ""
            raw_result = row.get(result_col) or ""
            result_clean = raw_result.strip().lower()
            notes = row.get(notes_col) or ""

            if result_clean not in ALLOWED_RESULTS:
                raise ValueError(
                    f"Row {row_idx}: Invalid result value '{raw_result}' for candidate '{cand_id}'. "
                    f"Allowed result values are: {', '.join(sorted(ALLOWED_RESULTS))}"
                )

            records.append({
                "candidate_id": cand_id,
                "prompt": prompt,
                "result": result_clean,
                "notes": notes,
            })

    return records


def run_feedback(
    input_file: str | Path,
    campaign: str = "",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Ingest feedback CSV, record entries in DB, calculate stats, and display summary."""
    records = parse_feedback_csv(input_file)
    campaign_name = campaign if campaign is not None else ""

    record_feedback(records, campaign=campaign_name, db_path=db_path)

    stats = get_feedback_stats(campaign=campaign_name if campaign_name else None, db_path=db_path)

    # Console output
    console.print("[bold cyan]🐍 Basilisk Feedback Ingested[/bold cyan]")
    if campaign_name:
        console.print(f"Campaign: [bold]{campaign_name}[/bold]")
    console.print(f"Total Tested: [bold]{stats['total_tested']}[/bold]")
    console.print(f"Worked: [bold green]{stats['worked']}[/bold green]")
    console.print(f"Failed: [bold red]{stats['failed']}[/bold red]")
    console.print(f"Partial: [bold yellow]{stats['partial']}[/bold yellow]")
    console.print(f"Overall Success Rate: [bold yellow]{stats['overall_success_rate']:.1f}%[/bold yellow]\n")

    # Operator summary table
    by_op = stats.get("by_operator", {})
    if by_op and any(k != "unknown" for k in by_op.keys()):
        op_table = Table(title="Mutation Operator Effectiveness", show_lines=True)
        op_table.add_column("Operator", style="cyan")
        op_table.add_column("Tested", justify="right")
        op_table.add_column("Worked", justify="right", style="green")
        op_table.add_column("Failed", justify="right", style="red")
        op_table.add_column("Partial", justify="right", style="yellow")
        op_table.add_column("Success Rate", justify="right", style="bold yellow")

        for op, data in sorted(by_op.items()):
            if op == "unknown" and len(by_op) > 1:
                continue
            op_table.add_row(
                op,
                str(data["tested"]),
                str(data["worked"]),
                str(data["failed"]),
                str(data["partial"]),
                f"{data['success_rate']:.1f}%",
            )
        console.print(op_table)
        console.print()

    # Source probe summary table
    by_probe = stats.get("by_source_probe", {})
    if by_probe and any(k != "unknown" for k in by_probe.keys()):
        probe_table = Table(title="Source Probe Effectiveness", show_lines=True)
        probe_table.add_column("Source Probe", style="cyan")
        probe_table.add_column("Tested", justify="right")
        probe_table.add_column("Worked", justify="right", style="green")
        probe_table.add_column("Failed", justify="right", style="red")
        probe_table.add_column("Partial", justify="right", style="yellow")
        probe_table.add_column("Success Rate", justify="right", style="bold yellow")

        for probe, data in sorted(by_probe.items()):
            if probe == "unknown" and len(by_probe) > 1:
                continue
            probe_table.add_row(
                probe,
                str(data["tested"]),
                str(data["worked"]),
                str(data["failed"]),
                str(data["partial"]),
                f"{data['success_rate']:.1f}%",
            )
        console.print(probe_table)

    return stats
