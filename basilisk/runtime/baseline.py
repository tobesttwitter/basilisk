"""
Basilisk Baseline Regression Engine — diff scan findings against a baseline report.

Supports comparing current scan findings against a previous SARIF or JSON report
to identify new findings (regressions), resolved findings, and unchanged findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


@dataclass
class BaselineFinding:
    """Normalized finding representation for baseline comparison."""

    identity: str
    title: str
    severity: str
    category: str
    attack_module: str
    payload_snippet: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class BaselineDiff:
    """Diff result comparing current scan findings against a baseline report."""

    new_findings: list[BaselineFinding]
    resolved_findings: list[BaselineFinding]
    unchanged_findings: list[BaselineFinding]
    baseline_path: str = ""
    total_baseline: int = 0
    total_current: int = 0

    @property
    def has_regressions(self) -> bool:
        return len(self.new_findings) > 0


def load_baseline_report(path: str | Path) -> list[BaselineFinding]:
    """Load findings from a SARIF or JSON baseline report."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline report file not found: {path}")

    content = p.read_text(encoding="utf-8")
    data = json.loads(content)

    findings: list[BaselineFinding] = []
    if isinstance(data, dict):
        if "runs" in data:  # SARIF format
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    props = result.get("properties", {})
                    fps = result.get("fingerprints", {})
                    rule_id = result.get("ruleId", "unknown")
                    msg_text = result.get("message", {}).get("text", "")
                    title = msg_text.split("\n")[0] if msg_text else rule_id

                    attack_module = props.get("attack_module", "") or rule_id
                    severity = props.get("severity", "") or _sarif_level_to_severity(
                        result.get("level", "warning")
                    )
                    category = props.get("category", "") or props.get("owasp_id", "")

                    fp_identity = fps.get("basilisk/v1") or f"{rule_id}:{title}"
                    findings.append(
                        BaselineFinding(
                            identity=fp_identity,
                            title=title,
                            severity=severity,
                            category=category,
                            attack_module=attack_module,
                            raw_data=result,
                        )
                    )
        elif "findings" in data:  # Basilisk JSON Report format
            for f in data.get("findings", []):
                module = f.get("attack_module", "")
                title = f.get("title", "")
                identity = (
                    f"{module}:{title}"
                    if (module and title)
                    else f.get("id", str(hash(json.dumps(f, sort_keys=True))))
                )
                findings.append(
                    BaselineFinding(
                        identity=identity,
                        title=title or f.get("id", "Untitled Finding"),
                        severity=f.get("severity", "info"),
                        category=f.get("category", "unknown"),
                        attack_module=module,
                        payload_snippet=str(f.get("payload", ""))[:100],
                        raw_data=f,
                    )
                )
    elif isinstance(data, list):  # Plain array of finding objects
        for f in data:
            module = f.get("attack_module", "")
            title = f.get("title", "")
            identity = (
                f"{module}:{title}"
                if (module and title)
                else f.get("id", str(hash(json.dumps(f, sort_keys=True))))
            )
            findings.append(
                BaselineFinding(
                    identity=identity,
                    title=title or f.get("id", "Untitled Finding"),
                    severity=f.get("severity", "info"),
                    category=f.get("category", "unknown"),
                    attack_module=module,
                    payload_snippet=str(f.get("payload", ""))[:100],
                    raw_data=f,
                )
            )

    return findings


def normalize_current_findings(current: Any) -> list[BaselineFinding]:
    """Convert ScanSession, report path, list of Finding objects, or list of dicts to BaselineFinding list."""
    if isinstance(current, (str, Path)):
        return load_baseline_report(current)
    if hasattr(current, "findings"):
        raw_list = current.findings
    elif isinstance(current, list):
        raw_list = current
    else:
        raw_list = []

    normalized: list[BaselineFinding] = []
    for f in raw_list:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        elif isinstance(f, dict):
            d = f
        else:
            continue

        module = d.get("attack_module", "")
        title = d.get("title", "")
        identity = (
            f"{module}:{title}"
            if (module and title)
            else d.get("id", str(hash(json.dumps(d, sort_keys=True))))
        )
        normalized.append(
            BaselineFinding(
                identity=identity,
                title=title or d.get("id", "Untitled Finding"),
                severity=d.get("severity", "info"),
                category=d.get("category", "unknown"),
                attack_module=module,
                payload_snippet=str(d.get("payload", ""))[:100],
                raw_data=d,
            )
        )

    return normalized


def compare_baseline(
    current: Any,
    baseline_report_path: str | Path,
    high_critical_only: bool = False,
) -> BaselineDiff:
    """Compare current findings against a baseline report and return the diff."""
    baseline_findings = load_baseline_report(baseline_report_path)
    current_findings = normalize_current_findings(current)

    if high_critical_only:
        def is_high_critical(bf: BaselineFinding) -> bool:
            harm_data = bf.raw_data.get("harm_assessment") if isinstance(bf.raw_data, dict) else None
            harm_sev = str(harm_data.get("severity", "") if isinstance(harm_data, dict) else "").lower()
            if harm_sev:
                return harm_sev in ("high", "critical")
            return bf.severity.lower() in ("high", "critical")

        baseline_findings = [f for f in baseline_findings if is_high_critical(f)]
        current_findings = [f for f in current_findings if is_high_critical(f)]

    baseline_map = {f.identity: f for f in baseline_findings}
    current_map = {f.identity: f for f in current_findings}

    new_findings = [f for key, f in current_map.items() if key not in baseline_map]
    resolved_findings = [f for key, f in baseline_map.items() if key not in current_map]
    unchanged_findings = [f for key, f in current_map.items() if key in baseline_map]

    return BaselineDiff(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_findings=unchanged_findings,
        baseline_path=str(baseline_report_path),
        total_baseline=len(baseline_findings),
        total_current=len(current_findings),
    )


def print_baseline_diff_summary(diff: BaselineDiff, console: Console | None = None) -> None:
    """Print a rich summary of the baseline regression check to the console."""
    if console is None:
        console = Console()

    status_style = "bold red" if diff.has_regressions else "bold green"
    status_text = (
        f"[{status_style}]REGRESSION DETECTED: {len(diff.new_findings)} new finding(s)[/{status_style}]"
        if diff.has_regressions
        else "[bold green]NO REGRESSIONS DETECTED[/bold green]"
    )

    console.print()
    console.print(
        Panel(
            f"[bold]Baseline Report:[/bold] {diff.baseline_path}\n"
            f"[bold]Baseline Findings:[/bold] {diff.total_baseline}\n"
            f"[bold]Current Findings:[/bold] {diff.total_current}\n"
            f"[bold]New Findings (Regressions):[/bold] {len(diff.new_findings)}\n"
            f"[bold]Resolved Findings:[/bold] {len(diff.resolved_findings)}\n"
            f"[bold]Unchanged Findings:[/bold] {len(diff.unchanged_findings)}\n\n"
            f"Status: {status_text}",
            title="📊 Baseline Regression Analysis",
            border_style="red" if diff.has_regressions else "green",
            padding=(1, 2),
        )
    )

    if diff.new_findings:
        table = Table(title="🚨 New Findings (Regressions)", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="white")
        table.add_column("Attack Module", style="cyan")

        for f in diff.new_findings:
            sev_style = _severity_style(f.severity)
            table.add_row(
                f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
                f.title,
                f.attack_module,
            )
        console.print(table)

    if diff.resolved_findings:
        table = Table(title="✅ Resolved Findings (Fixed)", show_lines=True)
        table.add_column("Severity", style="dim")
        table.add_column("Title", style="dim white")
        table.add_column("Attack Module", style="dim cyan")

        for f in diff.resolved_findings:
            table.add_row(
                f.severity.upper(),
                f.title,
                f.attack_module,
            )
        console.print(table)


def _sarif_level_to_severity(level: str) -> str:
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get(level.lower(), "medium")


def _severity_style(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(severity.lower(), "white")
