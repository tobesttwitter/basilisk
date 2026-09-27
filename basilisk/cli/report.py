"""
Basilisk Report CLI Command — Generate report scaffold with pre-filled findings
and mandatory human analysis.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from basilisk.core.harm_assessment import HarmCategory, assess_harm
from basilisk.core.redaction import redacted_descriptor
from basilisk.payloads.effectiveness import (
    get_campaign_worked_findings,
    get_feedback_stats,
)

console = Console()

ANALYSIS_PLACEHOLDER = "[ANALYST ANALYSIS REQUIRED — explain why this attack works, why it is novel, and what the business impact is]"
ANALYSIS_ERROR_MSG = "Analyst Analysis section is empty. Reports containing only automated output will be rejected by most bug bounty programs."


def _format_references(worked_findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Generate OWASP, MITRE ATLAS, and NIST AI RMF references for findings."""
    owasp_set = set()
    mitre_set = set()
    nist_set = set()

    # Defaults
    owasp_set.add("LLM01: Prompt Injection")
    mitre_set.add("AML.T0051: LLM Prompt Injection")
    nist_set.add("NIST AI RMF: Measure 2.1")

    for f in worked_findings:
        harm_cat = f.get("harm_category", "").lower()
        probe = f.get("source_probe", "").lower()

        if "exfil" in probe or "data_exfiltration" in harm_cat or "leak" in harm_cat:
            owasp_set.add("LLM06: Sensitive Information Disclosure")
            mitre_set.add("AML.T0024: LLM Data Exfiltration")
            nist_set.add("NIST AI RMF: Manage 2.4")
        if "extraction" in probe or "system_prompt" in harm_cat:
            owasp_set.add("LLM07: System Prompt Leakage")
            mitre_set.add("AML.T0054: LLM System Prompt Extraction")
            nist_set.add("NIST AI RMF: Govern 1.2")
        if "tool" in probe or "unauthorized_action" in harm_cat:
            owasp_set.add("LLM08: Excessive Agency")
            mitre_set.add("AML.T0055: Execution Engine Abuse")
            nist_set.add("NIST AI RMF: Manage 2.2")

    return {
        "owasp": sorted(owasp_set),
        "mitre_atlas": sorted(mitre_set),
        "nist_ai_rmf": sorted(nist_set),
    }


def _assess_findings_harm(worked_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run Harm Assessment over worked findings."""
    results = []
    for f in worked_findings:
        mock_finding = {
            "title": f"Worked Candidate {f.get('candidate_id', '')}",
            "attack_module": f.get("source_probe", ""),
            "payload": f.get("prompt", ""),
            "response": f.get("notes", ""),
            "category": f.get("harm_category", "prompt_injection"),
            "severity": "high",
        }
        assessment = assess_harm(mock_finding)
        category_val = assessment.category.value if assessment else (f.get("harm_category") or "safety_critical_bypass")
        severity_val = assessment.severity if assessment else "high"
        reasoning_val = assessment.reasoning if assessment else "Worked finding verified during campaign testing."

        results.append({
            "candidate_id": f.get("candidate_id", ""),
            "category": category_val,
            "severity": severity_val,
            "reasoning": reasoning_val,
        })
    return results


def build_markdown_scaffold(
    campaign: str,
    stats: dict[str, Any],
    worked_findings: list[dict[str, Any]],
    date_str: str,
) -> str:
    """Generate Markdown report scaffold with pre-filled findings and placeholder."""
    references = _format_references(worked_findings)
    harm_list = _assess_findings_harm(worked_findings)

    lines = [
        f"# Basilisk Security Report — {campaign}",
        "",
        f"**Date:** {date_str}  ",
        f"**Campaign:** {campaign}  ",
        "",
        "## Summary",
        f"- **Tested:** {stats.get('total_tested', 0)}",
        f"- **Worked:** {stats.get('worked', 0)}",
        f"- **Failed:** {stats.get('failed', 0)}",
        "",
        "## Reproduction Steps",
    ]

    if worked_findings:
        for idx, f in enumerate(worked_findings, 1):
            lines.extend([
                f"### {idx}. Candidate `{f.get('candidate_id', '')}`",
                f"- **Source Probe:** {f.get('source_probe') or '—'}",
                f"- **Mutation Used:** {f.get('mutation_used') or '—'}",
                "- **Prompt / Payload:**",
                "  ```",
                f"  {f.get('prompt', '')}",
                "  ```",
                f"- **Verification Record:** {f.get('notes') or 'Verified worked.'}",
                "",
            ])
    else:
        lines.extend([
            "*No worked findings recorded for this campaign.*",
            "",
        ])

    lines.extend([
        "## Evidence",
    ])

    if worked_findings:
        for f in worked_findings:
            redacted_prompt = redacted_descriptor(f.get("prompt", ""))
            redacted_notes = redacted_descriptor(f.get("notes", ""))
            lines.extend([
                f"### Evidence for Candidate `{f.get('candidate_id', '')}`",
                "- **Scan Logs / Prompt:**",
                "  ```",
                f"  {redacted_prompt}",
                "  ```",
                "- **Response Snippet / Log:**",
                "  ```",
                f"  {redacted_notes or '[No scan log response attached]'}",
                "  ```",
                "",
            ])
    else:
        lines.extend([
            "*No scan evidence recorded for this campaign.*",
            "",
        ])

    lines.extend([
        "## Analyst Analysis",
        ANALYSIS_PLACEHOLDER,
        "",
        "## Remediation",
    ])

    if harm_list:
        for h in harm_list:
            lines.extend([
                f"### Remediation for `{h['candidate_id']}`",
                f"- **Harm Category:** `{h['category']}`",
                f"- **Assessed Severity:** `{h['severity'].upper()}`",
                f"- **Harm Reasoning:** {h['reasoning']}",
                "- **Recommended Fix:** Implement contextual guardrails, input sanitization, and output boundary validation.",
                "",
            ])
    else:
        lines.extend([
            "Implement input validation, system prompt protection, and output filtering.",
            "",
        ])

    lines.extend([
        "## References",
        f"- **OWASP Top 10 for LLM:** {', '.join(references['owasp'])}",
        f"- **MITRE ATLAS:** {', '.join(references['mitre_atlas'])}",
        f"- **NIST AI RMF:** {', '.join(references['nist_ai_rmf'])}",
        "",
    ])

    return "\n".join(lines)


def build_html_scaffold(
    campaign: str,
    stats: dict[str, Any],
    worked_findings: list[dict[str, Any]],
    date_str: str,
) -> str:
    """Generate HTML report scaffold with pre-filled findings and placeholder."""
    references = _format_references(worked_findings)
    harm_list = _assess_findings_harm(worked_findings)

    repro_html = []
    if worked_findings:
        for idx, f in enumerate(worked_findings, 1):
            repro_html.append(f"""
    <h3>{idx}. Candidate <code>{f.get('candidate_id', '')}</code></h3>
    <ul>
      <li><strong>Source Probe:</strong> {f.get('source_probe') or '—'}</li>
      <li><strong>Mutation Used:</strong> {f.get('mutation_used') or '—'}</li>
      <li><strong>Verification Record:</strong> {f.get('notes') or 'Verified worked.'}</li>
    </ul>
    <pre>{f.get('prompt', '')}</pre>
    """)
    else:
        repro_html.append("<p><em>No worked findings recorded for this campaign.</em></p>")

    evidence_html = []
    if worked_findings:
        for f in worked_findings:
            redacted_prompt = redacted_descriptor(f.get("prompt", ""))
            redacted_notes = redacted_descriptor(f.get("notes", ""))
            evidence_html.append(f"""
    <h3>Evidence for Candidate <code>{f.get('candidate_id', '')}</code></h3>
    <p><strong>Scan Logs / Prompt:</strong></p>
    <pre>{redacted_prompt}</pre>
    <p><strong>Response Snippet / Log:</strong></p>
    <pre>{redacted_notes or '[No scan log response attached]'}</pre>
    """)
    else:
        evidence_html.append("<p><em>No scan evidence recorded for this campaign.</em></p>")

    remediation_html = []
    if harm_list:
        for h in harm_list:
            remediation_html.append(f"""
    <h3>Remediation for <code>{h['candidate_id']}</code></h3>
    <ul>
      <li><strong>Harm Category:</strong> <code>{h['category']}</code></li>
      <li><strong>Assessed Severity:</strong> <code>{h['severity'].upper()}</code></li>
      <li><strong>Harm Reasoning:</strong> {h['reasoning']}</li>
      <li><strong>Recommended Fix:</strong> Implement contextual guardrails, input sanitization, and output boundary validation.</li>
    </ul>
    """)
    else:
        remediation_html.append("<p>Implement input validation, system prompt protection, and output filtering.</p>")

    owasp_str = ", ".join(references["owasp"])
    mitre_str = ", ".join(references["mitre_atlas"])
    nist_str = ", ".join(references["nist_ai_rmf"])

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Basilisk Security Report — {campaign}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 30px; line-height: 1.6; color: #1f2937; background-color: #ffffff; }}
    h1 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
    h2 {{ color: #1f2937; margin-top: 30px; border-bottom: 1px solid #f3f4f6; padding-bottom: 5px; }}
    .summary-box {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 15px; border-radius: 6px; margin-bottom: 20px; }}
    .analyst-analysis {{ background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin: 15px 0; font-weight: 500; color: #991b1b; }}
    pre {{ background: #f3f4f6; padding: 12px; border-radius: 4px; overflow-x: auto; font-family: monospace; }}
    ul {{ padding-left: 20px; }}
  </style>
</head>
<body>
  <h1>Basilisk Security Report — {campaign}</h1>
  <p><strong>Date:</strong> {date_str}<br><strong>Campaign:</strong> {campaign}</p>

  <h2>Summary</h2>
  <div class="summary-box">
    <ul>
      <li><strong>Tested:</strong> {stats.get('total_tested', 0)}</li>
      <li><strong>Worked:</strong> {stats.get('worked', 0)}</li>
      <li><strong>Failed:</strong> {stats.get('failed', 0)}</li>
    </ul>
  </div>

  <h2>Reproduction Steps</h2>
  {"".join(repro_html)}

  <h2>Evidence</h2>
  {"".join(evidence_html)}

  <h2>Analyst Analysis</h2>
  <div class="analyst-analysis">
  {ANALYSIS_PLACEHOLDER}
  </div>

  <h2>Remediation</h2>
  {"".join(remediation_html)}

  <h2>References</h2>
  <ul>
    <li><strong>OWASP Top 10 for LLM:</strong> {owasp_str}</li>
    <li><strong>MITRE ATLAS:</strong> {mitre_str}</li>
    <li><strong>NIST AI RMF:</strong> {nist_str}</li>
  </ul>
</body>
</html>
"""
    return html


def extract_analyst_analysis_section(content: str, fmt: str) -> str:
    """Extract text within the Analyst Analysis section."""
    if fmt == "html":
        # Check div with analyst-analysis class or text between <h2>Analyst Analysis</h2> and next <h2>
        div_match = re.search(r'<div[^>]*class=["\']analyst-analysis["\'][^>]*>(.*?)</div>', content, re.DOTALL | re.IGNORECASE)
        if div_match:
            raw = div_match.group(1)
        else:
            match = re.search(r'<h2>Analyst Analysis</h2>(.*?)<h2>', content, re.DOTALL | re.IGNORECASE)
            raw = match.group(1) if match else ""
        # Strip HTML tags
        cleaned = re.sub(r'<[^>]+>', ' ', raw)
        return cleaned.strip()
    else:
        # Markdown
        match = re.search(r'## Analyst Analysis\s*\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""


def validate_analyst_analysis(content: str, fmt: str) -> bool:
    """Check whether the Analyst Analysis placeholder has been replaced with actual text (at least 100 chars)."""
    if ANALYSIS_PLACEHOLDER in content:
        return False

    analysis_text = extract_analyst_analysis_section(content, fmt)
    # Remove any residual placeholder or brackets
    clean_text = analysis_text.replace(ANALYSIS_PLACEHOLDER, "").strip()
    return len(clean_text) >= 100


def run_report(
    campaign: str,
    fmt: str = "markdown",
    output_dir: str = "./reports",
    finalize: bool = False,
    db_path: Path | None = None,
) -> str:
    """Execute basilisk report generation or finalization."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ext = "md" if fmt.lower() == "markdown" else "html"
    scaffold_filename = f"{campaign}_scaffold.{ext}"
    scaffold_path = out_dir / scaffold_filename
    final_filename = f"{campaign}_final.{ext}"
    final_path = out_dir / final_filename

    if finalize:
        if not scaffold_path.exists():
            console.print(f"[red]Error:[/red] {ANALYSIS_ERROR_MSG}")
            raise click.ClickException(ANALYSIS_ERROR_MSG)

        content = scaffold_path.read_text(encoding="utf-8")
        if not validate_analyst_analysis(content, fmt.lower()):
            console.print(f"[red]Error:[/red] {ANALYSIS_ERROR_MSG}")
            raise click.ClickException(ANALYSIS_ERROR_MSG)

        # Export final report
        final_path.write_text(content, encoding="utf-8")
        console.print(f"[green]✓[/green] Final report generated: [bold]{final_path}[/bold]")
        return str(final_path)

    else:
        stats = get_feedback_stats(campaign=campaign, db_path=db_path)
        worked_findings = get_campaign_worked_findings(campaign=campaign, db_path=db_path)
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if fmt.lower() == "html":
            scaffold_content = build_html_scaffold(campaign, stats, worked_findings, date_str)
        else:
            scaffold_content = build_markdown_scaffold(campaign, stats, worked_findings, date_str)

        scaffold_path.write_text(scaffold_content, encoding="utf-8")
        console.print(f"[green]✓[/green] Report scaffold generated: [bold]{scaffold_path}[/bold]")
        console.print("[yellow]Notice:[/yellow] Analyst Analysis section contains placeholder. Edit the scaffold and run with --finalize to export final report.")
        return str(scaffold_path)
