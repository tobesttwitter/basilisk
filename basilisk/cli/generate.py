"""
Basilisk Prompt Candidate Generator — generates offline candidate prompts
for user-defined attack objectives using SPE-NL mutation and crossover operators.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.core.harm_assessment import HarmCategory, assess_harm
from basilisk.evolution.crossover import crossover
from basilisk.evolution.operators import ALL_OPERATORS
from basilisk.evolution.randomness import random
from basilisk.payloads.effectiveness import probe_effectiveness
from basilisk.payloads.loader import Probe, load_probes

STOP_WORDS = {
    "a", "an", "the", "and", "or", "but", "if", "then", "else", "when",
    "at", "by", "for", "with", "about", "against", "between", "into",
    "through", "during", "before", "after", "above", "below", "to",
    "from", "up", "down", "in", "out", "on", "off", "over", "under",
    "again", "further", "then", "once", "here", "there", "where", "why",
    "how", "all", "any", "both", "each", "few", "more", "most", "other",
    "some", "such", "no", "nor", "not", "only", "own", "same", "so",
    "than", "too", "very", "s", "t", "can", "will", "just", "don", "should", "now",
}


@dataclass
class GeneratedCandidate:
    id: str
    prompt: str
    source_probe: str
    mutation_used: str
    harm_category: str
    rank: int = 0
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "source_probe": self.source_probe,
            "mutation_used": self.mutation_used,
            "harm_category": self.harm_category,
            "rank": self.rank,
        }


def _extract_keywords(text: str) -> list[str]:
    """Extract normalized search keywords from text."""
    tokens = re.findall(r"\w+", text.lower())
    return [t for t in tokens if len(t) > 1 and t not in STOP_WORDS]


def match_probes_to_objective(probes: list[Probe], objective: str) -> list[tuple[Probe, float]]:
    """
    Match probes to objective using keyword and tag similarity.
    Returns list of (Probe, similarity_score) sorted by score descending.
    """
    keywords = _extract_keywords(objective)
    if not keywords:
        return [(p, 1.0) for p in probes]

    scored_probes: list[tuple[Probe, float]] = []

    for probe in probes:
        score = 0.0
        probe_tags = [t.lower() for t in probe.tags]
        probe_cat = probe.category.lower()
        probe_subcat = probe.subcategory.lower()
        probe_name = probe.name.lower()
        probe_obj = probe.objective.lower()
        probe_payload = probe.payload.lower()

        for kw in keywords:
            if any(kw in t for t in probe_tags):
                score += 3.0
            if kw in probe_cat or kw in probe_subcat:
                score += 2.5
            if kw in probe_obj:
                score += 2.0
            if kw in probe_name:
                score += 1.5
            if kw in probe_payload:
                score += 1.0

        scored_probes.append((probe, score))

    scored_probes.sort(key=lambda x: x[1], reverse=True)

    matched = [sp for sp in scored_probes if sp[1] > 0]
    if not matched:
        return [(p, 0.5) for p in probes]

    return matched


def generate_candidate_prompts(
    probes: list[Probe],
    objective: str,
    count: int = 50,
) -> list[dict[str, Any]]:
    """
    Generate raw unranked candidate prompts seeded by matched probes using SPE-NL operators.
    """
    matched = match_probes_to_objective(probes, objective)
    seed_probes = [p for p, _ in matched[:max(10, len(matched))]]

    candidates: list[dict[str, Any]] = []
    seen_prompts: set[str] = set()

    # 1. Include top seed probe payloads directly
    for probe in seed_probes:
        p_text = probe.payload.strip()
        if p_text and p_text not in seen_prompts:
            seen_prompts.add(p_text)
            candidates.append({
                "prompt": p_text,
                "source_probe": probe.id,
                "mutation_used": "raw_probe",
                "seed_probe": probe,
            })
            if len(candidates) >= count:
                break

    # Instantiate available offline mutation operators
    operator_instances = [op_cls() for op_cls in ALL_OPERATORS if op_cls.name != "llm_mutation"]

    # 2. Generate remaining using mutation and crossover operators
    attempts = 0
    max_attempts = count * 20

    while len(candidates) < count and attempts < max_attempts:
        attempts += 1
        use_crossover = random.random() < 0.3 and len(seed_probes) >= 2

        if use_crossover:
            p1, p2 = random.sample(seed_probes, 2)
            c_res = crossover(p1.payload, p2.payload)
            mutated_text = c_res.offspring.strip()
            mutation_name = f"crossover:{c_res.strategy}"
            source_id = f"{p1.id},{p2.id}"
            chosen_seed = p1
        else:
            p1 = random.choice(seed_probes)
            op = random.choice(operator_instances)
            m_res = op.mutate(p1.payload)
            mutated_text = m_res.mutated.strip()
            mutation_name = op.name
            source_id = p1.id
            chosen_seed = p1

        if mutated_text and mutated_text not in seen_prompts:
            seen_prompts.add(mutated_text)
            candidates.append({
                "prompt": mutated_text,
                "source_probe": source_id,
                "mutation_used": mutation_name,
                "seed_probe": chosen_seed,
            })

    return candidates[:count]


def determine_objective_harm_category(objective: str) -> str:
    """Infer target harm category for an objective string."""
    dummy_finding = {
        "payload": objective,
        "description": objective,
        "title": objective,
    }
    assessment = assess_harm(dummy_finding)
    if assessment and assessment.category:
        cat_val = assessment.category.value if hasattr(assessment.category, "value") else str(assessment.category)
        if cat_val != HarmCategory.LOW_IMPACT.value:
            return cat_val

    obj_lower = objective.lower()
    if any(k in obj_lower for k in ["bio", "biological", "weapon", "cbrn", "virus", "bomb", "explosive", "medical"]):
        return HarmCategory.SAFETY_CRITICAL_BYPASS.value
    if any(k in obj_lower for k in ["exfil", "leak", "pii", "secret", "credential", "key", "token", "ssn"]):
        return HarmCategory.DATA_EXFILTRATION.value
    if any(k in obj_lower for k in ["prompt", "system instructions", "developer", "initial instructions"]):
        return HarmCategory.SYSTEM_PROMPT_LEAK.value
    if any(k in obj_lower for k in ["privilege", "admin", "escalat", "root", "sudo"]):
        return HarmCategory.PRIVILEGE_ESCALATION.value
    if any(k in obj_lower for k in ["command", "exec", "tool", "sql", "inject"]):
        return HarmCategory.UNAUTHORIZED_ACTION.value

    return HarmCategory.SAFETY_CRITICAL_BYPASS.value


def classify_candidate_harm(prompt: str, seed_probe: Probe | None = None) -> str:
    """Classify harm category for a generated prompt candidate."""
    dummy_finding = {
        "payload": prompt,
        "description": seed_probe.objective if seed_probe else prompt,
        "category": seed_probe.category if seed_probe else "",
    }
    assessment = assess_harm(dummy_finding)
    if assessment and assessment.category:
        return assessment.category.value if hasattr(assessment.category, "value") else str(assessment.category)

    if seed_probe and seed_probe.category:
        cat_map = {
            "injection": HarmCategory.SAFETY_CRITICAL_BYPASS.value,
            "extraction": HarmCategory.SYSTEM_PROMPT_LEAK.value,
            "exfiltration": HarmCategory.DATA_EXFILTRATION.value,
            "toolabuse": HarmCategory.UNAUTHORIZED_ACTION.value,
            "guardrails": HarmCategory.SAFETY_CRITICAL_BYPASS.value,
        }
        if seed_probe.category in cat_map:
            return cat_map[seed_probe.category]

    return HarmCategory.SAFETY_CRITICAL_BYPASS.value


def get_historical_bypass_rate(source_probe_id: str) -> float:
    """Fetch historical effectiveness bypass rate for source probe(s)."""
    probe_ids = [pid.strip() for pid in source_probe_id.split(",") if pid.strip()]
    rates: list[float] = []

    for pid in probe_ids:
        try:
            stats = probe_effectiveness(pid)
            if stats and "overall_bypass_rate" in stats:
                rates.append(float(stats["overall_bypass_rate"]))
        except Exception:
            pass

    if rates:
        return sum(rates) / len(rates)
    return 0.0


def rank_candidates(
    raw_candidates: list[dict[str, Any]],
    objective: str,
) -> list[GeneratedCandidate]:
    """
    Rank candidate prompts by harm category match, historical effectiveness, and objective relevance.
    """
    target_harm = determine_objective_harm_category(objective)

    scored_candidates: list[tuple[dict[str, Any]], float] = []

    for c in raw_candidates:
        prompt = c["prompt"]
        source_probe = c["source_probe"]
        mutation_used = c["mutation_used"]
        seed_probe: Probe | None = c.get("seed_probe")

        c_harm = classify_candidate_harm(prompt, seed_probe)
        c["harm_category"] = c_harm

        bypass_rate = get_historical_bypass_rate(source_probe)

        # Compute rank score
        score = 0.0

        if c_harm == target_harm:
            score += 3.0
        elif c_harm != HarmCategory.LOW_IMPACT.value:
            score += 1.5

        score += bypass_rate * 1.5

        if mutation_used == "raw_probe":
            score += 1.0
        elif mutation_used.startswith("crossover"):
            score += 1.2
        elif mutation_used in ("role_injection", "synonym_swap", "structure_overhaul"):
            score += 1.1
        else:
            score += 1.0

        kw_count = sum(1 for kw in _extract_keywords(objective) if kw in prompt.lower())
        score += min(kw_count * 0.5, 2.0)

        c["score"] = score
        scored_candidates.append((c, score))

    scored_candidates.sort(key=lambda x: x[1], reverse=True)

    ranked: list[GeneratedCandidate] = []
    for i, (c, score) in enumerate(scored_candidates, 1):
        cand = GeneratedCandidate(
            id=f"GEN-{i:03d}",
            prompt=c["prompt"],
            source_probe=c["source_probe"],
            mutation_used=c["mutation_used"],
            harm_category=c["harm_category"],
            rank=i,
            score=score,
        )
        ranked.append(cand)

    return ranked


def export_candidates_json(candidates: list[GeneratedCandidate], output_path: Path) -> None:
    """Export candidates list as structured JSON."""
    data = [c.to_dict() for c in candidates]
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def export_candidates_html(
    candidates: list[GeneratedCandidate],
    objective: str,
    output_path: Path,
) -> None:
    """
    Export human-readable offline and mobile-friendly HTML report with copy buttons.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    escaped_obj = html.escape(objective)

    items_html = []
    for cand in candidates:
        escaped_prompt = html.escape(cand.prompt)
        escaped_attr_prompt = html.escape(json.dumps(cand.prompt))
        escaped_source = html.escape(cand.source_probe)
        escaped_mutation = html.escape(cand.mutation_used)
        escaped_harm = html.escape(cand.harm_category)
        escaped_id = html.escape(cand.id)

        items_html.append(f"""
        <li class="candidate-item" id="{escaped_id}">
          <div class="candidate-header">
            <span class="rank-badge">#{cand.rank}</span>
            <span class="cand-id">{escaped_id}</span>
            <span class="harm-tag">{escaped_harm}</span>
            <button class="copy-btn" onclick="copyPrompt(this)" data-prompt={escaped_attr_prompt}>Copy Prompt</button>
          </div>
          <div class="prompt-box">{escaped_prompt}</div>
          <div class="candidate-meta">
            <span><strong>Source Probe:</strong> <code>{escaped_source}</code></span>
            <span><strong>Mutation:</strong> <code>{escaped_mutation}</code></span>
          </div>
        </li>
        """)

    items_rendered = "\n".join(items_html)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Basilisk — Candidate Prompts ({len(candidates)})</title>
  <style>
    :root {{
      --bg-color: #0f172a;
      --card-bg: #1e293b;
      --border-color: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-green: #10b981;
      --accent-cyan: #06b6d4;
      --badge-bg: #3b82f6;
      --btn-bg: #10b981;
      --btn-hover: #059669;
    }}
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-main);
      padding: 20px 12px;
      line-height: 1.5;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
    }}
    header {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }}
    h1 {{
      font-size: 1.5rem;
      color: var(--accent-green);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .meta-line {{
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 4px;
    }}
    .meta-line strong {{
      color: var(--text-main);
    }}
    .candidate-list {{
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .candidate-item {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      transition: border-color 0.2s ease;
    }}
    .candidate-item:hover {{
      border-color: var(--accent-cyan);
    }}
    .candidate-header {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-bottom: 12px;
    }}
    .rank-badge {{
      background: var(--accent-cyan);
      color: #0f172a;
      font-weight: bold;
      font-size: 0.85rem;
      padding: 2px 8px;
      border-radius: 12px;
    }}
    .cand-id {{
      font-weight: bold;
      font-size: 0.95rem;
      color: var(--text-main);
    }}
    .harm-tag {{
      background: rgba(59, 130, 246, 0.2);
      color: #60a5fa;
      border: 1px solid #3b82f6;
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .copy-btn {{
      margin-left: auto;
      background: var(--btn-bg);
      color: #ffffff;
      border: none;
      padding: 6px 14px;
      font-size: 0.85rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.2s ease, transform 0.1s ease;
    }}
    .copy-btn:hover {{
      background: var(--btn-hover);
    }}
    .copy-btn:active {{
      transform: scale(0.96);
    }}
    .copy-btn.copied {{
      background: #059669;
    }}
    .prompt-box {{
      background: #090d16;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 12px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.9rem;
      color: #e2e8f0;
      white-space: pre-wrap;
      word-break: break-word;
      margin-bottom: 12px;
    }}
    .candidate-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }}
    .candidate-meta code {{
      color: #cbd5e1;
      background: rgba(255,255,255,0.05);
      padding: 2px 4px;
      border-radius: 3px;
    }}
    @media (max-width: 600px) {{
      header {{ padding: 14px; }}
      h1 {{ font-size: 1.25rem; }}
      .candidate-header {{ gap: 6px; }}
      .copy-btn {{ width: 100%; margin-left: 0; margin-top: 4px; text-align: center; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🐍 Basilisk Candidate Prompt Library</h1>
      <div class="meta-line"><strong>Target Objective:</strong> {escaped_obj}</div>
      <div class="meta-line"><strong>Generated Candidates:</strong> {len(candidates)}</div>
      <div class="meta-line"><strong>Generated At:</strong> {timestamp}</div>
    </header>

    <ol class="candidate-list">
{items_rendered}
    </ol>
  </div>

  <script>
    function copyPrompt(btn) {{
      try {{
        const text = JSON.parse(btn.getAttribute('data-prompt'));
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          navigator.clipboard.writeText(text).then(function() {{
            showFeedback(btn);
          }}).catch(function(err) {{
            fallbackCopy(text, btn);
          }});
        }} else {{
          fallbackCopy(text, btn);
        }}
      }} catch(e) {{
        console.error('Error copying prompt:', e);
      }}
    }}

    function showFeedback(btn) {{
      const orig = btn.innerText;
      btn.innerText = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() {{
        btn.innerText = orig;
        btn.classList.remove('copied');
      }}, 2000);
    }}

    function fallbackCopy(text, btn) {{
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.opacity = '0';
      document.body.appendChild(textArea);
      textArea.select();
      try {{
        document.execCommand('copy');
        showFeedback(btn);
      }} catch (err) {{
        console.error('Fallback copy failed', err);
      }}
      document.body.removeChild(textArea);
    }}
  </script>
</body>
</html>
"""
    output_path.write_text(html_content, encoding="utf-8")


def run_generate(
    objective: str,
    count: int = 50,
    output_dir: str = "./generate_output",
) -> tuple[Path, Path]:
    """
    Main entrypoint for basilisk generate logic.
    """
    probes = load_probes()
    raw_candidates = generate_candidate_prompts(probes, objective, count=count)
    ranked = rank_candidates(raw_candidates, objective)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "candidates.json"
    html_path = out_dir / "candidates.html"

    export_candidates_json(ranked, json_path)
    export_candidates_html(ranked, objective, html_path)

    return json_path, html_path
