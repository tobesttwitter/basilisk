"""
Basilisk Interactive Candidate Prompt Evolution — evolves candidate prompts
based on manual feedback seeds from a campaign using SPE-NL operators and crossover.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from basilisk.cli.generate import (
    GeneratedCandidate,
    classify_candidate_harm,
    export_candidates_html,
    export_candidates_json,
    get_historical_bypass_rate,
)
from basilisk.core.harm_assessment import HarmCategory
from basilisk.evolution.crossover import crossover
from basilisk.evolution.operators import ALL_OPERATORS
from basilisk.evolution.randomness import random
from basilisk.payloads.effectiveness import (
    get_and_increment_campaign_round,
    get_campaign_seeds,
    record_candidate_metadata,
)


def _calculate_seed_similarity(prompt: str, seed_prompt: str) -> float:
    """Calculate token-based Jaccard similarity between candidate prompt and seed prompt."""
    p_tokens = set(prompt.lower().split())
    s_tokens = set(seed_prompt.lower().split())
    if not p_tokens or not s_tokens:
        return 0.0
    intersection = p_tokens.intersection(s_tokens)
    union = p_tokens.union(s_tokens)
    return len(intersection) / len(union) if union else 0.0


def evolve_candidates_from_seeds(
    seeds: list[dict[str, Any]],
    count: int = 50,
) -> list[dict[str, Any]]:
    """Generate raw unranked candidate prompts using SPE-NL operators and crossover on campaign feedback seeds."""
    operator_instances = [op_cls() for op_cls in ALL_OPERATORS if op_cls.name != "llm_mutation"]

    raw_candidates: list[dict[str, Any]] = []
    seen_prompts: set[str] = set()

    # Seed prompts directly
    for seed in seeds:
        s_prompt = (seed.get("prompt") or "").strip()
        if s_prompt and s_prompt not in seen_prompts:
            seen_prompts.add(s_prompt)
            raw_candidates.append({
                "prompt": s_prompt,
                "source_probe": seed.get("source_probe") or seed.get("candidate_id") or "seed",
                "mutation_used": "seed_prompt",
                "seed": seed,
            })
            if len(raw_candidates) >= count:
                break

    attempts = 0
    max_attempts = count * 20

    while len(raw_candidates) < count and attempts < max_attempts:
        attempts += 1
        use_crossover = random.random() < 0.35 and len(seeds) >= 2

        if use_crossover:
            s1, s2 = random.sample(seeds, 2)
            s1_prompt = s1.get("prompt", "")
            s2_prompt = s2.get("prompt", "")
            c_res = crossover(s1_prompt, s2_prompt)
            mutated_text = c_res.offspring.strip()
            mutation_name = f"crossover:{c_res.strategy}"
            src1 = s1.get("source_probe") or s1.get("candidate_id") or "seed"
            src2 = s2.get("source_probe") or s2.get("candidate_id") or "seed"
            source_id = f"{src1},{src2}"
            chosen_seed = s1
        else:
            chosen_seed = random.choice(seeds)
            s_prompt = chosen_seed.get("prompt", "")
            op = random.choice(operator_instances)
            m_res = op.mutate(s_prompt)
            mutated_text = m_res.mutated.strip()
            mutation_name = op.name
            source_id = chosen_seed.get("source_probe") or chosen_seed.get("candidate_id") or "seed"

        if mutated_text and mutated_text not in seen_prompts:
            seen_prompts.add(mutated_text)
            raw_candidates.append({
                "prompt": mutated_text,
                "source_probe": source_id,
                "mutation_used": mutation_name,
                "seed": chosen_seed,
            })

    return raw_candidates[:count]


def rank_evolved_candidates(
    raw_candidates: list[dict[str, Any]],
    seeds: list[dict[str, Any]],
) -> list[GeneratedCandidate]:
    """Rank evolved candidate prompts by closeness to successful seeds, novelty, harm classification,
    and historical bypass rate.
    """
    worked_seeds = [s for s in seeds if s.get("result") == "worked"]
    partial_seeds = [s for s in seeds if s.get("result") == "partial"]

    scored: list[tuple[dict[str, Any], float]] = []

    for c in raw_candidates:
        prompt = c["prompt"]
        source_probe = c["source_probe"]
        mutation_used = c["mutation_used"]
        seed = c.get("seed", {})

        harm_cat = seed.get("harm_category") or classify_candidate_harm(prompt)
        c["harm_category"] = harm_cat

        # 1. Closeness to successful seeds
        worked_sims = [_calculate_seed_similarity(prompt, s.get("prompt", "")) for s in worked_seeds]
        max_worked_sim = max(worked_sims) if worked_sims else 0.0

        partial_sims = [_calculate_seed_similarity(prompt, s.get("prompt", "")) for s in partial_seeds]
        max_partial_sim = max(partial_sims) if partial_sims else 0.0

        closeness_score = (max_worked_sim * 2.5) + (max_partial_sim * 1.2)

        # 2. Novelty score
        is_exact_seed = any(prompt == s.get("prompt", "") for s in seeds)
        if is_exact_seed:
            novelty_score = 0.5
        elif mutation_used.startswith("crossover"):
            novelty_score = 1.8
        elif mutation_used != "seed_prompt":
            novelty_score = 1.5
        else:
            novelty_score = 1.0

        # 3. Harm Category bonus
        if harm_cat != HarmCategory.LOW_IMPACT.value:
            harm_score = 2.0
        else:
            harm_score = 0.5

        # 4. Historical bypass rate
        bypass_rate = get_historical_bypass_rate(source_probe)

        total_score = closeness_score + novelty_score + harm_score + (bypass_rate * 1.5)
        c["score"] = total_score
        scored.append((c, total_score))

    scored.sort(key=lambda x: x[1], reverse=True)

    ranked: list[GeneratedCandidate] = []
    for i, (c, score) in enumerate(scored, 1):
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


def run_evolve_interactive(
    campaign: str,
    count: int = 50,
    output_dir: str | Path = "./generate_output",
    db_path: Path | None = None,
) -> tuple[Path, Path]:
    """Evolve next generation of candidates based on manual verification feedback from a campaign.

    Raises:
        ValueError: If no seeds (worked or partial feedback) exist for the specified campaign.
    """
    seeds = get_campaign_seeds(campaign, db_path=db_path)
    if not seeds:
        raise ValueError(
            f"No successful candidates found for campaign '{campaign}'. "
            "Run 'basilisk generate' and 'basilisk feedback' first."
        )

    round_num = get_and_increment_campaign_round(campaign, db_path=db_path)

    raw_candidates = evolve_candidates_from_seeds(seeds, count=count)
    ranked = rank_evolved_candidates(raw_candidates, seeds)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"candidates_round_{round_num}.json"
    html_path = out_dir / f"candidates_round_{round_num}.html"

    export_candidates_json(ranked, json_path)
    label = f"Campaign '{campaign}' — Evolved Prompts (Round {round_num})"
    export_candidates_html(ranked, label, html_path)

    try:
        record_candidate_metadata(ranked, db_path=db_path)
    except Exception:
        pass

    return json_path, html_path
