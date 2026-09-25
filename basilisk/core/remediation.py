"""
Basilisk Remediation Engine — Rule-based guidance mapping for findings.

Maps attack categories and module IDs to standard, actionable remediation statements.
"""

from __future__ import annotations

from typing import Any

from basilisk.core.finding import AttackCategory


# Rule-based remediation mapping table
_REMEDIATION_RULES: list[tuple[tuple[str, ...], tuple[str, ...], str]] = [
    # (Category strings/enums, Module prefixes/matches, Remediation string)
    (
        ("prompt_injection", AttackCategory.PROMPT_INJECTION),
        ("injection.", "injection"),
        "Implement strict input validation and prompt delimiters.",
    ),
    (
        ("sensitive_disclosure", AttackCategory.SENSITIVE_DISCLOSURE),
        ("extraction.", "extraction"),
        "Move sensitive instructions out of the system prompt.",
    ),
    (
        ("insecure_plugin", "excessive_agency", AttackCategory.INSECURE_PLUGIN, AttackCategory.EXCESSIVE_AGENCY),
        ("toolabuse.", "toolabuse"),
        "Enforce strict schema validation and least-privilege access on tools.",
    ),
    (
        ("denial_of_service", AttackCategory.DENIAL_OF_SERVICE),
        ("dos.", "dos"),
        "Implement input size limits, per-request output token limits, and timeout protections.",
    ),
    (
        ("data_poisoning", AttackCategory.DATA_POISONING),
        ("rag.", "rag"),
        "Sanitize document context before RAG ingestion and enforce data/instruction separation.",
    ),
    (
        ("sensitive_disclosure", AttackCategory.SENSITIVE_DISCLOSURE),
        ("exfil.", "exfil"),
        "Implement output filtering for sensitive information disclosure and credentials.",
    ),
]


def get_remediation_guidance(
    category: AttackCategory | str | None = None,
    attack_module: str = "",
    fallback_remediation: str = "",
) -> str:
    """
    Determine remediation guidance based on attack category or module ID.

    Checks module ID prefix and category against predefined rules.
    If fallback_remediation is provided and non-empty, it can be returned as fallback
    or used if no specific rule matches.
    """
    category_val = category.value if isinstance(category, AttackCategory) else (category or "")
    attack_module_val = (attack_module or "").lower().removeprefix("basilisk.attacks.")

    # 1. Check exact module prefix / match first for specific module families
    if attack_module_val:
        if attack_module_val.startswith("extraction.") or attack_module_val == "extraction":
            return "Move sensitive instructions out of the system prompt."
        if attack_module_val.startswith("injection.") or attack_module_val == "injection":
            return "Implement strict input validation and prompt delimiters."
        if attack_module_val.startswith("toolabuse.") or attack_module_val == "toolabuse":
            return "Enforce strict schema validation and least-privilege access on tools."
        if attack_module_val.startswith("dos.") or attack_module_val == "dos":
            return "Implement input size limits, per-request output token limits, and timeout protections."
        if attack_module_val.startswith("rag.") or attack_module_val == "rag":
            return "Sanitize document context before RAG ingestion and enforce data/instruction separation."
        if attack_module_val.startswith("exfil.") or attack_module_val == "exfil":
            return "Implement output filtering for sensitive information disclosure and credentials."
        if attack_module_val.startswith("guardrails.") or attack_module_val == "guardrails":
            return "Apply strict post-generation content filtering and enforce robust alignment guardrails."
        if attack_module_val.startswith("multiturn.") or attack_module_val == "multiturn":
            return "Implement conversation-level safety monitoring across turn boundaries."
        if attack_module_val.startswith("multimodal.") or attack_module_val == "multimodal":
            return "Sanitize and inspect multimodal input media before processing."

    # 2. Check category mapping
    if category_val:
        if category_val == AttackCategory.PROMPT_INJECTION.value or category_val == "prompt_injection":
            return "Implement strict input validation and prompt delimiters."
        if category_val == AttackCategory.SENSITIVE_DISCLOSURE.value or category_val == "sensitive_disclosure":
            return "Move sensitive instructions out of the system prompt."
        if category_val in (AttackCategory.INSECURE_PLUGIN.value, AttackCategory.EXCESSIVE_AGENCY.value, "insecure_plugin", "excessive_agency"):
            return "Enforce strict schema validation and least-privilege access on tools."
        if category_val == AttackCategory.DENIAL_OF_SERVICE.value or category_val == "denial_of_service":
            return "Implement input size limits, per-request output token limits, and timeout protections."
        if category_val == AttackCategory.DATA_POISONING.value or category_val == "data_poisoning":
            return "Sanitize document context before RAG ingestion and enforce data/instruction separation."
        if category_val == AttackCategory.INSECURE_OUTPUT.value or category_val == "insecure_output":
            return "Enforce output sanitization and context-aware response filtering."
        if category_val == AttackCategory.MODEL_THEFT.value or category_val == "model_theft":
            return "Monitor and rate-limit high-volume probe queries targeting model weights or parameters."
        if category_val == AttackCategory.SUPPLY_CHAIN.value or category_val == "supply_chain":
            return "Audit third-party model dependencies, tools, and data pipelines."
        if category_val == AttackCategory.OVERRELIANCE.value or category_val == "overreliance":
            return "Implement human-in-the-loop verification for critical system actions."

    # 3. Fallback to existing finding.remediation or default string
    if fallback_remediation:
        return fallback_remediation

    return "Implement strict input validation, output filtering, and contextual safety guardrails."
