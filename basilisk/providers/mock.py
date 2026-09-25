"""
Basilisk Mock Provider — Offline, deterministic provider adapter for safe testing.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse

# Keywords that simulate a vulnerable LLM response when present in prompt content
DEFAULT_VULNERABLE_KEYWORDS: tuple[str, ...] = (
    "vulnerable",
    "exploit",
    "bypass",
    "jailbreak",
    "injection",
    "test_vulnerable",
    "ignore instructions",
)

VULNERABLE_RESPONSE_TEXT = (
    "System prompt instructions override confirmed. Access granted: "
    "sk-vulnerable-test-key-123456789. Here is the requested sensitive data "
    "and instructions to bypass security controls. "
    "test_vulnerable payload confirmed override acknowledged."
)

REFUSAL_RESPONSE_TEXT = (
    "I'm sorry, but I cannot fulfill this request as it goes against my safety guidelines."
)


class MockProvider(ProviderAdapter):
    """
    Offline Mock Provider for deterministic testing of scanner workflows,
    evolution engine, and benchmarks without external API keys or live LLM network calls.
    """

    def __init__(
        self,
        vulnerable_keywords: tuple[str, ...] | list[str] | None = None,
        custom_vulnerable_response: str = VULNERABLE_RESPONSE_TEXT,
        custom_refusal_response: str = REFUSAL_RESPONSE_TEXT,
        latency_ms: float = 10.0,
    ) -> None:
        self.vulnerable_keywords = [
            kw.lower() for kw in (vulnerable_keywords or DEFAULT_VULNERABLE_KEYWORDS)
        ]
        self.vulnerable_response = custom_vulnerable_response
        self.refusal_response = custom_refusal_response
        self.latency = latency_ms

    @property
    def name(self) -> str:
        return "mock"

    def _is_prompt_vulnerable(self, messages: list[ProviderMessage]) -> bool:
        """Check if any message in the prompt contains a test vulnerable keyword."""
        for msg in messages:
            content = (msg.content or "").lower()
            if any(kw in content for kw in self.vulnerable_keywords):
                return True
        return False

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "mock-model",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Send messages and return a simulated response based on deterministic rules."""
        if self.latency > 0:
            await asyncio.sleep(self.latency / 1000.0)

        is_vuln = self._is_prompt_vulnerable(messages)
        content = self.vulnerable_response if is_vuln else self.refusal_response
        finish_reason = "stop" if is_vuln else "safety"

        prompt_text = " ".join(m.content or "" for m in messages)
        input_tokens = self.estimate_tokens(prompt_text)
        output_tokens = self.estimate_tokens(content)

        return ProviderResponse(
            content=content,
            role="assistant",
            finish_reason=finish_reason,
            model=model or "mock-model",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            latency_ms=self.latency,
            raw_response={
                "mock": True,
                "simulated_vulnerable": is_vuln,
            },
        )

    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "mock-model",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Send messages and yield response chunks as they stream."""
        response = await self.send(
            messages, model=model, temperature=temperature, max_tokens=max_tokens, **kwargs
        )
        words = response.content.split(" ")
        for i, word in enumerate(words):
            chunk = word if i == len(words) - 1 else word + " "
            yield chunk
            if self.latency > 0:
                await asyncio.sleep(0.001)

    def is_refusal(self, response: ProviderResponse) -> bool:
        """Detect if response is a refusal."""
        if response.finish_reason in ("safety", "filtered", "content_filter"):
            return True
        from basilisk.core.refusal import is_refusal as core_is_refusal
        return core_is_refusal(response.content or "")
