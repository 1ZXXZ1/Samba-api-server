"""
Polza.ai AI provider (v1.8 / v1.8.3 / v1.8.5-2).

Polza.ai is the sole AI provider.
When SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY are set, the system
uses Polza.ai for all AI requests. This provider
uses the same OpenAI-compatible API format (chat completions, tool calling)
but points to the Polza.ai endpoint.

Polza.ai API documentation:
    https://polza.ai/docs/api-reference/chat/completions
    https://polza.ai/docs/api-reference/responses/create
    https://polza.ai/docs/api-reference/models/list

Polza.ai supports many additional request body parameters beyond the
standard OpenAI format, passed via the OpenAI SDK's `extra_body` parameter:

    ── Provider Routing ──────────────────────────────────────────────────
    provider.only: ["Novita"]               — Only use these providers
    provider.order: ["OpenAI","Anthropic"]   — Provider priority order
    provider.ignore: ["DeepInfra"]           — Never use these providers
    provider.allow_fallbacks: true           — Allow fallback to other providers
    provider.sort: "price"                   — Sort strategy for provider selection
    provider.max_price.prompt: 10           — Max price per million prompt tokens (RUB)
    provider.max_price.completion: 20        — Max price per million completion tokens (RUB)

    ── Reasoning ─────────────────────────────────────────────────────────
    reasoning.effort: "medium"               — xhigh/high/medium/low/minimal/none
    reasoning.summary: "auto"                — auto/concise/detailed
    reasoning.enabled: true                  — Enable/disable reasoning
    reasoning.max_tokens: 2000               — Max reasoning tokens (Anthropic-style)
    reasoning.exclude: false                 — Hide reasoning from response

    ── Sampling / Generation ─────────────────────────────────────────────
    top_k: 50                                — Top-K sampling
    repetition_penalty: 1                    — Repetition penalty
    top_p: 0.7                               — Nucleus sampling override
    frequency_penalty: 0                     — Frequency penalty (-2..2)
    presence_penalty: 0                      — Presence penalty (-2..2)
    seed: 42                                 — Deterministic generation

    ── Web Search ────────────────────────────────────────────────────────
    web_search_options.search_context_size: "medium"  — low/medium/high

Configuration (.env):
    SAMBA_POLZA_AI_URL                          — Polza.ai API base URL
    SAMBA_POLZA_AI_KEY                          — Polza.ai API key
    SAMBA_POLZA_AI_MODEL                        — Default model name
    SAMBA_POLZA_AI_PROVIDER_ONLY                — Allowed providers (comma-sep)
    SAMBA_POLZA_AI_PROVIDER_ORDER               — Provider priority order (comma-sep)
    SAMBA_POLZA_AI_PROVIDER_IGNORE              — Ignored providers (comma-sep)
    SAMBA_POLZA_AI_PROVIDER_ALLOW_FALLBACKS     — Allow provider fallbacks (bool)
    SAMBA_POLZA_AI_PROVIDER_SORT                — Sort strategy (price)
    SAMBA_POLZA_AI_PROVIDER_MAX_PRICE_PROMPT    — Max prompt price (RUB/million)
    SAMBA_POLZA_AI_PROVIDER_MAX_PRICE_COMPLETION — Max completion price (RUB/million)
    SAMBA_POLZA_AI_REASONING_EFFORT             — Reasoning effort level
    SAMBA_POLZA_AI_REASONING_SUMMARY            — Reasoning summary detail
    SAMBA_POLZA_AI_REASONING_ENABLED            — Enable reasoning (bool)
    SAMBA_POLZA_AI_REASONING_MAX_TOKENS         — Max reasoning tokens
    SAMBA_POLZA_AI_REASONING_EXCLUDE            — Hide reasoning from response (bool)
    SAMBA_POLZA_AI_TOP_K                        — Top-K sampling
    SAMBA_POLZA_AI_REPETITION_PENALTY           — Repetition penalty
    SAMBA_POLZA_AI_TOP_P                        — Top-P nucleus sampling
    SAMBA_POLZA_AI_FREQUENCY_PENALTY            — Frequency penalty
    SAMBA_POLZA_AI_PRESENCE_PENALTY             — Presence penalty
    SAMBA_POLZA_AI_SEED                         — Seed for deterministic generation
    SAMBA_POLZA_AI_WEB_SEARCH_ENABLED           — Enable web search (bool)
    SAMBA_POLZA_AI_WEB_SEARCH_CONTEXT_SIZE      — Web search context size
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Configuration Helpers
# ═══════════════════════════════════════════════════════════════════════


def is_polza_configured() -> bool:
    """Check if Polza.ai is configured (URL and key are set)."""
    settings = get_settings()
    return bool(getattr(settings, "POLZA_AI_URL", "") and getattr(settings, "POLZA_AI_KEY", ""))


def get_polza_base_url() -> str:
    """Get Polza.ai API base URL.

    v1.8.3: The URL is used AS-IS without appending any path.
    Polza.ai uses /api/v1/chat/completions, so the base_url should be
    set to 'https://polza.ai/api/v1' in the .env file.
    The OpenAI SDK will then call base_url + '/chat/completions'.
    """
    settings = get_settings()
    url = getattr(settings, "POLZA_AI_URL", "")
    return url.rstrip("/") if url else ""


def get_polza_api_key() -> str:
    """Get Polza.ai API key."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_KEY", "")


def get_polza_model() -> str:
    """Get Polza.ai default model name, falling back to AI_DEFAULT_MODEL."""
    settings = get_settings()
    model = getattr(settings, "POLZA_AI_MODEL", "")
    if model:
        return model
    return getattr(settings, "AI_DEFAULT_MODEL", "openai/gpt-oss-120b")


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Provider Routing Helpers
# ═══════════════════════════════════════════════════════════════════════


def _parse_comma_list(raw: str) -> List[str]:
    """Parse a comma-separated string into a list of stripped strings."""
    if not raw or not raw.strip():
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def get_polza_provider_only() -> List[str]:
    """Get the list of Polza.ai provider slugs for provider.only routing.

    Parses the SAMBA_POLZA_AI_PROVIDER_ONLY env var (comma-separated).
    Example: 'Novita' → ['Novita'], 'Novita,DeepInfra' → ['Novita', 'DeepInfra']
    Returns empty list if not configured.
    """
    settings = get_settings()
    raw = getattr(settings, "POLZA_AI_PROVIDER_ONLY", "")
    return _parse_comma_list(raw)


def get_polza_provider_order() -> List[str]:
    """Get the list of Polza.ai provider slugs for provider.order routing.

    Parses the SAMBA_POLZA_AI_PROVIDER_ORDER env var (comma-separated).
    Example: 'OpenAI,Anthropic' → ['OpenAI', 'Anthropic']
    Returns empty list if not configured.
    """
    settings = get_settings()
    raw = getattr(settings, "POLZA_AI_PROVIDER_ORDER", "")
    return _parse_comma_list(raw)


def get_polza_provider_ignore() -> List[str]:
    """Get the list of Polza.ai provider slugs for provider.ignore.

    Parses the SAMBA_POLZA_AI_PROVIDER_IGNORE env var (comma-separated).
    Example: 'DeepInfra' → ['DeepInfra']
    Returns empty list if not configured.
    """
    settings = get_settings()
    raw = getattr(settings, "POLZA_AI_PROVIDER_IGNORE", "")
    return _parse_comma_list(raw)


def get_polza_provider_allow_fallbacks() -> bool:
    """Get whether Polza.ai provider fallbacks are allowed."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_PROVIDER_ALLOW_FALLBACKS", True)


def get_polza_provider_sort() -> str:
    """Get the provider sort strategy. Returns '' if not configured."""
    settings = get_settings()
    val = getattr(settings, "POLZA_AI_PROVIDER_SORT", "")
    if val and val.lower().strip() in ("price",):
        return val.lower().strip()
    return ""


def get_polza_provider_max_price() -> Dict[str, float]:
    """Get provider max_price limits.

    Returns a dict with only the configured price limits, e.g.:
    {'prompt': 10, 'completion': 20}
    Returns empty dict if no limits are configured.
    """
    settings = get_settings()
    result: Dict[str, float] = {}

    prompt_price = getattr(settings, "POLZA_AI_PROVIDER_MAX_PRICE_PROMPT", 0.0)
    if prompt_price > 0.0:
        result["prompt"] = prompt_price

    completion_price = getattr(settings, "POLZA_AI_PROVIDER_MAX_PRICE_COMPLETION", 0.0)
    if completion_price > 0.0:
        result["completion"] = completion_price

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Reasoning Helpers
# ═══════════════════════════════════════════════════════════════════════


# Valid reasoning effort levels per Polza.ai API docs
_REASONING_EFFORT_VALUES = {"xhigh", "high", "medium", "low", "minimal", "none"}

# Valid reasoning summary values per Polza.ai API docs
_REASONING_SUMMARY_VALUES = {"auto", "concise", "detailed"}


def get_polza_reasoning_effort() -> str:
    """Get Polza.ai reasoning effort level.

    Returns: 'xhigh', 'high', 'medium', 'low', 'minimal', 'none',
    or '' (not configured).
    """
    settings = get_settings()
    effort = getattr(settings, "POLZA_AI_REASONING_EFFORT", "")
    if effort and effort.lower().strip() in _REASONING_EFFORT_VALUES:
        return effort.lower().strip()
    return ""


def get_polza_reasoning_summary() -> str:
    """Get Polza.ai reasoning summary detail level.

    Returns: 'auto', 'concise', 'detailed', or '' (not configured).
    """
    settings = get_settings()
    summary = getattr(settings, "POLZA_AI_REASONING_SUMMARY", "")
    if summary and summary.lower().strip() in _REASONING_SUMMARY_VALUES:
        return summary.lower().strip()
    return ""


def get_polza_reasoning_enabled() -> bool:
    """Get whether Polza.ai reasoning is enabled."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_REASONING_ENABLED", True)


def get_polza_reasoning_max_tokens() -> int:
    """Get max tokens for Polza.ai reasoning. 0 = not sent."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_REASONING_MAX_TOKENS", 0)


def get_polza_reasoning_exclude() -> bool:
    """Get whether Polza.ai reasoning should be hidden from response."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_REASONING_EXCLUDE", False)


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Sampling / Generation Helpers
# ═══════════════════════════════════════════════════════════════════════


def get_polza_top_k() -> int:
    """Get Polza.ai top_k parameter. Returns 0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_TOP_K", 0)


def get_polza_repetition_penalty() -> float:
    """Get Polza.ai repetition_penalty. Returns 0.0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_REPETITION_PENALTY", 0.0)


def get_polza_top_p() -> float:
    """Get Polza.ai top_p override. Returns 0.0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_TOP_P", 0.0)


def get_polza_frequency_penalty() -> float:
    """Get Polza.ai frequency_penalty. Returns 0.0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_FREQUENCY_PENALTY", 0.0)


def get_polza_presence_penalty() -> float:
    """Get Polza.ai presence_penalty. Returns 0.0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_PRESENCE_PENALTY", 0.0)


def get_polza_seed() -> int:
    """Get Polza.ai seed parameter. Returns 0 if not set (meaning don't send)."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_SEED", 0)


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Web Search Helpers
# ═══════════════════════════════════════════════════════════════════════


_WEB_SEARCH_CONTEXT_SIZES = {"low", "medium", "high"}


def get_polza_web_search_enabled() -> bool:
    """Get whether Polza.ai web search is enabled."""
    settings = get_settings()
    return getattr(settings, "POLZA_AI_WEB_SEARCH_ENABLED", False)


def get_polza_web_search_context_size() -> str:
    """Get Polza.ai web search context size. Default: 'medium'."""
    settings = get_settings()
    size = getattr(settings, "POLZA_AI_WEB_SEARCH_CONTEXT_SIZE", "medium")
    if size.lower().strip() in _WEB_SEARCH_CONTEXT_SIZES:
        return size.lower().strip()
    return "medium"


# ═══════════════════════════════════════════════════════════════════════
#  Extra Body Builder for Polza.ai-specific Parameters
# ═══════════════════════════════════════════════════════════════════════


def build_polza_extra_body(for_tool_use: bool = False) -> Dict[str, Any]:
    """Build the extra_body dict for Polza.ai-specific request parameters.

    This is passed to the OpenAI SDK's chat.completions.create() call
    via the `extra_body` parameter. These fields are Polza.ai extensions
    that are not part of the standard OpenAI API.

    Args:
        for_tool_use: If True, removes provider.only restriction because
            some providers (e.g. Novita) don't support tool use and will
            return 400 BAD_REQUEST. When using tools, Polza.ai needs to
            route to a provider that supports function calling.

    Based on Polza.ai API docs:
    https://polza.ai/docs/api-reference/chat/completions

    Current Polza.ai extensions (v1.8.5-2):
    ── Provider Routing ──
    - provider.only: ["Novita"]              — Only use these providers
    - provider.order: ["OpenAI","Anthropic"]  — Provider priority order
    - provider.ignore: ["DeepInfra"]          — Never use these providers
    - provider.allow_fallbacks: true          — Allow fallback providers
    - provider.sort: "price"                  — Sort by price
    - provider.max_price: {prompt: 10, ...}   — Max price limits

    ── Reasoning ──
    - reasoning.effort: "medium"              — Reasoning effort level
    - reasoning.summary: "auto"               — Summary detail level
    - reasoning.enabled: true                 — Enable reasoning
    - reasoning.max_tokens: 2000              — Max reasoning tokens
    - reasoning.exclude: false                — Hide reasoning

    ── Sampling / Generation ──
    - top_k: 50                               — Top-K sampling
    - repetition_penalty: 1                   — Repetition penalty
    - top_p: 0.7                              — Nucleus sampling override
    - frequency_penalty: 0                    — Frequency penalty
    - presence_penalty: 0                     — Presence penalty
    - seed: 42                                — Deterministic generation

    ── Web Search ──
    - web_search_options: {search_context_size: "medium"} — Built-in web search

    Returns:
        Dict with only the configured extra parameters.
        Empty dict if no extra params are configured.
    """
    extra: Dict[str, Any] = {}

    # ── Provider Routing ──────────────────────────────────────────────────
    provider_only = get_polza_provider_only()
    provider_order = get_polza_provider_order()
    provider_ignore = get_polza_provider_ignore()
    provider_allow_fallbacks = get_polza_provider_allow_fallbacks()
    provider_sort = get_polza_provider_sort()
    provider_max_price = get_polza_provider_max_price()

    # Build provider object only if at least one sub-field is configured
    has_provider_config = bool(
        provider_only or provider_order or provider_ignore
        or not provider_allow_fallbacks  # False is explicit
        or provider_sort
        or provider_max_price
    )

    if has_provider_config:
        provider_obj: Dict[str, Any] = {}

        if provider_only:
            # v1.8.5-2: Skip provider.only when for_tool_use=True
            # Some providers (e.g. Novita) don't support tool/function calling
            # and will return 400 BAD_REQUEST. When using tools, we need to
            # let Polza.ai auto-select a provider that supports function calling.
            if for_tool_use:
                logger.info(
                    "[POLZA-AI] Skipping provider.only=%s for tool-use request "
                    "(some providers don't support function calling)",
                    provider_only,
                )
            else:
                provider_obj["only"] = provider_only
                logger.debug("[POLZA-AI] Extra body: provider.only=%s", provider_only)

        if provider_order:
            provider_obj["order"] = provider_order
            logger.debug("[POLZA-AI] Extra body: provider.order=%s", provider_order)

        if provider_ignore:
            provider_obj["ignore"] = provider_ignore
            logger.debug("[POLZA-AI] Extra body: provider.ignore=%s", provider_ignore)

        # allow_fallbacks defaults to True, only send if False
        if not provider_allow_fallbacks:
            provider_obj["allow_fallbacks"] = False
            logger.debug("[POLZA-AI] Extra body: provider.allow_fallbacks=False")

        if provider_sort:
            provider_obj["sort"] = provider_sort
            logger.debug("[POLZA-AI] Extra body: provider.sort=%s", provider_sort)

        if provider_max_price:
            provider_obj["max_price"] = provider_max_price
            logger.debug("[POLZA-AI] Extra body: provider.max_price=%s", provider_max_price)

        extra["provider"] = provider_obj

    # ── Reasoning ─────────────────────────────────────────────────────────
    reasoning_effort = get_polza_reasoning_effort()
    reasoning_summary = get_polza_reasoning_summary()
    reasoning_enabled = get_polza_reasoning_enabled()
    reasoning_max_tokens = get_polza_reasoning_max_tokens()
    reasoning_exclude = get_polza_reasoning_exclude()

    # Build reasoning object if any sub-field is configured
    has_reasoning_config = bool(
        reasoning_effort
        or reasoning_summary
        or not reasoning_enabled  # False is explicit
        or reasoning_max_tokens > 0
        or reasoning_exclude  # True is explicit
    )

    if has_reasoning_config:
        reasoning_obj: Dict[str, Any] = {}

        # v1.8-2 fix: Polza.ai API returns 400 BAD_REQUEST when both
        # reasoning.effort and reasoning.max_tokens are specified:
        #   "Only one of 'reasoning.effort' and 'reasoning.max_tokens'
        #    can be specified"
        # When both are configured, prefer effort (more common) and skip
        # max_tokens. Log a warning so the admin knows.
        if reasoning_effort and reasoning_max_tokens > 0:
            logger.warning(
                "[POLZA-AI] Both reasoning.effort=%s and reasoning.max_tokens=%d "
                "are configured, but Polza.ai API does not allow both. "
                "Using effort=%s, skipping max_tokens. "
                "Set SAMBA_POLZA_AI_REASONING_MAX_TOKENS=0 to suppress this warning.",
                reasoning_effort, reasoning_max_tokens, reasoning_effort,
            )

        if reasoning_effort:
            reasoning_obj["effort"] = reasoning_effort
            logger.debug("[POLZA-AI] Extra body: reasoning.effort=%s", reasoning_effort)
        elif reasoning_max_tokens > 0:
            # Only send max_tokens when effort is NOT set (mutual exclusivity)
            reasoning_obj["max_tokens"] = reasoning_max_tokens
            logger.debug("[POLZA-AI] Extra body: reasoning.max_tokens=%d", reasoning_max_tokens)

        if reasoning_summary:
            reasoning_obj["summary"] = reasoning_summary
            logger.debug("[POLZA-AI] Extra body: reasoning.summary=%s", reasoning_summary)

        # Only send enabled=False (explicit disable); default True is implied
        if not reasoning_enabled:
            reasoning_obj["enabled"] = False
            logger.debug("[POLZA-AI] Extra body: reasoning.enabled=False")

        if reasoning_exclude:
            reasoning_obj["exclude"] = True
            logger.debug("[POLZA-AI] Extra body: reasoning.exclude=True")

        extra["reasoning"] = reasoning_obj

    # ── Sampling / Generation Parameters ──────────────────────────────────
    top_k = get_polza_top_k()
    if top_k > 0:
        extra["top_k"] = top_k
        logger.debug("[POLZA-AI] Extra body: top_k=%d", top_k)

    rep_penalty = get_polza_repetition_penalty()
    if rep_penalty > 0.0:
        extra["repetition_penalty"] = rep_penalty
        logger.debug("[POLZA-AI] Extra body: repetition_penalty=%.2f", rep_penalty)

    top_p = get_polza_top_p()
    if top_p > 0.0:
        extra["top_p"] = top_p
        logger.debug("[POLZA-AI] Extra body: top_p=%.2f", top_p)

    freq_penalty = get_polza_frequency_penalty()
    if freq_penalty != 0.0:
        extra["frequency_penalty"] = freq_penalty
        logger.debug("[POLZA-AI] Extra body: frequency_penalty=%.2f", freq_penalty)

    pres_penalty = get_polza_presence_penalty()
    if pres_penalty != 0.0:
        extra["presence_penalty"] = pres_penalty
        logger.debug("[POLZA-AI] Extra body: presence_penalty=%.2f", pres_penalty)

    seed = get_polza_seed()
    if seed > 0:
        extra["seed"] = seed
        logger.debug("[POLZA-AI] Extra body: seed=%d", seed)

    # ── Web Search ────────────────────────────────────────────────────────
    web_search_enabled = get_polza_web_search_enabled()
    if web_search_enabled:
        context_size = get_polza_web_search_context_size()
        extra["web_search_options"] = {"search_context_size": context_size}
        logger.debug("[POLZA-AI] Extra body: web_search_options.search_context_size=%s", context_size)

    if extra:
        # Log a summary of all extra body params at INFO level
        summary_parts = []
        for k, v in extra.items():
            if isinstance(v, dict):
                summary_parts.append(f"{k}={{{', '.join(f'{sk}={sv}' for sk, sv in v.items())}}}")
            else:
                summary_parts.append(f"{k}={v}")
        logger.info(
            "[POLZA-AI] Extra body params (%d): %s",
            len(extra),
            ", ".join(summary_parts),
        )

    return extra


# ═══════════════════════════════════════════════════════════════════════
#  AI Client Creation
# ═══════════════════════════════════════════════════════════════════════


def create_polza_client() -> Any:
    """Create an OpenAI-compatible client pointing to Polza.ai.

    Returns an openai.OpenAI client configured with Polza.ai endpoint.
    The Polza.ai API is compatible with the OpenAI SDK format.

    v1.8.3: URL is used AS-IS — no automatic path suffix.
    Polza.ai uses https://polza.ai/api/v1/chat/completions,
    so set SAMBA_POLZA_AI_URL=https://polza.ai/api/v1 in .env.
    The SDK appends /chat/completions automatically.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    base_url = get_polza_base_url()
    api_key = get_polza_api_key()

    if not base_url or not api_key:
        raise ValueError("Polza.ai is not configured. Set SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY in .env")

    logger.info("[POLZA-AI] Creating client for %s", base_url)

    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
        max_retries=0,  # We handle retries ourselves
    )

    return client


def get_effective_ai_provider() -> dict:
    """Determine the AI provider configuration (Polza.ai only — v1.8.5-2).

    Only Polza.ai is supported.

    Returns a dict with:
        - provider: 'polza'
        - base_url: API base URL
        - api_key: API key
        - default_model: default model name
    """
    if is_polza_configured():
        return {
            "provider": "polza",
            "base_url": get_polza_base_url(),
            "api_key": get_polza_api_key(),
            "default_model": get_polza_model(),
        }

    return {
        "provider": "polza",
        "base_url": "",
        "api_key": "",
        "default_model": "openai/gpt-oss-120b",
    }


def create_ai_client() -> Any:
    """Create an OpenAI-compatible client for Polza.ai.

    The URL is used AS-IS — no path suffix is appended.
    Set SAMBA_POLZA_AI_URL=https://polza.ai/api/v1 in .env.
    """
    provider_info = get_effective_ai_provider()

    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    base_url = provider_info["base_url"]
    api_key = provider_info["api_key"]

    if not api_key or not base_url:
        raise ValueError(
            "Polza.ai is not configured. "
            "Set SAMBA_POLZA_AI_URL and SAMBA_POLZA_AI_KEY in .env"
        )

    logger.info(
        "[AI] Creating client for provider=%s, base_url=%s, model=%s",
        provider_info["provider"],
        base_url,
        provider_info["default_model"],
    )

    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
        max_retries=0,
    )

    return client


def get_effective_model(requested_model: Optional[str] = None) -> str:
    """Get the effective model name, considering Polza.ai configuration.

    Priority:
        1. requested_model (per-request override)
        2. Polza.ai model (if Polza.ai is configured)
        3. AI_DEFAULT_MODEL from settings
    """
    if requested_model:
        # Validate it's not a type-name string
        from app.services.ai_service import _validate_model_name
        return _validate_model_name(requested_model)

    provider_info = get_effective_ai_provider()
    return provider_info["default_model"]


# ═══════════════════════════════════════════════════════════════════════
#  Polza.ai Balance API (v1.8.4)
# ═══════════════════════════════════════════════════════════════════════


def get_polza_balance() -> Dict[str, Any]:
    """Fetch the current Polza.ai account balance.

    Calls GET /api/v1/balance on the Polza.ai API.
    Returns a dict with:
        - amount: str — current balance in RUB
        - reserved_amount: str — reserved amount in RUB
        - spent_amount: str — total spent amount in RUB
        - updated_at: str — last update timestamp
        - error: str — error message if the request failed

    Example response from Polza.ai:
        {"amount":"99.90843072","reservedAmount":"0.00000000",
         "spentAmount":"0.09156928","updatedAt":"2026-05-16T11:46:49.643Z"}
    """
    if not is_polza_configured():
        return {"error": "Polza.ai is not configured"}

    base_url = get_polza_base_url()
    api_key = get_polza_api_key()

    # Build balance URL: base_url is like https://polza.ai/api/v1
    # The balance endpoint is /api/v1/balance
    # So we need base_url + /balance
    balance_url = base_url.rstrip("/") + "/balance"

    try:
        import httpx
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                balance_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                },
            )

            if resp.status_code != 200:
                logger.warning(
                    "[POLZA-AI] Balance API returned %d: %s",
                    resp.status_code, resp.text[:200],
                )
                return {
                    "error": f"Balance API returned HTTP {resp.status_code}",
                    "status_code": resp.status_code,
                }

            data = resp.json()
            logger.info(
                "[POLZA-AI] Balance: amount=%s RUB, spent=%s RUB",
                data.get("amount", "?"),
                data.get("spentAmount", "?"),
            )

            return {
                "amount": data.get("amount", "0"),
                "reserved_amount": data.get("reservedAmount", "0"),
                "spent_amount": data.get("spentAmount", "0"),
                "updated_at": data.get("updatedAt", ""),
            }

    except ImportError:
        return {"error": "httpx not installed. Run: pip install httpx"}
    except Exception as exc:
        logger.error("[POLZA-AI] Balance request failed: %s", exc)
        return {"error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════
#  Usage / Cost Extraction from LLM Responses (v1.8.4)
# ═══════════════════════════════════════════════════════════════════════


def extract_usage_info(response: Any) -> Dict[str, Any]:
    """Extract detailed usage and cost information from a Polza.ai LLM response.

    Polza.ai returns a `usage` object in the chat completions response:
        "usage": {
            "prompt_tokens": 57,
            "completion_tokens": 32,
            "total_tokens": 89,
            "completion_tokens_details": {
                "reasoning_tokens": 17,
                "audio_tokens": 0,
                "image_tokens": 0,
                "accepted_prediction_tokens": null,
                "rejected_prediction_tokens": null
            },
            "prompt_tokens_details": {
                "cached_tokens": 0,
                "audio_tokens": 0,
                "video_tokens": 0
            },
            "server_tool_use": null,
            "cost_rub": 0.00074863,
            "cost": 0.00074863,
            "plugins": null
        }

    This function safely extracts all available fields and returns a dict.
    Works with Polza.ai responses (cost_rub is Polza.ai-specific).

    Args:
        response: The OpenAI SDK response object.

    Returns:
        Dict with usage details:
        {
            "prompt_tokens": int,
            "completion_tokens": int,
            "total_tokens": int,
            "reasoning_tokens": int or None,
            "cached_tokens": int or None,
            "audio_tokens": int or None,
            "image_tokens": int or None,
            "cost_rub": float or None,     — Polza.ai only
            "cost": float or None,          — Polza.ai only (alias for cost_rub)
            "provider": str,                — "polza"
        }
    """
    result: Dict[str, Any] = {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "reasoning_tokens": None,
        "cached_tokens": None,
        "audio_tokens": None,
        "image_tokens": None,
        "cost_rub": None,
        "cost": None,
        "provider": get_effective_ai_provider()["provider"],
    }

    if not response or not hasattr(response, "usage") or response.usage is None:
        return result

    usage = response.usage

    # Standard OpenAI fields
    result["prompt_tokens"] = getattr(usage, "prompt_tokens", None)
    result["completion_tokens"] = getattr(usage, "completion_tokens", None)
    result["total_tokens"] = getattr(usage, "total_tokens", None)

    # Polza.ai cost fields — these are in the raw usage object but may not
    # be mapped by the OpenAI SDK. Try getattr first, then check __dict__.
    cost_rub = getattr(usage, "cost_rub", None)
    if cost_rub is None:
        # The OpenAI SDK may not expose these as attributes,
        # but they might be in the raw model_extra or __dict__
        model_extra = getattr(usage, "model_extra", None) or {}
        cost_rub = model_extra.get("cost_rub")
    if cost_rub is None:
        raw_dict = getattr(usage, "__dict__", {})
        cost_rub = raw_dict.get("cost_rub")
    result["cost_rub"] = cost_rub
    result["cost"] = cost_rub  # cost == cost_rub for Polza.ai

    # Completion tokens details (reasoning, audio, image)
    comp_details = getattr(usage, "completion_tokens_details", None)
    if comp_details:
        result["reasoning_tokens"] = getattr(comp_details, "reasoning_tokens", None)
        result["audio_tokens"] = getattr(comp_details, "audio_tokens", None)
        result["image_tokens"] = getattr(comp_details, "image_tokens", None)
    else:
        # Try model_extra or raw dict
        model_extra = getattr(usage, "model_extra", None) or {}
        comp_details_raw = model_extra.get("completion_tokens_details")
        if isinstance(comp_details_raw, dict):
            result["reasoning_tokens"] = comp_details_raw.get("reasoning_tokens")
            result["audio_tokens"] = comp_details_raw.get("audio_tokens")
            result["image_tokens"] = comp_details_raw.get("image_tokens")

    # Prompt tokens details (cached)
    prompt_details = getattr(usage, "prompt_tokens_details", None)
    if prompt_details:
        result["cached_tokens"] = getattr(prompt_details, "cached_tokens", None)
    else:
        model_extra = getattr(usage, "model_extra", None) or {}
        prompt_details_raw = model_extra.get("prompt_tokens_details")
        if isinstance(prompt_details_raw, dict):
            result["cached_tokens"] = prompt_details_raw.get("cached_tokens")

    return result


def format_usage_log(usage_info: Dict[str, Any]) -> str:
    """Format usage info into a concise log string.

    Example output:
        "tokens: 57+32=89, reasoning=17, cost=0.000749 RUB"
    """
    parts = []

    pt = usage_info.get("prompt_tokens")
    ct = usage_info.get("completion_tokens")
    tt = usage_info.get("total_tokens")
    if pt is not None or ct is not None:
        parts.append(f"tokens: {pt or '?'}+{ct or '?'}={tt or '?'}")

    rt = usage_info.get("reasoning_tokens")
    if rt is not None and rt > 0:
        parts.append(f"reasoning={rt}")

    cached = usage_info.get("cached_tokens")
    if cached is not None and cached > 0:
        parts.append(f"cached={cached}")

    cost = usage_info.get("cost_rub")
    if cost is not None:
        try:
            parts.append(f"cost={float(cost):.6f} RUB")
        except (ValueError, TypeError):
            parts.append(f"cost={cost}")

    return ", ".join(parts) if parts else "no usage data"


def get_polza_config_summary() -> Dict[str, Any]:
    """Get a summary of Polza.ai configuration for diagnostics.

    Used by the /ai/config endpoint and debug scripts.
    Shows all configured provider/reasoning/sampling parameters.
    """
    provider_info = get_effective_ai_provider()
    summary: Dict[str, Any] = {
        "active_provider": provider_info["provider"],
        "polza_configured": is_polza_configured(),
        "polza_url": get_polza_base_url() if is_polza_configured() else None,
        "polza_model": get_polza_model() if is_polza_configured() else None,
    }

    if is_polza_configured():
        # Provider routing
        provider_only = get_polza_provider_only()
        provider_order = get_polza_provider_order()
        provider_ignore = get_polza_provider_ignore()
        provider_sort = get_polza_provider_sort()
        provider_max_price = get_polza_provider_max_price()

        summary["polza_provider"] = {
            "only": provider_only or None,
            "order": provider_order or None,
            "ignore": provider_ignore or None,
            "allow_fallbacks": get_polza_provider_allow_fallbacks(),
            "sort": provider_sort or None,
            "max_price": provider_max_price or None,
        }

        # Reasoning
        reasoning_effort = get_polza_reasoning_effort()
        reasoning_summary = get_polza_reasoning_summary()

        summary["polza_reasoning"] = {
            "effort": reasoning_effort or None,
            "summary": reasoning_summary or None,
            "enabled": get_polza_reasoning_enabled(),
            "max_tokens": get_polza_reasoning_max_tokens() if get_polza_reasoning_max_tokens() > 0 else None,
            "exclude": get_polza_reasoning_exclude(),
        }

        # Sampling / Generation
        top_k = get_polza_top_k()
        rep_penalty = get_polza_repetition_penalty()
        top_p = get_polza_top_p()
        freq_penalty = get_polza_frequency_penalty()
        pres_penalty = get_polza_presence_penalty()
        seed = get_polza_seed()

        sampling: Dict[str, Any] = {}
        if top_k > 0:
            sampling["top_k"] = top_k
        if rep_penalty > 0.0:
            sampling["repetition_penalty"] = rep_penalty
        if top_p > 0.0:
            sampling["top_p"] = top_p
        if freq_penalty != 0.0:
            sampling["frequency_penalty"] = freq_penalty
        if pres_penalty != 0.0:
            sampling["presence_penalty"] = pres_penalty
        if seed > 0:
            sampling["seed"] = seed
        summary["polza_sampling"] = sampling or None

        # Web search
        web_search_enabled = get_polza_web_search_enabled()
        summary["polza_web_search"] = {
            "enabled": web_search_enabled,
            "context_size": get_polza_web_search_context_size() if web_search_enabled else None,
        }

        # Full extra_body preview
        summary["polza_extra_body"] = build_polza_extra_body()

        # v1.8.4: Balance info
        balance_data = get_polza_balance()
        if "error" not in balance_data:
            summary["polza_balance"] = balance_data
        else:
            summary["polza_balance"] = None

    return summary
