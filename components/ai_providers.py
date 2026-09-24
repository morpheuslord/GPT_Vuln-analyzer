"""Agentic, multi-provider AI analysis engine for GVA, built on Pydantic AI.

Each provider is a Pydantic AI agent that returns a *validated* structured object
(see ``components/schemas.py``). When more than one provider is selected they each
analyse the scan independently and concurrently, then a **deliberation agent**
(one of the selected models) reconciles those independent analyses into a single
consolidated report — instead of dumping N parallel results on the user.

Provider SDKs are imported lazily so the tool loads even if only some are present.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Type

from dotenv import load_dotenv
from pydantic import BaseModel

from components.schemas import SCAN_SCHEMAS

# Load .env before any key / model id is resolved, regardless of import order.
load_dotenv()
# Keep CLI output clean (no Pydantic AI startup banner).
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

# Latest, economical default model per provider (verified Sep 2026); override
# each with the matching env var.
DEFAULT_MODELS: Dict[str, str] = {
    "openai": "gpt-5.6-luna",       # GPT-5.6 family, ~$0.20/$1.20 per 1M tokens
    "claude": "claude-haiku-4-5",   # cheapest current Claude, $1/$5 per 1M tokens
    "gemini": "gemini-3.6-flash",   # latest Flash, ~$0.75/$3.75 per 1M tokens
    "ollama": "llama3",             # local, free
}

MODEL_ENV_VARS: Dict[str, str] = {
    "openai": "OPENAI_MODEL",
    "claude": "ANTHROPIC_MODEL",
    "gemini": "GEMINI_MODEL",
    "ollama": "OLLAMA_MODEL",
}


@dataclass(frozen=True)
class ProviderInfo:
    key: str
    label: str
    needs_key: bool


PROVIDER_CLASSES: Dict[str, ProviderInfo] = {
    "openai": ProviderInfo("openai", "OpenAI", True),
    "claude": ProviderInfo("claude", "Anthropic Claude", True),
    "gemini": ProviderInfo("gemini", "Google Gemini", True),
    "ollama": ProviderInfo("ollama", "Ollama (local)", False),
}

PROVIDER_ALIASES = {
    "gpt": "openai",
    "chatgpt": "openai",
    "anthropic": "claude",
    "bard": "gemini",
    "google": "gemini",
    "llama": "ollama",
    "local": "ollama",
}

# Per-scan instructions. Structure is enforced by the schema, so these focus on
# the analysis task, not the output format.
INSTRUCTIONS: Dict[str, str] = {
    "nmap": (
        "You are a penetration tester analysing raw Nmap scan output. Work from a "
        "pentester's viewpoint, be concise, leave a field empty when the data does "
        "not support it, and derive the critical score from any CVEs or the nature "
        "of the exposed services."
    ),
    "dns": (
        "You are a penetration tester analysing DNS reconnaissance output. Populate "
        "each record type from the supplied data, note reverse-DNS and zone-transfer "
        "findings, and leave fields empty where nothing was found."
    ),
    "jwt": (
        "You are a penetration tester analysing a JSON Web Token. Use the supplied "
        "algorithm, header and payload; enumerate realistic JWT attacks and suggest "
        "endpoints worth testing."
    ),
}

DELIBERATION_INSTRUCTION = (
    "You are a senior security analyst reconciling several independent AI analyses "
    "of the SAME scan. Produce one consolidated, accurate report: keep findings "
    "that multiple analyses agree on, include credible findings even if only one "
    "raised them, drop contradictions and anything that looks hallucinated, and "
    "never invent data that no analysis supports."
)


def normalize_selection(selection: Iterable[str] | str) -> List[str]:
    """Turn a user selection (str/list, aliases, ``all``) into provider keys."""
    if isinstance(selection, str):
        selection = [part.strip() for part in selection.split(",") if part.strip()]
    keys: List[str] = []
    for item in selection:
        item = item.strip().lower()
        if item == "all":
            return list(PROVIDER_CLASSES)
        item = PROVIDER_ALIASES.get(item, item)
        if item in PROVIDER_CLASSES and item not in keys:
            keys.append(item)
    return keys


def config_from_keys(
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    gemini_key: Optional[str] = None,
    **_ignored: Any,
) -> Dict[str, Dict[str, Any]]:
    """Build the engine config mapping from individual credentials.

    Extra keyword arguments (e.g. legacy runpod_* values) are accepted and
    ignored so older call sites keep working.
    """
    return {
        "openai": {"api_key": openai_key},
        "claude": {"api_key": anthropic_key},
        "gemini": {"api_key": gemini_key},
        "ollama": {},
    }


def _model_id(key: str, cfg: Dict[str, Any]) -> str:
    return cfg.get("model") or os.getenv(MODEL_ENV_VARS.get(key, ""), "") or DEFAULT_MODELS[key]


def _is_available(key: str, cfg: Dict[str, Any]) -> bool:
    if PROVIDER_CLASSES[key].needs_key:
        return bool(cfg.get("api_key"))
    return True


def _build_model(key: str, cfg: Dict[str, Any]):
    """Construct a Pydantic AI model object for a provider (lazy imports)."""
    model_id = _model_id(key, cfg)
    if key == "openai":
        # GPT-5.x reasoning models require the Responses API for tool/structured
        # output (chat/completions rejects tools alongside reasoning_effort).
        from pydantic_ai.models.openai import OpenAIResponsesModel
        from pydantic_ai.providers.openai import OpenAIProvider
        return OpenAIResponsesModel(model_id, provider=OpenAIProvider(api_key=cfg["api_key"]))
    if key == "claude":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider
        return AnthropicModel(model_id, provider=AnthropicProvider(api_key=cfg["api_key"]))
    if key == "gemini":
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider
        return GoogleModel(model_id, provider=GoogleProvider(api_key=cfg["api_key"]))
    if key == "ollama":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider
        base_url = cfg.get("base_url", "http://localhost:11434/v1")
        return OpenAIChatModel(model_id, provider=OpenAIProvider(base_url=base_url, api_key="ollama"))
    raise ValueError(f"Unknown provider: {key}")


def _agent(model, scan_type: str, output_type: Type[BaseModel], instructions: str):
    from pydantic_ai import Agent
    return Agent(model, output_type=output_type, instructions=instructions)


@dataclass
class AnalysisReport:
    """Result of an analysis run across one or more providers."""

    scan_type: str
    individual: Dict[str, dict] = field(default_factory=dict)   # provider -> structured dict
    errors: Dict[str, str] = field(default_factory=dict)         # provider -> error message
    consolidated: Optional[dict] = None                          # deliberated result (multi-model)
    summarizer: Optional[str] = None                             # provider that deliberated

    @property
    def contributors(self) -> List[str]:
        return list(self.individual)

    @property
    def primary(self) -> Optional[dict]:
        """The single result a caller should show: consolidated, else the lone one."""
        if self.consolidated is not None:
            return self.consolidated
        if len(self.individual) == 1:
            return next(iter(self.individual.values()))
        return None


class AIEngine:
    """Runs a scan-type analysis across providers with an agentic deliberation step."""

    def __init__(self, config: Dict[str, Dict[str, Any]], summarizer: Optional[str] = None,
                 progress: bool = False) -> None:
        self.config = config
        self.summarizer = summarizer
        self.progress = progress

    def run(self, scan_type: str, data: str, selection: Iterable[str] | str,
            summarizer: Optional[str] = None) -> AnalysisReport:
        if scan_type not in SCAN_SCHEMAS:
            raise ValueError(f"Unknown scan type: {scan_type}")
        providers = normalize_selection(selection)
        if not providers:
            raise ValueError("No valid AI providers selected.")
        summarizer = summarizer or self.summarizer

        if self.progress:
            from components.progress import LiveScan
            with LiveScan(f"GVA {scan_type.upper()} — AI analysis") as reporter:
                return asyncio.run(self._run(scan_type, data, providers, summarizer, reporter))
        return asyncio.run(self._run(scan_type, data, providers, summarizer, None))

    async def _run(self, scan_type: str, data: str, providers: List[str],
                   summarizer: Optional[str], reporter=None) -> AnalysisReport:
        schema = SCAN_SCHEMAS[scan_type]
        report = AnalysisReport(scan_type=scan_type)

        usable, unusable = [], []
        for key in providers:
            (usable if _is_available(key, self.config.get(key, {})) else unusable).append(key)

        if reporter:
            reporter.start_providers({k: PROVIDER_CLASSES[k].label for k in providers})
        for key in unusable:
            report.errors[key] = f"{PROVIDER_CLASSES[key].label} is not configured (missing key)."
            if reporter:
                reporter.provider_done(key, error="not configured")

        # 1) Independent analysis per provider, concurrently.
        async def analyse(key: str):
            try:
                model = _build_model(key, self.config.get(key, {}))
                agent = _agent(model, scan_type, schema, INSTRUCTIONS[scan_type])
                result = await agent.run(f"Data to analyse:\n{data}")
                return key, result.output.model_dump(), None
            except Exception as exc:  # noqa: BLE001 - surface any provider failure
                return key, None, f"{PROVIDER_CLASSES[key].label} failed: {exc}"

        for key, output, err in await asyncio.gather(*(analyse(k) for k in usable)):
            if err:
                report.errors[key] = err
            else:
                report.individual[key] = output
            if reporter:
                reporter.provider_done(key, error=err)

        # 2) Deliberate when more than one provider produced a result.
        if len(report.individual) > 1:
            summarizer = self._pick_summarizer(summarizer, list(report.individual))
            if reporter:
                reporter.start_deliberation(PROVIDER_CLASSES[summarizer].label)
            try:
                report.consolidated = await self._deliberate(scan_type, schema, summarizer, report.individual)
                report.summarizer = summarizer
                if reporter:
                    reporter.deliberation_done()
            except Exception as exc:  # noqa: BLE001
                report.errors["deliberation"] = f"Deliberation ({summarizer}) failed: {exc}"
                if reporter:
                    reporter.deliberation_done(error=str(exc))

        return report

    def _pick_summarizer(self, requested: Optional[str], available: List[str]) -> str:
        if requested:
            requested = PROVIDER_ALIASES.get(requested.lower(), requested.lower())
            if requested in available:
                return requested
        env_choice = os.getenv("GVA_SUMMARIZER", "").lower()
        env_choice = PROVIDER_ALIASES.get(env_choice, env_choice)
        if env_choice in available:
            return env_choice
        return available[0]

    async def _deliberate(self, scan_type: str, schema: Type[BaseModel],
                          summarizer: str, individual: Dict[str, dict]) -> dict:
        import json

        model = _build_model(summarizer, self.config.get(summarizer, {}))
        agent = _agent(model, scan_type, schema, DELIBERATION_INSTRUCTION)
        analyses = "\n\n".join(
            f"Analysis from {PROVIDER_CLASSES[k].label}:\n{json.dumps(v, indent=2)}"
            for k, v in individual.items()
        )
        prompt = f"Independent analyses of the same {scan_type} scan:\n\n{analyses}"
        result = await agent.run(prompt)
        return result.output.model_dump()
