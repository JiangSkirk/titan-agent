"""Memory Flush: consolidate trusted experience before compression drops tokens."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from echo_core.memory.experience import ExperienceBank
from echo_core.taint import USER_TURN, WEB_CONTENT


def flush_before_compress(
    state_dir: Path,
    owner: str,
    pattern_text: str,
    action_hint: str,
    *,
    taint: int,
    signals: dict[str, float] | None = None,
) -> Any:
    """Deep-write only if taint is trusted. Untrusted sources are dropped."""

    if taint & WEB_CONTENT or taint != USER_TURN:
        return None
    bank = ExperienceBank(state_dir)
    return bank.consolidate_deep(
        owner,
        pattern_text,
        action_hint,
        taint=taint,
        signals=signals
        or {
            "relevance": 0.8,
            "frequency": 0.7,
            "query_diversity": 0.6,
            "recency": 0.9,
            "consolidation": 0.7,
            "conceptual_richness": 0.5,
            "recall_count": 1,
            "unique_queries": 1,
        },
    )
