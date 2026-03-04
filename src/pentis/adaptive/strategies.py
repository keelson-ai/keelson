"""Mutation selection strategies."""

from __future__ import annotations

import random
from collections import Counter

from pentis.core.models import MutationType

# All available mutation types in order
ALL_MUTATIONS = list(MutationType)

PROGRAMMATIC_TYPES = [
    MutationType.BASE64_ENCODE,
    MutationType.LEETSPEAK,
    MutationType.CONTEXT_OVERFLOW,
]

LLM_TYPES = [
    MutationType.PARAPHRASE,
    MutationType.ROLEPLAY_WRAP,
    MutationType.GRADUAL_ESCALATION,
]


def round_robin(history: list[MutationType], available: list[MutationType] | None = None) -> MutationType:
    """Select the next mutation type in round-robin order.

    Cycles through available mutations. If history is empty, starts from the first.
    """
    pool = available or ALL_MUTATIONS
    if not history:
        return pool[0]
    last = history[-1]
    try:
        idx = pool.index(last)
        return pool[(idx + 1) % len(pool)]
    except ValueError:
        return pool[0]


def weighted_by_history(
    history: list[MutationType],
    success_map: dict[MutationType, int] | None = None,
    available: list[MutationType] | None = None,
) -> MutationType:
    """Select mutation type weighted by past success rates.

    Mutations that have produced more VULNERABLE results get higher weight.
    Unexplored mutations get a bonus.
    """
    pool = available or ALL_MUTATIONS
    if not pool:
        raise ValueError("No available mutation types")

    if not success_map:
        return random.choice(pool)

    # Count how many times each type has been tried
    tried = Counter(history)
    max_success = max(success_map.values()) if success_map else 1

    weights: list[float] = []
    for mt in pool:
        successes = success_map.get(mt, 0)
        times_tried = tried.get(mt, 0)
        # Exploration bonus for untried mutations
        if times_tried == 0:
            weights.append(max_success + 1)
        else:
            weights.append(max(successes, 0.1))

    return random.choices(pool, weights=weights, k=1)[0]


def should_mutate(success_rate: float, low_threshold: float = 0.05, high_threshold: float = 0.80) -> bool:
    """Return True when a partial success rate warrants mutation attempts.

    The sweet spot is attacks that sometimes succeed (above noise) but aren't
    fully bypassing defences (below saturation). Outside that window mutations
    are unlikely to add signal.

    Args:
        success_rate: Fraction of trials that returned a VULNERABLE verdict (0.0–1.0).
        low_threshold:  Below this the attack shows no signal — skip mutations.
        high_threshold: Above this the attack already saturates — skip mutations.

    Returns:
        True iff ``low_threshold <= success_rate <= high_threshold``.
    """
    return low_threshold <= success_rate <= high_threshold


def select_mutation(
    strategy: str,
    history: list[MutationType],
    success_map: dict[MutationType, int] | None = None,
    available: list[MutationType] | None = None,
) -> MutationType:
    """Select a mutation type based on the given strategy name.

    Args:
        strategy: "round_robin" or "weighted"
        history: List of previously used mutation types
        success_map: Mapping of mutation type → number of successful (VULNERABLE) results
        available: Subset of mutations to choose from
    """
    if strategy == "round_robin":
        return round_robin(history, available)
    elif strategy == "weighted":
        return weighted_by_history(history, success_map, available)
    else:
        raise ValueError(f"Unknown strategy: {strategy}")
