"""Sort strategies for case_id / system_id / resource_id.

The repository says rows are "sorted by case_id" and steps are sorted by
"system_id and resource_id in ascending order" but never says whether
``case_100`` sorts before ``case_33`` (lexical) or after it (natural/numeric).
The 32 public samples cannot tell the two apart (their IDs are zero-padded and
no multi-item group differs between the two orders), so this module makes the
choice an explicit, named, configurable setting instead of a hidden assumption.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Tuple


class SortStrategy(str, Enum):
    LEXICAL = "lexical"   # plain string comparison (code-point order)
    NATURAL = "natural"   # digit runs compared as integers: case_9 < case_10
    EITHER = "either"     # accept a file consistent with lexical OR natural
    NONE = "none"         # do not check this axis


# DEFAULT: EITHER. Reason: the repository does not settle the question, so the
# validator refuses to pick a winner on the author's behalf. It accepts a file
# that is wholly lexical or wholly natural, rejects a file that is neither, and
# records which one(s) the file satisfied (see ValidationReport.ordering and an
# INFO issue when exactly one is satisfied). The final writer (a later stage)
# should pin one concrete strategy and validate with it.
DEFAULT_CASE_ID_ORDER = SortStrategy.EITHER
DEFAULT_RESOURCE_ORDER = SortStrategy.EITHER

CONCRETE_STRATEGIES: Tuple[SortStrategy, ...] = (
    SortStrategy.LEXICAL,
    SortStrategy.NATURAL,
)

_DIGITS = re.compile(r"(\d+)")


def lexical_key(value: str) -> Tuple[str]:
    return (value,)


def natural_key(value: str) -> Tuple[Tuple[int, int, int, str], ...]:
    """Key that orders digit runs numerically.

    Each chunk becomes a comparable 4-tuple ``(is_text, number, width, text)``.
    Ties between numerically equal runs (``005`` vs ``5``) are broken by width so
    the order is total and deterministic; the raw string is the final tiebreak.
    """
    chunks = []
    for part in _DIGITS.split(value):
        if not part:
            continue
        if part.isdigit():
            chunks.append((0, int(part), len(part), ""))
        else:
            chunks.append((1, 0, 0, part))
    chunks.append((2, 0, 0, value))
    return tuple(chunks)


def sort_key(strategy: SortStrategy, value: str):
    if strategy is SortStrategy.LEXICAL:
        return lexical_key(value)
    if strategy is SortStrategy.NATURAL:
        return natural_key(value)
    raise ValueError(
        "sort_key needs a concrete strategy (lexical or natural), got %r" % (strategy,)
    )


def concrete_strategies(strategy: SortStrategy) -> Tuple[SortStrategy, ...]:
    """Concrete strategies a configured strategy accepts (``NONE`` -> empty)."""
    if strategy is SortStrategy.EITHER:
        return CONCRETE_STRATEGIES
    if strategy is SortStrategy.NONE:
        return ()
    return (strategy,)
