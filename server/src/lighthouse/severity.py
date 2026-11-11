from __future__ import annotations

from enum import Enum
from typing import Final


class Severity(Enum):
    """Alert severity, ordered from least to most severe.

    The member order must match the declaration order of the `lh.severity` enum in the
    database, because the database enforces the severity floor with `>=` on that enum.
    A test compares the two.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    # Comparisons are by rank, not by the string value: "critical" < "high" alphabetically,
    # and a lexical comparison here would quietly invert the severity floor.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_RANK: Final[dict[Severity, int]] = {member: index for index, member in enumerate(Severity)}
