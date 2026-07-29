"""Display caps for the human-readable reports.

The JSON export is deliberately never capped -- it stays the complete record.
The HTML and PDF reports are for reading, so they bound each section, and the
rule here is that *every* section which hides rows says so. Silently dropping
evidence is worse than showing none: an analyst who sees 500 artifacts and no
notice has no reason to suspect another 40,000 exist.

Keeping the limits in one module also stops the HTML template and the PDF
renderer from drifting apart, and stops a cap from disagreeing with the
condition that reports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

MAX_FINDINGS = 500
MAX_IOCS = 1000
MAX_OBSERVED_ARTIFACTS = 500
MAX_TIMELINE = 200


@dataclass(frozen=True)
class LimitedSection:
    """A capped slice of a report section, plus what it left out."""

    items: list[Any]
    total: int
    ordering: str

    @property
    def hidden(self) -> int:
        return max(0, self.total - len(self.items))

    @property
    def truncated(self) -> bool:
        return self.hidden > 0

    @property
    def notice(self) -> str:
        if not self.truncated:
            return ""
        return (
            f"Showing the {self.ordering} {len(self.items):,} of {self.total:,} entries. "
            f"{self.hidden:,} not shown -- see the JSON output for the complete list."
        )


def limited(items: Iterable[Any], limit: int, ordering: str = "first") -> LimitedSection:
    """Cap `items` at `limit`, recording the true total for disclosure.

    `ordering` describes how the kept entries were chosen so the notice can say
    "the highest-scoring 500" rather than a misleading "the first 500".
    """
    values = list(items)
    return LimitedSection(items=values[:limit], total=len(values), ordering=ordering)
