from __future__ import annotations

import re


HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str | None:
    """Return a validated, lower-case ASCII hostname or None."""
    if not value:
        return None
    candidate = value.strip().rstrip(".")
    if not candidate or candidate != value.rstrip("."):
        return None
    if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in candidate):
        return None
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not normalized or len(normalized) > 253:
        return None
    labels = normalized.split(".")
    if any(not label or len(label) > 63 or not HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return normalized
