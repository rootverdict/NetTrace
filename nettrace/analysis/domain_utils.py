from __future__ import annotations

import re


# Labels may contain letters, digits, hyphen and underscore. Underscore-prefixed
# labels are legitimate in DNS (_dmarc, _dkim, SRV names like _sip._tcp) and were
# previously rejected outright because the IDNA codec forbids them. Hyphens may
# not lead or trail a label; underscores may appear anywhere.
HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_domain(value: str) -> str | None:
    """Return a validated, lower-case ASCII hostname or None."""
    if not value:
        return None
    candidate = value.strip().rstrip(".")
    if not candidate or candidate != value.rstrip("."):
        return None
    if any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in candidate):
        return None
    if candidate.isascii():
        # Skip the IDNA codec for plain-ASCII names: it rejects underscores and
        # is otherwise a no-op here. The regex below enforces label validity.
        normalized = candidate.lower()
    else:
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
