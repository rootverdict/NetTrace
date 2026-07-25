from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path

import yaml

from nettrace.analysis.domain_utils import normalize_domain
from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import DNSEvent
from nettrace.models.findings import Finding

DEFAULT_ALLOWLIST_PATH = Path(__file__).parent.parent / "rules" / "dga_allowlist.yaml"

COMMON_BIGRAMS = {
    "th",
    "he",
    "in",
    "er",
    "an",
    "re",
    "on",
    "at",
    "en",
    "nd",
    "or",
    "es",
    "to",
    "te",
    "st",
    "ar",
    "ng",
}


@lru_cache(maxsize=8)
def _load_dga_allowlist(path: Path = DEFAULT_ALLOWLIST_PATH) -> dict[str, list[str]]:
    if not path.exists():
        return {"domains": [], "suffixes": [], "regexes": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        "domains": [item.lower().lstrip(".") for item in data.get("domains", [])],
        "suffixes": [item.lower().lstrip(".") for item in data.get("suffixes", [])],
        "regexes": data.get("regexes", []),
    }


def _matches_suffix(normalized: str, suffix: str) -> bool:
    # Boundary-safe: "attacker-microsoft.com".endswith("microsoft.com") would be a
    # false allow, so require an exact match or a "." boundary before the suffix.
    return normalized == suffix or normalized.endswith("." + suffix)


def is_allowlisted_domain(domain: str, allowlist: dict[str, list[str]] | None = None) -> bool:
    rules = _load_dga_allowlist() if allowlist is None else allowlist
    normalized = normalize_domain(domain)
    if normalized is None:
        return False
    if any(normalized == exact for exact in rules.get("domains", [])):
        return True
    if any(_matches_suffix(normalized, suffix) for suffix in rules.get("suffixes", [])):
        return True
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in rules.get("regexes", []))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Labels that never carry a DGA signal on their own -- generic subdomain/hostname
# prefixes seen in front of a registered domain (www.<random>.biz, cdn.<random>.biz).
_GENERIC_PREFIX_LABELS = {
    "www", "cdn", "api", "mail", "smtp", "ftp", "ns1", "ns2", "vpn", "mx",
    "static", "img", "img1", "img2", "cdn1", "cdn2", "app", "m", "web",
}


def domain_label(domain: str) -> str:
    """Backward-compatible single-label accessor: still the leftmost label.

    Kept for callers/tests that only care about one label; scoring itself uses
    candidate_labels() below so it isn't fooled by a benign www/cdn prefix.
    """
    return domain.split(".")[0].lower()


def candidate_labels(domain: str) -> list[str]:
    """Labels worth DGA-scoring, skipping a leading generic hostname prefix.

    This is a lightweight approximation of eTLD+1 (no public-suffix-list
    dependency): for "www.xj3k9q2z7m1p0a8c.biz" it returns
    ["xj3k9q2z7m1p0a8c"], not ["www"]. It does not handle multi-part public
    suffixes like ".co.uk" correctly -- that needs a real PSL lookup and is
    tracked as a follow-up, not silently claimed as solved here.
    """
    labels = [label.lower() for label in domain.rstrip(".").split(".") if label]
    if not labels:
        return []
    if len(labels) == 1:
        return labels
    if labels[0] in _GENERIC_PREFIX_LABELS and len(labels) > 2:
        return labels[1:-1] or labels[:1]
    return labels[:-1]


def _label_score(label: str) -> float:
    cleaned = re.sub(r"[^a-z0-9]", "", label)
    if len(cleaned) < 8:
        return 0.0
    entropy = shannon_entropy(cleaned)
    bigrams = [cleaned[index : index + 2] for index in range(len(cleaned) - 1)]
    common = sum(1 for bigram in bigrams if bigram in COMMON_BIGRAMS)
    common_ratio = common / max(1, len(bigrams))
    digit_ratio = sum(1 for char in cleaned if char.isdigit()) / len(cleaned)
    entropy_component = min(1.0, entropy / 4.0)
    language_component = 1.0 - common_ratio
    digit_component = min(1.0, digit_ratio * 2.0)
    return round((entropy_component * 0.5) + (language_component * 0.35) + (digit_component * 0.15), 3)


def dga_score(domain: str) -> float:
    """Highest DGA score across candidate labels. See scored_label() for which
    label produced it."""
    labels = candidate_labels(domain) or [domain_label(domain)]
    return max((_label_score(label) for label in labels), default=0.0)


def scored_label(domain: str) -> str:
    labels = candidate_labels(domain) or [domain_label(domain)]
    return max(labels, key=_label_score, default=domain_label(domain))


def score_domains(dns_events: list[DNSEvent], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    score_threshold = float(thresholds.get("dga_score_threshold", 0.6))
    entropy_threshold = float(thresholds.get("dga_entropy_threshold", 3.4))
    allowlist = _load_dga_allowlist()
    seen: set[str] = set()
    for event in dns_events:
        normalized_query = normalize_domain(event.query)
        if normalized_query is None:
            continue
        if normalized_query in seen:
            continue
        seen.add(normalized_query)
        if is_allowlisted_domain(event.query, allowlist):
            continue
        label = scored_label(normalized_query)
        score = dga_score(normalized_query)
        entropy = shannon_entropy(re.sub(r"[^a-z0-9]", "", label))
        if score >= score_threshold and entropy >= entropy_threshold:
            findings.append(
                Finding(
                    title="Possible DGA domain",
                    description="Domain structure has high entropy and weak language-like character patterns.",
                    category="dga_domain",
                    timestamp=event.timestamp,
                    confidence="high" if score >= 0.8 else "medium",
                    evidence={
                        "domain": event.query,
                        "scored_label": label,
                        "entropy": round(entropy, 3),
                        "dga_score": score,
                        **packet_evidence(event.packet_number),
                    },
                    tags=["dga"],
                )
            )
    return findings
