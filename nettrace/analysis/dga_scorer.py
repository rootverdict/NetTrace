from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path

import yaml

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
        return {"suffixes": [], "contains": [], "regexes": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        "suffixes": [item.lower() for item in data.get("suffixes", [])],
        "contains": [item.lower() for item in data.get("contains", [])],
        "regexes": data.get("regexes", []),
    }


def is_allowlisted_domain(domain: str, allowlist: dict[str, list[str]] | None = None) -> bool:
    rules = _load_dga_allowlist() if allowlist is None else allowlist
    normalized = domain.lower().rstrip(".")
    if any(normalized.endswith(suffix) for suffix in rules.get("suffixes", [])):
        return True
    if any(token in normalized for token in rules.get("contains", [])):
        return True
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in rules.get("regexes", []))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def domain_label(domain: str) -> str:
    return domain.split(".")[0].lower()


def dga_score(domain: str) -> float:
    label = re.sub(r"[^a-z0-9]", "", domain_label(domain))
    if len(label) < 8:
        return 0.0
    entropy = shannon_entropy(label)
    bigrams = [label[index : index + 2] for index in range(len(label) - 1)]
    common = sum(1 for bigram in bigrams if bigram in COMMON_BIGRAMS)
    common_ratio = common / max(1, len(bigrams))
    digit_ratio = sum(1 for char in label if char.isdigit()) / len(label)
    entropy_component = min(1.0, entropy / 4.0)
    language_component = 1.0 - common_ratio
    digit_component = min(1.0, digit_ratio * 2.0)
    return round((entropy_component * 0.5) + (language_component * 0.35) + (digit_component * 0.15), 3)


def score_domains(dns_events: list[DNSEvent], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    score_threshold = float(thresholds.get("dga_score_threshold", 0.6))
    entropy_threshold = float(thresholds.get("dga_entropy_threshold", 3.4))
    allowlist = _load_dga_allowlist()
    seen: set[str] = set()
    for event in dns_events:
        normalized_query = event.query.lower().rstrip(".")
        if normalized_query in seen:
            continue
        seen.add(normalized_query)
        if is_allowlisted_domain(event.query, allowlist):
            continue
        score = dga_score(event.query)
        entropy = shannon_entropy(domain_label(event.query))
        if score >= score_threshold and entropy >= entropy_threshold:
            findings.append(
                Finding(
                    title="Possible DGA domain",
                    description="Domain structure has high entropy and weak language-like character patterns.",
                    category="dga_domain",
                    timestamp=event.timestamp,
                    evidence={
                        "domain": event.query,
                        "entropy": round(entropy, 3),
                        "dga_score": score,
                        **packet_evidence(event.packet_number),
                    },
                    tags=["dga"],
                )
            )
    return findings
