from __future__ import annotations

from nettrace.models.findings import Finding


BASE_SCORES = {
    "threat_intel_match": 90,
    "dns_beaconing": 75,
    "network_beaconing": 70,
    "dga_domain": 70,
    "http_c2": 65,
    "http_automation_client": 20,
    "tls_c2": 55,
    "high_frequency_connections": 55,
    "unusual_port": 50,
    "long_tls_session": 45,
    "ftp_upload": 45,
    "ftp_cleartext_credentials": 55,
    "misp_error": 15,
}

# Bug #6: severity was previously a flat category lookup, so a 5-event borderline
# beacon and a 200-event tight-cadence beacon against known-bad infrastructure
# scored identically. Confidence (set per-finding by the analyzer that produced
# it -- see beaconing.py, dga_scorer.py, http_analyzer.py) now shifts the score.
CONFIDENCE_ADJUSTMENT = {
    "high": 12,
    "medium": 0,
    "low": -18,
}


def _label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def score_findings(findings: list[Finding]) -> None:
    for finding in findings:
        score = BASE_SCORES.get(finding.category, 20)
        score += CONFIDENCE_ADJUSTMENT.get(finding.confidence, 0)
        if "MISP_HIT" in finding.tags:
            score += 10
        if "IOC_MATCH" in finding.tags:
            score += 5
        finding.score = max(0, min(100, score))
        finding.severity = _label(finding.score)
