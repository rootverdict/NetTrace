from nettrace.mapping.severity import score_findings
from nettrace.models.findings import Finding


def test_threat_intel_match_scores_critical():
    finding = Finding("hit", "desc", {}, "threat_intel_match", tags=["IOC_MATCH"])
    score_findings([finding])
    assert finding.severity == "critical"
