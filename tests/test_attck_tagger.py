from nettrace.mapping.attck_tagger import _load_attack_map, tag_findings
from nettrace.models.findings import Finding


def test_tag_findings_uses_yaml_attack_mapping():
    finding = Finding("DGA", "desc", {}, "dga_domain")

    tag_findings([finding])

    assert finding.attack_id == "T1568.002"
    assert finding.attack_name == "Dynamic Resolution: Domain Generation Algorithms"
    assert "T1568.002" in finding.tags


def test_threat_intel_mapping_is_refined_by_source():
    dns_hit = Finding("hit", "desc", {"source": "dns"}, "threat_intel_match")
    http_hit = Finding("hit", "desc", {"source": "http_flow"}, "threat_intel_match")

    tag_findings([dns_hit, http_hit])

    assert dns_hit.attack_id == "T1071.004"
    assert http_hit.attack_id == "T1071.001"


def test_connect_target_intel_mapping_is_refined_as_web_protocol():
    finding = Finding("hit", "desc", {"source": "http_connect_target"}, "threat_intel_match")

    tag_findings([finding])

    assert finding.attack_id == "T1071.001"


def test_threat_intel_flow_mapping_uses_destination_port():
    finding = Finding("hit", "desc", {"source": "flow:tcp:4444"}, "threat_intel_match")

    tag_findings([finding])

    assert finding.attack_id == "T1571"
    assert finding.attack_name == "Non-Standard Port"


def test_threat_intel_flow_mapping_requires_exact_source_format():
    finding = Finding("hit", "desc", {"source": "flow:tcp:4444:extra"}, "threat_intel_match")

    tag_findings([finding])

    assert finding.attack_id == "T1071"
    assert finding.attack_name == "Application Layer Protocol"


def test_missing_attack_yaml_loads_empty_map(tmp_path):
    assert _load_attack_map(tmp_path / "missing.yaml") == {}


def test_malformed_attack_yaml_loads_empty_map(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("bad: [", encoding="utf-8")

    assert _load_attack_map(path) == {}
