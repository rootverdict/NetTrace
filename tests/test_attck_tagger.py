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


def test_unusual_port_and_ftp_upload_are_not_mapped_from_weak_context():
    unusual_port = Finding("port", "desc", {}, "unusual_port")
    ftp_upload = Finding("ftp", "desc", {}, "ftp_upload")

    tag_findings([unusual_port, ftp_upload])

    assert unusual_port.attack_id is None
    assert ftp_upload.attack_id is None


def test_threat_intel_tls_source_maps_to_encrypted_channel():
    finding = Finding("hit", "desc", {"source": "tls_flow"}, "threat_intel_match")

    tag_findings([finding])

    assert finding.attack_id == "T1573"
    assert finding.attack_name == "Encrypted Channel"


def test_threat_intel_flow_port_selects_protocol_technique():
    dns_flow = Finding("hit", "desc", {"source": "flow:udp:53"}, "threat_intel_match")
    web_flow = Finding("hit", "desc", {"source": "flow:tcp:80"}, "threat_intel_match")
    tls_flow = Finding("hit", "desc", {"source": "flow:tcp:443"}, "threat_intel_match")

    tag_findings([dns_flow, web_flow, tls_flow])

    assert dns_flow.attack_id == "T1071.004"
    assert web_flow.attack_id == "T1071.001"
    assert tls_flow.attack_id == "T1573"


def test_threat_intel_flow_with_unparseable_source_falls_back_to_base_technique():
    # A non-tcp/udp protocol, a non-numeric port, and an out-of-range port must
    # each fail the flow parse and fall back to the category's base T1071 rather
    # than crash or guess.
    for bad_source in ("flow:sctp:80", "flow:tcp:not-a-port", "flow:tcp:99999"):
        finding = Finding("hit", "desc", {"source": bad_source}, "threat_intel_match")

        tag_findings([finding])

        assert finding.attack_id == "T1071"
        assert finding.attack_name == "Application Layer Protocol"


def test_network_beaconing_maps_only_when_port_confirms_protocol():
    web_beacon = Finding("beacon", "desc", {"dst_port": 80}, "network_beaconing")
    tls_beacon = Finding("beacon", "desc", {"dst_port": 443}, "network_beaconing")
    opaque_beacon = Finding("beacon", "desc", {"dst_port": 4444}, "network_beaconing")

    tag_findings([web_beacon, tls_beacon, opaque_beacon])

    assert web_beacon.attack_id == "T1071.001"
    assert tls_beacon.attack_id == "T1573"
    # An unconfirmed port stays unmapped rather than being forced onto a guess.
    assert opaque_beacon.attack_id is None


def test_missing_attack_yaml_loads_empty_map(tmp_path):
    assert _load_attack_map(tmp_path / "missing.yaml") == {}


def test_malformed_attack_yaml_loads_empty_map(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("bad: [", encoding="utf-8")

    assert _load_attack_map(path) == {}
