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


def test_threat_intel_flow_bare_port_is_left_unmapped():
    # A raw flow endpoint reveals only a port number, which confirms neither the
    # application protocol nor whether it is non-standard for that protocol.
    # Such a match must stay unmapped: not T1571 "Non-Standard Port" (system
    # ports 22/25/123 and standard registered services 3306/3389/5432 are not
    # non-standard), and not even the generic T1071 base technique (a port-only
    # flow does not establish any application-layer protocol).
    for port_source in (
        "flow:tcp:22",
        "flow:tcp:25",
        "flow:udp:123",
        "flow:tcp:3306",
        "flow:tcp:3389",
        "flow:tcp:5432",
        "flow:tcp:4444",
    ):
        finding = Finding("hit", "desc", {"source": port_source}, "threat_intel_match")

        tag_findings([finding])

        assert finding.attack_id is None, port_source
        assert finding.attack_name is None, port_source
        assert finding.tags == [], port_source


def test_threat_intel_malformed_flow_source_is_left_unmapped():
    # A flow source we cannot even parse establishes strictly less than a bare
    # port, so it likewise stays unmapped rather than defaulting to T1071.
    finding = Finding("hit", "desc", {"source": "flow:tcp:4444:extra"}, "threat_intel_match")

    tag_findings([finding])

    assert finding.attack_id is None
    assert finding.attack_name is None


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


def test_threat_intel_flow_well_known_ports_are_left_unmapped():
    # A port does not confirm its application protocol: DNS-on-53, HTTP-on-80 and
    # TLS-on-443 are conventions, not proof. A raw flow match therefore stays
    # unmapped even on these well-known ports, consistent with every other
    # flow:* source. Protocol techniques come only from parser-confirmed sources
    # (see the dns/http/tls source tests above), never from a bare port.
    dns_flow = Finding("hit", "desc", {"source": "flow:udp:53"}, "threat_intel_match")
    web_flow = Finding("hit", "desc", {"source": "flow:tcp:80"}, "threat_intel_match")
    tls_flow = Finding("hit", "desc", {"source": "flow:tcp:443"}, "threat_intel_match")

    tag_findings([dns_flow, web_flow, tls_flow])

    assert dns_flow.attack_id is None
    assert web_flow.attack_id is None
    assert tls_flow.attack_id is None


def test_threat_intel_flow_with_unparseable_source_stays_unmapped():
    # A non-tcp/udp protocol, a non-numeric port, and an out-of-range port each
    # fail the flow parse. Because they are still raw flow observations that
    # confirm no application-layer protocol, they stay unmapped (no T1071)
    # rather than crash or guess.
    for bad_source in ("flow:sctp:80", "flow:tcp:not-a-port", "flow:tcp:99999"):
        finding = Finding("hit", "desc", {"source": bad_source}, "threat_intel_match")

        tag_findings([finding])

        assert finding.attack_id is None, bad_source
        assert finding.attack_name is None, bad_source


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
