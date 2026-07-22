from __future__ import annotations

from pathlib import Path
from typing import Any

from scapy.layers.inet import TCP

from nettrace.analysis.beaconing import detect_beaconing
from nettrace.analysis.dga_scorer import score_domains
from nettrace.analysis.ftp_analyzer import analyze_ftp_events
from nettrace.analysis.http_analyzer import analyze_http_events
from nettrace.analysis.ioc_extractor import extract_iocs
from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.analysis.tls_analyzer import analyze_tls_events
from nettrace.intel.local_ioc_lookup import LocalIntel
from nettrace.intel.misp_lookup import MispLookup
from nettrace.mapping.attck_tagger import tag_findings
from nettrace.mapping.severity import score_findings
from nettrace.mapping.timeline import build_timeline
from nettrace.models.events import Flow
from nettrace.models.report import AnalysisReport
from nettrace.parsers.dns_extractor import DNSStreamExtractor, extract_dns_events_from_packet
from nettrace.parsers.flow_builder import update_flow
from nettrace.parsers.ftp_extractor import FTPStreamExtractor
from nettrace.parsers.http_extractor import HTTPStreamExtractor, extract_http_event
from nettrace.parsers.ip_reassembly import IPFragmentReassembler
from nettrace.parsers.pcap_loader import iter_packets
from nettrace.parsers.tls_extractor import TLSStreamExtractor


def _limit(config: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(1, int(config.get("limits", {}).get(key, default)))
    except (TypeError, ValueError):
        return default


def analyze_pcap(pcap_path: Path, config: dict[str, Any]) -> AnalysisReport:
    dns_events = []
    http_events = []
    tls_events = []
    ftp_events = []
    http_event_keys: set[tuple[int, str, str, str, str]] = set()
    flow_state: dict[tuple, Flow] = {}
    warnings: set[str] = set()
    max_dns_events = _limit(config, "max_dns_events", 100_000)
    max_http_events = _limit(config, "max_http_events", 100_000)
    max_tls_events = _limit(config, "max_tls_events", 100_000)
    max_ftp_events = _limit(config, "max_ftp_events", 100_000)
    max_flows = _limit(config, "max_flows", 50_000)
    max_flow_samples = _limit(config, "max_flow_samples", 256)
    max_timeline_entries = _limit(config, "max_timeline_entries", 100_000)
    total_tcp_buffer_bytes = _limit(config, "max_tcp_total_buffer_bytes", 67_108_864)
    stream_options = {
        "max_streams": _limit(config, "max_tcp_streams", 10_000),
        "max_buffer_bytes": _limit(config, "max_tcp_stream_buffer_bytes", 1_048_576),
        "max_pending_segments": _limit(config, "max_tcp_pending_segments", 256),
        # Four protocol extractors share the configured process budget evenly.
        "max_total_buffer_bytes": max(1, total_tcp_buffer_bytes // 4),
    }
    http_ports = {int(port) for port in config.get("protocols", {}).get("http_ports", [80, 8000, 8080, 8888])}
    http_extractor = HTTPStreamExtractor(http_ports=http_ports, stream_options=stream_options)
    tls_extractor = TLSStreamExtractor(stream_options=stream_options)
    ftp_extractor = FTPStreamExtractor(stream_options=stream_options)
    dns_stream_extractor = DNSStreamExtractor(stream_options=stream_options)
    fragment_reassembler = IPFragmentReassembler()
    packet_count = 0

    for raw_packet_number, raw_packet in enumerate(iter_packets(pcap_path), start=1):
        packet_count = raw_packet_number
        reassembled = fragment_reassembler.feed(raw_packet, raw_packet_number)
        if reassembled is None:
            continue
        packet, packet_number = reassembled
        dns_events_from_packet = dns_stream_extractor.feed(packet, packet_number=packet_number)
        if not dns_events_from_packet and not packet.haslayer(TCP):
            dns_events_from_packet = extract_dns_events_from_packet(packet, packet_number=packet_number)
        for dns_event in dns_events_from_packet:
            if len(dns_events) < max_dns_events:
                dns_events.append(dns_event)
            else:
                warnings.add(f"DNS events truncated at {max_dns_events} entries.")
        http_events_from_packet = http_extractor.feed(packet, packet_number=packet_number)
        if not http_events_from_packet:
            direct_http_event = extract_http_event(
                packet,
                packet_number=packet_number,
                http_ports=http_ports,
                allow_any_port=True,
            )
            if direct_http_event is not None:
                http_events_from_packet = [direct_http_event]
        for http_event in http_events_from_packet:
            event_key = (
                http_event.packet_number,
                http_event.src_ip,
                http_event.dst_ip,
                http_event.method,
                http_event.uri,
            )
            if event_key in http_event_keys:
                continue
            http_event_keys.add(event_key)
            if len(http_events) < max_http_events:
                http_events.append(http_event)
            else:
                warnings.add(f"HTTP events truncated at {max_http_events} entries.")
        for tls_event in tls_extractor.feed(packet, packet_number=packet_number):
            if len(tls_events) < max_tls_events:
                tls_events.append(tls_event)
            else:
                warnings.add(f"TLS events truncated at {max_tls_events} entries.")
        for ftp_event in ftp_extractor.feed(packet, packet_number=packet_number):
            if len(ftp_events) < max_ftp_events:
                ftp_events.append(ftp_event)
            else:
                warnings.add(f"FTP events truncated at {max_ftp_events} entries.")
        flow_recorded = update_flow(
            flow_state,
            packet,
            packet_number=packet_number,
            max_flows=max_flows,
            sample_limit=max_flow_samples,
        )
        if not flow_recorded:
            warnings.add(f"Flow records truncated at {max_flows} entries.")

    fragment_failures = fragment_reassembler.discarded_datagrams + fragment_reassembler.incomplete_datagrams
    if fragment_failures:
        warnings.add(
            f"IP fragment reassembly discarded {fragment_failures} incomplete or invalid datagrams."
        )
    discarded_tcp_streams = sum(
        extractor.streams.discarded_streams
        for extractor in (dns_stream_extractor, http_extractor, tls_extractor, ftp_extractor)
    )
    if discarded_tcp_streams:
        warnings.add(f"TCP reassembly discarded {discarded_tcp_streams} incomplete or resource-limited streams.")

    flows = list(flow_state.values())

    findings = []
    findings.extend(detect_beaconing(flows, config["thresholds"]))
    findings.extend(score_domains(dns_events, config["thresholds"]))
    findings.extend(analyze_http_events(http_events, config))
    findings.extend(analyze_ftp_events(ftp_events))
    findings.extend(analyze_tls_events(tls_events, flows, config["thresholds"]))
    findings.extend(analyze_flows(flows, config["thresholds"]))

    iocs = extract_iocs(dns_events, http_events, tls_events, flows)
    for key in ("known_bad_domains", "known_bad_ips", "suspicious_user_agents"):
        intel_path = config.get("intel", {}).get(key, "")
        if intel_path and not Path(intel_path).is_file():
            warnings.add(f"Local intelligence file not found for {key}: {intel_path}")
    local_intel = LocalIntel.from_config(config["intel"])
    findings.extend(local_intel.match_iocs(iocs))

    misp = MispLookup.from_config(config.get("misp", {}))
    findings.extend(misp.match_iocs(iocs))

    tag_findings(findings)
    score_findings(findings)
    timeline_item_count = (
        len(dns_events)
        + len(http_events)
        + len(tls_events)
        + len(ftp_events)
        + len(flows)
        + sum(1 for finding in findings if finding.timestamp is not None)
    )
    timeline = build_timeline(
        dns_events,
        http_events,
        tls_events,
        flows,
        findings,
        ftp_events=ftp_events,
        max_entries=max_timeline_entries,
    )
    if timeline_item_count > max_timeline_entries:
        warnings.add(f"Timeline truncated at {max_timeline_entries} entries.")

    return AnalysisReport(
        pcap_path=str(pcap_path),
        dns_events=dns_events,
        http_events=http_events,
        tls_events=tls_events,
        ftp_events=ftp_events,
        flows=flows,
        iocs=iocs,
        findings=findings,
        timeline=timeline,
        packet_count=packet_count,
        warnings=sorted(warnings),
    )
