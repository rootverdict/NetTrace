from __future__ import annotations

import ipaddress
import html
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

COMMON_HOST_TOKENS = (
    "microsoft",
    "windowsupdate",
    "msedge",
    "azure",
    "bing.com",
    "lencr.org",
    "msn.com",
    "wns.windows.com",
    "msftncsi.com",
    "officeapps.live.com",
    "office.net",
    "office365.com",
)
COMMON_DOMAIN_PREFIXES = ("_ldap.", "_kerberos.", "_gc.", "_kpasswd.", "wpad.")
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def is_rfc1918(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in INTERNAL_NETWORKS)


def format_ip_port(ip: str, port: int | str) -> str:
    try:
        host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    except ValueError:
        host = ip
    return f"{host}:{port}"


def is_common_host(value: str) -> bool:
    lowered = value.lower()
    return (
        any(token in lowered for token in COMMON_HOST_TOKENS)
        or any(lowered.startswith(prefix) for prefix in COMMON_DOMAIN_PREFIXES)
        or lowered.endswith(".local")
        or lowered.endswith(".localdomain")
    )


def unique(values: list[str], limit: int = 10) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
        if len(output) >= limit:
            break
    return output


def infer_victim_host(report: dict[str, Any]) -> str:
    # Heuristic: for multi-host captures this picks the busiest internal host, not guaranteed patient zero.
    counts: Counter[str] = Counter()
    for flow in report.get("flows", []):
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        if is_rfc1918(src_ip) and not is_rfc1918(dst_ip):
            counts[src_ip] += int(flow.get("packet_count", 1))
    if counts:
        return counts.most_common(1)[0][0]
    for event_type in ("http_events", "dns_events", "tls_events"):
        for event in report.get(event_type, []):
            src_ip = event.get("src_ip", "")
            if is_rfc1918(src_ip):
                return src_ip
    return "unknown"


def top_http_urls(report: dict[str, Any], limit: int = 8) -> list[str]:
    urls = [
        event.get("url", "")
        for event in sorted(report.get("http_events", []), key=lambda item: item.get("timestamp", 0))
        if not is_common_host(event.get("host", ""))
    ]
    return unique(urls, limit)


def top_domains(report: dict[str, Any], limit: int = 12) -> list[str]:
    values = [
        ioc.get("value", "")
        for ioc in report.get("iocs", [])
        if ioc.get("kind") == "domain" and not is_common_host(ioc.get("value", ""))
    ]
    return unique(values, limit)


def top_ips(report: dict[str, Any], victim: str, limit: int = 12) -> list[str]:
    candidates: list[str] = []
    for finding in report.get("findings", []):
        evidence = finding.get("evidence", {})
        if finding.get("category") == "high_frequency_connections":
            src_ip = evidence.get("src_ip", "")
            dst_ip = evidence.get("dst_ip", "")
            dst_port = evidence.get("dst_port", 0)
            if src_ip == victim and dst_ip and not is_rfc1918(dst_ip):
                candidates.append(format_ip_port(dst_ip, dst_port))
        elif finding.get("category") in {"unusual_port", "network_beaconing", "tls_c2"}:
            dst_ip = evidence.get("dst_ip", "")
            dst_port = evidence.get("dst_port", "")
            if dst_ip and not is_rfc1918(dst_ip):
                candidates.append(format_ip_port(dst_ip, dst_port) if dst_port else dst_ip)
    for ioc in report.get("iocs", []):
        value = ioc.get("value", "")
        if ioc.get("kind") == "ip" and not is_rfc1918(value):
            if not any(item == value or item.startswith(f"{value}:") or item.startswith(f"[{value}]:") for item in candidates):
                candidates.append(value)
    return unique(candidates, limit)


def finding_counts(report: dict[str, Any]) -> Counter[str]:
    return Counter(finding.get("title", "Unknown finding") for finding in report.get("findings", []))


def attack_techniques(report: dict[str, Any]) -> list[str]:
    values = []
    for finding in report.get("findings", []):
        attack_id = finding.get("attack_id")
        attack_name = finding.get("attack_name")
        if attack_id and attack_name:
            values.append(f"{attack_id} - {attack_name}")
    return unique(values, 12)


def markdown_text(value: str) -> str:
    return html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=False)


def _single_line(value: str) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")


def markdown_code(value: str) -> str:
    # Deliberately not HTML-escaped: a Markdown code span renders its content
    # literally, so escaping here surfaced as a literal "&amp;" in every URL
    # carrying a query string. A conforming renderer escapes the span's content
    # itself when emitting HTML, so the value stays inert.
    sanitized = _single_line(value)
    longest_run = max((len(run) for run in re.findall(r"`+", sanitized)), default=0)
    delimiter = "`" * max(1, longest_run + 1)
    padding = " " if sanitized.startswith(("`", " ")) or sanitized.endswith(("`", " ")) else ""
    return f"{delimiter}{padding}{sanitized}{padding}{delimiter}"


def bullet_list(values: list[str]) -> str:
    if not values:
        return "- None observed"
    return "\n".join(f"- {markdown_code(value)}" for value in values)


def build_analyst_paragraph(report: dict[str, Any], victim: str, urls: list[str], ips: list[str]) -> str:
    summary = report.get("summary", {})
    url_text = ", ".join(markdown_code(url) for url in urls[:5]) if urls else "no plaintext HTTP staging URLs"
    ip_text = ", ".join(markdown_code(ip) for ip in ips[:8]) if ips else "no public C2 candidates"
    findings = report.get("findings", [])
    findings_count = summary.get("findings", len(findings))
    strong_findings = sum(1 for finding in findings if finding.get("severity") in {"high", "critical"})

    host_clause = (
        f"identified {markdown_code(victim)} as the internal host with the highest observed external traffic "
        "volume (a triage heuristic, not confirmation of compromise)"
        if victim and victim != "unknown"
        else "did not identify a single dominant internal host"
    )
    base = (
        f"NetTrace analyzed {markdown_code(report.get('pcap_path', 'unknown'))} and {host_clause}. "
        f"The capture contains {summary.get('dns_events', 0)} DNS events, "
        f"{summary.get('http_events', 0)} plaintext HTTP requests, {summary.get('tls_events', 0)} TLS SNI events, "
        f"{summary.get('ftp_events', 0)} FTP commands, and {summary.get('flows', 0)} flows."
    )

    # Bug #18: the old text asserted "consistent with malware staging and C2
    # triage" even on a capture with zero findings and zero staging URLs. The
    # conclusion now scales with what was actually found.
    if strong_findings:
        conclusion = (
            f" {strong_findings} high/critical-severity finding(s) were produced, with the strongest signal being "
            f"HTTP staging activity ({url_text}) and high-volume or encrypted traffic involving {ip_text}. This "
            "warrants malware staging and command-and-control triage; heuristic findings should still be validated "
            "with packet context before conclusions are drawn."
        )
    elif findings_count:
        conclusion = (
            f" NetTrace produced {findings_count} lower-confidence heuristic finding(s) ({url_text}; {ip_text}) that "
            "should be reviewed with packet context. None reached high or critical severity, so this capture does "
            "not, on its own, establish malware staging or command-and-control activity."
        )
    else:
        conclusion = " No behavioral findings were produced from this capture."
    return base + conclusion


def build_markdown(report: dict[str, Any], source: str = "", source_url: str = "") -> str:
    summary = report.get("summary", {})
    victim = infer_victim_host(report)
    urls = top_http_urls(report)
    domains = top_domains(report)
    ips = top_ips(report, victim)
    counts = finding_counts(report)
    techniques = attack_techniques(report)
    warnings = [str(warning) for warning in report.get("warnings", [])]

    lines = [f"# NetTrace Findings: {markdown_text(Path(report.get('pcap_path', 'pcap')).name)}", "", "## Dataset", ""]
    if source:
        lines.append(f"- Source: {markdown_text(source)}")
    if source_url:
        lines.append(f"- Source page: {markdown_text(source_url)}")
    lines.extend(
        [
            f"- PCAP analyzed: {markdown_code(report.get('pcap_path', 'unknown'))}",
            "",
            "## Tool Summary",
            "",
            f"- DNS events: {summary.get('dns_events', 0)}",
            f"- HTTP events: {summary.get('http_events', 0)}",
            f"- TLS events: {summary.get('tls_events', 0)}",
            f"- FTP events: {summary.get('ftp_events', 0)}",
            f"- Flows: {summary.get('flows', 0)}",
            f"- IOCs: {summary.get('iocs', 0)}",
            f"- Findings: {summary.get('findings', 0)}",
            f"- Critical findings: {summary.get('critical', 0)}",
            f"- High findings: {summary.get('high', 0)}",
            f"- Medium findings: {summary.get('medium', 0)}",
            f"- Low findings: {summary.get('low', 0)}",
            "",
            "## Analysis Warnings",
            "",
            bullet_list(warnings),
            "",
            "## Analyst Finding",
            "",
            build_analyst_paragraph(report, victim, urls, ips),
            "",
            "## Finding Types",
            "",
        ]
    )
    for title, count in counts.most_common():
        lines.append(f"- {markdown_text(title)}: {count}")
    lines.extend(
        [
            "",
            "## Potential ATT&CK Technique Associations",
            "",
            bullet_list(techniques),
            "",
            "## Notable URLs",
            "",
            bullet_list(urls),
            "",
            "## Notable Domains",
            "",
            bullet_list(domains),
            "",
            "## Notable IPs And Ports",
            "",
            bullet_list(ips),
            "",
            "## Notes",
            "",
            "- This write-up was generated automatically from NetTrace JSON output.",
            "- Treat heuristic detections as triage leads and validate them against packet context.",
            "- This workflow analyzes PCAP files only and does not execute malware.",
            "",
        ]
    )
    return "\n".join(lines)


def default_output_path(json_report: Path) -> Path:
    stem = json_report.stem
    if stem.endswith("_findings"):
        stem = stem[: -len("_findings")]
    return Path("findings") / f"{stem}_FINDINGS.md"


def write_markdown_report(json_report: Path, output_path: Path | None = None, source: str = "", source_url: str = "") -> Path:
    report = json.loads(json_report.read_text(encoding="utf-8"))
    markdown = build_markdown(report, source=source, source_url=source_url)
    destination = output_path or default_output_path(json_report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(markdown, encoding="utf-8")
    return destination
