from __future__ import annotations

from pathlib import Path

import yaml

from nettrace.models.findings import Finding

DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules" / "attck_map.yaml"


def _load_attack_map(path: Path = DEFAULT_RULES_PATH) -> dict[str, tuple[str, str]]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}
    return {
        key: (value["id"], value["name"])
        for key, value in data.items()
        if isinstance(value, dict) and "id" in value and "name" in value
    }


ATTACK_MAP = _load_attack_map()


def _refine_threat_intel_technique(finding: Finding) -> tuple[str, str] | None:
    source = finding.evidence.get("source", "")
    if "dns" in source:
        return "T1071.004", "Application Layer Protocol: DNS"
    if source in {"http_host", "http_url_host", "http_connect_target", "http_flow", "http_request"}:
        return "T1071.001", "Application Layer Protocol: Web Protocols"
    if "tls" in source:
        return "T1573", "Encrypted Channel"
    if source.startswith("flow:"):
        # A raw flow endpoint reveals only a port number, never the application
        # protocol running on it -- a port does not confirm its protocol (DNS on
        # 53, HTTP on 80, TLS on 443 are conventions, not proof), and it says
        # nothing about whether the port is non-standard for that protocol. So a
        # raw flow match yields no technique regardless of port. tag_findings
        # keeps it unmapped rather than defaulting to the generic T1071 base.
        return None
    return None


_HTTP_PORTS = {80, 8080, 8000, 8888}
_TLS_PORTS = {443, 4443, 8443, 9443}


def _refine_network_beaconing(finding: Finding) -> tuple[str, str] | None:
    """Only tag a technique when the destination port confirms the protocol.

    Bug #1: the previous code mapped every non-DNS beacon straight to
    T1071.001 (Web Protocols) even when the destination was, say, port 4444.
    A beacon on an unconfirmed port is reported without an ATT&CK id rather
    than guessing.
    """
    port = finding.evidence.get("dst_port")
    if port in _HTTP_PORTS:
        return "T1071.001", "Application Layer Protocol: Web Protocols"
    if port in _TLS_PORTS:
        return "T1573", "Encrypted Channel"
    return None


def tag_findings(findings: list[Finding]) -> None:
    for finding in findings:
        attack = ATTACK_MAP.get(finding.category)
        if finding.category == "threat_intel_match":
            refined = _refine_threat_intel_technique(finding)
            if refined is not None:
                attack = refined
            elif str(finding.evidence.get("source", "")).startswith("flow:"):
                # A raw flow endpoint is a port-only observation: it confirms no
                # application-layer protocol, so it must NOT fall back to the
                # generic T1071 base technique. A technique comes only from a
                # source whose protocol was actually parsed (dns/http/tls); every
                # flow:* match stays unmapped rather than asserting an unproven
                # protocol from its port.
                attack = None
        elif finding.category == "network_beaconing":
            attack = _refine_network_beaconing(finding)
        if attack:
            finding.attack_id, finding.attack_name = attack
            if finding.attack_id not in finding.tags:
                finding.tags.append(finding.attack_id)
