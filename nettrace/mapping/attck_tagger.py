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


def _parse_flow_source(source: str) -> tuple[str, int] | None:
    parts = source.split(":")
    if len(parts) != 3 or parts[0] != "flow":
        return None
    protocol = parts[1].lower()
    if protocol not in {"tcp", "udp"}:
        return None
    try:
        port = int(parts[2])
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return protocol, port


def _refine_threat_intel_technique(finding: Finding) -> tuple[str, str] | None:
    source = finding.evidence.get("source", "")
    if "dns" in source:
        return "T1071.004", "Application Layer Protocol: DNS"
    if source in {"http_host", "http_flow", "http_request"}:
        return "T1071.001", "Application Layer Protocol: Web Protocols"
    if "tls" in source:
        return "T1573", "Encrypted Channel"
    if source.startswith("flow:"):
        flow_source = _parse_flow_source(source)
        if not flow_source:
            return None
        _, port = flow_source
        if port == 53:
            return "T1071.004", "Application Layer Protocol: DNS"
        if port in {80, 8080, 8000, 8888}:
            return "T1071.001", "Application Layer Protocol: Web Protocols"
        if port in {443, 4443, 8443, 9443}:
            return "T1573", "Encrypted Channel"
        return "T1571", "Non-Standard Port"
    return None


def tag_findings(findings: list[Finding]) -> None:
    for finding in findings:
        attack = ATTACK_MAP.get(finding.category)
        if finding.category == "threat_intel_match":
            attack = _refine_threat_intel_technique(finding) or attack
        if attack:
            finding.attack_id, finding.attack_name = attack
            if finding.attack_id not in finding.tags:
                finding.tags.append(finding.attack_id)
