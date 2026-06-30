from __future__ import annotations

from pathlib import Path

from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import IOC
from nettrace.models.findings import Finding


def _read_set(path: str) -> set[str]:
    if not path:
        return set()
    file_path = Path(path)
    if not file_path.is_file():
        return set()
    return {
        line.strip().lower()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


class LocalIntel:
    def __init__(self, domains: set[str], ips: set[str]) -> None:
        self.domains = domains
        self.ips = ips

    @classmethod
    def from_config(cls, config: dict) -> "LocalIntel":
        return cls(
            domains=_read_set(config.get("known_bad_domains", "")),
            ips=_read_set(config.get("known_bad_ips", "")),
        )

    def match_iocs(self, iocs: list[IOC]) -> list[Finding]:
        findings: list[Finding] = []
        for ioc in iocs:
            matched = (ioc.kind == "domain" and ioc.value in self.domains) or (
                ioc.kind == "ip" and ioc.value in self.ips
            )
            if matched:
                findings.append(
                    Finding(
                        title="Local threat intel match",
                        description="IOC matched the local known-bad intelligence list.",
                        category="threat_intel_match",
                        evidence={
                            "ioc_type": ioc.kind,
                            "ioc_value": ioc.value,
                            "source": ioc.source,
                            **packet_evidence(ioc.packet_number),
                        },
                        tags=["IOC_MATCH", "LOCAL_INTEL"],
                    )
                )
        return findings
