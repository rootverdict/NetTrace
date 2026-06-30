from __future__ import annotations

from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import IOC
from nettrace.models.findings import Finding


class MispLookup:
    def __init__(self, enabled: bool, url: str = "", api_key: str = "", verify_ssl: bool = True) -> None:
        self.enabled = enabled
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    @classmethod
    def from_config(cls, config: dict) -> "MispLookup":
        return cls(
            enabled=bool(config.get("enabled", False)),
            url=config.get("url", ""),
            api_key=config.get("api_key", ""),
            verify_ssl=bool(config.get("verify_ssl", True)),
        )

    def match_iocs(self, iocs: list[IOC]) -> list[Finding]:
        if not self.enabled or not self.url or not self.api_key:
            return []
        try:
            from pymisp import PyMISP
        except Exception:
            return [
                Finding(
                    title="MISP lookup skipped",
                    description="MISP is enabled, but pymisp could not be imported.",
                    category="misp_error",
                    evidence={"misp_url": self.url},
                    severity="low",
                    tags=["MISP_ERROR"],
                )
            ]

        findings: list[Finding] = []
        try:
            misp = PyMISP(self.url, self.api_key, self.verify_ssl)
        except Exception as exc:
            return [
                Finding(
                    title="MISP lookup error",
                    description="MISP client initialization failed.",
                    category="misp_error",
                    evidence={"misp_url": self.url, "error": str(exc)},
                    severity="low",
                    tags=["MISP_ERROR"],
                )
            ]
        for ioc in iocs:
            try:
                result = misp.search(controller="attributes", value=ioc.value)
            except Exception as exc:
                findings.append(
                    Finding(
                        title="MISP lookup error",
                        description="MISP query failed for an IOC.",
                        category="misp_error",
                        evidence={"ioc": ioc.value, "error": str(exc)},
                        severity="low",
                        tags=["MISP_ERROR"],
                    )
                )
                continue
            attributes = result.get("Attribute", []) if isinstance(result, dict) else result
            if attributes:
                findings.append(
                    Finding(
                        title="MISP threat intel match",
                        description="IOC matched attributes in the configured MISP instance.",
                        category="threat_intel_match",
                        evidence={
                            "ioc_type": ioc.kind,
                            "ioc_value": ioc.value,
                            "misp_result_count": len(attributes),
                            **packet_evidence(ioc.packet_number),
                        },
                        tags=["IOC_MATCH", "MISP_HIT"],
                    )
                )
        return findings
