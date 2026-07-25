from __future__ import annotations

import os
import ipaddress

from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import IOC
from nettrace.models.findings import Finding


SOURCE_QUERY_PRIORITY = {
    "http_request": 0,
    "http_host": 1,
    "http_url_host": 1,
    "http_connect_target": 1,
    "tls_sni": 2,
    "dns": 3,
    "dns_answer_domain": 4,
    "http_flow": 5,
    "tls_flow": 6,
    "dns_answer": 7,
}

KIND_QUERY_PRIORITY = {
    "url": 0,
    "domain": 1,
    "ip": 2,
}


def _ioc_query_priority(ioc: IOC) -> tuple[int, int, int]:
    source_priority = SOURCE_QUERY_PRIORITY.get(ioc.source, 50)
    if ioc.confidence != "confirmed":
        source_priority += 50
    packet_number = ioc.packet_number or 10**12
    return (source_priority, KIND_QUERY_PRIORITY.get(ioc.kind, 9), packet_number)


class MispLookup:
    def __init__(
        self,
        enabled: bool,
        url: str = "",
        api_key: str = "",
        verify_ssl: bool = True,
        max_iocs: int = 5_000,
        batch_size: int = 100,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.enabled = enabled
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.max_iocs = max(1, max_iocs)
        self.batch_size = max(1, batch_size)
        self.timeout_seconds = max(0.1, timeout_seconds)

    @classmethod
    def from_config(cls, config: dict) -> "MispLookup":
        api_key = config.get("api_key", "")
        api_key_env = config.get("api_key_env", "NETTRACE_MISP_API_KEY")
        if not api_key and api_key_env:
            api_key = os.environ.get(str(api_key_env), "")
        return cls(
            enabled=bool(config.get("enabled", False)),
            url=config.get("url", ""),
            api_key=api_key,
            verify_ssl=bool(config.get("verify_ssl", True)),
            max_iocs=int(config.get("max_iocs", 5_000)),
            batch_size=int(config.get("batch_size", 100)),
            timeout_seconds=float(config.get("timeout_seconds", 10.0)),
        )

    @staticmethod
    def _attributes(result) -> list:
        if isinstance(result, dict):
            attributes = result.get("Attribute", [])
            return attributes if isinstance(attributes, list) else []
        return result if isinstance(result, list) else []

    @staticmethod
    def _attribute_values(attribute) -> set[str]:
        if isinstance(attribute, dict):
            return {
                str(attribute[key])
                for key in ("value", "value1", "value2")
                if attribute.get(key) not in (None, "")
            }
        value = getattr(attribute, "value", None)
        return {str(value)} if value not in (None, "") else set()

    def match_iocs(self, iocs: list[IOC]) -> list[Finding]:
        if not self.enabled:
            return []
        if not self.url or not self.api_key:
            missing = [name for name, value in (("url", self.url), ("api_key", self.api_key)) if not value]
            return [
                Finding(
                    title="MISP configuration incomplete",
                    description="MISP enrichment was enabled but required connection settings were missing.",
                    category="misp_error",
                    evidence={"missing_settings": missing, "misp_url": self.url},
                    severity="low",
                    tags=["MISP_ERROR"],
                )
            ]
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
            try:
                misp = PyMISP(self.url, self.api_key, self.verify_ssl, timeout=self.timeout_seconds)
            except TypeError:
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
        selected_iocs = [
            ioc
            for _, ioc in sorted(enumerate(iocs), key=lambda item: (_ioc_query_priority(item[1]), item[0]))
        ][: self.max_iocs]
        if len(iocs) > self.max_iocs:
            findings.append(
                Finding(
                    title="MISP lookup truncated",
                    description="MISP enrichment was limited to the configured maximum IOC count.",
                    category="misp_error",
                    evidence={"total_iocs": len(iocs), "queried_iocs": self.max_iocs},
                    severity="low",
                    tags=["MISP_LIMIT"],
                )
            )
        for start in range(0, len(selected_iocs), self.batch_size):
            batch = selected_iocs[start : start + self.batch_size]
            values = [ioc.value for ioc in batch]
            try:
                result = misp.search(controller="attributes", value=values)
            except Exception as exc:
                findings.append(
                    Finding(
                        title="MISP lookup error",
                        description="MISP query failed for an IOC batch.",
                        category="misp_error",
                        evidence={"ioc_count": len(batch), "ioc_sample": values[:5], "error": str(exc)},
                        severity="low",
                        tags=["MISP_ERROR"],
                    )
                )
                continue
            attributes = self._attributes(result)
            matched_counts = {ioc.value: 0 for ioc in batch}
            for attribute in attributes:
                attribute_values = self._attribute_values(attribute)
                for ioc in batch:
                    if ioc.kind == "domain":
                        matched = any(value.lower().rstrip(".") == ioc.value.lower().rstrip(".") for value in attribute_values)
                    elif ioc.kind == "ip":
                        normalized_values = set()
                        for value in attribute_values:
                            try:
                                normalized_values.add(str(ipaddress.ip_address(value)))
                            except ValueError:
                                continue
                        matched = ioc.value in normalized_values
                    else:
                        matched = ioc.value in attribute_values
                    if matched:
                        matched_counts[ioc.value] += 1
            for ioc in batch:
                match_count = matched_counts.get(ioc.value, 0)
                if not match_count:
                    continue
                findings.append(
                    Finding(
                        title="MISP threat intel match",
                        description="IOC matched attributes in the configured MISP instance.",
                        category="threat_intel_match",
                        evidence={
                            "ioc_type": ioc.kind,
                            "ioc_value": ioc.value,
                            "source": ioc.source,
                            "misp_result_count": match_count,
                            **packet_evidence(ioc.packet_number),
                        },
                        tags=["IOC_MATCH", "MISP_HIT"],
                    )
                )
        return findings
