# Version Scope

This document defines the product boundary for NetTrace so new work can be sorted into the right release instead of expanding the current version without control.

## Scope Rule

When a new idea appears, decide where it belongs before implementation:

- If it is required for the first usable offline malware-traffic triage workflow, it can be part of V1.
- If it improves analyst workflow, expands coverage, or adds polish after the core workflow works, it belongs in V2.
- If it needs a different product surface, external service dependency, or major architecture change, keep it out of V1 unless explicitly approved.

## V1 Scope

Goal: deliver a reliable offline PCAP malware-traffic analysis tool that produces analyst-ready evidence without requiring external services.

Included:

- Offline PCAP analysis from the CLI.
- Single-pass parsing with bounded memory controls.
- IPv4 and IPv6 packet metadata.
- Bounded IP fragment and TCP stream reassembly.
- DNS extraction for UDP and TCP queries, responses, answers, and TTLs.
- Plaintext HTTP extraction for methods, hosts, URIs, URLs, and user agents.
- TLS ClientHello SNI extraction on common TLS ports.
- FTP control-traffic analysis, including cleartext credential and upload detection with passwords redacted.
- Flow and conversation metadata.
- IOC extraction for domains, URLs, and public IP addresses.
- Filtering of private, reserved, documentation, multicast, loopback, link-local, unspecified, and known resolver IPs from public-IP IOC output.
- Beaconing detection based on interval regularity.
- DGA-style domain scoring with a known-good allowlist.
- Suspicious HTTP behavior and executable/script download detection.
- High-frequency flow and unusual-port detection.
- Local IOC matching.
- Optional MISP enrichment through configuration.
- MITRE ATT&CK mapping.
- Severity scoring.
- Chronological timeline generation.
- Packet numbers and Wireshark `frame.number` filters in evidence.
- JSON, HTML, PDF, and Markdown findings output.
- Configurable event, flow, TCP stream-buffer, and timeline limits.
- Safe synthetic demo PCAP generation.
- Validation against the current five-sample malware-traffic corpus.
- Automated tests for the core parser, analysis, mapping, reporting, and CLI paths.

Not included in V1:

- Live packet capture or network monitoring.
- A desktop or web GUI.
- Malware-family classification as a final verdict.
- HTTPS payload decryption.
- Full IDS rule compatibility such as Suricata or Zeek rule execution.
- Enterprise case management, collaboration, or ticketing workflows.
- Cloud storage, SIEM, EDR, Slack, email, or SOAR integrations.
- Automatic threat-intelligence feed downloads or scheduled enrichment jobs.
- Distributed processing for very large capture repositories.
- User accounts, roles, permissions, or multi-tenant operation.

Done when:

- A user can install the project, analyze an offline PCAP, and receive JSON, HTML, PDF, and Markdown outputs.
- Findings include explainable evidence that can be checked against the original capture.
- The safe demo and current validation corpus can be reproduced.
- The test suite passes with coverage at or above the configured threshold.
- Known V1 limitations are documented instead of hidden.

## V2 Scope

Goal: improve analyst workflow, expand detection coverage, and make NetTrace easier to operate after the V1 core remains stable.

Candidate V2 work:

- Lightweight analyst UI for opening reports, browsing evidence, and filtering findings.
- Report comparison across multiple PCAPs.
- Richer protocol coverage, such as SMTP, SMB, IRC, WebDAV, JA3/JA4-style TLS fingerprints, and HTTP/2 metadata where feasible.
- Rule authoring and validation helpers for project-specific detections.
- Better tuning workflow for thresholds, allowlists, and suspicious-port rules.
- Additional real-world validation samples and regression datasets.
- Optional exports for SIEM-friendly formats.
- Optional case-package export that bundles findings, reports, config, and reproducibility metadata.
- More detailed performance profiling and memory regression checks.
- Improved false-positive controls for high-frequency and unusual-port findings.
- Optional integrations with external tools, provided offline-only operation remains intact.

V2 work should not weaken the V1 promise: NetTrace must remain useful as an offline CLI tool with explainable evidence.

## Parking Lot

Use this section for ideas that are interesting but not yet assigned.

- Live capture sensor mode.
- Full browser-based investigation workspace.
- Multi-user case collaboration.
- Malware-family attribution model.
- Automatic scheduled intelligence sync.
