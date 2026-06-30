# NetTrace

NetTrace is a Python malware traffic analysis platform for offline PCAP analysis. It extracts network artifacts, identifies suspicious behavior, maps findings to MITRE ATT&CK techniques, and generates analyst-ready JSON, HTML, and PDF reports.

The project is designed for malware traffic analysis, SOC triage, threat hunting practice, and resume-ready detection engineering work.

## What NetTrace Does

- Parses PCAP files in a single pass
- Extracts DNS queries, DNS responses, and TTLs
- Extracts plaintext HTTP methods, hosts, URIs, URLs, and user agents
- Extracts TLS ClientHello SNI values on common TLS ports
- Builds IP flow and conversation metadata
- Extracts IOCs including domains, URLs, and public IP addresses
- Filters internal/private IPs and known public DNS resolvers from IOC output
- Detects beaconing using interval regularity
- Scores possible DGA domains using entropy and character-pattern analysis
- Applies a DGA allowlist for Windows, Microsoft, local, and known-good infrastructure
- Detects suspicious HTTP behavior and executable/script downloads
- Detects high-frequency flows and unusual ports
- Supports local IOC matching
- Supports optional MISP enrichment
- Maps findings to MITRE ATT&CK
- Scores finding severity
- Builds a chronological activity timeline
- Adds packet numbers and Wireshark `frame.number` filters to report evidence
- Exports JSON, HTML, and PDF reports

## Architecture

```text
PCAP input
  |
  v
Parser layer
  - DNS extractor
  - HTTP extractor
  - TLS SNI extractor
  - Flow builder
  |
  v
Analysis layer
  - Beaconing detector
  - DGA scorer
  - HTTP analyzer
  - TLS analyzer
  - Port and frequency analyzer
  - IOC extractor
  |
  v
Intel and mapping layer
  - Local IOC lookup
  - Optional MISP lookup
  - MITRE ATT&CK tagging
  - Severity scoring
  - Timeline building
  |
  v
Report layer
  - JSON findings
  - HTML report
  - PDF report
```

## Project Structure

```text
NetTrace/
|-- pyproject.toml
|-- LICENSE
|-- main.py
|-- config.yaml
|-- FINDINGS.md
|-- findings/
|-- requirements.txt
|-- nettrace/
|   |-- analysis/
|   |-- data/
|   |-- intel/
|   |-- mapping/
|   |-- models/
|   |-- parsers/
|   |-- report/
|   |-- rules/
|-- samples/
|-- tests/
|-- tools/
```

## Install

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -e ".[dev]"
```

This installs the `nettrace` console command and the test dependency. If you prefer the simple script workflow, `pip install -r requirements.txt` also works.

## Run Tests

```powershell
python -m pytest
```

Expected result:

```text
All tests should pass.
```

## Run the Safe Demo

Generate a safe synthetic PCAP:

```powershell
python tools\generate_demo_pcap.py
```

Analyze it:

```powershell
nettrace samples\suspicious\demo_beacon_http.pcap -o output
```

You can also run the same CLI through the repository entry point:

```powershell
python main.py samples\suspicious\demo_beacon_http.pcap -o output
```

Generated outputs:

- `output/demo_beacon_http_findings.json`
- `output/demo_beacon_http_report.html`
- `output/demo_beacon_http_report.pdf`
- `findings/demo_beacon_http_FINDINGS.md`

The Markdown analyst write-up is generated automatically. You can also regenerate it from the JSON report:

```powershell
python tools\generate_findings_md.py output\demo_beacon_http_findings.json
```

By default, this creates:

```text
findings/demo_beacon_http_FINDINGS.md
```

## Analyze a PCAP

```powershell
nettrace path\to\traffic.pcap -o output
```

Script-style execution is still supported:

```powershell
python main.py path\to\traffic.pcap -o output
```

Optional flags:

- `--no-json` - skip JSON export
- `--no-html` - skip HTML report
- `--no-pdf` - skip PDF report
- `--no-md` - skip Markdown analyst findings
- `--md-output path\to\file.md` - write Markdown findings to a custom path
- `--source "Dataset name"` - add source metadata to Markdown findings
- `--source-url "https://example.test"` - add source URL metadata to Markdown findings
- `-c config.yaml` - use a custom config file

## Generate Analyst Findings

NetTrace can turn a JSON findings report into a Markdown analyst write-up:

```powershell
python tools\generate_findings_md.py output\real\2023-03-17-Emotet-E5-infection-traffic_findings.json --source "Malware-Traffic-Analysis.net - 2023-03-17 Emotet Epoch 5 Activity" --source-url "https://www.malware-traffic-analysis.net/2023/03/17/index.html"
```

By default, the script writes one separate file per scan:

```text
findings/2023-03-17-Emotet-E5-infection-traffic_FINDINGS.md
```

To create or update the root showcase report, pass `-o FINDINGS.md`:

```powershell
python tools\generate_findings_md.py output\real\2023-03-17-Emotet-E5-infection-traffic_findings.json -o FINDINGS.md --source "Malware-Traffic-Analysis.net - 2023-03-17 Emotet Epoch 5 Activity" --source-url "https://www.malware-traffic-analysis.net/2023/03/17/index.html"
```

The generated Markdown includes:

- dataset metadata
- summary counts
- analyst paragraph
- finding type counts
- ATT&CK techniques
- notable URLs
- notable domains
- notable IPs and ports
- triage notes

## Real Malware Traffic Analysis

NetTrace was validated against 5 real public Malware-Traffic-Analysis.net PCAP samples across multiple malware families and traffic patterns:

- Emotet Epoch 5 - staging URLs and command-and-control traffic
- Raspberry Robin - loader/worm-style infection traffic
- Redtail - Linux malware and server-side infection traffic
- AgentTesla - credential-stealer traffic using FTP behavior
- NetSupport RAT - remote access malware traffic

Included real PCAP files:

- `samples/real/2023-03-17-Emotet-E5-infection-traffic.pcap`
- `samples/real/2024-11-14-Raspberry-Robin-infection-traffic.pcap`
- `samples/real/2024-11-24-infection-by-Redtail-bash-script-from-45.202.35_190.pcap`
- `samples/real/2024-12-04-AgentTesla-variant-using-FTP.pcap`
- `samples/real/2024-12-17-SmartApeSG-to-NetSupport-RAT.pcap`

Showcase analysis:

- Source page: `https://www.malware-traffic-analysis.net/2023/03/17/index.html`
- Dataset: `2023-03-17 - Emotet Epoch 5 Activity`
- Analysis write-up: `FINDINGS.md`

The Emotet showcase analysis produced:

- 327 DNS events
- 8 plaintext HTTP requests
- 32 TLS SNI events
- 813 flows
- 138 IOCs
- 31 findings

The analyst write-up identifies Emotet staging URLs, C2 infrastructure, high-frequency encrypted flows, and ATT&CK-mapped behavior.

## Known Limitations

- Flow direction is inferred from TCP SYN/SYN-ACK when available, then private-to-public and service-port heuristics. Ambiguous one-direction mid-session captures can still report direction incorrectly.
- The generated analyst paragraph identifies the busiest internal host as the likely victim. In multi-host captures, treat this as a triage heuristic rather than ground truth.
- Demo traffic uses documentation-range addresses where applicable. Real IOC analysis filters documentation, private, loopback, link-local, multicast, reserved, unspecified, and known resolver IPs from public-IP IOC output.

## Detection Rules

Rules and tunable values live in `nettrace/rules/`:

- `attck_map.yaml` - maps finding categories to MITRE ATT&CK techniques
- `thresholds.yaml` - stores detection thresholds
- `suspicious_ports.yaml` - lists suspicious or non-standard ports
- `dga_allowlist.yaml` - suppresses known benign DGA false positives

## MISP Integration

MISP enrichment is optional. NetTrace works offline with local IOC lists in `nettrace/data/`.

To enable MISP, edit `config.yaml`:

```yaml
misp:
  enabled: true
  url: "https://misp.example.local"
  api_key: "YOUR_API_KEY"
  verify_ssl: true
```

## Technical Notes

- PCAP files are processed in a single pass.
- NetTrace keeps extracted events and flow metadata, not every raw packet.
- Reports include packet references so findings can be rechecked in Wireshark with `frame.number` filters.
- HTTP parsing is plaintext HTTP only.
- HTTPS payloads cannot be inspected unless the traffic is decrypted before analysis.
- TLS analysis focuses on SNI, destination IP, port, timing, and flow duration.
- PDF reports are generated with ReportLab for a Windows-friendly Python setup.
- Scapy may print `No libpcap provider available` on Windows. This is harmless for offline PCAP parsing.

## Limitations

- DGA scoring is heuristic and should be reviewed by an analyst.
- Encrypted traffic analysis is metadata-based unless decrypted traffic is available.
- High-frequency flow detection can include benign large transfers and should be triaged with context.
- Local IOC lists are demonstration data unless replaced with operational threat intelligence.

## Safety

NetTrace analyzes packet captures only. Do not execute malware on a host operating system. Use isolated virtual machines for malware detonation, sample handling, or live infection-lab work.

## Author

Aryan - MSc DFIS, NFSU Gandhinagar

## Resume Bullets

- Built NetTrace, a Python malware traffic analysis platform that parses PCAPs, extracts IOCs, detects suspicious DNS, HTTP, TLS, and flow behavior, maps findings to MITRE ATT&CK, and generates JSON, HTML, and PDF reports.
- Validated NetTrace against 5 real Malware-Traffic-Analysis.net PCAP samples across Emotet, Raspberry Robin, Redtail, AgentTesla, and NetSupport RAT traffic.
