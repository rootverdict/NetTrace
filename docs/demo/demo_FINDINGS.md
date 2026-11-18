# NetTrace Findings: demo_beacon_http.pcap

## Dataset

- PCAP analyzed: `samples\suspicious\demo_beacon_http.pcap`

## Tool Summary

- DNS events: 1
- HTTP events: 1
- TLS events: 0
- FTP events: 0
- Flows: 3
- IOCs: 3
- Findings: 7
- Critical findings: 2
- High findings: 1
- Medium findings: 2
- Low findings: 1
- Info findings: 1

## Analysis Warnings

- None observed

## Analyst Finding

NetTrace analyzed `samples\suspicious\demo_beacon_http.pcap` and identified `10.0.0.5` as the internal host with the highest observed external traffic volume (a triage heuristic, not confirmation of compromise). The capture contains 1 DNS events, 1 plaintext HTTP requests, 0 TLS SNI events, 0 FTP commands, and 3 flows. 3 high/critical-severity finding(s) were produced, led by Possible DGA domain, Local threat intel match. Associated network indicators include plaintext HTTP staging URLs (`http://malware-test.example/payload.exe`) and public IP/port candidates `203.0.113.66:4444`. These warrant focused triage; heuristic findings should still be validated with packet context before conclusions are drawn.

## Finding Types

- Local threat intel match: 2
- Possible beaconing behavior: 1
- Possible DGA domain: 1
- Command-line or automation HTTP client observed: 1
- Possible executable/script download request: 1
- Connection to suspicious non-standard port: 1

## AI Threat Intelligence

- Threat Verdict: MALICIOUS (Confidence: HIGH)

**Executive Summary:** Analysis of network capture 'demo_beacon_http.pcap' indicates an active malware infection on internal host 10.0.0.5. The endpoint is communicating via periodic TCP beaconing to an external IP on port 4444, performing DNS lookups for a high-entropy domain identified as a DGA, and subsequently downloading a payload via HTTP from a known malicious domain matching local threat intelligence.

### Attack Narrative

- `Step 1: Host 10.0.0.5 initiates periodic TCP beaconing activity to external IP 203.0.113.66 on port 4444 with a consistent 10-second interval.`
- `Step 2: The infected host performs a DNS resolution request for a Domain Generation Algorithm (DGA) domain 'xj3k9q2z7m1p0a8c.biz', which matches known threat intelligence IOCs.`
- `Step 3: The host issues an HTTP GET request to 'malware-test.example' to download an executable payload ('/payload.exe'), confirming C2 stage-2 download behavior.`

### Recommended Containment Actions

- `Isolate host 10.0.0.5 immediately from the network to prevent further lateral movement or data exfiltration.`
- `Block outbound traffic to IP 203.0.113.66 and domains 'xj3k9q2z7m1p0a8c.biz' and 'malware-test.example' at the perimeter firewall/proxy.`
- `Perform forensic analysis on host 10.0.0.5 to identify the execution vector and remove the downloaded 'payload.exe' artifact.`

### Wireshark Hunting Guidance

- `Use filter 'ip.addr == 10.0.0.5' to review all network activity originating from the compromised host.`
- `Use filter 'tcp.port == 4444 or http.request' to isolate potential C2 channels and payload download requests.`

## Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1071.001 - Application Layer Protocol: Web Protocols`
- `T1071.004 - Application Layer Protocol: DNS`

## Notable URLs

- `http://malware-test.example/payload.exe`

## Notable Domains

- `malware-test.example`
- `xj3k9q2z7m1p0a8c.biz`

## Notable IPs And Ports

- `203.0.113.66:4444`

## Notes

- This write-up was generated automatically from NetTrace JSON output.
- Treat heuristic detections as triage leads and validate them against packet context.
- This workflow analyzes PCAP files only and does not execute malware.
