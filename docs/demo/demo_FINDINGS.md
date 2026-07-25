# NetTrace Findings: demo_beacon_http.pcap

## Dataset

- Source: NetTrace synthetic safety demo
- PCAP analyzed: `samples\suspicious\demo_beacon_http.pcap`

## Tool Summary

- DNS events: 1
- HTTP events: 1
- TLS events: 0
- FTP events: 0
- Flows: 3
- IOCs: 3
- Findings: 6
- Critical findings: 2
- High findings: 1
- Medium findings: 3
- Low findings: 0

## Analysis Warnings

- None observed

## Analyst Finding

NetTrace analyzed `samples\suspicious\demo_beacon_http.pcap` and identified `10.0.0.5` as the internal host with the highest observed external traffic volume (a triage heuristic, not confirmation of compromise). The capture contains 1 DNS events, 1 plaintext HTTP requests, 0 TLS SNI events, 0 FTP commands, and 3 flows. High-confidence findings warrant malware staging and command-and-control triage; heuristic findings should still be validated with packet context before conclusions are drawn.

## Finding Types

- Local threat intel match: 2
- Possible DGA domain: 1
- Command-line or automation HTTP client observed: 1
- Possible executable/script download request: 1
- Connection to suspicious non-standard port: 1

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
