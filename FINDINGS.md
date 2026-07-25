# NetTrace Findings

## Dataset

NetTrace was run against 5 real public Malware-Traffic-Analysis.net PCAP samples. The workflow analyzes packet captures only and does not execute malware.

## Scan Summary

| Sample | Packets | DNS | HTTP | TLS | FTP | Flows | IOCs | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Emotet Epoch 5 | 19895 | 327 | 8 | 32 | 0 | 813 | 180 | 32 |
| Raspberry Robin | 91481 | 4 | 0 | 0 | 0 | 51 | 20 | 42 |
| Redtail Linux malware | 43041 | 0 | 3 | 0 | 0 | 40687 | 40650 | 2 |
| AgentTesla FTP variant | 182 | 6 | 0 | 1 | 14 | 10 | 7 | 6 |
| SmartApeSG to NetSupport RAT | 16931 | 8 | 32 | 9 | 0 | 16 | 12 | 4 |

## Aggregate Totals

- Packets: 171530
- DNS events: 345
- HTTP events: 43
- TLS events: 42
- FTP events: 14
- Flows: 41577
- IOCs: 40869
- Findings: 86

## Potential ATT&CK Technique Associations

- `T1573 - Encrypted Channel`

## Emotet Epoch 5

- Source: https://www.malware-traffic-analysis.net/2023/03/17/index.html
- PCAP: `samples\real\2023-03-17-Emotet-E5-infection-traffic.pcap`
- Primary internal host heuristic: `10.3.18.101`
- Findings: 32

### Finding Types

- High-frequency connection: 28
- Long TLS session: 2
- Possible beaconing behavior: 1
- Unusually long TLS SNI: 1

### Notable URLs

- `http://aristonbentre.com/slideshow/O1uPzXd2YscA/`
- `http://attatory.com/i-bmail/6AfEa8G0W8NOtUh7hqFj/`
- `http://asakitreks.com/uploads/ce8u7/`
- `http://bvdkhuyentanyen.vn/files/TKK8yKdEvyYAbBE5avb/`
- `http://bluegdps100.7m.pl/app/Ac8wwulKxqZjc/`

### Notable Domains

- `applink.gr`
- `aristonbentre.com`
- `asakitreks.com`
- `attatory.com`
- `bitefreehand-dc.bitethefreehand.net`
- `bitethefreehand.net`
- `bluegdps100.7m.pl`
- `bvdkhuyentanyen.vn`

### Notable IPs And Ports

- `72.21.81.200`
- `52.159.126.152`
- `13.107.5.88`
- `213.79.120.196:443`
- `112.213.89.130:80`
- `95.216.27.211:443`
- `150.60.21.231:80`
- `91.237.33.134:443`

## Raspberry Robin

- Source: https://www.malware-traffic-analysis.net/2024/11/14/index.html
- PCAP: `samples\real\2024-11-14-Raspberry-Robin-infection-traffic.pcap`
- Primary internal host heuristic: `10.0.0.101`
- Findings: 42

### Finding Types

- High-frequency connection: 26
- Connection to suspicious non-standard port: 16

### Notable URLs

- None observed

### Notable Domains

- `2z.si`
- `735dba63.bright-witted.skin`
- `www.vfnbzcosotyp.com`

### Notable IPs And Ports

- `38.180.208.173`
- `172.67.153.95:443`
- `194.165.16.82:443`
- `185.141.56.26:443`
- `107.189.29.184:443`
- `139.99.134.168:80`
- `194.26.192.77:110`
- `139.99.170.35:443`

## Redtail Linux malware

- Source: https://www.malware-traffic-analysis.net/2024/11/24/index.html
- PCAP: `samples\real\2024-11-24-infection-by-Redtail-bash-script-from-45.202.35_190.pcap`
- Primary internal host heuristic: `10.11.24.101`
- Findings: 2

### Finding Types

- High-frequency connection: 2

### Notable URLs

- `http://45.202.35.190/sh`
- `http://45.202.35.190/clean`
- `http://45.202.35.190/x86_64`

### Notable Domains

- `45.202.35.190`

### Notable IPs And Ports

- `45.202.35.190:80`
- `87.120.113.231:43782`
- `1.1.107.147`
- `1.10.42.45`
- `1.101.228.228`
- `1.103.127.173`
- `1.104.177.55`
- `1.105.162.243`

## AgentTesla FTP variant

- Source: https://www.malware-traffic-analysis.net/2024/12/04/index.html
- PCAP: `samples\real\2024-12-04-AgentTesla-variant-using-FTP.pcap`
- Primary internal host heuristic: `10.12.4.101`
- Findings: 6

### Finding Types

- File upload over FTP: 4
- Cleartext FTP credentials: 2

### Potential ATT&CK Technique Associations

- None observed

### Notable URLs

- None observed

### Notable Domains

- `api.ipify.org`
- `ercolina-usa.com`
- `ftp.ercolina-usa.com`

### Notable IPs And Ports

- `104.26.12.205`
- `104.26.13.205`
- `172.67.74.152`
- `192.254.225.136`

## SmartApeSG to NetSupport RAT

- Source: https://www.malware-traffic-analysis.net/2024/12/17/index.html
- PCAP: `samples\real\2024-12-17-SmartApeSG-to-NetSupport-RAT.pcap`
- Primary internal host heuristic: `10.12.17.101`
- Findings: 4

### Finding Types

- High-frequency connection: 4

### Notable URLs

- `http://geo.netsupportsoftware.com/location/loca.asp`
- `http://194.180.191.64/fakeurl.htm`

### Notable Domains

- `banks-canada.com`
- `depostsolo.biz`
- `geo.netsupportsoftware.com`
- `taktlat.xyz`

### Notable IPs And Ports

- `194.180.191.64`
- `34.42.173.126:443`
- `185.33.84.25:443`
- `194.180.191.64:443`
- `104.26.0.231`
- `104.26.1.231`
- `172.67.68.212`
- `185.33.84.25`

## Notes

- This write-up was generated from NetTrace JSON output across all five real PCAP scans.
- Treat heuristic detections as triage leads and validate them against packet context.
- Output reports for each scan are available under `output/real/` after running the analysis commands.
