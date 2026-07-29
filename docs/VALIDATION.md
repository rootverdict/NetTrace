# Detection Validation

NetTrace was evaluated against twelve public, labeled malware-traffic captures from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/). The goal is artifact and behavior coverage, not a claim of malware-family classification accuracy.

## Method

1. Use each source page as case-level ground truth.
2. Verify the downloaded PCAP against `samples/real/manifest.json`.
3. Run the default NetTrace configuration.
4. Compare extracted artifacts and behavior findings with indicators described by the source.
5. Record relevant misses and false-positive risks rather than converting a small case set into a misleading precision or recall percentage.

## Results

| Case | Source-described behavior | NetTrace evidence | Result |
|---|---|---|---|
| [Emotet Epoch 5](https://www.malware-traffic-analysis.net/2023/03/17/index.html) | Emotet infection traffic | 8 HTTP requests including five staging domains, 32 TLS SNI events, one 900s-interval beaconing finding, one DGA-scored domain, and 25 total findings | Detected |
| [Raspberry Robin](https://www.malware-traffic-analysis.net/2024/11/14/index.html) | Infection using a WebDAV server | 21 TLS SNI events covering the known infrastructure; repeated connections and a suspicious non-standard-port finding covering all 16 flows identified | Detected with behavioral heuristics |
| [Redtail](https://www.malware-traffic-analysis.net/2024/11/24/index.html) | Downloads `/sh`, `/clean`, and `/x86_64` from `45.202.35.190` | All three HTTP requests and URLs extracted; high-frequency behavior plus telnet scanning across 4,963 destinations identified | Detected |
| [AgentTesla FTP variant](https://www.malware-traffic-analysis.net/2024/12/04/index.html) | FTP control traffic and data exfiltration to `192.254.225.136` | FTP host/IP extracted; two cleartext-credential findings and four upload findings; password values redacted | Detected |
| [SmartApeSG to NetSupport RAT](https://www.malware-traffic-analysis.net/2024/12/17/index.html) | NetSupport geolocation request and repeated POST traffic to `194.180.191.64/fakeurl.htm` | Geolocation GET, 31 plaintext HTTP-on-443 POST requests carrying the `NetSupport Manager/1.3` user agent, destination IOC, and repeated-connection findings extracted | Detected |
| [Mirai IoT botnet](https://www.malware-traffic-analysis.net/2025/12/17/index.html) | Post-infection Telnet (23) and TCP 37215 connection attempts | Telnet scanning across 27,261 destinations and 22,519 destinations on 37215 reported as two aggregated port findings, plus 13 automation-client HTTP detections | Detected |
| [XLoader (Formbook)](https://www.malware-traffic-analysis.net/2025/09/05/index.html) | XLoader infection traffic | 4,151 DNS events, 1,484 HTTP requests, four DGA-scored domains | Detected |
| [Koi Loader / Koi Stealer](https://www.malware-traffic-analysis.net/2025/07/08/index.html) | Koi Loader/Koi Stealer infection | 303 DNS events, 120 TLS SNI events, three DGA-scored domains, two unusually long SNIs | Detected |
| [Infected Android phone](https://www.malware-traffic-analysis.net/2025/10/02/index.html) | NFC-relay malware with WebSocket C2 | 126 DNS events, 40 TLS SNI events, four DGA-scored domains | Detected with behavioral heuristics |
| [XWorm from email](https://www.malware-traffic-analysis.net/2025/11/19/index.html) | XWorm infection following an emailed lure | Persistent 3,970-packet C2 flow to `193.187.91.217:60875` flagged as a high-frequency connection | Detected with behavioral heuristics |
| [Ten days of scans and probes](https://www.malware-traffic-analysis.net/2025/12/28/index.html) | Ten days of internet background scanning against a web server | 6,180 HTTP requests, 107 automation-client detections, 12 aggregated port findings; used as a false-positive control rather than an infection case | Control sample |

## Current limitations observed

- NetTrace identifies suspicious network behavior; it does not assign a malware-family verdict.
- High-frequency and unusual-port findings can also represent benign traffic and require analyst review.
- The Raspberry Robin case is detected primarily through infrastructure and connection heuristics because much of its application traffic is encrypted or uses WebDAV patterns outside the current protocol-specific findings.
- A twelve-capture corpus is useful regression evidence but is still too small and too case-selected for a defensible global detection-rate claim.
- Beaconing detection is bounded to a maximum mean interval (`thresholds.beacon_max_interval_seconds`, default 3600s). The ten-day scanning capture otherwise produced 127 "beacons" with 2-to-48-hour intervals that were scheduled scanners, not C2. Slow-beacon hunting requires raising this bound.
- Unusual-port and high-frequency findings are aggregated (per port, and per destination endpoint respectively). This bounds output on scanning traffic but means one finding can represent tens of thousands of flows; read `flow_count` and `distinct_destinations` in the evidence.

The aggregate event and finding counts are recorded in [`../FINDINGS.md`](../FINDINGS.md).
