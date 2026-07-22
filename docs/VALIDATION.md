# Detection Validation

NetTrace was evaluated against five public, labeled malware-traffic captures from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/). The goal is artifact and behavior coverage, not a claim of malware-family classification accuracy.

## Method

1. Use each source page as case-level ground truth.
2. Verify the downloaded PCAP against `samples/real/manifest.json`.
3. Run the default NetTrace configuration.
4. Compare extracted artifacts and behavior findings with indicators described by the source.
5. Record relevant misses and false-positive risks rather than converting a small case set into a misleading precision or recall percentage.

## Results

| Case | Source-described behavior | NetTrace evidence | Result |
|---|---|---|---|
| [Emotet Epoch 5](https://www.malware-traffic-analysis.net/2023/03/17/index.html) | Emotet infection traffic | 8 HTTP requests including five staging domains, 32 TLS SNI events, one beaconing finding, and 32 total findings | Detected |
| [Raspberry Robin](https://www.malware-traffic-analysis.net/2024/11/14/index.html) | Infection using a WebDAV server | Known infrastructure extracted; repeated connections and 16 suspicious non-standard-port findings identified | Detected with behavioral heuristics |
| [Redtail](https://www.malware-traffic-analysis.net/2024/11/24/index.html) | Downloads `/sh`, `/clean`, and `/x86_64` from `45.202.35.190` | All three HTTP requests and URLs extracted; high-frequency scanning behavior identified | Detected |
| [AgentTesla FTP variant](https://www.malware-traffic-analysis.net/2024/12/04/index.html) | FTP control traffic and data exfiltration to `192.254.225.136` | FTP host/IP extracted; two cleartext-credential findings and four upload findings; password values redacted | Detected |
| [SmartApeSG to NetSupport RAT](https://www.malware-traffic-analysis.net/2024/12/17/index.html) | NetSupport geolocation request and repeated POST traffic to `194.180.191.64/fakeurl.htm` | Geolocation GET, plaintext HTTP-on-443 POST requests, destination IOC, and repeated-connection findings extracted | Detected |

## Current limitations observed

- NetTrace identifies suspicious network behavior; it does not assign a malware-family verdict.
- High-frequency and unusual-port findings can also represent benign traffic and require analyst review.
- The Raspberry Robin case is detected primarily through infrastructure and connection heuristics because much of its application traffic is encrypted or uses WebDAV patterns outside the current protocol-specific findings.
- A five-capture corpus is useful regression evidence but is too small and too case-selected for a defensible global detection-rate claim.

The aggregate event and finding counts are recorded in [`../FINDINGS.md`](../FINDINGS.md).
