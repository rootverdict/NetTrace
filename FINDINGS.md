# NetTrace Findings

## Dataset

NetTrace was run against 12 real public Malware-Traffic-Analysis.net PCAP samples. The workflow analyzes packet captures only and does not execute malware.

## Scan Summary

| Sample | Packets | DNS | HTTP | TLS | FTP | Flows | IOCs | Observed Artifacts | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Emotet Epoch 5 | 19895 | 327 | 8 | 32 | 0 | 813 | 135 | 81 | 25 |
| Raspberry Robin | 91481 | 4 | 0 | 21 | 0 | 51 | 7 | 17 | 13 |
| Redtail Linux malware | 43041 | 0 | 3 | 0 | 0 | 40687 | 4 | 40647 | 6 |
| AgentTesla FTP variant | 182 | 6 | 0 | 1 | 16 | 10 | 7 | 2 | 6 |
| SmartApeSG to NetSupport RAT | 16931 | 8 | 32 | 9 | 0 | 16 | 12 | 4 | 3 |
| Mirai IoT botnet | 118105 | 8 | 13 | 0 | 0 | 50000 | 8 | 49890 | 16 |
| In-the-wild scans (Dec 1-3) | 42 | 0 | 5 | 0 | 0 | 5 | 2 | 6 | 0 |
| XWorm from email | 4645 | 4 | 0 | 2 | 0 | 5 | 5 | 3 | 2 |
| Ten days of scans and probes | 374554 | 640 | 6180 | 0 | 0 | 50000 | 1784 | 10297 | 134 |
| XLoader (Formbook) | 41424 | 4151 | 1484 | 89 | 0 | 1960 | 816 | 115 | 40 |
| Infected Android phone | 29125 | 126 | 33 | 40 | 0 | 400 | 152 | 44 | 23 |
| Koi Loader / Koi Stealer | 43721 | 303 | 55 | 120 | 0 | 216 | 335 | 66 | 37 |

## Aggregate Totals

- Packets: 783146
- DNS events: 5577
- HTTP events: 7813
- TLS events: 314
- FTP events: 16
- Flows: 144163
- IOCs: 3267
- Observed artifacts: 101172
- Findings: 305

## Potential ATT&CK Technique Associations

- `T1071.001 - Application Layer Protocol: Web Protocols`
- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1573 - Encrypted Channel`

## Emotet Epoch 5

- Source: https://www.malware-traffic-analysis.net/2023/03/17/index.html
- PCAP: `samples\real\2023-03-17-Emotet-E5-infection-traffic.pcap`
- Primary internal host heuristic: `10.3.18.101`
- Findings: 25

### Finding Types

- High-frequency connection: 20
- Long TLS session: 2
- Possible beaconing behavior: 1
- Possible DGA domain: 1
- Unusually long TLS SNI: 1

### Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1573 - Encrypted Channel`

### Notable URLs

- `http://aristonbentre.com/slideshow/O1uPzXd2YscA/`
- `http://attatory.com/i-bmail/6AfEa8G0W8NOtUh7hqFj/`
- `http://asakitreks.com/uploads/ce8u7/`
- `http://bvdkhuyentanyen.vn/files/TKK8yKdEvyYAbBE5avb/`
- `http://bluegdps100.7m.pl/app/Ac8wwulKxqZjc/`

### Notable Domains

- `a767.dspw65.akamai.net`
- `ak.privatelink.msidentity.com`
- `applink.gr`
- `arc.trafficmanager.net`
- `aristonbentre.com`
- `asakitreks.com`
- `atm-settingsfe-prod-geo2.trafficmanager.net`
- `attatory.com`
- `bg.apr-52dd2-0503.edgecastdns.net`
- `bitefreehand-dc.bitethefreehand.net`
- `bitethefreehand.net`
- `bluegdps100.7m.pl`

### Notable IPs And Ports

- `224.0.0.252:5355`
- `13.107.5.88`
- `103.77.162.25:80`
- `112.213.89.130:80`
- `115.178.55.22:80`
- `116.125.120.88:443`
- `138.197.14.67:8080`
- `139.196.72.155:8080`
- `149.202.75.212:80`
- `150.60.21.231:80`
- `165.227.211.222:8080`
- `178.62.112.199:8080`

## Raspberry Robin

- Source: https://www.malware-traffic-analysis.net/2024/11/14/index.html
- PCAP: `samples\real\2024-11-14-Raspberry-Robin-infection-traffic.pcap`
- Primary internal host heuristic: `10.0.0.101`
- Findings: 13

### Finding Types

- High-frequency connection: 12
- Connection to suspicious non-standard port: 1

### Notable URLs

- None observed

### Notable Domains

- `2z.si`
- `735dba63.bright-witted.skin`
- `www.vfnbzcosotyp.com`

### Notable IPs And Ports

- `107.189.29.184:443`
- `139.99.134.168:80`
- `139.99.170.35:443`
- `162.251.116.50:443`
- `172.67.153.95:443`
- `185.141.56.26:443`
- `193.219.97.25:9001`
- `194.165.16.82:443`
- `194.26.192.77:110`
- `37.114.55.122:9001`
- `38.180.208.173:443`
- `62.141.48.175:444`

## Redtail Linux malware

- Source: https://www.malware-traffic-analysis.net/2024/11/24/index.html
- PCAP: `samples\real\2024-11-24-infection-by-Redtail-bash-script-from-45.202.35_190.pcap`
- Primary internal host heuristic: `10.11.24.101`
- Findings: 6

### Finding Types

- Command-line or automation HTTP client observed: 3
- High-frequency connection: 2
- Connection to suspicious non-standard port: 1

### Notable URLs

- `http://45.202.35.190/sh`
- `http://45.202.35.190/clean`
- `http://45.202.35.190/x86_64`

### Notable Domains

- None observed

### Notable IPs And Ports

- `45.202.35.190:80`
- `87.120.113.231:43782`

## AgentTesla FTP variant

- Source: https://www.malware-traffic-analysis.net/2024/12/04/index.html
- PCAP: `samples\real\2024-12-04-AgentTesla-variant-using-FTP.pcap`
- Primary internal host heuristic: `10.12.4.101`
- Findings: 6

### Finding Types

- File upload over FTP: 4
- Cleartext FTP credentials: 2

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
- Findings: 3

### Finding Types

- High-frequency connection: 3

### Notable URLs

- `http://geo.netsupportsoftware.com/location/loca.asp`
- `http://194.180.191.64/fakeurl.htm`

### Notable Domains

- `banks-canada.com`
- `depostsolo.biz`
- `geo.netsupportsoftware.com`
- `taktlat.xyz`

### Notable IPs And Ports

- `185.33.84.25:443`
- `194.180.191.64:443`
- `34.42.173.126:443`
- `104.26.0.231`
- `104.26.1.231`
- `172.67.68.212`

## Mirai IoT botnet

- Source: https://www.malware-traffic-analysis.net/2025/12/17/index.html
- PCAP: `samples\real\2025-12-17-testing-the-Mirai-botnet-URL-on-a-VM.pcap`
- Primary internal host heuristic: `10.12.17.101`
- Findings: 16

### Finding Types

- Command-line or automation HTTP client observed: 13
- Connection to suspicious non-standard port: 2
- High-frequency connection: 1

### Notable URLs

- `http://158.94.210.88/jaws`
- `http://158.94.210.88/596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.x86`
- `http://158.94.210.88/596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips`
- `http://158.94.210.88/596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mpsl`

### Notable Domains

- `cnc.504.su`

### Notable IPs And Ports

- `158.94.210.88:80`

## In-the-wild scans (Dec 1-3)

- Source: https://www.malware-traffic-analysis.net/2025/12/17/index.html
- PCAP: `samples\real\2025-12-01-thru-12-03-in-the-wild-scans.pcap`
- Primary internal host heuristic: `unknown`
- Findings: 0

### Finding Types

- None observed

### Notable URLs

- `http://127.0.0.1:80/shell?cd+/tmp;rm+-rf+*;wget+`

### Notable Domains

- None observed

### Notable IPs And Ports

- `203.161.44.208`

## XWorm from email

- Source: https://www.malware-traffic-analysis.net/2025/11/19/index.html
- PCAP: `samples\real\2025-11-19-Xworm-infection-traffic.pcap`
- Primary internal host heuristic: `10.11.19.101`
- Findings: 2

### Finding Types

- High-frequency connection: 2

### Notable URLs

- None observed

### Notable Domains

- `mail.intibu.com`
- `pastebin.com`

### Notable IPs And Ports

- `193.187.91.217:60875`
- `213.238.165.14:443`
- `104.20.29.150`
- `172.66.171.73`

## Ten days of scans and probes

- Source: https://www.malware-traffic-analysis.net/2025/12/28/index.html
- PCAP: `samples\real\2025-12-28-ten-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap`
- Primary internal host heuristic: `unknown`
- Findings: 134

### Finding Types

- Command-line or automation HTTP client observed: 107
- Connection to suspicious non-standard port: 12
- High-frequency connection: 10
- Possible executable/script download request: 4
- Possible DGA domain: 1

### Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1071.001 - Application Layer Protocol: Web Protocols`

### Notable URLs

- `http://203.161.44.208/`
- `http://203.161.44.208:8080/goform/set_LimitClient_cfg`
- `http://203.161.44.208:80/`
- `http://203.161.44.208:8080/`
- `http://203.161.44.208:8080/favicon.ico`
- `http://api.ipify.org/?format=json`
- `https://www.shadowserver.org:443`
- `http://203.161.44.208:8080/geoserver/web/`

### Notable Domains

- `00064659aca8aaf7.36bf.203-161-44-208.asertdnsresearch.com`
- `000646b44b61e584.5b2b.203-161-44-208.asertdnsresearch.com`
- `000646fcae109b35.9df4.203-161-44-208.asertdnsresearch.com`
- `203.161.044.208`
- `203.161.44.208.1766401200.main.research.openresolve.rs`
- `3416337616.round2025-12-01.odns.m.dnsmeasure.top`
- `3416337616.round2025-12-08.odns.m.dnsmeasure.top`
- `3416337616.round2025-12-22.odns.m.dnsmeasure.top`
- `a.gtld-servers.net`
- `a.root-servers.net`
- `aaa.heimaoip.com`
- `api.ip.pn`

### Notable IPs And Ports

- `203.161.44.208:23`
- `203.161.44.208:1337`
- `203.161.44.208:2323`
- `203.161.44.208:4444`
- `203.161.44.208:5555`
- `203.161.44.208:6667`
- `203.161.44.208:7547`
- `203.161.44.208:9001`
- `203.161.44.208:31337`
- `203.161.44.208:37215`
- `203.161.44.208:52869`
- `112.124.42.80`

## XLoader (Formbook)

- Source: https://www.malware-traffic-analysis.net/2025/09/05/index.html
- PCAP: `samples\real\2025-09-05-XLoader-infection-traffic.pcap`
- Primary internal host heuristic: `10.9.5.71`
- Findings: 40

### Finding Types

- High-frequency connection: 34
- Possible DGA domain: 4
- Unusually long TLS SNI: 2

### Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1573 - Encrypted Channel`

### Notable URLs

- `http://www.rvsrdp.top/mih1/?_u=bonrQWH&ImjI=JCsMENO1DaHtsDaMnB9ganhSrR2D+Y3mCW2ko3bk24A1yexe0V+5VHhew4Chr6OzdNfI9aUdNcQZGjTJfv51CaJCaI+PaSCbdwyIjHK3IMoTF99WaAiIPdROKKN6n+9pTSj9ByI=`
- `http://www.tvvpg.vip/wrld/`
- `http://www.tvvpg.vip/wrld/?ImjI=fc8biP0K1wqSv2gzSaQykErzvO7Wp17do+so+0skkIa7+GSzAfbF6wCkZtUP+Wnb/m7R5Od1NSKr+0RGtsh9mxc5B4Jc6g3eIheJb4R7l9c/eMyWOhz061/O6wsVwpQA3jLd06w=&_u=bonrQWH`
- `http://www.printerapp.xyz/d3v5/`
- `http://www.printerapp.xyz/d3v5/?_u=bonrQWH&ImjI=MUvYfkz6yatg91MRlmiDHfYjbtLl2FjK/LvQ8zjrFJei16kgg7+1IL1Yscqe1Dg7flgnO/25PDzORpg+zHq6a4Go34yYuGgNx6AsdkLFE9tSYJuVcdoCo1HD0J1y1d2BVWEWE7s=`
- `http://www.translateplatform.xyz/5czy/`
- `http://www.translateplatform.xyz/5czy/?ImjI=m7J2nKSGN5V9/v9seyEH6MwLbma4z+uBmmzv6/vatDHGCQ/JNs8PgQHLMIb7Bo4dV2qWayKAqegWhX/TF4BIu+OsX94ujZhLeRawDXAybrETuAwdHCHomHzuQyTAXMpDBXZOFSs=&_u=bonrQWH`
- `http://www.g732b1.top/f51i/`

### Notable Domains

- `01vk.top`
- `02eg.top`
- `3300bei2.cdn.91ddos.com`
- `a1666.dscr.akamai.net`
- `a1672.dscr.akamai.net`
- `a1830.dscg2.akamai.net`
- `a1834.dscg2.akamai.net`
- `a1847.dscd.akamai.net`
- `agconcrete.info`
- `arr.pt.cdn-dysxb.com`
- `assets-msn-com-world-atm-default.trafficmanager.net`
- `atm-settingsfe-prod-geo2.trafficmanager.net`

### Notable IPs And Ports

- `23.55.178.209`
- `146.75.106.172:80`
- `149.104.35.113:80`
- `151.101.114.172:80`
- `154.91.28.243:80`
- `162.0.239.7:80`
- `166.117.110.61:80`
- `172.67.148.61:80`
- `172.67.206.4:80`
- `20.242.39.171:443`
- `20.59.87.227:443`
- `23.219.157.196:443`

## Infected Android phone

- Source: https://www.malware-traffic-analysis.net/2025/10/02/index.html
- PCAP: `samples\real\2025-10-02-traffic-from-infected-Android-phone.pcap`
- Primary internal host heuristic: `10.10.2.101`
- Findings: 23

### Finding Types

- High-frequency connection: 19
- Possible DGA domain: 4

### Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`

### Notable URLs

- `http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/obedbbhbpmojnkanicioggnmelmoomoc/e057e03e3bd3244505eaa18e4159e3fc610d98ee9d6052194e0c35ec30e4403f`
- `http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/niikhdgajlphfehepabhhblakbdgeefj/97b4e68a7a79ae5be44033dbc869b57b36884d4ba50887521547c98b08363638`
- `http://edgedl.me.gvt1.com/edgedl/release2/chrome_component/hygn7z545gyhab6hxx4zqnojge_543/lmelglejhemejginpboagddgdfbepgmp_543_all_ZZ_ftuvgw5w5hhii42dlplkieokxe.crx3`
- `http://edgedl.me.gvt1.com/edgedl/diffgen-puffin/kiabhabjdbkjdpjbpigfodbdjmbglcoo/576b942245c712f8103348d8b5f9e7c450e48603f5456b10bcce51de0c5783ad`
- `http://edgedl.me.gvt1.com/edgedl/release2/chrome_component/V3P1l2hLvLw_7/7_all_sslErrorAssistant.crx3`
- `http://edgedl.me.gvt1.com/edgedl/release2/chrome_component/pmwjjzrzpgfwjodqqj542dn6kq_67/khaoiebndkojlmppeemjhbpbandiljpe_67_android_epp2f7wtecwsnk5eqcobxrqmyi.crx3`
- `http://edgedl.me.gvt1.com/edgedl/release2/chrome_component/ioziu5q5vmx3mpiu4gpl7nc2qi_10067/hfnkpimlhhgieaddgfemjhofmfblmnib_10067_all_acumisz3pmtwnc34aafsgh2jp6aq.crx3`
- `http://app.nfuenglish2025.com//api/user_login`

### Notable Domains

- `accounts.google.com`
- `android-safebrowsing.google.com`
- `android.apis.google.com`
- `android.googleapis.com`
- `app.nfuenglish2025.com`
- `clients.l.google.com`
- `clients4.google.com`
- `connectivitycheck.gstatic.com`
- `de0mpg.cdn-settings.appsflyersdk.com`
- `digitalassetlinks.googleapis.com`
- `edgedl.me.gvt1.com`
- `eip-terr-na.v5bkduxxffeipb.akahost.net`

### Notable IPs And Ports

- `101.32.207.8:8080`
- `141.207.227.233:4500`
- `142.250.113.139:443`
- `142.250.113.17:443`
- `142.250.113.94:443`
- `142.250.114.132:443`
- `142.250.114.94:443`
- `142.251.116.91:443`
- `142.251.116.95:443`
- `142.251.186.17:443`
- `173.194.208.95:443`
- `192.178.220.95:443`

## Koi Loader / Koi Stealer

- Source: https://www.malware-traffic-analysis.net/2025/07/08/index.html
- PCAP: `samples\real\2025-07-08-traffic-from-Koi-Loader-Koi-Stealer-infection.pcap`
- Primary internal host heuristic: `10.7.8.101`
- Findings: 37

### Finding Types

- High-frequency connection: 32
- Possible DGA domain: 3
- Unusually long TLS SNI: 2

### Potential ATT&CK Technique Associations

- `T1568.002 - Dynamic Resolution: Domain Generation Algorithms`
- `T1573 - Encrypted Channel`

### Notable URLs

- `http://adl.windows.com/appraiseradl/2025_07_02_04_05_AMD64.cab`
- `http://193.29.57.167/topotactic.php`
- `http://193.29.57.167/index.php?id=&subid=HTdJFr1M`
- `http://193.29.57.167/index.php`
- `http://193.29.57.167/index.php?ver=64&type=1`
- `http://193.29.57.167/index.php?ver=64&type=2`
- `http://www.msftconnecttest.com/connecttest.txt`
- `http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Doh%2FsBYgFV7gQUA95QNVbRTLtm8KPiGxvDl7I90VUCEAJ0LqoXyo4hxxe7H%2Fz9DKA%3D`

### Notable Domains

- `483230049-atari-embeds.googleusercontent.com`
- `a1666.dscr.akamai.net`
- `a1672.dscr.akamai.net`
- `a1830.dscg2.akamai.net`
- `a1834.dscg2.akamai.net`
- `a1943.g2.akamai.net`
- `a1961.g2.akamai.net`
- `a1968.i6g1.akamai.net`
- `a2033.dscd.akamai.net`
- `a978.i6g1.akamai.net`
- `adl.windows.com`
- `adl.windows.com.edgesuite.net`

### Notable IPs And Ports

- `23.47.50.160`
- `104.18.21.213:80`
- `128.85.113.134:443`
- `13.107.246.57:443`
- `130.213.27.180:443`
- `142.250.114.101:443`
- `142.250.114.99:443`
- `142.250.115.138:443`
- `142.251.186.132:443`
- `142.251.186.94:443`
- `150.171.28.11:443`
- `151.101.182.172:80`

## Notes

- This write-up was generated from NetTrace JSON output across every real PCAP scan in the corpus.
- Treat heuristic detections as triage leads and validate them against packet context.
- Output reports for each scan are available under `output/real/` after running the analysis commands.
