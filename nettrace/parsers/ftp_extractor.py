from __future__ import annotations

from scapy.layers.inet import TCP

from nettrace.models.events import FTPEvent
from nettrace.parsers.tcp_stream import TCPStreamBuffers

FTP_CONTROL_PORT = 21
FTP_COMMANDS = {"USER", "PASS", "STOR", "RETR", "APPE", "DELE", "CWD", "PWD", "TYPE", "PASV", "PORT"}


class FTPStreamExtractor:
    def __init__(self, stream_options: dict | None = None) -> None:
        options = dict(stream_options or {})
        options["max_buffer_bytes"] = min(int(options.get("max_buffer_bytes", 65_536)), 65_536)
        self.streams = TCPStreamBuffers(**options)

    def feed(self, packet, packet_number: int = 0) -> list[FTPEvent]:
        if not packet.haslayer(TCP) or int(packet[TCP].dport) != FTP_CONTROL_PORT:
            return []
        state = self.streams.feed(packet, packet_number)
        if state is None:
            return []
        events: list[FTPEvent] = []
        while True:
            line_end = state.buffer.find(b"\r\n")
            if line_end < 0:
                break
            raw_line = bytes(state.buffer[:line_end]).decode("utf-8", errors="replace")
            event_packet_number = state.first_packet_number
            event_timestamp = state.first_timestamp
            command, _, argument = raw_line.partition(" ")
            command = command.upper()
            if command not in FTP_COMMANDS:
                # Resync to the next known command. A command may be followed by
                # a space (has an argument) or by CRLF directly (argument-less
                # commands such as PWD/PASV) -- match both so the resync can
                # land on a bare "PWD\r\n".
                possible_starts = [
                    position
                    for candidate in FTP_COMMANDS
                    for suffix in (b" ", b"\r\n")
                    for position in (state.buffer.find(candidate.encode() + suffix, 1),)
                    if position >= 0
                ]
                next_start = min(possible_starts, default=-1)
                if next_start < 0:
                    break
                self.streams.consume(state, next_start, packet_number, float(packet.time))
                continue
            self.streams.consume(state, line_end + 2, packet_number, float(packet.time))
            if command == "PASS":
                argument = "<redacted>"
            events.append(
                FTPEvent(
                    timestamp=event_timestamp,
                    src_ip=state.src_ip,
                    dst_ip=state.dst_ip,
                    src_port=state.src_port,
                    dst_port=state.dst_port,
                    command=command,
                    argument=argument,
                    packet_number=event_packet_number,
                )
            )
        if state.closing:
            self.streams.close(state)
        return events
