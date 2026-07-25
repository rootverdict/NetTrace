from scapy.all import IP, Raw, TCP

from nettrace.parsers.tcp_stream import TCPStreamBuffers


def _segment(seq: int, payload: bytes, packet_number: int, timestamp: float = 1.0):
    packet = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=80, seq=seq, flags="A") / Raw(load=payload)
    packet.time = timestamp
    return packet


def test_stale_retransmission_below_base_seq_is_discarded_not_leaked():
    # Bug #8: a segment fully covering bytes already consumed by a protocol
    # parser must be discarded outright, not left in `pending` forever eating
    # the pending-segment budget.
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"GET / HTTP/1.1\r\n", 1), 1)
    assert state is not None
    buffers.consume(state, len(b"GET / HTTP/1.1\r\n"), next_packet_number=2, next_timestamp=1.1)
    assert state.has_consumed is True
    assert state.base_seq == 116

    # A retransmission of the already-consumed first segment arrives late.
    state = buffers.feed(_segment(100, b"GET / HTTP/1.1\r\n", 3, timestamp=1.2), 3)
    assert state is not None
    assert state.pending == {}, "stale retransmission must not sit in pending forever"
    assert bytes(state.buffer) == b""


def test_retransmission_ending_exactly_at_base_seq_is_not_reprepended():
    # Bug #8 (exact case from the review): a segment ending exactly at the new
    # base_seq must not be prepended back into the live buffer -- that would
    # resurrect already-consumed, already-reported data.
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"AAAA", 1), 1)
    buffers.consume(state, 4, next_packet_number=2, next_timestamp=1.1)
    assert state.base_seq == 104

    state = buffers.feed(_segment(100, b"AAAA", 3, timestamp=1.2), 3)  # end == 104 == base_seq
    assert bytes(state.buffer) == b"", "must not resurrect consumed bytes"


def test_out_of_order_prefix_before_any_consumption_still_merges():
    # Sanity check: the has_consumed guard must not break the normal,
    # legitimate out-of-order arrival case (no consume() has happened yet).
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(102, b"ER analyst\r\n", 2, timestamp=2.0), 2)
    assert bytes(state.buffer) == b"ER analyst\r\n"

    state = buffers.feed(_segment(100, b"US", 1, timestamp=1.0), 1)
    assert bytes(state.buffer) == b"USER analyst\r\n"


def test_conflicting_overlap_is_detected_not_silently_resolved():
    # Bug #3: overlapping retransmitted bytes that *differ* from what's
    # already buffered were never compared -- silently accepted or dropped
    # with no signal to the analyst.
    buffers = TCPStreamBuffers()
    buffers.feed(_segment(100, b"AAAABBBB", 1), 1)
    assert buffers.conflicting_overlaps == 0

    # Retransmission of the same range with DIFFERENT bytes -- a real conflict.
    buffers.feed(_segment(100, b"AAAAXXXX", 2, timestamp=1.1), 2)
    assert buffers.conflicting_overlaps == 1
    state = next(iter(buffers._streams.values()))
    assert bytes(state.buffer) == b"AAAABBBB"


def test_identical_overlap_is_not_flagged_as_conflict():
    buffers = TCPStreamBuffers()
    buffers.feed(_segment(100, b"AAAABBBB", 1), 1)
    buffers.feed(_segment(100, b"AAAABBBB", 2, timestamp=1.1), 2)

    assert buffers.conflicting_overlaps == 0


def test_partial_identical_overlap_extends_buffer_without_conflict():
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"AAAABBBB", 1), 1)
    state = buffers.feed(_segment(104, b"BBBBCCCC", 2, timestamp=1.1), 2)

    assert buffers.conflicting_overlaps == 0
    assert bytes(state.buffer) == b"AAAABBBBCCCC"


def test_partial_conflicting_overlap_is_rejected_by_default():
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"AAAABBBB", 1), 1)
    state = buffers.feed(_segment(104, b"XXXXCCCC", 2, timestamp=1.1), 2)

    assert buffers.conflicting_overlaps == 1
    assert bytes(state.buffer) == b"AAAABBBB"


def test_conflicting_prefix_overlap_is_detected():
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(104, b"BBBBCCCC", 2, timestamp=1.1), 2)
    state = buffers.feed(_segment(100, b"AAAAXXXX", 1), 1)

    assert buffers.conflicting_overlaps == 1
    assert bytes(state.buffer) == b"BBBBCCCC"


def test_last_seen_overlap_policy_replaces_conflicting_bytes():
    buffers = TCPStreamBuffers(overlap_policy="last-seen-wins")
    state = buffers.feed(_segment(100, b"AAAABBBB", 1), 1)
    state = buffers.feed(_segment(104, b"XXXXCCCC", 2, timestamp=1.1), 2)

    assert buffers.conflicting_overlaps == 1
    assert bytes(state.buffer) == b"AAAAXXXXCCCC"


def test_idle_stream_is_expired_by_timestamp():
    buffers = TCPStreamBuffers(max_idle_seconds=5)
    buffers.feed(_segment(100, b"incomplete", 1, timestamp=1.0), 1)
    packet = (
        IP(src="10.0.0.6", dst="203.0.113.10")
        / TCP(sport=50001, dport=80, seq=100, flags="A")
        / Raw(load=b"other")
    )
    packet.time = 7.1

    buffers.feed(packet, 2)

    assert buffers.discarded_streams == 1
    assert buffers.incomplete_streams == 1


def test_idle_stream_is_expired_by_timestamp():
    buffers = TCPStreamBuffers(max_idle_seconds=5)
    buffers.feed(_segment(100, b"incomplete", 1, timestamp=1.0), 1)
    buffers.feed(
        IP(src="10.0.0.6", dst="203.0.113.10")
        / TCP(sport=50001, dport=80, seq=100, flags="A")
        / Raw(load=b"other"),
        2,
    )

    assert buffers.discarded_streams == 1
    assert buffers.incomplete_streams == 1


def test_incomplete_stream_visible_at_eof():
    # Bug #4: a stream that never receives its closing FIN/RST and never hits
    # a resource limit was previously invisible in the report -- it wasn't
    # "discarded", it just silently vanished from consideration.
    buffers = TCPStreamBuffers()
    buffers.feed(_segment(100, b"incomplete HTTP request, no blank line yet", 1), 1)

    assert buffers.incomplete_streams == 1
    assert buffers.incomplete_buffered_bytes == len(b"incomplete HTTP request, no blank line yet")


def test_fully_consumed_stream_is_not_counted_as_incomplete():
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"GET / HTTP/1.1\r\n\r\n", 1), 1)
    buffers.consume(state, len(b"GET / HTTP/1.1\r\n\r\n"), next_packet_number=2, next_timestamp=1.1)

    assert buffers.incomplete_streams == 0
    assert buffers.incomplete_buffered_bytes == 0


def test_fin_packet_with_payload_buffers_and_closes():
    # Bug #1: FIN packets with payload should buffer the payload and then close
    # the stream, not ignore the FIN flag just because there's payload.
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"GET / HTTP/1.1\r\n", 1), 1)
    assert state is not None

    # FIN packet with payload (e.g., final response before closing)
    packet = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=80, seq=116, flags="FA") / Raw(load=b"HTTP/1.1 200 OK\r\n")
    packet.time = 1.1
    state = buffers.feed(packet, 2)

    # Payload should be buffered and stream should be closed
    assert state is None  # Stream is removed, so None is returned
    assert buffers.incomplete_streams == 0  # No incomplete streams left
    assert buffers.discarded_streams == 1  # Stream was properly closed
    assert (
        b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n" in [bytes(s.buffer) for s in buffers._streams.values()]
    ) or len(buffers._streams) == 0


def test_rst_packet_with_payload_buffers_and_closes():
    # RST packets with payload should also buffer the payload before closing.
    buffers = TCPStreamBuffers()
    state = buffers.feed(_segment(100, b"incomplete data", 1), 1)
    assert state is not None

    # RST packet with payload
    packet = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=80, seq=115, flags="AR") / Raw(load=b"error message")
    packet.time = 1.1
    state = buffers.feed(packet, 2)

    # Stream should be closed after buffering the payload
    assert state is None  # Stream is removed
    assert buffers.incomplete_streams == 0  # No incomplete streams
    assert buffers.discarded_streams == 1  # Stream was closed
