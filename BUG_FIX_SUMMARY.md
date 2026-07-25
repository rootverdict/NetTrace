# NetTrace Bug Fix Summary

## Date: 2026-07-26

### Bug Fixed

**Bug #1: FIN/RST Packets with Payload Not Properly Closed**

**Location:** `nettrace/parsers/tcp_stream.py:225-278`

**Severity:** MEDIUM

### Problem

The TCP stream handler incorrectly handled FIN and RST packets that contained payload data. The original code only closed streams when:
- The TCP packet had **no payload** AND
- The FIN or RST flag was set

This violated TCP semantics where FIN/RST signals should close the connection immediately, even if the final packet carries data (e.g., a server sending a response with `Connection: close` before terminating).

### Impact

**Before Fix:**
- FIN/RST packets with payload had their data buffered but the stream remained open
- Stream remained in memory until idle timeout (up to 300 seconds)
- Semantically incorrect handling of TCP connection termination

**After Fix:**
- Payload is buffered if present
- Stream is properly closed immediately after FIN/RST is detected
- Correct TCP semantics maintained
- More efficient resource usage

### Solution

Restructured the packet handling logic in `TCPStreamBuffers.feed()`:

1. **Early exit for empty packets with FIN/RST:** Close stream immediately if no payload
2. **Payload buffering:** Buffer payload data if present (regardless of flags)
3. **Stream closure on FIN/RST:** After buffering, check for FIN/RST flags and close stream
4. **Return value:** Return None (stream closed) after FIN/RST to signal end of stream to extractors

### Code Changes

**File:** `nettrace/parsers/tcp_stream.py`

```python
# Before (lines 225-228):
if not payload:
    if flags & 0x05:  # FIN or RST
        self._remove_stream(key, discarded=True)
    return None

# After (lines 225-277):
has_fin_or_rst = bool(flags & 0x05)
if not payload and has_fin_or_rst:
    self._remove_stream(key, discarded=True)
    return None

if not payload:
    return None

# ... buffer payload handling ...

if has_fin_or_rst:
    self._remove_stream(key, discarded=True)
    return None

return state
```

### Tests Added

Two new tests in `tests/test_tcp_stream.py`:

1. **`test_fin_packet_with_payload_buffers_and_closes()`**
   - Verifies FIN packet with payload is buffered and stream is closed
   - Tests the exact bug scenario

2. **`test_rst_packet_with_payload_buffers_and_closes()`**
   - Verifies RST packet with payload is buffered and stream is closed
   - Covers the RST flag variant

### Verification

- ✅ All 177 existing tests pass
- ✅ 2 new tests pass
- ✅ Code coverage: 90.95% (exceeds 80% requirement)
- ✅ TCP stream module coverage: 94%
- ✅ No regressions detected

### Impact on Analysis

- **Correctness:** Network analysis now properly reflects TCP connection semantics
- **Resource efficiency:** Streams close faster, reducing memory footprint
- **Report accuracy:** Timeline and event extraction are more semantically accurate
