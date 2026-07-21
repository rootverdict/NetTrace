from nettrace.mapping.timeline import build_timeline
from nettrace.models.events import DNSEvent


def test_timeline_limit_keeps_earliest_entries():
    events = [DNSEvent(float(value), "10.0.0.1", "8.8.8.8", f"{value}.example") for value in [5, 1, 3, 2, 4]]

    timeline = build_timeline(events, [], [], [], [], max_entries=3)

    assert [item["timestamp"] for item in timeline] == [1.0, 2.0, 3.0]
