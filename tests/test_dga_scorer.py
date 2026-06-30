from nettrace.analysis.dga_scorer import _load_dga_allowlist, dga_score, is_allowlisted_domain, score_domains, shannon_entropy
from nettrace.models.events import DNSEvent


def test_entropy_increases_for_mixed_random_text():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a8xq9z2p")


def test_dga_score_flags_random_looking_domain():
    assert dga_score("xj3k9q2z7m1p0a8c.biz") >= 0.6


def test_dga_allowlist_skips_windows_and_microsoft_domains():
    assert is_allowlisted_domain("DESKTOP-65VY1H3.local")
    assert is_allowlisted_domain("DESKTOP-65VY1H3.bitethefreehand.net")
    assert is_allowlisted_domain("dual-s-ring-fallback.msedge.net")
    assert is_allowlisted_domain("ctldl.windowsupdate.com")


def test_score_domains_does_not_emit_allowlisted_dga_candidates():
    events = [
        DNSEvent(1.0, "10.0.0.5", "10.0.0.1", "DESKTOP-65VY1H3.local"),
        DNSEvent(2.0, "10.0.0.5", "10.0.0.1", "evoke-windowsservices-tas.msedge.net"),
    ]

    findings = score_domains(events, {"dga_entropy_threshold": 3.4, "dga_score_threshold": 0.6})

    assert findings == []


def test_dga_allowlist_loader_is_cached(tmp_path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("suffixes:\n  - example.com\n", encoding="utf-8")
    _load_dga_allowlist.cache_clear()

    first = _load_dga_allowlist(path)
    second = _load_dga_allowlist(path)

    assert first is second


def test_is_allowlisted_domain_respects_explicit_empty_allowlist():
    assert not is_allowlisted_domain(
        "ctldl.windowsupdate.com",
        {"suffixes": [], "contains": [], "regexes": []},
    )
