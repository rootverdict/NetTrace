from nettrace.analysis.domain_utils import normalize_domain


def test_idna_normalization_and_casefolding():
    assert normalize_domain("EXAMPLE.com.") == "example.com"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


def test_invalid_hosts_are_rejected():
    assert normalize_domain("bad host.example") is None  # embedded space
    assert normalize_domain("empty..label.example") is None  # empty label
    assert normalize_domain("-leading.example") is None  # leading hyphen
    assert normalize_domain("trailing-.example") is None  # trailing hyphen
    assert normalize_domain("") is None
    assert normalize_domain("  spaced.example  ") is None  # surrounding whitespace


def test_underscore_labels_are_accepted():
    # Bug #4: underscore-prefixed DNS labels are legitimate (_dmarc, _dkim, SRV
    # names) but were rejected outright because the IDNA codec forbids them.
    assert normalize_domain("_dmarc.example.com") == "_dmarc.example.com"
    assert normalize_domain("_sip._tcp.example.com") == "_sip._tcp.example.com"
    assert normalize_domain("_DKIM.Example.COM") == "_dkim.example.com"
