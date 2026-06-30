from nettrace.report.pdf_report import MAX_EVIDENCE_CHARS, format_evidence


def test_format_evidence_truncates_large_payloads():
    evidence = {"blob": "A" * (MAX_EVIDENCE_CHARS + 200)}

    text = format_evidence(evidence)

    assert len(text) < MAX_EVIDENCE_CHARS + 100
    assert "... truncated ..." in text
