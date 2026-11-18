from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from nettrace.models.report import AnalysisReport
from nettrace.report.display_limits import MAX_FINDINGS, limited


MAX_EVIDENCE_CHARS = 1200


def format_evidence(evidence: dict) -> str:
    text = json.dumps(evidence, indent=2)
    if len(text) > MAX_EVIDENCE_CHARS:
        return text[:MAX_EVIDENCE_CHARS] + "\n... truncated ..."
    return text


def pdf_text(value: object) -> str:
    return escape(str(value))


def render_pdf_report(report: AnalysisReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # ReportLab otherwise embeds the current creation/modification time and a
    # run-specific document ID, so identical analysis input produces different
    # PDF bytes on every run. The document template forwards invariant mode to
    # its canvas, fixing those metadata fields and making committed reports
    # mechanically reproducible.
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, invariant=1)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("NetTrace Malware Traffic Analysis Report", styles["Title"]),
        Paragraph(f"PCAP: {pdf_text(report.pcap_path)}", styles["Normal"]),
        Spacer(1, 12),
    ]
    summary_rows = [["Metric", "Count"]] + [
        [key.replace("_", " ").title(), value] for key, value in report.summary().items()
    ]
    summary = Table(summary_rows, hAlign="LEFT")
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.extend([summary, Spacer(1, 16)])
    if report.warnings:
        elements.append(Paragraph("Analysis Warnings", styles["Heading2"]))
        for warning in report.warnings:
            elements.append(Paragraph(f"&bull; {pdf_text(warning)}", styles["Normal"]))
        elements.append(Spacer(1, 12))
    if report.ai_assessment:
        elements.append(Paragraph("AI Threat Intelligence", styles["Heading2"]))
        verdict = report.ai_assessment.get("threat_verdict", "UNKNOWN")
        confidence = report.ai_assessment.get("confidence", "UNKNOWN")
        elements.append(Paragraph(f"<b>Verdict:</b> {pdf_text(verdict)} (Confidence: {pdf_text(confidence)})", styles["Normal"]))
        summary_text = report.ai_assessment.get("executive_summary", "")
        if summary_text:
            elements.append(Paragraph(f"<b>Executive Summary:</b> {pdf_text(summary_text)}", styles["Normal"]))
        narrative = report.ai_assessment.get("attack_narrative", [])
        if narrative:
            elements.append(Paragraph("<b>Attack Narrative:</b>", styles["Normal"]))
            if isinstance(narrative, list):
                for step in narrative:
                    elements.append(Paragraph(f"&bull; {pdf_text(step)}", styles["Normal"]))
            else:
                elements.append(Paragraph(pdf_text(narrative), styles["Normal"]))
        actions = report.ai_assessment.get("recommended_actions", [])
        if actions:
            elements.append(Paragraph("<b>Recommended Containment Actions:</b>", styles["Normal"]))
            for act in actions:
                elements.append(Paragraph(f"&bull; {pdf_text(act)}", styles["Normal"]))
        elements.append(Spacer(1, 12))
    elements.append(Paragraph("Findings", styles["Heading2"]))
    findings = limited(
        sorted(report.findings, key=lambda item: item.score, reverse=True),
        MAX_FINDINGS,
        ordering="highest-scoring",
    )
    for finding in findings.items:
        elements.append(Paragraph(f"{pdf_text(finding.severity.upper())} - {pdf_text(finding.title)}", styles["Heading3"]))
        elements.append(Paragraph(pdf_text(finding.description), styles["Normal"]))
        if finding.attack_id:
            elements.append(
                Paragraph(
                    f"MITRE ATT&CK: {pdf_text(finding.attack_id)} {pdf_text(finding.attack_name)}",
                    styles["Normal"],
                )
            )
        evidence = pdf_text(format_evidence(finding.evidence))
        elements.append(Paragraph(f"Evidence: {evidence}", styles["Code"]))
        elements.append(Spacer(1, 8))
    if findings.truncated:
        elements.append(Paragraph(pdf_text(findings.notice), styles["Italic"]))
    doc.build(elements)
    return output_path
