from __future__ import annotations

from pathlib import Path
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from nettrace.models.report import AnalysisReport
from nettrace.report.display_limits import (
    MAX_FINDINGS,
    MAX_IOCS,
    MAX_OBSERVED_ARTIFACTS,
    MAX_TIMELINE,
    limited,
)


def render_html_report(report: AnalysisReport, output_path: Path) -> Path:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["to_pretty_json"] = lambda value: json.dumps(value, indent=2)
    template = env.get_template("report.html")
    # Sections are capped here rather than in the template so the HTML and PDF
    # renderers share one set of limits, and so each cap cannot drift away from
    # the notice that discloses it.
    html = template.render(
        report=report,
        summary=report.summary(),
        findings=limited(
            sorted(report.findings, key=lambda item: item.score, reverse=True),
            MAX_FINDINGS,
            ordering="highest-scoring",
        ),
        iocs=limited(report.iocs, MAX_IOCS),
        artifacts=limited(report.observed_artifacts, MAX_OBSERVED_ARTIFACTS),
        timeline=limited(report.timeline, MAX_TIMELINE),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
