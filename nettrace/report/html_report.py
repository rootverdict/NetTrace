from __future__ import annotations

from pathlib import Path
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from nettrace.models.report import AnalysisReport


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
    html = template.render(report=report, summary=report.summary())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
