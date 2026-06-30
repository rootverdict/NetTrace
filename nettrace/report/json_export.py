from __future__ import annotations

import json
from pathlib import Path

from nettrace.models.report import AnalysisReport


def export_json(report: AnalysisReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return output_path
