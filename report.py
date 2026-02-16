from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import json
from typing import Dict, Any


def write_json(result: Dict[str, Any], out_dir: str) -> str:
    """Write `result` to `out_dir`/result.json and return filepath."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "result.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return path


def write_html(result: Dict[str, Any], out_dir: str) -> str:
    """Render `templates/report.html` with `result` and write to `out_dir`/report.html."""
    os.makedirs(out_dir, exist_ok=True)
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tmpl = env.get_template("report.html")
    rendered = tmpl.render(result=result)
    out_path = os.path.join(out_dir, "report.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    return out_path


def write_reports(result: Dict[str, Any], out_dir: str, base_name: str = "surfacesnap-report"):
    """Backward-compatible helper: write JSON and HTML reports to `out_dir`.

    Returns tuple(html_path, json_path).
    """
    html_path = write_html(result, out_dir)
    json_path = write_json(result, out_dir)
    return html_path, json_path
