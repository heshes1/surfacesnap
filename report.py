import json
import os
import tempfile
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportWriteError(RuntimeError):
    """Raised when a report cannot be rendered or written."""


def write_json(result: Dict[str, Any], out_dir: str) -> str:
    """Write the JSON report to disk and return its final path."""
    path = os.path.join(out_dir, "result.json")
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
    except OSError as exc:
        raise ReportWriteError(
            f"Failed to write JSON report to {path}: {exc}"
        ) from exc
    return path


def _write_json_to_path(result: Dict[str, Any], path: str) -> None:
    """Serialize scan results to a specific JSON file path."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
    except OSError as exc:
        raise ReportWriteError(f"Failed to write JSON report to {path}: {exc}") from exc


def _render_html(result: Dict[str, Any]) -> str:
    """Render the HTML report template for a scan result."""
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    try:
        env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        tmpl = env.get_template("report.html")
        return tmpl.render(result=result)
    except Exception as exc:
        raise ReportWriteError(
            f"Failed to render HTML report from template {templates_dir}: {exc}"
        ) from exc


def _write_html_to_path(result: Dict[str, Any], path: str) -> None:
    """Render and write the HTML report to a specific file path."""
    rendered = _render_html(result)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    except OSError as exc:
        raise ReportWriteError(f"Failed to write HTML report to {path}: {exc}") from exc


def write_html(result: Dict[str, Any], out_dir: str) -> str:
    """Render the HTML report into the output directory and return its path."""
    out_path = os.path.join(out_dir, "report.html")
    try:
        os.makedirs(out_dir, exist_ok=True)
        _write_html_to_path(result, out_path)
    except OSError as exc:
        raise ReportWriteError(
            f"Failed to write HTML report to {out_path}: {exc}"
        ) from exc
    return out_path


def write_reports(
    result: Dict[str, Any],
    out_dir: str,
    base_name: str = "surfacesnap-report",
) -> tuple[str, str]:
    """Write HTML and JSON reports atomically and return both final paths."""
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, "report.html")
    json_path = os.path.join(out_dir, "result.json")

    # Use temp files so callers never see half-finished output.
    html_fd, html_tmp_path = tempfile.mkstemp(
        prefix="report.", suffix=".html.tmp", dir=out_dir
    )
    os.close(html_fd)
    json_fd, json_tmp_path = tempfile.mkstemp(
        prefix="result.", suffix=".json.tmp", dir=out_dir
    )
    os.close(json_fd)

    try:
        _write_html_to_path(result, html_tmp_path)
        _write_json_to_path(result, json_tmp_path)

        # Promote both files only after both writes succeed.
        os.replace(html_tmp_path, html_path)
        os.replace(json_tmp_path, json_path)
    except Exception:
        for temp_path in (html_tmp_path, json_tmp_path):
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except OSError:
                pass
        raise
    return html_path, json_path
