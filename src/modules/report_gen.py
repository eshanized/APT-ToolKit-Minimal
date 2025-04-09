import os
from datetime import datetime
from typing import Dict, Optional

from utils.logger import get_logger
from utils.helpers import load_template

logger = get_logger("ReportGenerator")


def generate_report(scan_data: Dict, output_path: Optional[str] = None) -> str:
    """
    Generate a report from scan results using a template.

    Args:
        scan_data (Dict): Dictionary of scan results.
        output_path (str, optional): File path to save the generated report.

    Returns:
        str: The generated HTML report as a string.
    """
    logger.info("Generating HTML report...")

    try:
        template = load_template("report_template.html")
    except FileNotFoundError:
        logger.error("Template file not found.")
        return "<h1>Error: Template not found</h1>"

    report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    target = scan_data.get("target", "Unknown Target")
    modules = scan_data.get("modules", [])

    module_sections = ""
    for module in modules:
        name = module.get("name", "Unnamed Module")
        status = module.get("status", "Unknown")
        output = module.get("output", "No output")
        module_sections += f"""
            <div class="module">
                <h3>{name} — <span class="status">{status}</span></h3>
                <pre>{output}</pre>
            </div>
        """

    html_report = template.format(
        report_time=report_time,
        target=target,
        module_sections=module_sections
    )

    if output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            logger.success(f"Report written to {output_path}")
        except Exception as e:
            logger.error(f"Failed to write report: {e}")

    return html_report
