import json
import os
from datetime import datetime, timezone

from mdtemplate import MDTemplate

# Shared store for JSON export — populated by each spider's close_spider
_alerts_json_store = {}


def store_alerts_json(source: str, items: list) -> None:
    """
    Stores raw alert items for a source in the shared JSON store.
    Called by the pipeline when each spider closes.
    """
    _alerts_json_store[source] = {"items": items}


def write_alerts_json() -> None:
    """
    Writes all collected alerts to a single JSON file.
    Called after all spiders have finished.
    """
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": _alerts_json_store,
    }
    output_file = os.path.join(os.path.dirname(__file__), "./../../docs/.vuepress/public/alerts.json")
    output_file = os.path.normpath(output_file)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def generate_alerts_table(source, alerts: list) -> None:
    """
    Generates per-source markdown files in docs/activity/.
    """
    OUTPUT_FILE = f"./../../docs/activity/{source}.md"
    OUTPUT_FILE = os.path.join(os.path.dirname(__file__), OUTPUT_FILE)
    ALERT_GENERATOR = MDTemplate(OUTPUT_FILE)
    ALERT_GENERATOR.new_header(level=1, text=f"{source}")
    ALERT_GENERATOR.generate_table(alerts)
    ALERT_GENERATOR.new_line()

    ALERT_GENERATOR.create_md_file()
