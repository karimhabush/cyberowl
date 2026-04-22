import os
from datetime import datetime, timezone

from mdtemplate import MDTemplate
from settings import README_GENERATOR
from sources import CYBEROWL_SOURCES


def generate_heading() -> None:
    """
    Generates the heading of the readme file.
    """
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    README_GENERATOR.new_line("<div id='top'></div>")
    README_GENERATOR.new_header(level=1, text="CyberOwl")
    README_GENERATOR.new_line(f"> Last Updated {now} UTC")
    README_GENERATOR.new_line()
    README_GENERATOR.new_line(
        "A daily updated summary of the most frequent types of security"
        " incidents currently being reported from different sources."
    )
    README_GENERATOR.new_line()
    README_GENERATOR.new_line(
        "For more information, please check out the documentation"
        " [here](./docs/README.md)."
    )
    README_GENERATOR.new_line()
    README_GENERATOR.new_line("---")


def generate_table_of_content() -> None:
    """
    Generates the table of content.
    """
    README_GENERATOR.generate_table(CYBEROWL_SOURCES)
    README_GENERATOR.new_line()
    README_GENERATOR.new_line(
        "> Suggest a source by opening an [issue]"
        "(https://github.com/karimhabush/cyberowl/issues)! :raised_hands:"
    )


def generate_alerts_for_readme(source, alerts: list) -> None:
    """
    Generates the table of alerts.
    """
    # Write to the file located in ./../../docs/activity/f{source}.md
    README_GENERATOR.new_header(level=1, text=f"{source}")
    README_GENERATOR.generate_table(alerts)
    README_GENERATOR.new_line()

    README_GENERATOR.create_md_file()


def write_to_readme() -> None:
    README_GENERATOR.create_md_file()


def generate_alerts_table(source, alerts: list) -> None:
    """
    Generates the table of alerts.
    """
    # Write to the file located in ./../../docs/activity/f{source}.md

    OUTPUT_FILE = f"./../../docs/activity/{source}.md"
    OUTPUT_FILE = os.path.join(os.path.dirname(__file__), OUTPUT_FILE)
    ALERT_GENERATOR = MDTemplate(OUTPUT_FILE)
    ALERT_GENERATOR.new_header(level=1, text=f"{source}")
    ALERT_GENERATOR.generate_table(alerts)
    ALERT_GENERATOR.new_line()

    ALERT_GENERATOR.create_md_file()
