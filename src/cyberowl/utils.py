from datetime import datetime, timezone

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


def generate_alerts_table(source, alerts: list) -> None:
    """
    Generates the table of alerts.
    """
    README_GENERATOR.new_line("---")
    README_GENERATOR.new_header(
        level=2, text=f"{source} [:arrow_heading_up:](#cyberowl)"
    )
    README_GENERATOR.generate_table(alerts)
    README_GENERATOR.new_line()


def write_to_readme() -> None:
    README_GENERATOR.create_md_file()
