from datetime import datetime, timezone

from mdtemplate import MDTemplate
from settings import OUTPUT_FILE
from sources import CYBEROWL_SOURCES

readme_gen = MDTemplate(filename=OUTPUT_FILE)


def generate_heading() -> None:
    """
    Generates the heading of the readme file.
    """
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    readme_gen.new_line("<div id='top'></div>")
    readme_gen.new_header(level=1, text="CyberOwl")
    readme_gen.new_line(f"> Last Updated {now} UTC")
    readme_gen.new_line()
    readme_gen.new_line(
        "A daily updated summary of the most frequent types of security"
        " incidents currently being reported from different sources."
    )
    readme_gen.new_line()
    readme_gen.new_line("---")


def generate_table_of_content() -> None:
    """
    Generates the table of content.
    """
    readme_gen.generate_table(CYBEROWL_SOURCES)
    readme_gen.new_line()
    readme_gen.new_line(
        "> Suggest a source by opening an [issue]"
        "(https://github.com/karimhabush/cyberowl/issues)! :raised_hands:"
    )


def generate_alerts_table(source, alerts: list) -> None:
    """
    Generates the table of alerts.
    """
    readme_gen.new_line("---")
    readme_gen.new_header(level=2, text=f"{source} [:arrow_heading_up:](#cyberowl)")
    readme_gen.generate_table(alerts)
    readme_gen.new_line()


def write_to_readme():
    readme_gen.create_md_file()
