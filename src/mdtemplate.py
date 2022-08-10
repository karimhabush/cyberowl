"""
Contains the MDTemplate class. This class is used to
create a Markdown template used to generate a Markdown table.
"""


class Template:
    """
    This class is used to format the data into a table in markdown format.
    """

    source: str
    data: list

    def __init__(self, _source, _data):
        self.source = _source
        self.data = _data

    def _set_heading(self):
        return f"""---\n### {self.source} [:arrow_heading_up:](#cyberowl)\n"""

    def _set_table_headers(self):
        return """|Title|Description|Date|\n|---|---|---|\n"""

    def _set_table_content(self, title, link, description, date):
        return f"""| [{title}]({link}) | {description} | {date} |\n"""

    def fill_table(self) -> str:
        """
        Returns a table ready to be written to a file.
        """
        table = self._set_heading()
        table += self._set_table_headers()
        for row in self.data:
            table += self._set_table_content(
                row["title"], row["link"], row["description"], row["date"]
            )
        return table
