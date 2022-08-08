# Returns the template of a bulletin


class Template:
    def __init__(self, _source, _data):
        self.SOURCE = _source
        self.DATA = _data
        # Data validation
        self._validate_data()

    def _validate_data(self):
        for row in self.DATA:
            if "title" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element title."
                )
            if "description" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element description."
                )
            if "link" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element link."
                )
            if "date" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element date."
                )

    def _set_heading(self):
        return f"""---\n### {self.SOURCE} [:arrow_heading_up:](#cyberowl)\n"""

    def _set_table_headers(self):
        return """|Title|Description|Date|\n|---|---|---|\n"""

    def _set_table_content(self, title, link, description, date):
        return f"""| [{title}]({link}) | {description} | {date} |\n"""

    def _fill_table(self):
        TABLE = self._set_heading()
        TABLE += self._set_table_headers()
        for row in self.DATA:
            TABLE += self._set_table_content(
                row["title"], row["link"], row["description"], row["date"]
            )
        return TABLE
