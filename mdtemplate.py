# Returns the template of a bulletin

class Template:
    def __init__(self, _source, _data):
        self.SOURCE = _source
        self.DATA = _data
        # Data validation
        self._validate_data()

    def _validate_data(self):
        for row in self.DATA:
            if "_title" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element _title.")
            if "_desc" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element _desc.")
            if "_link" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element _link.")
            if "_date" not in row:
                raise ValueError(
                    "The dictionnaries in _data arrow is expecting the element _date.")

    def _set_heading(self):
        return f"""## {self.SOURCE} [:arrow_heading_up:](#cyberowl)\n"""

    def _set_table_headers(self):
        return """|Title|Description|Date|\n|---|---|---|\n"""

    def _set_table_content(self, _title, _link, _desc, _date):
        return f"""| [{_title}]({_link}) | {_desc} | {_date} |\n"""

    def _fill_table(self):
        TABLE = self._set_heading()
        TABLE += self._set_table_headers()
        for row in self.DATA:
            TABLE += self._set_table_content(row["_title"],
                                             row["_link"], row["_desc"], row["_date"])
        return TABLE
