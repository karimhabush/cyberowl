"""
Contains the CyberOwlReadmeGenerator class. This class is used to
to generate the readme markdown file.
"""


class MDTemplate:
    """
    Generates the readme file.
    """

    def __init__(self, filename: str, buffer: str = "") -> None:
        self.__filename = filename
        self.__buffer = buffer

    @property
    def filename(self) -> str:
        """
        Returns the filename.
        """
        return self.__filename

    @property
    def buffer(self) -> str:
        """
        Returns the buffer
        """
        return self.__buffer

    def new_line(self, text="") -> str:
        """
        Linebreak then adds the text if given.
        """
        self.__buffer = f"{self.buffer}\n{text}"

    def new_header(self, level, text) -> str:
        """
        Adds a new header of given level number.
        """
        if level == 1:
            self.__buffer = f"{self.buffer}\n\n# {text}\n"
        elif level == 2:
            self.__buffer = f"{self.buffer}\n\n## {text}\n"
        elif level == 3:
            self.__buffer = f"{self.buffer}\n\n### {text}\n"
        elif level == 4:
            self.__buffer = f"{self.buffer}\n\n#### {text}\n"
        else:
            self.__buffer = f"{self.buffer}\n{text}\n"

    def generate_table(self, data: list) -> None:
        """
        Returns a table ready to be written to a file.
        Args:
            data: A list of lists. The first list is the headers, and the rest are the rows.
            for e.g.
            [
                ['Title','Description','Date'],
                ['Title1','Description1','Date1'],
                ['Title2','Description2','Date2']
            ]
        """
        for idx, item in enumerate(data):
            row = "|"
            separator = "|"

            # Generate the headers row
            if idx == 0:
                for col in item:
                    row += f"{col}|"
                    separator += "---|"
                self.new_line(row)
                self.new_line(separator)
                continue

            # Generate the content row
            for col in item:
                row += f"{col}|"
            self.new_line(row)

    def create_md_file(self) -> None:
        """
        Creates a markdown file. This is the final method to be called.
        Args:
            filename: The name of the file to be created.
        """
        with open(self.filename, "w", encoding="utf-8") as file:
            file.write(self.buffer)
            file.close()
