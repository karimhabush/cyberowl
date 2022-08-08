"""

"""
from mdtemplate import Template


class AlertPipeline:
    """
    AlertPipeline class
    """

    result: list = []

    def remove_special_characters(self, text):
        """
        Remove special characters from text.
        """
        return (
            text.replace("\n", " ")
            .replace("\r", "")
            .replace("\t", "")
            .replace("  ", "")
        )

    def process_item(self, item, spider):
        """
        Process item.
        """
        item["title"] = self.remove_special_characters(item["title"])
        item["link"] = self.remove_special_characters(item["link"])
        item["date"] = self.remove_special_characters(item["date"])
        item["description"] = self.remove_special_characters(item["description"])

        self.result.append(item)

    def close_spider(self, spider):
        """
        Close spider
        """
        print("oooooooooooooooooooooooOODDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
        _to_write = Template(spider.name, self.result)
        self.result = []
        print(self.result)
        with open("README.md", "a", encoding="utf-8") as file:
            file.write(_to_write._fill_table())
            file.close()
