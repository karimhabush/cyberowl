"""
    Pipelines for cyberowl scraper.
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
            text.replace("\n", "")
            .replace("\r", "")
            .replace("\t", "")
            .replace("  ", "")
            .replace("|", "")
        )

    def open_spider(self, spider):
        """
        Open spider
        """
        self.result = []

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
        to_write = Template(spider.name, self.result)
        with open("README.md", "a", encoding="utf-8") as file:
            file.write(to_write.fill_table())
            file.close()
