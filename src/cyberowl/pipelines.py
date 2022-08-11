"""
    Pipelines for cyberowl scraper.
"""
from mdtemplate import Template


class AlertPipeline:
    """
    AlertPipeline class
    Args:
        items : list of items.
    """

    items: list = []

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

    def open_spider(self, *args, **kwargs):
        """
        Open spider
        """
        self.items = []

    def process_item(self, item, *args, **kwargs):
        """
        Process item.
        """
        item["title"] = self.remove_special_characters(item["title"])
        item["link"] = self.remove_special_characters(item["link"])
        item["date"] = self.remove_special_characters(item["date"])
        item["description"] = self.remove_special_characters(item["description"])

        self.items.append(item)

    def close_spider(self, spider):
        """
        Close spider
        """
        to_write = Template(spider.name, self.items)
        with open("README.md", "a", encoding="utf-8") as file:
            file.write(to_write.fill_table())
            file.close()
