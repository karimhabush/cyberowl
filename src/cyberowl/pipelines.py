"""
    Pipelines for cyberowl scraper.
"""
from cyberowl.utils import generate_alerts_table


class AlertPipeline:
    """
    AlertPipeline class
    Args:
        items : list of items.
    """

    def __init__(self, items: list = []):
        self.__items = items

    @property
    def items(self):
        return self.__items

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
        self.__items = [["Title", "Description", "Date"]]

    def process_item(self, item, *args, **kwargs):
        """
        Process item.
        """
        item["title"] = self.remove_special_characters(item["title"])
        item["link"] = self.remove_special_characters(item["link"])
        item["date"] = self.remove_special_characters(item["date"])
        item["description"] = self.remove_special_characters(item["description"])

        self.__items.append(
            [f"[{item['title']}]({item['link']})", item["description"], item["date"]]
        )

    def close_spider(self, spider):
        """
        Close spider
        """
        generate_alerts_table(spider.name, self.__items)
