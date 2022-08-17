"""
    Pipelines for cyberowl scraper.
"""
from cyberowl.utils import generate_alerts_table


class AlertPipeline:
    """
    AlertPipeline class
    Attributes:
        items {list} : A list of scraped and processed items.
        e.g [["Title", "Description", "Date"],["Title1", "Description1", "Date1"]]
    """

    __items: list = None

    def __init__(self) -> None:
        if self.__items is None:
            self.__items = []

    @property
    def items(self):
        return self.__items

    def remove_special_characters(self, text):
        """Remove special characters from text.

        Arguments:
            text str : Text to be processed.

        Returns:
            str : Processed text.
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
        Method to be called when spider is opened.
        """
        self.__items = [["Title", "Description", "Date"]]

    def process_item(self, item, *args, **kwargs):
        """
        This method is used to process the item.
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
        Method to be called when spider is closed.
        """
        generate_alerts_table(spider.name, self.__items)
