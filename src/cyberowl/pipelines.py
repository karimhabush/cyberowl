"""
    Pipelines for cyberowl scraper.
"""
import re

from utils import generate_alerts_table, store_alerts_json


class AlertPipeline:
    """
    AlertPipeline class
    Attributes:
        items {list} : A list of scraped and processed items.
        e.g [["Title", "Description", "Date"],["Title1", "Description1", "Date1"]]
    """

    __items: list = None
    __raw_items: list = None

    def __init__(self) -> None:
        if self.__items is None:
            self.__items = []
        if self.__raw_items is None:
            self.__raw_items = []

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
            .replace("<wbr>", "")
            .replace("</wbr>", "")
        )

    def open_spider(self, *args, **kwargs):
        """
        Method to be called when spider is opened.
        """
        self.__items = [["Title", "Description", "Date"]]
        self.__raw_items = []

    def process_item(self, item, *args, **kwargs):
        """
        This method is used to process the item.
        """
        item["title"] = self.remove_special_characters(item.get("title") or "")
        item["link"] = self.remove_special_characters(item.get("link") or "")
        item["date"] = self.remove_special_characters(item.get("date") or "")
        item["description"] = self.remove_special_characters(item.get("description") or "")

        self.__items.append(
            [f"[{item['title']}]({item['link']})", item["description"], item["date"]]
        )

        self.__raw_items.append({
            "title": re.sub(r"<[^>]+>", "", item["title"]).strip(),
            "link": item["link"],
            "date": item["date"],
            "description": re.sub(r"<[^>]+>", "", item["description"]).strip(),
        })

    def close_spider(self, spider):
        """
        Method to be called when spider is closed.
        """
        generate_alerts_table(spider.name, self.__items)
        store_alerts_json(spider.name, self.__raw_items)
