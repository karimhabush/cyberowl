"""VulDB Spider.

This spider is used to scrape alerts from the following source:
https://vuldb.com/?live.recent
"""
from datetime import date

import scrapy

from cyberowl.items import AlertItem


class VulDBSpider(scrapy.Spider):
    """Spider for the VulDB website.

    This spider is used to scrape data from the official website of
    VulDB.

    Attributes:
        name : Name of the spider.
        max_items : The maximum number of items to scrape.
        start_url : The website from which to start crawling.
        block_selector : The CSS/XPATH selector of the block containing the data.
        link_selector : The CSS/XPATH selector of the link of the alert.
        title_selector : The CSS/XPATH selector of the title of the alert.
        date_selector : The CSS/XPATH selector of the date of creation of the alert.
        description_selector : The CSS/XPATH selector of the description of the alert.
    """

    name = "VulDB"
    max_items = 10
    start_urls = ["https://vuldb.com/?live.recent"]
    block_selector = "table>tr"
    link_selector = "descendant-or-self::td[4]//@href"
    date_selector = "descendant-or-self::td[1]//text()"
    title_selector = "descendant-or-self::td[4]//text()"
    description_selector = ""

    def parse(self, response):
        """Parse the response."""
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            # Skip table headers
            if idx == 0:
                continue

            # Max number of alerts to scrape
            if idx > self.max_items:
                break

            item = AlertItem()
            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://vuldb.com/" + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = (
                str(date.today()) + " at " + bulletin.xpath(self.date_selector).get()
            )
            item["description"] = "Visit link for details"

            yield item
