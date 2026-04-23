"""
This spider is used to scrape alerts from the following source:
https://vuldb.com via RSS feed
"""

import re

import scrapy
from items import AlertItem


class VulDBSpider(scrapy.Spider):
    """Spider for the VulDB website.

    This spider is used to scrape data from the official website of
    VulDB via their public RSS feed.

    Attributes:
        name : Name of the spider.
        max_items : The maximum number of items to scrape.
        start_url : The RSS feed URL.
    """

    name = "VulDB"
    max_items = 10
    start_urls = ["https://vuldb.com/?rss.recent"]

    def parse(self, response):
        """
        Parsing the RSS feed response
        """
        response.selector.remove_namespaces()
        for idx, entry in enumerate(response.xpath("//item")):

            if idx >= self.max_items:
                break

            item = AlertItem()
            item["title"] = entry.xpath("title/text()").get()
            item["link"] = entry.xpath("link/text()").get()
            item["date"] = entry.xpath("pubDate/text()").get()
            description = entry.xpath("description/text()").get()
            if description:
                description = re.sub(r"<[^>]+>", "", description)[:200]
            item["description"] = description or "Visit link for details"

            yield item
