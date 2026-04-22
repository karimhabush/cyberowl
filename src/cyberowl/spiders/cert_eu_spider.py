"""
This spider is used to scrape alerts from the following source:
https://cert.europa.eu/publications/security-advisories/
"""
from datetime import date

import scrapy
from items import AlertItem


class EUCERTSpider(scrapy.Spider):
    """Spider for the CERT-EU website.

    This spider is used to scrape data from the official website of
    EU CERT.

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

    name = "EU-CERT"
    max_items = 10
    block_selector = "li.publications--list--item"
    link_selector = "descendant-or-self::a[contains(@class,'publications--list--item--link')]/@href"
    date_selector = ".//div[contains(@class,'publications--list--item--link--date')]/text()"
    title_selector = ".//h3[contains(@class,'publications--list--item--link--title')]/text()"
    description_selector = (
        ".//p[contains(@class,'publications--list--item--link--description')]/text()"
    )

    @property
    def start_urls(self):
        return [f"https://cert.europa.eu/publications/security-advisories/{date.today().year}"]

    def parse(self, response):
        """
        Parsing the response.
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx >= self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            link = bulletin.xpath(self.link_selector).get()
            item["link"] = ("https://cert.europa.eu" + link) if link else ""
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
