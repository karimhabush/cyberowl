"""
This spider is used to scrape alerts from the following source:
https://www.cisa.gov/uscert/ncas/current-activity
"""
import scrapy
from items import AlertItem


class CisaSpider(scrapy.Spider):
    """Spider for the US-CERT website.

    This spider is used to scrape data from the official website of
    US CERT.

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

    name = "US-CERT"
    max_items = 10
    start_urls = ["https://www.cisa.gov/uscert/ncas/current-activity"]
    block_selector = "div.views-row"
    link_selector = "descendant-or-self::h3/span/a/@href"
    date_selector = (
        "descendant-or-self::div[contains(@class,'entry-date')]/span[2]/text()"
    )
    title_selector = "descendant-or-self::h3/span/a/text()"
    description_selector = "descendant-or-self::div[contains(@class,'field-content')]/p"

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://www.cisa.gov/uscert" + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
