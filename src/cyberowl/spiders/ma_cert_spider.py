"""MA-CERT Spider.

This spider is used to scrape alerts from the following source:
https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html
"""
import scrapy

from cyberowl.items import AlertItem


class MACertSpider(scrapy.Spider):
    """Spider for the MA-CERT website.

    This spider is used to scrape data from the official website of
    Moroccan CERT.

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

    name = "MA-CERT"
    max_items = 10
    start_urls = ["https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html"]
    block_selector = "div.event_row1"
    link_selector = "descendant-or-self::h4/a/@href"
    date_selector = "span.event_date::text"
    title_selector = "descendant-or-self::h4/a[2]/text()"
    description_selector = (
        "descendant-or-self::p[contains(@class,'body-evenement')]/text()"
    )

    def parse(self, response):
        """Parse the response."""
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = bulletin.xpath(self.link_selector).get()
            item["date"] = bulletin.css(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
