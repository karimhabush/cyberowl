"""
This spider is used to scrape alerts from the following source:
https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html
"""
import scrapy

from items import AlertItem


class MACertSpider(scrapy.Spider):
    """
    Spider for the MA-CERT website.
    """

    name = "MA-CERT"
    start_urls = ["https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html"]
    block_selector = "div.event_row1"
    link_selector = "descendant-or-self::h4/a/@href"
    date_selector = "span.event_date::text"
    title_selector = "descendant-or-self::h4/a[2]/text()"
    description_selector = (
        "descendant-or-self::p[contains(@class,'body-evenement')]/text()"
    )

    def parse(self, response):
        """
        Parsing the response
        """
        for bulletin in response.css(self.block_selector):
            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = bulletin.xpath(self.link_selector).get()
            item["date"] = bulletin.css(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
