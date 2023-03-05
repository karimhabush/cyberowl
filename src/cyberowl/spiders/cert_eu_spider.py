"""
This spider is used to scrape alerts from the following source:
https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html
"""
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
    start_urls = ["https://cert.europa.eu/publications/security-advisories/2023"]
    block_selector = "li.publications--list--item"
    link_selector = "descendant-or-self::ul[contains(@class,'publications--list--item--share')]/li[5]/a/@href"
    date_selector = ".//div[contains(@class,'publications--list--item--date')]/text()"
    title_selector = ".//h3/text()"
    description_selector = (
        ".//p[contains(@class,'publications--list--item--description')]/text()"
    )

    def parse(self, response):
        """
        Parsing the response.
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = "https://cert.europa.eu" + bulletin.xpath(self.link_selector).get()
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
