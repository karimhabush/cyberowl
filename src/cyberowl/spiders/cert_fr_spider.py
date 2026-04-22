"""
This spider is used to scrape alerts from the following source:
https://www.cert.ssi.gouv.fr/avis/
"""
import scrapy
from items import AlertItem


class CertFRSpider(scrapy.Spider):
    """Spider for the CERT-FR Website.

    This spider is used to scrape data from the official website of
    CERT FR.

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

    name = "CERT-FR"
    max_items = 10
    start_urls = ["https://www.cert.ssi.gouv.fr/avis/"]

    block_selector = "article.item.cert-avis"
    link_selector = "descendant-or-self::section[contains(@class,'item-header')]/div[contains(@class,'item-title')]/h3/a/@href"
    date_selector = "descendant-or-self::span[contains(@class,'item-date')]//text()"
    title_selector = "descendant-or-self::section[contains(@class,'item-header')]/div[contains(@class,'item-title')]/h3/a/text()"
    description_selector = (
        "descendant-or-self::section[contains(@class,'item-excerpt')]/p//text()"
    )

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx >= self.max_items:
                break
            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://www.cert.ssi.gouv.fr"
                + (bulletin.xpath(self.link_selector).get() or "")
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
