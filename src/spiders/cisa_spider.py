import scrapy

from items import AlertItem


class CisaSpider(scrapy.Spider):
    """
    Spider for the US-CERT website.
    """

    name = "US-CERT"
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
        for bulletin in response.css(self.block_selector):
            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://www.cisa.gov/uscert" + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
