import scrapy
from items import AlertItem


class VigilanceSpider(scrapy.Spider):
    """
    Spider for the OBS-Vigilance website.
    """

    name = "OBS-Vigilance"
    max_items = 10
    start_urls = ["https://vigilance.fr/?action=1135154048&langue=2"]
    block_selector = "article > table"
    link_selector = "descendant-or-self::tr/td/a/@href"
    date_selector = ""
    title_selector = "descendant-or-self::tr/td/a"
    description_selector = "descendant-or-self::tr/td/font/i/a/text()"

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx > self.max_items:
                break

            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = bulletin.xpath(self.link_selector).get()
            item["date"] = "Visit link for details"
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
