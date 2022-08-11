import scrapy
from items import AlertItem


class VulDBSpider(scrapy.Spider):
    """
    Spider for the VulDB website.
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
        """
        Parsing the response
        """
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
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = "Visit link for details"

            yield item
