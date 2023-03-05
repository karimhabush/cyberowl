"""
    This spider is used to scrape alerts from the following source:
    https://www.hkcert.org/security-bulletin?item_per_page=10
"""
import scrapy
from items import AlertItem


class HKCERTSpider(scrapy.Spider):
    """Spider for the Hong Kong CERT.

    This spider is used to scrape data from the official website of
    Hong Kong CERT.

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

    name = "HK-CERT"
    max_items = 10
    start_urls = ["https://www.hkcert.org/security-bulletin?item_per_page=10"]
    block_selector = "a.listingcard__item"
    link_selector = "./@href"
    title_selector = ".//p[contains(@class, 'listingcard__title')]//text()"
    date_selector = ".//div[contains(@class, 'listingcard__info')]/text()[substring-after(.,'Release Date:')]"
    description_selector = ".//div[contains(@class, 'listingcard__desc')]//text()"

    def parse(self, response):
        """
        Parsing the response
        """
        for idx, bulletin in enumerate(response.css(self.block_selector)):

            if idx > self.max_items:
                break
            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = "https://www.hkcert.org" + bulletin.xpath(self.link_selector).get()
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item