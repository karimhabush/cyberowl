"""
This spider is used to scrape alerts from the following source:
https://www.dgssi.gov.ma/fr/bulletins
"""
import scrapy
from items import AlertItem


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
    start_urls = ["https://www.dgssi.gov.ma/fr/bulletins/"]
    custom_settings = {
        "USER_AGENT": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "ROBOTSTXT_OBEY": False,
        "DOWNLOAD_TIMEOUT": 30,
    }
    block_selector = "div.single-blog-content"
    link_selector = "descendant-or-self::h3/a/@href"
    title_selector = "descendant-or-self::h3/a/text()"
    date_selector = "descendant-or-self::ul[contains(@class,'admin')]/li/text()"
    description_selector = "descendant-or-self::p/text()"

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
            item["link"] = link if link and link.startswith("http") else ""
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
