import scrapy

from items import AlertItem


class CertFRSpider(scrapy.Spider):
    """
    Spider for the CERT-FR website.
    """

    name = "CERT-FR"
    start_urls = ["https://www.cert.ssi.gouv.fr/avis/"]

    block_selector = "article.cert-avis"
    link_selector = (
        "descendant-or-self::article/section/div[contains(@class,'item-title')]//@href"
    )
    date_selector = "descendant-or-self::article/section/div/span[contains(@class,'item-date')]//text()"
    title_selector = "descendant-or-self::article/section/div[contains(@class,'item-title')]/h3//text()"
    description_selector = (
        "descendant-or-self::article/section[contains(@class,'item-excerpt')]/p//text()"
    )

    def parse(self, response):
        """
        Parsing the response
        """
        for bulletin in response.css(self.block_selector):
            item = AlertItem()

            item["title"] = bulletin.xpath(self.title_selector).get()
            item["link"] = (
                "https://www.cert.ssi.gouv.fr"
                + bulletin.xpath(self.link_selector).get()
            )
            item["date"] = bulletin.xpath(self.date_selector).get()
            item["description"] = bulletin.xpath(self.description_selector).get()

            yield item
