import scrapy

from mdtemplate import Template


class CertFRSpider(scrapy.Spider):
    """
    Spider for the CERT-FR website.
    """

    name = "cert-fr"
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
        Parsing the response.
        """
        alert_results = []

        for bulletin in response.css(self.block_selector):
            link = (
                "https://www.cert.ssi.gouv.fr"
                + bulletin.xpath(self.link_selector).get()
            )
            date = (
                bulletin.xpath(self.date_selector)
                .get()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("  ", "")
            )
            title = (
                bulletin.xpath(self.title_selector)
                .get()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("  ", "")
            )
            description = (
                bulletin.xpath(self.description_selector)
                .get()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("  ", "")
            )

            item = {"_title": title, "_link": link, "_date": date, "_desc": description}

            alert_results.append(item)

        _to_write = Template("CERT-FR", alert_results)

        with open("README.md", "a", encoding="utf-8") as file:
            file.write(_to_write._fill_table())
            file.close()
