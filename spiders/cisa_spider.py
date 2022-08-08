import scrapy

from mdtemplate import Template


class CisaSpider(scrapy.Spider):
    """
    Spider for the CISA website.
    """

    name = "cisa"
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
        Parsing the response.
        """
        alert_results = []

        for bulletin in response.css(self.block_selector):
            link = (
                "https://www.cisa.gov/uscert" + bulletin.xpath(self.link_selector).get()
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

        _to_write = Template("US-CERT", alert_results)

        with open("README.md", "a", encoding="utf-8") as file:
            file.write(_to_write._fill_table())
            file.close()
