import scrapy

from mdtemplate import Template


class MACertSpider(scrapy.Spider):
    """
    Spider for the MA-CERT website.
    """

    name = "ma-cert"
    start_urls = ["https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html"]
    block_selector = "div.event_row1"
    link_selector = "descendant-or-self::h4/a/@href"
    date_selector = "span.event_date::text"
    title_selector = "descendant-or-self::h4/a[2]/text()"
    description_selector = (
        "descendant-or-self::p[contains(@class,'body-evenement')]/text()"
    )

    def parse(self, response):
        """
        Parsing the response.
        """
        alert_results = []

        for bulletin in response.css(self.block_selector):
            link = "https://www.dgssi.gov.ma" + bulletin.xpath(self.link_selector).get()
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

        _to_write = Template("MA-CERT", alert_results)

        with open("README.md", "a", encoding="utf-8") as file:
            file.write(_to_write._fill_table())
            file.close()
