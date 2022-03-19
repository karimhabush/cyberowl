import scrapy
from mdtemplate import Template


class DgssiSpider(scrapy.Spider):
    name = 'dgssi'
    start_urls = [
        'https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html'
    ]

    def parse(self, response):
        if('cached' in response.flags):
            return

        _data = []
        for bulletin in response.css("div.event_row1"):
            LINK = "https://www.dgssi.gov.ma" + \
                bulletin.xpath("descendant-or-self::h4/a/@href").get()
            DATE = bulletin.css("span.event_date::text").get().replace(
                "\n", "").replace("\t", "").replace("\r", "").replace("  ", "")
            TITLE = bulletin.xpath("descendant-or-self::h4/a[2]/text()").get().replace(
                "\n", "").replace("\t", "").replace("\r", "").replace("  ", "")
            DESC = bulletin.xpath('descendant-or-self::p[contains(@class,"body-evenement")]/text()').get(
            ).replace("\n", "").replace("\t", "").replace("\r", "").replace("  ", "")

            ITEM = {
                "_title": TITLE,
                "_link": LINK,
                "_date": DATE,
                "_desc": DESC
            }

            _data.append(ITEM)

        _to_write = Template("MA-CERT", _data)

        with open("README.md", "a") as f:
            f.write(_to_write._fill_table())
            f.close()
