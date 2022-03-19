import scrapy
from mdtemplate import Template


class CisaSpider(scrapy.Spider):
    name = 'cisa'
    start_urls = [
        'https://www.cisa.gov/uscert/ncas/current-activity'
    ]

    def parse(self, response):
        if('cached' in response.flags):
            return

        _data = []
        for bulletin in response.css("div.views-row"):
            LINK = "https://www.cisa.gov/uscert"+bulletin.xpath("descendant-or-self::h3/span/a/@href").get()
            DATE = bulletin.xpath("descendant-or-self::div[contains(@class,'entry-date')]/span[2]/text()").get().replace(
                "\n", "").replace("\t", "").replace("\r", "").replace("  ", "")
            TITLE = bulletin.xpath("descendant-or-self::h3/span/a/text()").get().replace("\n",
                                                                                         "").replace("\t", "").replace("\r", "").replace("  ", "")
            DESC = bulletin.xpath('descendant-or-self::div[contains(@class,"field-content")]/p').get().replace(
                "\n", "").replace("\t", "").replace("\r", "").replace("  ", "")

            ITEM = {
                "_title": TITLE,
                "_link": LINK,
                "_date": DATE,
                "_desc": DESC
            }

            _data.append(ITEM)

        _to_write = Template("CISA", _data)

        with open("README.md", "a") as f:
            f.write(_to_write._fill_table())
            f.close()
