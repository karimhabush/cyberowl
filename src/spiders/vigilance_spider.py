import scrapy

from mdtemplate import Template


class VigilanceSpider(scrapy.Spider):
    name = "vigilance"
    start_urls = ["https://vigilance.fr/?action=1135154048&langue=2"]

    def parse(self, response):
        if "cached" in response.flags:
            return
        num_bulletins = 0
        _data = []
        for bulletin in response.css("article > table"):
            LINK = bulletin.xpath("descendant-or-self::tr/td/a/@href").get()
            DATE = "Visit link for details"
            TITLE = (
                bulletin.xpath("descendant-or-self::tr/td/a")
                .get()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("  ", "")
                .replace("|", "-")
            )
            DESC = (
                bulletin.xpath("descendant-or-self::tr/td/font/i/a/text()")
                .get()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("  ", "")
                .replace("|", "-")
            )
            ITEM = {"_title": TITLE, "_link": LINK, "_date": DATE, "_desc": DESC}

            _data.append(ITEM)
            num_bulletins += 1
            if num_bulletins >= 10:
                break

        _to_write = Template("OBS-Vigilance", _data)

        with open("README.md", "a", encoding="utf-8") as f:
            f.write(_to_write._fill_table())
            f.close()
