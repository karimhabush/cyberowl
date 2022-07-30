from urllib import response
import scrapy
from mdtemplate import Template
from datetime import date


class VulDBSpider(scrapy.Spider):
    name = 'VulDB'
    start_urls = [
        'https://vuldb.com/?live.recent'
    ]
    def parse(self, response):
        if('cached' in response.flags):
            return
        num_bulletins=0
        _data = []
        print(response.css("table>tr").extract())
        for bulletin in response.css("table>tr"):
            if num_bulletins==0:
                num_bulletins+=1
                continue
            LINK = "https://vuldb.com/"+bulletin.xpath("descendant-or-self::td[4]//@href").get()
            DATE = str(date.today())+" at "+bulletin.xpath("descendant-or-self::td[1]//text()").get()
            TITLE = bulletin.xpath("descendant-or-self::td[4]//text()").get().replace(
                "\n", "").replace("\t", "").replace("\r", "").replace("  ", "").replace("|","-")
            DESC = "Visit link for details"
            ITEM = {
                "_title": TITLE,
                "_link": LINK,
                "_date": DATE,
                "_desc": DESC
            }

            _data.append(ITEM)
            num_bulletins += 1
            if num_bulletins >= 11:
                break

        _to_write = Template("VulDB", _data)

        with open("README.md", "a", encoding="utf-8") as f:
            f.write(_to_write._fill_table())
            f.close()
