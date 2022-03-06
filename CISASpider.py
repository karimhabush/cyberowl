import scrapy

class CisaSpider(scrapy.Spider):
    name = 'cisa'
    start_urls = [
        'https://www.cisa.gov/uscert/ncas/current-activity'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """## CISA [:arrow_heading_up:](#cyberowl)\n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()
        for bulletin in response.css("div.views-row"):
            link = "https://www.cisa.gov/uscert"+bulletin.xpath("descendant-or-self::h3/span/a/@href").get()
            date = bulletin.xpath("descendant-or-self::div[contains(@class,'entry-date')]/span[2]/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            title = bulletin.xpath("descendant-or-self::h3/span/a/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            description = bulletin.xpath('descendant-or-self::div[contains(@class,"field-content")]/p').get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")

            item = f"""| [{title}]({link}) | {description} | {date} |\n"""

            with open("README.md","a") as f:
                f.write(item)
                f.close()