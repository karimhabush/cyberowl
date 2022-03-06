import scrapy

class DgssiSpider(scrapy.Spider):
    name = 'dgssi'
    start_urls = [
        'https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """\n\n## MA-CERT [:arrow_heading_up:](#cyberowl) \n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()
        for bulletin in response.css("div.event_row1"):
            link = "https://www.dgssi.gov.ma" + bulletin.xpath("descendant-or-self::h4/a/@href").get()
            date = bulletin.css("span.event_date::text").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            title = bulletin.xpath("descendant-or-self::h4/a[2]/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            description = bulletin.xpath('descendant-or-self::p[contains(@class,"body-evenement")]/text()').get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            
            item = f"""| [{title}]({link}) | {description} | {date} |\n"""
            
            with open("README.md","a") as f:
                f.write(item)
                f.close()