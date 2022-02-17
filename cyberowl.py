import scrapy
from scrapy.crawler import CrawlerProcess
from datetime import datetime 

class CisaSpider(scrapy.Spider):
    name = 'cisa'
    start_urls = [
        'https://www.cisa.gov/uscert/ncas/current-activity'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """## CISA\n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()
        for bulletin in response.css("div.views-row"):
            link = "https://www.cisa.gov/uscert"+bulletin.xpath("descendant-or-self::h3/span/a/@href").get()
            date = bulletin.xpath("descendant-or-self::div[contains(@class,'entry-date')]/span[2]/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            title = bulletin.xpath("descendant-or-self::h3/span/a/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            description = bulletin.xpath('descendant-or-self::div[contains(@class,"field-content")]/p//text()').get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            
            item = f"""| [{title}]({link}) | {description} | {date} |\n"""
            
            with open("README.md","a") as f:
                f.write(item)
                f.close()

class CertFrSpider(scrapy.Spider):
    name = 'certfr'
    start_urls = [
        'https://www.cert.ssi.gouv.fr/avis/'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """## CERT-FR\n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()

        for bulletin in response.css("article.cert-avis"):
            source = 'certfr'
            link ="https://www.cert.ssi.gouv.fr"+bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]//@href").get()
            date = bulletin.xpath("descendant-or-self::article/section/div/span[contains(@class,'item-date')]//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("Publié le ","")
            title =  bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]/h3//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            description = bulletin.xpath("descendant-or-self::article/section[contains(@class,'item-excerpt')]/p//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            item = f"""| [{title}]({link}) | {description} | {date} |\n"""
            
            with open("README.md","a") as f:
                f.write(item)
                f.close()



class DgssiSpider(scrapy.Spider):
    name = 'dgssi'
    start_urls = [
        'https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """\n\n## DGSSI\n|Title|Description|Date|\n|---|---|---|\n"""
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

now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

with open("README.md","w") as f:
    f.write("# Current Incidents Activity \n# Last Updated "+now+" \n\n")
    f.close()

process = CrawlerProcess()
process.crawl(CisaSpider)
process.crawl(CertFrSpider)
process.crawl(DgssiSpider)
process.start()
