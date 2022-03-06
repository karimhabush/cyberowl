import scrapy

class CertFrSpider(scrapy.Spider):
    name = 'certfr'
    start_urls = [
        'https://www.cert.ssi.gouv.fr/avis/'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        item = """## CERT-FR [:arrow_heading_up:](#cyberowl) \n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()

        for bulletin in response.css("article.cert-avis"):
            link ="https://www.cert.ssi.gouv.fr"+bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]//@href").get()
            date = bulletin.xpath("descendant-or-self::article/section/div/span[contains(@class,'item-date')]//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("Publié le ","")
            title =  bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]/h3//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            description = bulletin.xpath("descendant-or-self::article/section[contains(@class,'item-excerpt')]/p//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            item = f"""| [{title}]({link}) | {description} | {date} |\n"""
            
            with open("README.md","a") as f:
                f.write(item)
                f.close()
