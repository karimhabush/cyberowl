import scrapy
from mdtemplate import Template
class CertFrSpider(scrapy.Spider):
    name = 'certfr'
    start_urls = [
        'https://www.cert.ssi.gouv.fr/avis/'
    ]
    def parse(self, response): 
        if('cached' in response.flags):
            return 
        
        _data =[]
        for bulletin in response.css("article.cert-avis"):
            LINK = "https://www.cert.ssi.gouv.fr"+bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]//@href").get()
            DATE = bulletin.xpath("descendant-or-self::article/section/div/span[contains(@class,'item-date')]//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("Publié le ","")
            TITLE = bulletin.xpath("descendant-or-self::article/section/div[contains(@class,'item-title')]/h3//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            DESC = bulletin.xpath("descendant-or-self::article/section[contains(@class,'item-excerpt')]/p//text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ","")
            
            ITEM={
                "_title":TITLE,
                "_link":LINK,
                "_date":DATE,
                "_desc":DESC
            }

            _data.append(ITEM)
        
        _to_write = Template("CERT-FR",_data)
        
        with open("README.md","a") as f:
                f.write(_to_write._fill_table())
                f.close()
