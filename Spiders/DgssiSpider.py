import scrapy 

class DgssiSpider(scrapy.Spider):
    name = 'dgssi'
    start_urls = [
        'https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html'
    ]
    def parse(self, response): 
        for bulletin in response.css("div.event_row1"):
            yield {
                'source' : "dgssi",
                'link' : "https://www.dgssi.gov.ma" + bulletin.xpath("descendant-or-self::h4/a/@href").get(),
                'date' : bulletin.css("span.event_date::text").get().replace("\n","").replace("\t","").replace("\r","").replace("  ",""),
                'title' : bulletin.xpath("descendant-or-self::h4/a[2]/text()").get().replace("\n","").replace("\t","").replace("\r","").replace("  ",""),
                'description' : bulletin.xpath('descendant-or-self::p[contains(@class,"body-evenement")]/text()').get().replace("\n","").replace("\t","").replace("\r","").replace("  ",""),
            }
