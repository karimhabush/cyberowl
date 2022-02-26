from IBMcloudSpider import IBMCloudSpider
from CISASpider import CisaSpider
from CertFrSpider import CertFrSpider
from DgssiSpider import DgssiSpider
from scrapy.crawler import CrawlerProcess
from datetime import datetime 

now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
item = f"""# Current Incidents Activity \n# Last Updated {now} \n\n 
A daily updated summary of the most frequent types of security incidents currently being reported from different sources.\n\n
## Jump to : \n* [CISA](#cisa)\n* [DGSSI](#dgssi)\n* [CERT-FR](#cert-fr)\n* [IBMCLOUD](#ibmcloud)\n\n"""
with open("README.md","w") as f:
    f.write(item)
    f.close()

process = CrawlerProcess()
process.crawl(CisaSpider)
process.crawl(DgssiSpider)
process.crawl(CertFrSpider)
process.crawl(IBMCloudSpider)
process.start()