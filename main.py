from spiders.IBMcloudSpider import IBMCloudSpider
from spiders.VigilanceSpider import VigilanceSpider
from spiders.CISASpider import CisaSpider
from spiders.CertFrSpider import CertFrSpider
from spiders.DgssiSpider import DgssiSpider
from spiders.ZDISpider import ZDISpider
from scrapy.crawler import CrawlerProcess
from datetime import datetime, timezone




def main():
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    item = f"""<div id="top"></div>\n\n## CyberOwl \n ![cyberowl](docs/images/logo.png)\n> Last Updated {now} UTC \n\nA daily updated summary of the most frequent types of security incidents currently being reported from different sources.\n\n--- \n\n### :kangaroo: Jump to \n | CyberOwl Sources | Description |\n|---|---|\n| [US-CERT](#us-cert-arrow_heading_up) | United States Computer Emergency and Readiness Team. |\n| [MA-CERT](#ma-cert-arrow_heading_up) | Moroccan Computer Emergency Response Team. |\n| [CERT-FR](#cert-fr-arrow_heading_up) | The French national government Computer Security Incident Response Team. |\n| [IBM X-Force Exchange](#ibmcloud-arrow_heading_up) | A cloud-based threat intelligence platform that allows to consume, share and act on threat intelligence. |\n| [ZeroDayInitiative](#zerodayinitiative-arrow_heading_up) | An international software vulnerability initiative that was started in 2005 by TippingPoint. |\n| [OBS Vigilance](#obs-vigilance-arrow_heading_up) |Vigilance is an initiative created by OBS (Orange Business Services) since 1999 to watch public vulnerabilities and then offer security fixes, a database and tools to remediate them. |\n\n> Suggest a source by opening an [issue](https://github.com/karimhabush/cyberowl/issues)! :raised_hands:\n\n"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(item)
        f.close()

    try:
        process = CrawlerProcess()
        process.crawl(CisaSpider) 
        process.crawl(DgssiSpider)
        process.crawl(CertFrSpider)
        process.crawl(IBMCloudSpider)
        process.crawl(ZDISpider)
        process.crawl(VigilanceSpider)
        process.start()

    except Exception:
        raise ValueError("Error in the spiders!")


if __name__ == "__main__":
    main()
