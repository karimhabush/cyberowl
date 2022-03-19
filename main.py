from spiders.IBMcloudSpider import IBMCloudSpider
from spiders.CISASpider import CisaSpider
from spiders.CertFrSpider import CertFrSpider
from spiders.DgssiSpider import DgssiSpider
from spiders.ZDISpider import ZDISpider
from scrapy.crawler import CrawlerProcess
from datetime import datetime
from autopush import git_push


def main():
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    item = f"""<div id="top"></div>\n\n## CyberOwl \n> Last Updated {now} \n\n
A daily updated summary of the most frequent types of security incidents currently being reported from different sources.\n\n
### Jump to \n * [CISA](#cisa-arrow_heading_up)\n* [MA-CERT](#ma-cert-arrow_heading_up)\n* [CERT-FR](#cert-fr-arrow_heading_up)
\n* [IBMCLOUD](#ibmcloud-arrow_heading_up)\n* [ZeroDayInitiative](#zerodayinitiative-arrow_heading_up)\n\n"""

    with open("README.md", "w") as f:
        f.write(item)
        f.close()

    try:
        process = CrawlerProcess()
        process.crawl(CisaSpider)
        process.crawl(DgssiSpider)
        process.crawl(CertFrSpider)
        process.crawl(IBMCloudSpider)
        process.crawl(ZDISpider)
        process.start()

    except Exception:
        raise ValueError("to print the error!")

    try:
        git_push()
    except Exception:
        raise ValueError("to print the errors about gitpuhs!")


if __name__ == "__main__":
    main()
