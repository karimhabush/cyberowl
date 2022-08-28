"""This module contains the main function used execute the crawler."""

from scrapy.crawler import CrawlerProcess
from scrapy.settings import Settings

import cyberowl.settings as cyberowl_settings
from cyberowl.spiders.cert_fr_spider import CertFRSpider
from cyberowl.spiders.cisa_spider import CisaSpider
from cyberowl.spiders.ibmcloud_spider import IBMCloudSpider
from cyberowl.spiders.ma_cert_spider import MACertSpider
from cyberowl.spiders.vigilance_spider import VigilanceSpider
from cyberowl.spiders.vuldb_spider import VulDBSpider
from cyberowl.spiders.zdi_spider import ZDISpider
from cyberowl.utils import generate_heading, generate_table_of_content, write_to_readme


def main():
    """Execute the crawler."""
    generate_heading()
    generate_table_of_content()

    crawler_settings = Settings()
    crawler_settings.setmodule(cyberowl_settings)
    process = CrawlerProcess(settings=crawler_settings)

    spiders_cls = [
        CisaSpider,
        MACertSpider,
        CertFRSpider,
        IBMCloudSpider,
        ZDISpider,
        VigilanceSpider,
        VulDBSpider,
    ]

    for spider in spiders_cls:
        process.crawl(spider)

    process.start()

    write_to_readme()


if __name__ == "__main__":
    main()
