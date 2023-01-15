import settings as cyberowl_settings
from scrapy.crawler import CrawlerProcess
from scrapy.settings import Settings
from spiders.ca_ccs_spider import CaCCSSpider
from spiders.cert_eu_spider import EUCERTSpider
from spiders.cert_fr_spider import CertFRSpider
from spiders.cisa_spider import CisaSpider
from spiders.hk_cert_spider import HKCERTSpider
from spiders.ibmcloud_spider import IBMCloudSpider
from spiders.ma_cert_spider import MACertSpider
from spiders.vigilance_spider import VigilanceSpider
from spiders.vuldb_spider import VulDBSpider
from spiders.zdi_spider import ZDISpider
from utils import generate_heading, generate_table_of_content, write_to_readme


def main():
    """
    Main function.
    """

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
        HKCERTSpider,
        CaCCSSpider,
        EUCERTSpider,
    ]

    for spider in spiders_cls:
        process.crawl(spider)

    process.start()

    # write_to_readme()


if __name__ == "__main__":
    main()
