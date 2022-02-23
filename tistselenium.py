from shutil import which
import scrapy
from scrapy_selenium import SeleniumRequest

SELENIUM_DRIVER_NAME = 'firefox'
SELENIUM_DRIVER_EXECUTABLE_PATH = "./msedgedriver.exe"
SELENIUM_DRIVER_ARGUMENTS=['-headless']  # '--headless' if using chrome instead of firefox


class CisaSpider(scrapy.Spider):
    name = 'cisa'
    start_urls = [
        'https://www.cisa.gov/uscert/ncas/current-activity'
    ]

    def parse(self, response):
        print(response.request.meta['driver'].title)
