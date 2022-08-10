import scrapy
from msedge.selenium_tools import Edge, EdgeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from items import AlertItem


class IBMCloudSpider(scrapy.Spider):
    """
    Class to get dynamic content from Exchage X-force website.
    """

    name = "IBMCLOUD"
    max_bulletins = 6
    start_urls = [
        "https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities"
    ]
    block_selector = (
        "descendant-or-self::table[contains(@class,'searchresult')]/tbody/tr"
    )
    link_selector = ".//a"
    title_selector = ".//td[4]"
    date_selector = ""
    description_selector = ""

    def __init__(self):
        options = EdgeOptions()
        options.use_chromium = True
        options.add_argument("headless")
        options.add_argument("disable-gpu")
        self.driver = Edge(executable_path="./src/msedgedriver.exe", options=options)

    def _wait_until_website_is_ready(self) -> None:
        wait = WebDriverWait(self.driver, 5)
        wait.until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    self.block_selector,
                )
            )
        )

    def parse(self, response, **kwargs):

        self.driver.get(response.url)
        self._wait_until_website_is_ready()

        for idx, bulletin in enumerate(
            self.driver.find_elements_by_xpath(self.block_selector)
        ):
            if idx > self.max_bulletins:
                break

            item = AlertItem()
            item["link"] = response.url
            item["date"] = bulletin.find_element_by_xpath(self.title_selector).text
            item["title"] = bulletin.find_element_by_xpath(self.link_selector).text
            item["description"] = "Visit link for details"

            yield item
