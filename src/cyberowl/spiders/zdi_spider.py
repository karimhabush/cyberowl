"""
    This spider is used to scrape alerts from the following source:
    https://www.zerodayinitiative.com/advisories/published/
"""

import scrapy
from items import AlertItem
from msedge.selenium_tools import Edge, EdgeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class ZDISpider(scrapy.Spider):
    """Spider for the ZeroDayInitiative website.

    This spider is used to scrape data from the official website of
    ZeroDayInitiative.

    Attributes:
        name : Name of the spider.
        max_items : The maximum number of items to scrape.
        start_url : The website from which to start crawling.
        block_selector : The CSS/XPATH selector of the block containing the data.
        link_selector : The CSS/XPATH selector of the link of the alert.
        title_selector : The CSS/XPATH selector of the title of the alert.
        date_selector : The CSS/XPATH selector of the date of creation of the alert.
        description_selector : The CSS/XPATH selector of the description of the alert.
    """

    name = "ZERODAYINITIATIVE"
    max_bulletins = 7
    start_urls = ["https://www.zerodayinitiative.com/advisories/published/"]
    block_selector = "descendant-or-self::table[contains(@class,'table')]/tbody/tr"
    link_selector = ".//a"
    title_selector = ".//a"
    date_selector = ".//td[6]"
    description_selector = ""

    def __init__(self):
        options = EdgeOptions()
        options.use_chromium = True
        options.add_argument("headless")
        options.add_argument("disable-gpu")
        self.driver = Edge(
            executable_path="./src/cyberowl/msedgedriver.exe", options=options
        )

    def _wait_until_website_is_ready(self) -> None:
        """
        Wait until website is ready.
        """
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
            item["link"] = bulletin.find_element_by_xpath(
                self.link_selector
            ).get_attribute("href")
            item["date"] = bulletin.find_element_by_xpath(self.date_selector).text
            item["title"] = bulletin.find_element_by_xpath(self.link_selector).text
            item["description"] = "Visit link for details"

            yield item
