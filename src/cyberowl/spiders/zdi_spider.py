"""
    This spider is used to scrape alerts from the following source:
    https://www.zerodayinitiative.com/advisories/published/
"""

from datetime import date

import scrapy
from items import AlertItem
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.options import Options


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
    block_selector = "//table[contains(@class,'table')]/tbody/tr[@id='publishedAdvisories']"
    link_selector = ".//td[contains(@class,'sort-td')]/a"
    title_selector = ".//td[contains(@class,'sort-td')]/a"
    date_selector = ".//td[6]"
    description_selector = ""

    @property
    def start_urls(self):
        return [f"https://www.zerodayinitiative.com/advisories/published/{date.today().year}/"]

    def __init__(self):
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        self.driver = webdriver.Chrome(options=options)

    def _wait_until_website_is_ready(self) -> None:
        """
        Wait until website is ready.
        """
        wait = WebDriverWait(self.driver, 10)
        wait.until(
            EC.presence_of_element_located(
                (
                    By.XPATH,
                    "//tr[@id='publishedAdvisories']",
                )
            )
        )

    def parse(self, response, **kwargs):

        self.driver.get(response.url)
        self._wait_until_website_is_ready()

        for idx, bulletin in enumerate(
            self.driver.find_elements(By.XPATH, self.block_selector)
        ):
            if idx >= self.max_bulletins:
                break

            item = AlertItem()
            item["link"] = bulletin.find_element(
                By.XPATH, self.link_selector
            ).get_attribute("href")
            item["date"] = bulletin.find_element(By.XPATH, self.date_selector).text
            item["title"] = bulletin.find_element(By.XPATH, self.link_selector).text
            item["description"] = "Visit link for details"

            yield item

    def closed(self, reason):
        if hasattr(self, "driver"):
            self.driver.quit()
