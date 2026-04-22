"""
    This spider is used to scrape alerts from the following source:
    https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities
"""

import scrapy
from items import AlertItem
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.options import Options


class IBMCloudSpider(scrapy.Spider):
    """Spider for the IBMCLOUD website.

    This spider is used to scrape data from the official website of
    IBMCLOUD.

    Attributes:
        name : Name of the spider.
        max_items : The maximum number of items to scrape.
        start_url : The website from which to start crawling.
    """

    name = "IBM-X-FORCE-EXCHANGE"
    max_bulletins = 10
    start_urls = [
        "https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities"
    ]

    def __init__(self):
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        self.driver = webdriver.Chrome(options=options)

    def _wait_until_website_is_ready(self) -> None:
        wait = WebDriverWait(self.driver, 10)
        wait.until(
            EC.presence_of_element_located(
                (By.XPATH, "//table[contains(@class,'searchresult')]/tbody/tr/td")
            )
        )

    def parse(self, response, **kwargs):

        self.driver.get(response.url)
        self._wait_until_website_is_ready()

        rows = self.driver.find_elements(
            By.XPATH, "//table[contains(@class,'searchresult')]/tbody/tr"
        )

        count = 0
        for row in rows:
            tds = row.find_elements(By.TAG_NAME, "td")
            if len(tds) < 4:
                continue

            if count >= self.max_bulletins:
                break

            item = AlertItem()
            item["title"] = tds[2].text.replace("New vulnerability\n", "").strip()
            item["link"] = response.url
            item["date"] = tds[3].text.strip()
            item["description"] = "Visit link for details"

            count += 1
            yield item

    def closed(self, reason):
        if hasattr(self, "driver"):
            self.driver.quit()
