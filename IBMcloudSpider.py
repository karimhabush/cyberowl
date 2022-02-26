import scrapy
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from msedge.selenium_tools import EdgeOptions
from msedge.selenium_tools import Edge

class CountriesSpiderSpider(scrapy.Spider):
    name = "countries_spider"
    allowed_domains = ["toscrape.com"]

    # Using a dummy website to start scrapy request
    def start_requests(self):
        url = "http://quotes.toscrape.com"
        yield scrapy.Request(url=url, callback=self.parse_countries)

    def parse_countries(self, response):
        # Use headless option to not open a new browser window
        options = EdgeOptions()
        options.add_argument("headless")
        options.use_chromium = True
        options.add_argument("disable-gpu")
        driver = Edge(executable_path="./msedgedriver.exe",options=options)
        # Getting list of Countries
        driver.get("https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities")

        # Implicit wait
        driver.implicitly_wait(10)

        # Explicit wait
        wait = WebDriverWait(driver, 5)
        wait.until(EC.presence_of_element_located((By.XPATH, "descendant-or-self::table[contains(@class,'searchresult')]/tbody/tr")))

        # Extracting bulletins
        countries = driver.find_elements_by_xpath("descendant-or-self::table[contains(@class,'searchresult')]/tbody/tr")
        num_bulletins = 0
        # Using Scrapy's yield to store output instead of explicitly writing to a JSON file
        item = """## IBMCLOUD\n|Title|Description|Date|\n|---|---|---|\n"""
        with open("README.md","a") as f:
                f.write(item)
                f.close()
        
        for country in countries:
            link = country.find_element_by_xpath(".//a").get_attribute("href")
            date = country.find_element_by_xpath(".//td[4]").text
            title = country.find_element_by_xpath(".//a").text
            
            item = f"""| [{title}]({link}) | Visit link for details | {date} |\n"""
            
            with open("README.md","a") as f:
                f.write(item)
                f.close()
                
            num_bulletins+=1
            if num_bulletins >= 8:
                break

        driver.quit()
