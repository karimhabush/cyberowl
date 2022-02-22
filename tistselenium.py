import scrapy
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# from logzero import logfile, logger
class CountriesSpiderSpider(scrapy.Spider):
    # Initializing log file
    # logfile("openaq_spider.log", maxBytes=1e6, backupCount=3)
    name = "countries_spider"
    allowed_domains = ["toscrape.com"]
# Using a dummy website to start scrapy request
    def start_requests(self):
        url = "http://quotes.toscrape.com"
        yield scrapy.Request(url=url, callback=self.parse_countries)
    def parse_countries(self, response):
        # driver = webdriver.Chrome()  # To open a new browser window and navigate it
        # Use headless option to not open a new browser window
        options = webdriver.ChromeOptions()
        options.add_argument("headless")
        desired_capabilities = options.to_capabilities()
        driver = webdriver.Chrome(ChromeDriverManager().install())
        # Getting list of Countries
        driver.get("https://openaq.org/#/countries")
        # Implicit wait
        driver.implicitly_wait(10)
        # Explicit wait
        wait = WebDriverWait(driver, 5)
        wait.until(EC.presence_of_element_located((By.CLASS_NAME, "card__title")))
        countries = driver.find_elements_by_class_name("card__title")
        countries_count = 0
        # Using Scrapy's yield to store output instead of explicitly writing to a JSON file
        for country in countries:
            yield {
                "country": country.text,
            }
            countries_count += 1
        driver.quit()
        print(f"Total number of Countries in openaq.org: {countries_count}")