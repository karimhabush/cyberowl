"""
Scrapy settings file.
"""
BOT_NAME = "cyberowl"

SPIDER_MODULES = ["spiders"]
NEWSPIDER_MODULE = "spiders"


# Crawl responsibly by identifying yourself (and your website) on the user-agent
USER_AGENT = "cyberowl (+https://github.com/karimhabush/cyberowl)"

# Obey robots.txt rules
ROBOTSTXT_OBEY = True

# Configure maximum concurrent requests performed by Scrapy (default: 16)
CONCURRENT_REQUESTS = 16

# Configure item pipelines
# See https://docs.scrapy.org/en/latest/topics/item-pipeline.html
ITEM_PIPELINES = {
    "pipelines.AlertPipeline": 300,
}
