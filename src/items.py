"""
    Scrapy Item classes
"""

import scrapy


class AlertItem(scrapy.Item):
    """
    AlertItem class.
    """

    source = scrapy.Field()
    link = scrapy.Field()
    title = scrapy.Field()
    description = scrapy.Field()
    date = scrapy.Field()
