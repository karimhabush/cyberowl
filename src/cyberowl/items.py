"""
    Scrapy Item classes
"""

import scrapy


class AlertItem(scrapy.Item):
    """
    AlertItem class, representing an alert item.
    Args :
        title : title of the alert.
        link : link to the alert.
        date : date of the alert.
        description : description of the alert.
        source : source of the alert.
    """

    source = scrapy.Field()
    link = scrapy.Field()
    title = scrapy.Field()
    description = scrapy.Field()
    date = scrapy.Field()
