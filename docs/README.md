# Cyberowl Docs

## What is Cyberowl?

Cyberowl is a daily updated summary of the most frequent types of security incidents currently being reported from different sources.

The primary objective of Cyberowl is to assist analysts and security professionals in quickly identifying different types of security incidents affecting their organization's assets. This is the quickest and most effective way to always stay current on the latest types of incidents.


## Quick links

This documentation is broken down into different sections:

* [Core Concepts](#core-concepts)
* [Api Docs](#api-docs)
* [Installation](#installation)
* [Contributing](CONTRIBUTING.md)
* [License](#license)
* [Code of Conduct](#code-of-conduct)



## Core Concepts

In this section, we will outline the various steps Cyberowl takes to collect data and generate reports.

### Spiders

> Spiders are classes which define how a certain site will be scraped, including how to perform the crawl and how to extract structured data from their pages. In other words, Spiders are the place where you define the custom behaviour for crawling and parsing pages for a particular site.

Cyberowl uses both `Scrapy` spiders and `Selenium` web drivers to collect data from different sources.

* Scrapy is used for static content.
* Selenium is used for dynamically generated content.

Check out cyberwol spiders [here](./../src/cyberowl/spiders/).

### Data Processing

The Item Pipeline is the place where you define the custom behaviour for processing items after they have been scraped.

In other words, the Item Pipeline is where cleaning and processing of data is done as well as storing it in a markdown file.

Check out cyberwol pipelines [here](./../src/cyberowl/pipelines.py).

### Generate Reports

For report generation, we have implemented a custom `MDTemplate` class which is used to format the data into a markdown file.

And with that, we generate the reports using the functions in `utils.py`.

Check out `MDTemplate` [here](./../src/cyberowl/mdtemplate.py).

Check out `utils.py` [here](./../src/cyberowl/utils.py).


## Api Docs

Api Docs are generated using [mkdocs](https://www.mkdocs.org/). Check out [Contributing](CONTRIBUTING.md) for more details on how to generate the Api Docs.


## Installation

To setup Cyberowl, you need to install the following dependencies:

First install `poetry`:
```bash
pip install poetry
```
Clone the project, and install the dependencies:
```bash
poetry install
```
And finally, run the main script:
```bash
poetry run python src/cyberowl/main.py
```


## Contributing

Contributing to Cyberowl is a two step process. Please check out [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

Cyberowl is licensed under the [MIT License](./../LICENSE).


## Code of Conduct

Cyberowl is a community project and we welcome all contributors to join us. Please check out our [Code of Conduct](./../CODE_OF_CONDUCT.md) for more details.
