# Contributing

Contributions of any kind are welcome! ✨

Cyberowl is a community-driven project, so if you have any suggestions or bug reports, don't hesitate to do so.

When contributing to Cyberowl, please first discuss the change you wish to make via issue, email, or any other method with the owners of the repository.

Please also make sure you are following our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Getting Started

After cloning cyberowl into your local machine, you can start by first setting up the environment.

### Virtual Environment with `poetry`

First, install `poetry`:

```bash
pip install poetry
```

Install the dependencies:

```bash
poetry install
```

Activate the virtual environment:

```bash
poetry shell
```

### Development Dependencies

After setting up the environment, some development dependencies are also installed including `pre-commit`.

`Pre-commit` is a tool that helps you to run tests before committing to a repository.

To make sure it's activated, run the following command:

```bash
pre-commit install
```

### Running the Script

Now that everything's all set, you can run the script by running:

```bash
python src/cyberowl/main.py
```

Or with `poetry` :

```bash
poetry run python src/cyberowl/main.py
```

## Documentation

Cyberowl uses [mkdocs](https://www.mkdocs.org/) to generate the documentation.

To generate the documentation, navigate to `./docs/` folder and run the following command:

```bash
mkdocs serve
```
You can now navigate to [http://localhost:8000/] to view the documentation.

Or if you want to build it, run the following command:

```bash
mkdocs build
```


## Testing

Testing is a work in progress. It will be implemented very soon.
