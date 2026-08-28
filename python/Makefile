VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(PYTHON) -m pip

$(VENV)/stamp:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	@touch $@

all build: $(VENV)/stamp
	$(PIP) install -e .[dev]
	$(PYTHON) -m build

test: clean $(VENV)/stamp
	$(PIP) install -e .[dev]
	gcc -o test/test_exe test/test.c
	$(PYTHON) -m pytest --cov=r2papi --cov-report=html

doc: $(VENV)/stamp
	rm -rf docs/_build
	$(PIP) install -e .[docs]
	$(PYTHON) -m sphinx.cmd.build -M html docs docs/_build
	cd docs/_build \
		&& mv html r2papi-python-docs \
		&& zip -r ../../r2papi-python-docs.zip r2papi-python-docs

clean:
	rm -rf .venv build dist r2papi.egg-info ./htmlcov .coverage

install: $(VENV)/stamp
	$(PIP) install .

pub publish: all
#	python3 -m twine upload -u __token__ --repository testpypi dist/*
#	python3 -m twine upload --repository https://pypi.python.org dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*

twine: $(VENV)/stamp
	$(PIP) install -U twine

.PHONY: all build test doc clean install pub publish twine

