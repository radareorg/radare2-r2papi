all build:
	python -m pip install -e .[dev]
	python -m build

test: clean
	python -m pip install -e .[dev]
	gcc -o test/test_exe test/test.c
	pytest --cov=r2papi --cov-report=html

doc:
	rm -rf docs/_build
	python -m pip install -e .[docs]
	make -C docs html
	cd docs/_build \
		&& mv html r2papi-python-docs \
		&& zip -r ../../r2papi-python-docs.zip r2papi-python-docs

clean:
	rm -rf build dist r2papi.egg-info ./htmlcov .coverage

install:
	python -m pip install .

pub publish: all
#	python3 -m twine upload -u __token__ --repository testpypi dist/*
#	python3 -m twine upload --repository https://pypi.python.org dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*

twine:
	sudo pip install -U twine

.PHONY: all test clean install twine

