all build:
	python setup.py build sdist

test:
	make -C test min

doc:
	rm -rf docs/_build
	make -C docs html
	cd docs/_build \
		&& mv html r2papi-python-docs \
		&& zip -r ../../r2papi-python-docs.zip r2papi-python-docs

clean:
	python setup.py clean
	rm -rf build

install:
	python setup.py install

pub publish: all
#	python3 -m twine upload -u __token__ --repository testpypi dist/*
#	python3 -m twine upload --repository https://pypi.python.org dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*

twine:
	sudo pip install -U twine

.PHONY: all test clean install twine
