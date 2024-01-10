all build:
	python setup.py build sdist

test:
	make -C test min

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
