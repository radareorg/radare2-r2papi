.PHONY: tests clean

R2API_PATH=../r2api

tests: clean
	pytest --cov=$(R2API_PATH) --cov-report=html

min minimum:
	PYTHONPATH=.. python3 minimum.py | grep -e arm -e x86 -e x64

clean:
	rm -rf ./htmlcov
	rm -f .coverage
