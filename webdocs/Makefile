.PHONY: web clean

web: public/typescript public/python

public/typescript:
	rm -Rf public/typescript
	mkdir -p public/typescript
	make -C ../typescript docs-html
	mv ../typescript/sync/docs public/typescript/sync
	mv ../typescript/async/docs public/typescript/async

public/python:
	rm -Rf public/python
	make -C ../python/docs html
	mv ../python/docs/_build/html public/python

clean:
	rm -Rf public/typescript public/python 