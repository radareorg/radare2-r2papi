all:
	-mv node_modules/_r2pipe node_modules/r2pipe
	npm run node
	-#
	mv node_modules/r2pipe node_modules/_r2pipe
	cp -rf r2pipe-types node_modules/r2pipe
	-npm run qjs
	rm -rf node_modules/r2pipe
	mv node_modules/_r2pipe node_modules/r2pipe
