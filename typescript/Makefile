all: node_modules
	tsc --declaration index.ts

node_modules:
	mkdir -p node_modules
	npm i

node_modules/jsfmt:
	mkdir -p node_modules
	npm install jsfmt

MODVER=$(shell node -e 'console.log(JSON.parse(require("fs").readFileSync("package.json"))["version"])')

doc:
	npm run doc
	rm -f docs.zip
	zip -r docs.zip docs
	r2 -qc "open docs/index.html" --

npm publish pub:
	${MAKE}
	npm publish

unpublish:
	${MAKE}
	npm unpublish @${MODVER}

r2wip.d.ts:
	sh tsi.sh ij >> r2wip.d.ts
	sh tsi.sh pdj >> r2wip.d.ts
	sh tsi.sh afij >> r2wip.d.ts
	sh tsi.sh abj >> r2wip.d.ts
