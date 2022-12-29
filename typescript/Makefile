all: node_modules
	tsc --declaration index.ts
	tsc -m node16 --target es2020 shell.ts && mv shell.js shell.qjs
	tsc -m node16 --target es2020 esil.ts && mv esil.js esil.qjs
	tsc -m node16 --target es2020 index.ts && mv index.js index.qjs
	tsc -m node16 --target es2020 pdq.ts && mv pdq.js pdq.qjs

one:
	cat shell.qjs esil.qjs index.qjs pdq.qjs |grep -v require > one.qjs
	R2_DEBUG_NOPAPI=1 r2 -i one.qjs /bin/ls

test:
	R2_DEBUG_NOPAPI=1 r2 -qi index.ts /bin/ls

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
