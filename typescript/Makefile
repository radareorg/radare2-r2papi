TSC=node_modules/.bin/tsc

all: node_modules
	$(TSC) --declaration index.ts
	$(TSC) -m node16 --target es2020 shell.ts && cp -f shell.js shell.qjs
	$(TSC) -m node16 --target es2020 esil.ts && cp -f esil.js esil.qjs
	$(TSC) -m node16 --target es2020 index.ts && cp -f index.js index.qjs

pdq:
	$(TSC) -m node16 --target es2020 pdq.ts
	cat pdq.js | sed -e 's,require.*$$,global;,' > pdq.qjs

PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)

install user-install:
	mkdir -p $(PLUGDIR)
	cp pdq.qjs $(PLUGDIR)

uninstall user-uninstall:
	rm -f $(PLUGDIR)/pdq.qjs

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

clean:
	rm *.qjs
