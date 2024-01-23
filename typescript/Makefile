TSC=$(shell pwd)/node_modules/.bin/tsc
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)

all: node_modules
	$(MAKE) build

vs:
	open -a "Visual Studio Code" async || vscode .


SYNCREGEX=
SYNCREGEX+=-e 's,await ,,g'
SYNCREGEX+=-e 's,async ,,g'
SYNCREGEX+=-e 's,R2PipeAsync,R2PipeSync,g'
SYNCREGEX+=-e 's,R2PapiAsync,R2PapiSync,g'
SYNCREGEX+=-e 's/Promise<\(.*\)>/\1/'

lint:
	eslint --fix async/*.ts
#eslint async/*.ts

sync:
	rm -rf sync/*.ts
	cd async && cp -f r2pipe.ts r2papi.ts opt.ts esil.ts esil.ts shell.ts base64.ts ai.ts r2frida.ts index.ts ../sync
	for a in sync/*.ts ; do sed $(SYNCREGEX) -i=.bak $$a ; done
	rm -f sync/*.bak
	cp async/tsconfig.json sync

build: sync
	rm -rf build
	mkdir build
	cp -f sync/*.ts build
	cp -rf async/tsconfig.json build
	cd build && $(TSC)
	cd build && $(TSC) --declaration r2papi.ts
	cd build && $(TSC) -m node16 --target es2020 shell.ts && cp -f shell.js shell.r2.js
	cd build && $(TSC) -m node16 --target es2020 esil.ts && cp -f esil.js esil.r2.js
	cd build && $(TSC) -m node16 --target es2020 opt.ts && cp -f opt.js opt.r2.js
	cd build && $(TSC) -m node16 --target es2020 r2papi.ts && cp -f r2papi.js index.r2.js

.PHONY: sync build

pdq: node_modules
	# TODO: use pdq.r2.ts
	$(TSC) -m node16 --target es2020 pdq.ts
	cat pdq.js | sed -e 's,require.*$$,global;,' > pdq.r2.js

install user-install:
	mkdir -p $(PLUGDIR)
	cp -f pdq.r2.js $(PLUGDIR)

uninstall user-uninstall:
	rm -f $(PLUGDIR)/pdq.qjs

one:
	cat shell.r2.js esil.r2.js base64.r2.js r2pipe.r2.js ai.r2.js r2papi.r2.js pdq.r2.js |grep -v require > one.r2.js
	R2_DEBUG_NOPAPI=1 r2 -i one.r2.js /bin/ls

test:
	R2_DEBUG_NOPAPI=1 r2 -qi index.ts /bin/ls

node_modules:
	mkdir -p node_modules
	npm i

node_modules/jsfmt:
	mkdir -p node_modules
	npm install jsfmt

MODVER=$(shell node -e 'console.log(JSON.parse(require("fs").readFileSync("package.json"))["version"])')

doc docs: sync
	npm run adoc
	npm run sdoc
	rm -f docs.zip
	zip -r docs.zip sync/docs async/docs
	r2 -qc "open docs/index.html" --

.PHONY: doc docs webdoc

webdoc:
	npm run doc
	rm -rf .tmp
	mkdir .tmp
	mv docs .tmp/r2papi
	cd .tmp && tar czvf r2papi.tgz r2papi
	scp .tmp/r2papi.tgz radare.org:doc
	ssh radare.org 'cd doc && tar xzvf r2papi.tgz'
	rm -rf .tmp

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
	rm -rf *.qjs *.r2.js one.* dist __dist *.zip *.d.ts *.js
