TSC=$(shell pwd)/node_modules/.bin/tsc
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
ESLINT=$(shell pwd)/node_modules/.bin/eslint
TSI=sh tools/tsi.sh

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
	$(ESLINT) async/*.ts

FILES=r2pipe r2papi opt esil shell base64 ai r2frida index

sync:
	rm -rf sync/*.ts
	cd async && cp -f $(addsuffix .ts,$(FILES)) ../sync
	for a in sync/*.ts ; do sed $(SYNCREGEX) -i=.bak $$a ; done
	rm -f sync/*.bak
	cp async/tsconfig.json sync

abuild: sync
	rm -rf build
	mkdir build
	cp -f async/*.ts build
	cp -rf async/tsconfig.json build
	cd build && $(TSC)
	cd build && $(TSC) --declaration r2papi.ts
	cd build && \
		for a in $(FILES); do \
			echo Compiling $$a.r2.js: ; $(TSC) -m node16 --target es2020 $$a.ts && cp -f $$a.js $$a.r2.js ; \
		done

build: sync
	rm -rf build
	mkdir build
	cp -f sync/*.ts build
	cp -rf async/tsconfig.json build/tsconfig.json
	cd build && $(TSC)
	cd build && $(TSC) --declaration r2papi.ts
	for a in $(FILES); do \
		echo Compiling $$a.r2.js: ; \
		(cd build && $(TSC) -m node16 --target es2020 $$a.ts && cp -f $$a.js $$a.r2.js ) ; \
	done

buildjs:
	cd build && $(TSC) -m node16 --target es2020 index.ts && cp -f index.js index.r2.js
	cd build && $(TSC) -m node16 --target es2020 shell.ts && cp -f shell.js shell.r2.js
	cd build && $(TSC) -m node16 --target es2020 ai.ts && cp -f ai.js ai.r2.js
	cd build && $(TSC) -m node16 --target es2020 esil.ts && cp -f esil.js esil.r2.js
	cd build && $(TSC) -m node16 --target es2020 opt.ts && cp -f opt.js opt.r2.js
	cd build && $(TSC) -m node16 --target es2020 r2papi.ts && cp -f r2papi.js index.r2.js
	cd build && $(TSC) -m node16 --target es2020 r2frida.ts && cp -f r2frida.js r2frida.r2.js
	cd build && $(TSC) -m node16 --target es2020 base64.ts && cp -f base64.js base64.r2.js

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
	$(MAKE) abuild
	#-------------
	# Publishing the sync api
	$(MAKE) build
	cp -f README.md package.json package-lock.json build
	cd build && npm publish
	# Publishing the async api
	$(MAKE) abuild
	cp -f README.md build
	sed -e 's,r2papi",r2papi-async",' < package.json > build/package.json
	sed -e 's,r2papi",r2papi-async",' < package-lock.json > build/package-lock.json
	cd build && npm publish

unpub unpublish:
	npm unpublish r2papi@${MODVER}

r2wip.d.ts:
	$(TSI) ij >> r2wip.d.ts
	$(TSI) pdj >> r2wip.d.ts
	$(TSI) afij >> r2wip.d.ts
	$(TSI) abj >> r2wip.d.ts

clean:
	rm -rf *.qjs *.r2.js one.* dist __dist *.zip *.d.ts *.js
