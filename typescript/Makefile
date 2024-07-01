TSC=$(shell pwd)/node_modules/.bin/tsc
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
ESLINT=$(shell pwd)/node_modules/.bin/eslint
TSI=sh tools/tsi.sh
SRCDIR=async

.PHONY: doc docs docs-html webdoc sync
# build

all: node_modules
	$(MAKE) one
#	$(MAKE) build

one: build
	cd build ; cat shell.r2.js esil.r2.js base64.r2.js r2pipe.r2.js ai.r2.js r2papi.r2.js | grep -v require > ../r2papi.r2.js 
	echo 'var R2Papi=R2PapiSync;' >> r2papi.r2.js

#	cat $(addsuffix .r2.js,$(addprefix build/,$(FILES))) | grep -v require > one.r2.js
#	echo "var R2Papi=R2PapiSync;" >> one.r2.js
#shell.r2.js esil.r2.js base64.r2.js r2pipe.r2.js ai.r2.js r2papi.r2.js | grep -v require > one.r2.js
# R2_DEBUG_NOPAPI=1 r2 -i one.r2.js /bin/ls

onetest:
	R2_PAPI_SCRIPT=$(shell pwd)/r2papi.r2.js \
	r2 -c "'js r2.cmd((ptr().api)?'q!! 0':'q!! 1');" /bin/ls

vs:
	open -a "Visual Studio Code" $(SRCDIR) || vscode .

SYNCREGEX=
SYNCREGEX+=-e 's,await ,,g'
SYNCREGEX+=-e 's,async ,,g'
SYNCREGEX+=-e 's,R2PipeAsync,R2PipeSync,g'
SYNCREGEX+=-e 's,R2PapiAsync,R2PapiSync,g'
SYNCREGEX+=-e 's/Promise<\(.*\)>/\1/'

lint:
	$(ESLINT) $(SRCDIR)/*.ts

# FILES=r2pipe r2papi opt esil shell base64 ai r2frida index
FILES=shell esil base64 r2pipe ai r2papi

# Create a 'sync' version of the original 'async'
sync:
	rm -rf sync
	mkdir -p sync
	cp -f $(addprefix $(SRCDIR)/,$(addsuffix .ts,$(FILES))) sync
	for a in sync/*.ts ; do sed $(SYNCREGEX) -i=.bak $$a ; done
	rm -f sync/*.bak
	cp -f $(SRCDIR)/tsconfig.json sync/tsconfig.json

build: sync
	rm -rf build
	mkdir build
	cp -f sync/*.ts build
	cp -rf $(SRCDIR)/tsconfig.json build/tsconfig.json
	$(TSC) -p build -d
	for a in $(FILES); do \
		echo "tsc $$a.ts -o $$a.r2.js .." ; $(TSC) -m node16 --target es2020 sync/$$a.ts && mv sync/$$a.js build/$$a.r2.js ; \
	done

# TODO: dupe of build only for pub. this should be deleted to avoid confusion
abuild: sync
	rm -rf build
	mkdir build
	cp -f $(SRCDIR)/*.ts build
	cp -rf $(SRCDIR)/tsconfig.json build
	$(TSC) -p build -d
	@for a in $(FILES); do \
		echo "tsc $$a.ts -o $$a.r2.js .." ; \
		$(TSC) -m node16 --target es2020 $(SRCDIR)/$$a.ts && \
			mv $(SRCDIR)/$$a.js build/$$a.r2.js ; \
	done
	rm -f build/*.ts

pdq: node_modules
	# TODO: use pdq.r2.ts
	$(TSC) -m node16 --target es2020 pdq.ts
	cat pdq.js | sed -e 's,require.*$$,global;,' > pdq.r2.js

install user-install:
	mkdir -p $(PLUGDIR)
	cp -f pdq.r2.js $(PLUGDIR)

uninstall user-uninstall:
	rm -f $(PLUGDIR)/pdq.qjs

node_modules:
	mkdir -p node_modules
	npm i

node_modules/jsfmt: node_modules
	npm install jsfmt

MODVER=$(shell node -e 'console.log(JSON.parse(require("fs").readFileSync("package.json"))["version"])')

docs-html: sync
	npm run adoc
	npm run sdoc

doc docs: docs-html
	rm -f docs.zip
	zip -r docs.zip sync/docs $(SRCDIR)/docs
	r2 -qc "open docs/index.html" --

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

# Create a Typescript declaration file taking json output from r2 commands
r2wip.d.ts:
	$(TSI) ij >> r2wip.d.ts
	$(TSI) pdj >> r2wip.d.ts
	$(TSI) afij >> r2wip.d.ts
	$(TSI) abj >> r2wip.d.ts

clean:
	rm -rf *.qjs *.r2.js one.* dist __dist *.zip *.d.ts *.js build sync r2papi.r2.js r2wip.d.ts
