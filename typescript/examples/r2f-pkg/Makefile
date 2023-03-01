all:
	mkdir -p node_modules
	npm i
	r2pm -r r2frida-compile -S -o index.qjs index.ts
	r2 -qi index.qjs /bin/ls

clean:
	rm -f index.qjs
