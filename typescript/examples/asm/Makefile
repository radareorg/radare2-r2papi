all: rvcodecjs
	node index.js
	r2frida-compile -Sc index.js  > index.r2.js
	r2 -i index.r2.js -

rvcodecjs:
	git clone https://gitlab.com/luplab/rvcodecjs
	cd rvcodecjs && npm i
