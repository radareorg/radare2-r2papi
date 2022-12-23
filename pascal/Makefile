UNAME=$(shell uname | tr A-Z a-z)
PASVER=2.2.0

ifeq ($(UNAME),darwin)
OS=macos
else
OS=linux
endif
PAS2JS=pas2js-$(OS)-$(PASVER)/bin/x86_64-$(UNAME)/pas2js

all: $(PAS2JS)
	$(PAS2JS) -O2 -B -Jc -Tnodejs hello.pas
	r2 -j hello.js

$(PAS2JS):
	wget -c https://downloads.freepascal.org/fpc/contrib/pas2js/$(PASVER)/pas2js-$(OS)-$(PASVER).zip
	unzip pas2js-$(OS)-$(PASVER)
