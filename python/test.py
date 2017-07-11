#!/usr/bin/env python

import r2pipe
from r2api import R2Api

r = R2Api(r2pipe.open("/bin/ls"))
if r.info().stripped:
	print "This binary is stripped"

r.searchIn('io.sections.exec')
r.analyzeCalls()
print r.at('entry0').hexdump(16)
print r.at('sym.imp.setenv').hexdump(16)

print r.at('entry0').disassemble(10)

print r.seek('entry0');
print r.analyzeFunction()
print r.disassembleFunction()
for fcn in r.functions():
	print fcn.name

r.quit()
