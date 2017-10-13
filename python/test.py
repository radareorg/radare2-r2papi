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

print r.at('entry0').disasm(10)

print r.seek('entry0');
print r.analyzeFunction()
print r.disasmFunction()
for fcn in r.functions():
	print fcn.name

print r.at('entry0 + 8').read(10)

for bb in r.basicBlocks():
	print "B %s %s"%(bb.addr, bb.size)
	try:
		print r.at(bb.addr).opInfo().opcode #disasmBytes(bb.size)
		print "J %s"%(bb.jump)
		print "F %s"%(bb.fail)
	except:
		pass

r.quit()
