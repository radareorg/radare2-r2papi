# -*- coding:utf-8 -*-
from __future__ import print_function
import pytest

from r2api.print import Print

import r2pipe

def get_print():
	r = r2pipe.open('test_bin')
	return Print(r)

def test_byte():
	p = get_print()
	assert p.at('entry0').byte() == 0x55
	p.r2.quit()

def test_bytes():
	p = get_print()
	assert p.at('entry0').bytes(5) == [85,72,137,229,72]
	p.r2.quit()

def test_disassemble():
	p = get_print()
	assert len(p.at('entry0').disassemble(5)) == 5
	assert p.at('entry0').disassemble(5)[0]['esil'] == 'rbp,8,rsp,-=,rsp,=[8]'
	p.r2.quit()

def test_hash():
	p = get_print()
	assert p.at('entry0').hash('md5', size=1) == '4c614360da93c0a041b22e537de151eb'
	with pytest.raises(ValueError):
		p.at('entry0').hash('foo')
	p.r2.quit()
