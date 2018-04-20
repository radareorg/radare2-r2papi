# -*- coding:utf-8 -*-
import pytest
import sys
from r2api.r2api import R2Api, Function
from r2api.file import File

def get_r2api():
	return R2Api('test_bin')

def test_quit():
	r = get_r2api()
	r.quit()
	with pytest.raises(AttributeError):
		r._exec('px 1')

def test_info():
	r = get_r2api()
	info = r.info()
	# This may change (?)
	assert info.stripped == False
	assert info.endian == 'little'
	r.quit()

def test_files():
	r = get_r2api()
	files = r.files
	assert len(files) == 1
	assert type(files[0]) == File
	assert files[0].fd == 3
	r.quit()

def test_functions():
	r = get_r2api()
	r.analyzeAll()
	functions = r.functions()
	assert type(functions[0]) == Function
	assert len(functions) == 7
	r.quit()

def test_functionByName():
	r = get_r2api()
	r.analyzeAll()
	f = r.functionByName('sym._func1')[0]
	assert type(f) == Function
	assert f.name == 'sym._func1'
	r.quit()

def test_read():
	r = get_r2api()
	r.analyzeAll()
	offset = r.functionByName('entry0')[0].offset
	# Assume x86
	assert r[offset] == b'\x55'
	assert r.at(offset).read(1) == b'\x55'
	r.quit()

def test_write():
	r = get_r2api()
	print('z')
	r._exec('e io.cache = true')
	r.analyzeAll()
	offset = r.functionByName('entry0')[0].offset
	print('a')
	r[offset] = b'\xff'
	assert r[offset] == b'\xff'
	r.at(offset).write(b'\xee')
	assert r[offset] == b'\xee'
	print('b')
	if sys.version_info[0] == 3:
		# UTF-8 write
		r.at(offset).write('ñ')
		assert r[offset:offset+2] == b'\xc3\xb1'
	r.quit()
