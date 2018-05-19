# -*- coding:utf-8 -*-
import pytest

from r2api.flags import Flags

import r2pipe

def get_flags():
	r = r2pipe.open('test_bin')
	return Flags(r)

def test_new():
	f = get_flags()
	f.at(0x100).new('foo')
	assert f.all()[-1].name == 'foo'
	assert f.all()[-1].offset == 0x100
	assert f.all()[-1].size == 1
	f.r2.quit()

def test_delete():
	f = get_flags()
	flag = f.all()[-1]
	f.delete(name=flag.name)
	assert not f.exists(flag.name)

	flag = f.all()[-1]
	f.at(flag.offset).delete()
	assert not f.exists(flag.name)

	f.r2.quit()

def test_rename():
	f = get_flags()
	flag = f.all()[-1]
	f.rename(flag.name, 'foo')
	assert f.all()[-1].name == 'foo'
	f.r2.quit()
