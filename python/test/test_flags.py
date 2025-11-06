# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.flags import Flags


@pytest.fixture
def f():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    flags = Flags(r)
    yield flags
    flags.r2.quit()


def get_flag_from_offset(flags, offset):
    for f in flags:
        if f.addr == offset:
            return f
    raise ValueError("Flag not found")


def test_new(f):
    f.at(0x100).delete()
    f.at(0x100).new("foo")
    nflag = get_flag_from_offset(f.all(), 0x100)
    assert nflag.name == "foo"
    assert nflag.addr == 0x100
    assert nflag.size == 1


def test_delete(f):
    flag = f.all()[-1]
    f.delete(name=flag.name)
    assert not f.exists(flag.name)

    flag = f.all()[-1]
    f.at(flag.addr).delete()
    assert not f.exists(flag.name)


def test_rename(f):
    flag = f.all()[-1]
    f.rename(flag.name, "foo")
    assert f.all()[-1].name == "foo"
