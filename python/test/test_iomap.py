# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.iomap import IOMap


def get_iomap():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    return IOMap(r, 1)


def test_name():
    m = get_iomap()
    m.name = "foo"
    assert type(m.name) == str
    assert m.name == "foo"


def test_flags():
    m = get_iomap()
    print(m.flags)
    m.flags = "rwx"
    assert m.flags == "rwx"


def test_relocate():
    m = get_iomap()
    m.addr = 0x100
    assert m.addr == 0x100


def test_remove():
    m = get_iomap()
    m.remove()
    assert m._mapObj() is None
