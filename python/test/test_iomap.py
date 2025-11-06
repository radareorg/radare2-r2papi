# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.iomap import IOMap


@pytest.fixture
def m():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    return IOMap(r, 1)


def test_name(m):
    m.name = "foo"
    assert type(m.name) is str
    assert m.name == "foo"


def test_flags(m):
    print(m.flags)
    m.flags = "rwx"
    assert m.flags == "rwx"


def test_relocate(m):
    m.addr = 0x100
    assert m.addr == 0x100


def test_remove(m):
    m.remove()
    assert m._mapObj() is None
