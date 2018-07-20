# -*- coding:utf-8 -*-
import pytest
import sys

from r2api.iomap import IOMap
import r2pipe


def get_iomap():
    r = r2pipe.open("test_bin")
    return IOMap(r, 1)


def test_name():
    m = get_iomap()
    m.name = "foo"
    if sys.version_info[0] == 2:
        assert type(m.name) == unicode
    else:
        assert type(m.name) == str
    assert m.name == u"foo"


def test_flags():
    m = get_iomap()
    m.flags = "rwx"
    assert m.flags == u"rwx"


def test_relocate():
    m = get_iomap()
    m.offset = 0x100
    assert m.offset == 0x100
