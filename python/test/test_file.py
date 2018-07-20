# -*- coding:utf-8 -*-
import pytest

from r2api.file import File
from r2api.iomap import IOMap

import r2pipe


def get_file():
    r = r2pipe.open("test_bin")
    return File(r, 3)


def test_writable():
    f = get_file()
    assert f.writable == False
    f.writable = True
    assert f.writable == True
    f.r2.quit()


def test_getFilename():
    f = get_file()
    assert f.getFilename() == "test_bin"
    assert f.filename == "test_bin"
    assert f.uri == "test_bin"


def test_getSize():
    # TODO
    pass


def test_getFrom():
    f = get_file()
    assert f.getFrom() == 0
    assert f.offset == 0


def test_iomaps():
    f = get_file()
    iomaps = f.iomaps
    firstmap = f._exec("omj", json=True)[0]
    assert type(iomaps) == list
    assert type(iomaps[0]) == IOMap
    assert iomaps[0].name == firstmap["name"]


def test_close():
    f = get_file()
    f.close()
    assert f.uri == None
    assert f.fd == None
