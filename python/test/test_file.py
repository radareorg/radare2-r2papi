# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.file import File
from r2papi.iomap import IOMap


def get_file():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    return File(r, 3)


def test_writable():
    f = get_file()
    assert f.writable == False
    f.writable = True
    assert f.writable == True
    f.r2.quit()


def test_getFilename():
    f = get_file()
    assert f.getFilename() == f"{os.path.dirname(__file__)}/test_bin"
    assert f.filename == f"{os.path.dirname(__file__)}/test_bin"
    assert f.uri == f"{os.path.dirname(__file__)}/test_bin"


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
