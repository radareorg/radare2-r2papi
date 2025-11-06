# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.file import File
from r2papi.iomap import IOMap


@pytest.fixture
def f():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    file = File(r, 3)
    yield file
    file.r2.quit()


def test_writable(f):
    assert f.writable is False
    f.writable = True
    assert f.writable is True


def test_getFilename(f):
    assert f.getFilename() == f"{os.path.dirname(__file__)}/test_bin"
    assert f.filename == f"{os.path.dirname(__file__)}/test_bin"
    assert f.uri == f"{os.path.dirname(__file__)}/test_bin"


def test_getSize():
    # TODO
    pass


def test_getFrom(f):
    assert f.getFrom() == 0
    assert f.offset == 0


def test_iomaps(f):
    iomaps = f.iomaps
    firstmap = f._exec("omj", json=True)[0]
    assert type(iomaps) is list
    assert type(iomaps[0]) is IOMap
    assert iomaps[0].name == firstmap["name"]


def test_close(f):
    f.close()
    assert f.uri is None
    assert f.fd is None
