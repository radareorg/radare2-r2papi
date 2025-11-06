# -*- coding:utf-8 -*-
import os
import sys

import pytest
from r2papi.file import File
from r2papi.r2api import Function, R2Api


@pytest.fixture
def r():
    r = R2Api(f"{os.path.dirname(__file__)}/test_bin")
    yield r
    r.quit()


def test_quit(r):
    r.quit()
    with pytest.raises(AttributeError):
        r._exec("px 1")


def test_context():
    with R2Api(f"{os.path.dirname(__file__)}/test_bin") as r:
        pass
    with pytest.raises(AttributeError):
        r._exec("px 1")


def test_info(r):
    info = r.info()
    # This may change (?)
    assert info.stripped is False
    assert info.endian == "little"


def test_files(r):
    files = r.files
    print(files)
    assert len(files) == 2
    assert type(files[0]) is File
    assert files[0].fd == 3


def test_functions(r):
    r.analyzeAll()
    functions = r.functions()
    assert type(functions[0]) is Function
    assert len(functions) == 7


def test_functionByName(r):
    r.analyzeAll()
    f = r.functionByName("sym._func1")
    assert type(f) is Function
    assert f.name == "sym._func1"


def test_functionRename(r):
    r.analyzeAll()
    f = r.functionByName("sym._func1")
    assert type(f) is Function
    assert f.name == "sym._func1"
    f.name = "foo"
    assert f.name == "foo"


def test_function(r):
    r.analyzeAll()
    r._exec("s sym._func1")
    r._exec("s +1")
    f = r.function()
    assert type(f) is Function
    assert f.name == "sym._func1"

    f = r.at(f.offset + 1).function()
    assert type(f) is Function
    assert f.name == "sym._func1"
    f.analyze()


def test_functionGraphImg(r):
    r.analyzeAll()
    f = r.functionByName("sym._func1")

    try:
        f.graphImg()
        # Make sure the image is created
        expected = "sym._func1-graph.gif"
        with open(expected, "r") as _:
            pass
        os.remove(expected)

        custom = "custom-img-path.gif"
        f.graphImg(custom)
        with open(custom, "r") as _:
            pass
        os.remove(custom)
    except Exception:
        # Graphviz may not be installed
        print("Skipping graph image tests")


def test_read(r):
    r.analyzeAll()
    offset = r.functionByName("main").offset
    # Assume x86
    assert r[offset] == b"\x55"
    assert r.at(offset).read(1) == b"\x55"


def test_writeBytes(r):
    r._exec("e io.cache = true")
    r.analyzeAll()
    offset = r.functionByName("main").offset
    r[offset] = b"\xff"
    assert r[offset] == b"\xff"
    if sys.version_info[0] == 3:
        # UTF-8 write
        r[offset] = "ñ"
        assert r[offset : offset + 2] == b"\xc3\xb1"
