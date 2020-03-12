# -*- coding:utf-8 -*-
import pytest
import sys
import os
from r2api.r2api import R2Api, Function
from r2api.file import File


def get_r2api():
    return R2Api("test_bin")


def test_quit():
    r = get_r2api()
    r.quit()
    with pytest.raises(AttributeError):
        r._exec("px 1")

def test_context():
    with R2Api("test_bin") as r:
        pass
    with pytest.raises(AttributeError):
        r._exec("px 1")

def test_info():
    r = get_r2api()
    info = r.info()
    # This may change (?)
    assert info.stripped == False
    assert info.endian == "little"
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
    f = r.functionByName("sym._func1")
    assert type(f) == Function
    assert f.name == "sym._func1"
    r.quit()


def test_functionRename():
    r = get_r2api()
    r.analyzeAll()
    f = r.functionByName("sym._func1")
    assert type(f) == Function
    assert f.name == "sym._func1"
    f.name = "foo"
    assert f.name == "foo"
    r.quit()


def test_function():
    r = get_r2api()
    r.analyzeAll()
    r._exec("s sym._func1")
    r._exec("s +1")
    f = r.function()
    assert type(f) == Function
    assert f.name == "sym._func1"

    f = r.at(f.offset + 1).function()
    assert type(f) == Function
    assert f.name == "sym._func1"

    r.quit()


"""
This breaks travis CI
def test_functionGraphImg():
    r = get_r2api()
    r.analyzeAll()
    f = r.functionByName("sym._func1")
    f.graphImg()

    # Make sure the image is created
    expected = 'sym._func1-graph.gif'
    with open(expected, 'r') as _:
        pass
    os.remove(expected)

    custom = 'custom-img-path.gif'
    f.graphImg(custom)
    with open(custom, 'r') as _:
        pass
    os.remove(custom)

    r.quit()
"""


def test_read():
    r = get_r2api()
    r.analyzeAll()
    offset = r.functionByName("entry0").offset
    # Assume x86
    assert r[offset] == b"\x55"
    assert r.at(offset).read(1) == b"\x55"
    r.quit()


def test_writeBytes():
    r = get_r2api()
    r._exec("e io.cache = true")
    r.analyzeAll()
    offset = r.functionByName("entry0").offset
    r[offset] = b"\xff"
    assert r[offset] == b"\xff"
    if sys.version_info[0] == 3:
        # UTF-8 write
        r[offset] = "ñ"
        assert r[offset:offset + 2] == b"\xc3\xb1"
    r.quit()
