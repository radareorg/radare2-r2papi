# -*- coding:utf-8 -*-
from __future__ import print_function

import os

import pytest
import r2pipe
from r2papi.write import Write


@pytest.fixture
def w():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    r.cmd("e io.cache=true")
    write = Write(r)
    yield write
    write.r2.quit()


def test_hex(w):
    w.at("entry0").hex("aa")
    assert w._exec("p8 1 @ entry0") == "aa"


def test_string(w):
    w.at("entry0").string("gtfo")
    assert w._exec("ps 4 @ entry0") == "gtfo"
    w.at("0x100").string("AAA", final_nullbyte=True)
    assert w._exec("p8 4 @ 0x100") == "41414100"


def test_bytes(w):
    w.at("entry0").bytes(b"test")
    assert w._exec("p8 4 @ entry0") == "74657374"
    w.at("entry0").bytes("test")
    assert w._exec("p8 4 @ entry0") == "74657374"
    with pytest.raises(TypeError):
        w.at("entry0").bytes(123)


def test_random(w):
    w.at("entry0").random(4)
    assert len(w._exec("p8 4 @ entry0")) == 8


def test_base64(w):
    w.at("entry0").base64("dGVzdA==", encode=False)
    assert w._exec("ps 4 @ entry0") == "test"
    w.at("entry0").base64("test", encode=True)
    assert w._exec("ps 8 @ entry0") == "dGVzdA=="


def test_assemble(w):
    w.at("entry0").assembly("nop")
    assert w._exec("p8 1 @ entry0") == "90"
    w.at("entry0").assembly("nop; nop; nop")
    assert w._exec("p8 3 @ entry0") == "909090"


def test_nop(w):
    w.at("entry0").nop()
    assert w._exec("p8 1 @ entry0") == "90"
