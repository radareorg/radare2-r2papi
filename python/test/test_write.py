# -*- coding:utf-8 -*-
from __future__ import print_function
import pytest

from r2api.write import Write

import r2pipe


def get_write():
    r = r2pipe.open("test_bin")
    r.cmd("e io.cache=true")
    return Write(r)


def test_hex():
    w = get_write()
    w.at("entry0").hex("aa")
    assert w._exec("p8 1 @ entry0") == "aa"
    w.r2.quit()


def test_string():
    w = get_write()
    w.at("entry0").string("gtfo")
    assert w._exec("ps 4 @ entry0") == "gtfo"
    w.at("0x100").string("AAA", final_nullbyte=True)
    assert w._exec("p8 4 @ 0x100") == "41414100"
    w.r2.quit()


# TODO: Base64


def test_assemble():
    w = get_write()
    w.at("entry0").assembly("nop")
    assert w._exec("p8 1 @ entry0") == "90"
    w.at("entry0").assembly("nop; nop; nop")
    assert w._exec("p8 3 @ entry0") == "909090"
    w.r2.quit()


def test_nop():
    w = get_write()
    w.at("entry0").nop()
    assert w._exec("p8 1 @ entry0") == "90"
    w.r2.quit()
