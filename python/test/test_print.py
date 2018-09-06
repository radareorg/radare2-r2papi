# -*- coding:utf-8 -*-
from __future__ import print_function
import sys
import pytest

from r2api.print import Print

import r2pipe

PYTHON_VERSION = sys.version_info[0]


def get_print():
    r = r2pipe.open("test_bin")
    return Print(r)


def test_byte():
    p = get_print()
    assert p.at("entry0").byte() == 0x55
    p.r2.quit()


def test_bytes():
    p = get_print()
    assert p.at("entry0").bytes(5, asList=True) == [85, 72, 137, 229, 72]
    if PYTHON_VERSION == 3:
        assert p.at("entry0").bytes(5) == b"UH\x89\xe5H"
    else:
        assert p.at("entry0").bytes(5) == "UH\x89\xe5H"
    p.r2.quit()


def test_string():
    p = get_print()
    p._exec("e io.cache=1")
    p._exec("wx 4141410000 @ 0x100")
    assert p.at(0x100).string() == "AAA"
    p.r2.quit()


def test_bits():
    p = get_print()
    p._exec("e io.cache=1")
    p._exec("wx 4141410000 @ 0x100")
    assert p.at(0x100).bits(8) == "01000001"
    p.r2.quit()


def test_disassemble():
    p = get_print()
    assert len(p.at("entry0").disassemble(5)) == 5
    assert p.at("entry0").disassemble(5)[0].esil == "rbp,8,rsp,-,=[8],8,rsp,-="
    p.r2.quit()


def test_disasmBytes():
    p = get_print()
    assert len(p.at("entry0").disasmBytes(2)) == 2
    assert p.at("entry0").disasmBytes(1)[0].type == "upush"
    assert p.at("entry0").disasmBytes(2)[1].type == "invalid"


def test_hexdump():
    p = get_print()
    assert p.at("entry0").hexdump(2) == "5548"


def test_hash():
    p = get_print()
    assert p.at("entry0").hash("md5", size=1) == "4c614360da93c0a041b22e537de151eb"
    with pytest.raises(ValueError):
        p.at("entry0").hash("foo")
    p.r2.quit()
