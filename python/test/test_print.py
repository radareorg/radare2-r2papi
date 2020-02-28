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
    assert p.at("entry0").disasmBytes(1)[0].type == "rpush"
    assert p.at("entry0").disasmBytes(2)[1].type == "invalid"


def test_hexdump():
    p = get_print()
    assert p.at("entry0").hexdump(2) == "5548"


def test_debruijn():
    p = get_print()
    assert p.debruijn() == "4141414241414341414441414541414641414741414841414941414a41414b41414c41414d41414e41414f41415041415141415241415341415441415541415641415741415841415941415a41416141416241416341416441416541416641416741416841416941416a41416b41416c41416d41416e41416f41417041417141417241417341417441417541417641417741417841417941417a41413141413241413341413441413541413641413741413841413941413041424241424341424441424541424641424741424841424941424a41424b41424c41424d41424e41424f414250414251414252414253414254414255414256414257414258414259"
    assert p.debruijn(16) == "41414142414143414144414145414146"

    # Make sure it clear temporary offset
    p.at("foo").debruijn()
    assert p._tmp_off == ""


def test_hash():
    p = get_print()
    assert p.at("entry0").hash("md5", size=1) == "4c614360da93c0a041b22e537de151eb"
    with pytest.raises(ValueError):
        p.at("entry0").hash("foo")
    p.r2.quit()
