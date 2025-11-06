# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.config import Config


@pytest.fixture
def c():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    c = Config(r)
    yield c
    c.r2.quit()


def test_set_variable(c):
    assert c.asm.bits == 64
    c.asm.bits = 32
    assert c.asm.bits == 32


def test_get_variable_str(c):
    assert c.asm.arch == "x86"


def test_get_variable_bool(c):
    c._exec("e io.cache = true")
    assert c.io.cache
