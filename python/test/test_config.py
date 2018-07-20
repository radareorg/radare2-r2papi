# -*- coding:utf-8 -*-
import pytest

from r2api.config import Config

import r2pipe


def get_config():
    r = r2pipe.open("test_bin")
    return Config(r)


def test_set_variable():
    c = get_config()
    assert c.asm.bits == 64
    c.asm.bits = 32
    assert c.asm.bits == 32
    c.r2.quit()


def test_get_variable_str():
    c = get_config()
    assert c.asm.arch == "x86"
    c.r2.quit()


def test_get_variable_bool():
    c = get_config()
    c._exec("e io.cache = true")
    assert c.io.cache
    c.r2.quit()
