# -*- coding:utf-8 -*-
import pytest
import r2pipe
from r2api.base import R2Base, Result


def get_r2base():
    r2 = r2pipe.open("test_bin")
    return R2Base(r2)


def test_exec():
    r = get_r2base()
    ret = r._exec("?e foo")
    assert ret == "foo"
    ret_json = r._exec("pxj 1", json=True)
    assert type(ret_json) == list
    assert len(ret_json) == 1


def test_at():
    r = get_r2base()
    r.at(0x100)
    assert r._tmp_off == "@ 256"
    r.at("main")
    assert r._tmp_off == "@ main"


def test_result():
    o = {"bin": {"foo": "bar"}}
    r = Result(o)
    assert len(str(r).split("\n")) == 1
    o = {"foo": "bar"}
    r = Result(o)
    assert len(str(r).split("\n")) == 1


def test_sym_to_addr():
    r = get_r2base()
    assert r.sym_to_addr("entry0") == 0x100000f20
