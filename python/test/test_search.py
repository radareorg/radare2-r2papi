# -*- coding:utf-8 -*-
from __future__ import print_function

import os
import sys

import pytest
import r2pipe
from r2papi.search import Search
from r2papi.write import Write

PYTHON_VERSION = sys.version_info[0]


def get_search():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    return Search(r)


def _writer(search_obj):
    return Write(search_obj.r2)


def test_string_and_json():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("666f6f00")
    assert "foo" in s.at(0x200).string("foo")
    json_res = s.at(0x200).string_json("foo")
    assert isinstance(json_res, list)
    assert "foo" in json_res[0].data
    s.r2.quit()


def test_inverse_searches():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("000000ff")
    res = s.at(0x300).inverse_hex("00")
    assert isinstance(res, list)
    assert "11" in res[0].data
    s.r2.quit()


def test_base_and_deltified():
    s = get_search()
    assert isinstance(s.base_address(), str)
    assert s.base_address() == "0x08000000"
    w = _writer(search_obj=s)
    w.reopen()
    w.hex("10111213")
    res = s.at(0x400).deltified("010101")
    assert isinstance(res, list)
    assert "10111213" in res[0].data
    s.r2.quit()


def test_file_search(tmp_path):
    s = get_search()
    w = _writer(s)
    w.reopen()

    file_content = b"deadbeef"
    tmp_file = tmp_path / "search.bin"
    tmp_file.write_bytes(file_content)

    jes = s.file(str(tmp_file), int(0x00000000), 2)
    assert isinstance(jes, list)
    jes[0].data == "6465"
    jes[1].data == "6465"
    jes[2].data == "6465"
    s.r2.quit()


def test_case_insensitive_and_rabin_karp():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("466F4F00")
    res = s.at(0x700).case_insensitive("foo")
    assert isinstance(res, list)
    assert "FoO" in res[0].data
    res = s.at(0x700).rabin_karp("FoO")
    assert isinstance(res, list)
    assert "FoO" in res[0].data
    s.r2.quit()


def test_entropy():
    s = get_search()

    result_no_thr = s.entropy()
    assert isinstance(result_no_thr, list), "entropy() must return ResultArray"
    for entry in result_no_thr:
        assert "start" in entry, "missing start address"
        assert "end" in entry, "missing end address"
        assert "entropy" in entry, "missing entropy value"
        assert isinstance(entry["start"], int), "start should be int"
        assert isinstance(entry["end"], int), "end should be int"
        assert isinstance(entry["entropy"], float), "entropy should be float"

    result_thr = s.entropy(5)
    assert isinstance(result_thr, list), "entropy(5) must return ResultArray"
    for entry in result_thr:
        assert "start" in entry
        assert "end" in entry
        assert "entropy" in entry

    s.r2.quit()


def test_wide_string_plain():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("620061007200")
    assert s.at(0x800).wide_string("bar")[0].data == "620061007200"
    assert s.at(0x800).wide_string_ci("BaR")[0].data == "620061007200"
    s.r2.quit()


def test_wide_string_json():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("620061007200")
    res = s.at(0x800).wide_string_json("bar")
    assert len(res) == 1
    assert res[0]["type"] == "hexpair"
    assert res[0]["data"] == "620061007200"
    s.r2.quit()


def test_wide_string_ci_json():
    s = get_search()
    w = _writer(s)
    w.reopen()
    w.hex("620061007200")
    res = s.at(0x800).wide_string_ci_json("BAR")
    assert len(res) == 1
    assert res[0]["type"] == "hexpair"
    assert res[0]["data"] == "620061007200"
    s.r2.quit()


def test_size_range():
    s = get_search()
    res = s.size_range(5, 5)
    assert isinstance(res, list)
    assert len(res) == 7
    assert "guard" in res[0].data
    s.r2.quit()
