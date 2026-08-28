# -*- coding:utf-8 -*-
import os

import r2pipe
import pytest

from r2papi.debugger import Debugger


@pytest.fixture
def d():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_exe")
    dbg = Debugger(r)
    yield dbg
    dbg.r2.quit()


def test_start_and_cont(d):
    assert d.start() is None
    d.untilRet().cont()
    assert d._tmp_off == ""


def test_until_call_and_ret(d):
    d.untilCall()
    d.cont()
    assert not d._untilCall
    d.untilRet()
    d.cont()
    assert not d._untilRet
    d.untilUnknownCall()
    d.cont()
    assert not d._untilUnknownCall


def test_breakpoint_set_and_delete(d):
    d.setBreakpoint(addr=0x1000)
    bps = d.listBreakpoints()
    assert any(bp.addr == 0x1000 for bp in bps)
    d.deleteBreakpoint(addr=0x1000)
    bps = d.listBreakpoints()
    assert not any(bp.addr == 0x1000 for bp in bps)


def test_breakpoint_using_tmp_off(d):
    d.at("main").setBreakpoint()
    bps = d.listBreakpoints()
    assert len(bps) == 1
    assert bps[0].enabled is True
    d.deleteBreakpoint()


def test_read_register(d):
    d.start()
    # The test binary is arm64, use the stack pointer register name for that arch.
    sp_name = "sp"
    reg_value = d.cpu.readRegister(sp_name)
    if reg_value is None:
        pytest.skip("Debugger cannot attach on this platform")
    reg_value = d.cpu.readRegister("invalid_reg")
    assert reg_value is None


def test_read_register_using_getattr(d):
    d.start()
    sp_name = "sp"
    reg_value = getattr(d.cpu, sp_name)
    if reg_value is None:
        pytest.skip("Debugger cannot attach on this platform")
    reg_value = d.cpu.invalid_reg
    assert reg_value is None


def test_write_register(d):
    d.start()
    sp_name = "sp"
    d.cpu.writeRegister(sp_name, 0x12345678)
    reg_value = d.cpu.readRegister(sp_name)
    if reg_value is None:
        pytest.skip("Debugger cannot attach on this platform")
    assert reg_value == 0x12345678


def test_write_register_using_setattr(d):
    d.start()
    sp_name = "sp"
    setattr(d.cpu, sp_name, 0x12345678)
    reg_value = d.cpu.readRegister(sp_name)
    if reg_value is None:
        pytest.skip("Debugger cannot attach on this platform")
    assert reg_value == 0x12345678


def test_cpu_str(d):
    d.start()
    reg_str = str(d.cpu)
    assert isinstance(reg_str, str)
    if not reg_str:
        pytest.skip("Debugger cannot attach on this platform")
    assert any(reg in reg_str for reg in d.cpu.registers().keys())


def test_cpu_str_format(d):
    d.start()
    reg_str = str(d.cpu)
    if not reg_str:
        pytest.skip("Debugger cannot attach on this platform")
    lines = reg_str.split("\n")
    for line in lines:
        if line.strip():
            parts = line.split()
            assert len(parts) == 2, f"Line '{line}' doesn't have exactly two parts"
            reg_name = parts[0]
            reg_value = parts[1]
            assert (
                reg_name in d.cpu.registers().keys()
            ), f"Unknown register '{reg_name}'"
            assert reg_value.startswith(
                "0x"
            ), f"Value '{reg_value}' doesn't start with '0x'"
