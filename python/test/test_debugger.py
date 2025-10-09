# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.debugger import CPU, Debugger


def get_debugger():
    r = r2pipe.open(f"{os.path.dirname(__file__)}/test_exe")
    return Debugger(r)


def test_start_and_cont():
    d = get_debugger()
    assert d.start() == None
    d.untilRet().cont()
    assert d._tmp_off == ""
    d.r2.quit()


def test_until_call_and_ret():
    d = get_debugger()
    d.untilCall()
    d.cont()
    assert not d._untilCall
    d.untilRet()
    d.cont()
    assert not d._untilRet
    d.untilUnknownCall()
    d.cont()
    assert not d._untilUnknownCall
    d.r2.quit()


def test_breakpoint_set_and_delete():
    d = get_debugger()
    d.setBreakpoint(addr=0x1000)
    bps = d.listBreakpoints()
    assert any(bp.addr == 0x1000 for bp in bps)
    d.deleteBreakpoint(addr=0x1000)
    bps = d.listBreakpoints()
    assert not any(bp.addr == 0x1000 for bp in bps)

    d.r2.quit()


def test_breakpoint_using_tmp_off():
    d = get_debugger()
    d.at("main").setBreakpoint()
    bps = d.listBreakpoints()
    assert len(bps) == 1
    assert bps[0].enabled == True
    d.deleteBreakpoint()
    d.r2.quit()


def test_read_register():
    d = get_debugger()
    d.start()
    reg_value = d.cpu.readRegister("rsp")
    assert reg_value is not None
    reg_value = d.cpu.readRegister("invalid_reg")
    assert reg_value is None
    d.r2.quit()


def test_read_register_using_getattr():
    d = get_debugger()
    d.start()
    reg_value = d.cpu.rsp
    assert reg_value is not None
    reg_value = d.cpu.invalid_reg
    assert reg_value is None
    d.r2.quit()


def test_write_register():
    d = get_debugger()
    d.start()
    d.cpu.writeRegister("rsp", 0x12345678)
    reg_value = d.cpu.readRegister("rsp")
    assert reg_value == 0x12345678
    d.r2.quit()


def test_write_register_using_setattr():
    d = get_debugger()
    d.start()
    d.cpu.rsp = 0x12345678
    reg_value = d.cpu.readRegister("rsp")
    assert reg_value == 0x12345678
    d.r2.quit()


def test_cpu_str():
    d = get_debugger()
    d.start()
    reg_str = str(d.cpu)
    assert isinstance(reg_str, str)
    assert len(reg_str) > 0
    assert any(reg in reg_str for reg in d.cpu.registers().keys())
    d.r2.quit()


def test_cpu_str_format():
    d = get_debugger()
    d.start()
    reg_str = str(d.cpu)
    lines = reg_str.split("\n")
    for line in lines:
        if line.strip():
            parts = line.split()
            assert len(parts) == 2, f"Line '{line}' doesn't have exactly two parts"
            reg_name = parts[0]
            reg_value = parts[1]
            assert reg_name in d.cpu.registers().keys(), (
                f"Unknown register '{reg_name}'"
            )
            assert reg_value.startswith("0x"), (
                f"Value '{reg_value}' doesn't start with '0x'"
            )
    d.r2.quit()
