# -*- coding:utf-8 -*-
import os

import pytest
import r2pipe
from r2papi.base import Result
from r2papi.esil import Esil


def get_esil():
    r2 = r2pipe.open(f"{os.path.dirname(__file__)}/test_bin")
    return Esil(r2)


def test_eval():
    e = get_esil()
    assert e.eval("2,3,+") == 5
    e.r2.quit()


def test_vm_init():
    e = get_esil()
    e._exec("s 0x100")
    e.vm.init()
    assert e.vm.cpu.rip == 0x100
    assert e.vm.cpu.rsp == 0x178000
    assert e.vm.cpu.rbp == 0x178000
    assert e.vm.stack_from == 0x100000
    assert e.vm.stack_size == 0xF0000
    assert e.vm.stack_name == ""
    assert len(e._exec("oj", json=True)) == 3
    e.r2.quit()


def test_vm_utilAddr():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.untilAddr(0x100000EDA).cont()
    assert e.vm.cpu.rax == 1
    e.r2.quit()


def test_vm_utilExpr():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.untilExpr("1,rax,=").cont()
    assert e.vm.cpu.rax == 1
    e.r2.quit()


def test_vm_untilSyscall():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.untilSyscall(1).cont()
    assert e.vm.cpu.rax == 1
    e.r2.quit()


def test_vm_step():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.step()
    e.vm.step()
    e.vm.step()
    assert e.vm.cpu.rax == 1
    e.r2.quit()


def test_vm_instr():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.at("sym._func1").emulateInstr(3)
    assert e.vm.cpu.rax == 1
    e.vm.at("0x100000ed0").emulateInstr(3)
    assert e.vm.cpu.rax == 1
    e.vm.emulateInstr(3, "0x100000ed0")
    assert e.vm.cpu.rax == 1
    e.r2.quit()


def test_cpu_get():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    assert e.vm.cpu.rax == 0
    assert e.vm.cpu.rip == 0x100000ED0
    e.r2.quit()


def test_cpu_set():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.cpu.rip = 0x100
    assert e.vm.cpu.rip == 0x100
    e.r2.quit()


def test_vm_stepOver():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.stepOver()
    assert e.vm.cpu.rip == 0x100000ED1
    e.r2.quit()


def test_regs_used():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.step()
    regs = e.regsUsed()
    assert isinstance(regs, Result)
    used = getattr(regs, "_dict", {})
    assert isinstance(used, dict)
    assert len(used) > 0
    e.r2.quit()


def test_change_pc():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.cpu.changePC(0x200)
    assert e.vm.cpu.rip == 0x200
    e.r2.quit()


def test_cpu_str():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    cpu_str = str(e.vm.cpu)
    assert isinstance(cpu_str, str)
    assert "rip" in cpu_str.lower()
    assert "rsp" in cpu_str.lower()
    assert "rax" in cpu_str.lower()

    e.r2.quit()
