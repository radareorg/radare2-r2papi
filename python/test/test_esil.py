# -*- coding:utf-8 -*-
import pytest
import r2pipe
from r2api.esil import Esil


def get_esil():
    r2 = r2pipe.open("test_bin")
    return Esil(r2)


def test_eval():
    e = get_esil()
    assert e.eval("2,3,+") == 5
    e.r2.quit()


# TODO: regsUsed


def test_vm_init():
    e = get_esil()
    e._exec("s 0x100")
    e.vm.init()
    assert e.vm.cpu.rip == 0x100
    assert e.vm.cpu.rsp == 0x178000
    assert e.vm.cpu.rbp == 0x178000
    assert e.vm.stack_from == 0x100000
    assert e.vm.stack_size == 0xf0000
    assert e.vm.stack_name == ""
    assert len(e._exec("oj", json=True)) == 2
    e.r2.quit()


def test_vm_utilAddr():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.untilAddr(0x100000eda).cont()
    assert e.vm.cpu.rax == 1
    e.r2.quit()


# TODO: test untilSyscall


def test_vm_utilExpr():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.untilExpr("1,rax,=").cont()
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
    e.r2.quit()


def test_cpu_get():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    assert e.vm.cpu.rax == 0
    assert e.vm.cpu.rip == 0x100000ed0
    e.r2.quit()


def test_cpu_set():
    e = get_esil()
    e._exec("s sym._func1")
    e.vm.init()
    e.vm.cpu.rip = 0x100
    assert e.vm.cpu.rip == 0x100
    e.r2.quit()
