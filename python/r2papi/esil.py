from .base import R2Base, Result
import sys

PYTHON_VERSION = sys.version_info[0]


class EsilCPU(R2Base):

    def __init_(self, r2):
        super(CPU, self).__init__(r2)

    def registers(self):
        return self._exec("aerj", json=True)

    def readRegister(self, register):
        return int(self._exec("aer %s" % register), 16)

    def writeRegister(self, register, value):
        self._exec("aer %s=%s" % (register, value))

    def changePC(self, new_pc):
        self._exec("aepc %s" % new_pc)

    def __str__(self):
        regs = self.registers()
        if PYTHON_VERSION == 3:
            items = regs.items()
        else:
            items = regs.iteritems()

        ret_str = ""
        for r, v in items:
            ret_str += "{:<10}{:#016x}\n".format(r, v)
        return ret_str

    def __getattr__(self, attr):
        if attr in self.registers().keys():
            return self.readRegister(attr)

    def __setattr__(self, attr, val):
        if attr == "r2":
            # Hack to avoid infite recursion, maybe there's a better solution
            self.__dict__[attr] = val
        elif attr in self.registers().keys():
            self.writeRegister(attr, val)


class EsilVM(R2Base):

    def __init__(self, r2):
        super(EsilVM, self).__init__(r2)
        self.cpu = EsilCPU(r2)

        self.contUntilAddr = None
        self.contUntilExpr = None
        self.contUntilSyscall = None

        self.stack_from = None
        self.stack_size = None
        self.stack_name = None

    def init(self, stack_form=0x100000, stack_size=0xf0000, name=""):
        self._exec("aei")
        self._exec("aeip")
        self._exec("aeim %s %s %s" % (stack_form, stack_size, name))
        self.stack_from = stack_form
        self.stack_size = stack_size
        self.stack_name = name

    def untilAddr(self, addr):
        self.contUntilAddr = addr
        return self

    def untilExpr(self, esil_expr):
        self.contUntilExpr = esil_expr
        return self

    def untilSyscall(self, syscall_num):
        self.contUntilSyscall = syscall_num
        return self

    def cont(self, untilAddr=None):
        if untilAddr:
            self._exec("aecu %s" % (untilAddr))
        elif self.contUntilAddr:
            self._exec("aecu %s" % (self.contUntilAddr))
            self.contUntilAddr = None
        elif self.contUntilExpr:
            self._exec("aecue %s" % self.contUntilExpr)
            self.contUntilExpr = None
        elif self.contUntilSyscall:
            self._exec("aecs %s" % self.contUntilSyscall)
            self.contUntilSyscall = None

    def step(self, num=1):
        self._exec("%daes" % num)

    def stepOver(self):
        self._exec("aeso")

    def stepBack(self):
        # XXX: Not working ?
        self._exec("aesb")

    def emulateInstr(self, num=1, offset=None):
        if offset is None:
            if self._tmp_off == "":
                # Remove '@ '
                offset = self._tmp_off[2:]
            else:
                # XXX: Check if this is correct
                offset = "$$"
        self._exec("aesp %s %s" % (offset, num))


class Esil(R2Base):

    def __init__(self, r2):
        super(Esil, self).__init__(r2)
        self.vm = EsilVM(r2)

    def eval(self, esil_str):
        return int(self._exec('"ae %s"' % esil_str), 16)

    def regsUsed(self, num_instructions=1):
        res = self._exec("aeaj %d %s" % (num_instructions, self._tmp_off), json=True)
        self._tmp_off = ""
        return Result(res)
