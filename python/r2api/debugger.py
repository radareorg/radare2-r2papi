import sys
from .base import R2Base, Result, ResultArray

PYTHON_VERSION = sys.version_info[0]


class CPU(R2Base):

    def __init__(self, r2):
        super(CPU, self).__init__(r2)

    def readRegister(self, reg_name):
        res = self._exec("drj", json=True)
        try:
            return res[reg_name]
        except:
            return None

    def writeRegister(self, reg_name, value):
        res = self._exec("dr %s=%s" % (reg_name, value))
        if res == "":
            raise ValueError("Ivalid register %s" % reg_name)

    def registers(self):
        return self._exec("drj", json=True)

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

    def __setattr__(self, attr, value):
        if attr == "r2":
            # Hack to avoid infite recursion, maybe there's a better solution
            self.__dict__[attr] = value
        else:
            if attr in self.registers().keys():
                self.writeRegister(attr, value)
            else:
                self.__dict__[attr] = value


class Debugger(R2Base):

    def __init__(self, r2):
        super(Debugger, self).__init__(r2)

        self.cpu = CPU(r2)

        self._untilCall = False
        self._untilUnknownCall = False
        self._untilRet = False

        self.listBreakpoints = lambda: ResultArray(self._exec("dbj", json=True))
        self.step = lambda: self._exec("ds")
        self.memoryMaps = lambda: ResultArray(self._exec("dmj", json=True))
        self.backtrace = lambda: self._exec("dbtj", json=True)

    def start(self):
        self._exec("doo")

    def cont(self):
        if self._untilCall:
            self._exec("dcc")
        elif self._untilUnknownCall:
            self._exec("dccu")
        elif self._untilRet:
            self._exec("dcr")
        else:
            self._exec("dc")
        self._untilCall = False
        self._untilRet = False
        self._untilUnknownCall = False

    def untilCall(self):
        self._untilCall = True
        return self

    def untilRet(self):
        self._untilRet = True
        return self

    def untilUnknownCall(self):
        self._untilUnknownCall = True
        return self

    def setBreakpoint(self, addr=0):
        if self._tmp_off != "":
            # '@ foo' -> 'foo'
            addr = self._tmp_off[2:]
        self._exec("db %s" % addr)
        self._tmp_off = ""

    def deleteBreakpoint(self, addr=0):
        if self._tmp_off != "":
            # '@ foo' -> 'foo'
            addr = self._tmp_off[2:]
        self._exec("db- %s" % addr)
        self._tmp_off = ""
