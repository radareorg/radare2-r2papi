from r2papi.base import R2Base, ResultArray


class CPU(R2Base):
    def __init__(self, r2):
        super().__init__(r2)

    def readRegister(self, reg_name):
        res = self._exec_quiet("drj", json=True)
        if res is None:
            return None
        return res.get(reg_name)

    def writeRegister(self, reg_name, value):
        res = self._exec_quiet(f"dr {reg_name}={value}")
        if res is None or res == "":
            raise ValueError(f"Invalid register {reg_name}")

    def registers(self):
        return self._exec_quiet("drj", json=True) or {}

    def __str__(self):
        regs = self.registers()
        if not regs:
            return ""

        ret_str = ""
        for r, v in regs.items():
            if isinstance(v, int):
                ret_str += f"{r:<10}{v:#016x}\n"
            else:
                ret_str += f"{r:<10}{v}\n"
        return ret_str

    def __getattr__(self, attr):
        if attr in self.registers().keys():
            return self.readRegister(attr)

    def __setattr__(self, attr, value):
        if attr in ("r2", "_tmp_off"):
            self.__dict__[attr] = value
        elif attr in self.registers().keys():
            self.writeRegister(attr, value)
        else:
            self.__dict__[attr] = value


class Debugger(R2Base):
    def __init__(self, r2):
        super().__init__(r2)

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
        self._exec(f"db {addr}")
        self._tmp_off = ""

    def deleteBreakpoint(self, addr=0):
        if self._tmp_off != "":
            # '@ foo' -> 'foo'
            addr = self._tmp_off[2:]
        self._exec(f"db- {addr}")
        self._tmp_off = ""
