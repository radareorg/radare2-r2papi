from r2papi.base import R2Base, Result


class EsilCPU(R2Base):
    def __init__(self, r2):
        super().__init__(r2)

    def registers(self):
        return self._exec_quiet("aerj", json=True) or {}

    def readRegister(self, register):
        return int(self._exec(f"aer {register}"), 16)

    def writeRegister(self, register, value):
        self._exec(f"aer {register}={value}")

    def changePC(self, new_pc):
        self._exec(f"aepc {new_pc}")

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

    def __setattr__(self, attr, val):
        if attr in ("r2", "_tmp_off"):
            self.__dict__[attr] = val
        elif attr in self.registers().keys():
            self.writeRegister(attr, val)
        else:
            self.__dict__[attr] = val


class EsilVM(R2Base):
    def __init__(self, r2):
        super().__init__(r2)
        self.cpu = EsilCPU(r2)

        self.contUntilAddr = None
        self.contUntilExpr = None
        self.contUntilSyscall = None

        self.stack_from = None
        self.stack_size = None
        self.stack_name = None

    def init(self, stack_form=0x100000, stack_size=0xF0000, name=""):
        self._exec("aei")
        self._exec("aeip")
        self._exec(f"aeim {stack_form} {stack_size} {name}")
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
            self._exec(f"aecu {untilAddr}")
        elif self.contUntilAddr:
            self._exec(f"aecu {self.contUntilAddr}")
            self.contUntilAddr = None
        elif self.contUntilExpr:
            self._exec(self._cmd_arg("aecue", self.contUntilExpr))
            self.contUntilExpr = None
        elif self.contUntilSyscall:
            self._exec(f"aecs {self.contUntilSyscall}")
            self.contUntilSyscall = None

    def step(self, num=1):
        self._exec(f"{num}aes")

    def stepOver(self):
        self._exec("aeso")

    def stepBack(self):
        # XXX: Not working ?
        self._exec("aesb")

    def emulateInstr(self, num=1, offset=None):
        if offset is None:
            if self._tmp_off:
                # If the temporary seek is a symbol name, resolve it to a
                # numeric address because ``aesp`` does not accept symbols.
                if self._tmp_off.startswith("@ 0x"):
                    offset = self._tmp_off[2:]
                else:
                    offset = self.curr_seek_addr()
            else:
                offset = "$$"
        self._exec(f"aesp {offset} {num}")


class Esil(R2Base):
    def __init__(self, r2):
        super().__init__(r2)
        self.vm = EsilVM(r2)

    def eval(self, esil_str):
        return int(self._exec(self._cmd_arg("ae", esil_str)), 16)

    def regsUsed(self, num_instructions=1):
        res = self._exec(f"aeaj {num_instructions} {self._tmp_off}", json=True)
        return Result(res)
