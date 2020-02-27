import sys
from .base import R2Base, ResultArray

PYTHON_VERSION = sys.version_info[0]


class Print(R2Base):

    def __init__(self, r2):
        super(Print, self).__init__(r2)
        self.hash_types = self._exec("ph").split()

    def byte(self):
        return self.bytes(1, asList=True)[0]

    def bytes(self, size=0, asList=False):
        size = "" if size == 0 else size
        if asList:
            ret = self._exec("p8j %s%s" % (size, self._tmp_off), json=True)
        else:
            ret = self._exec("p8 %s%s" % (size, self._tmp_off))
            if PYTHON_VERSION == 3:
                ret = bytes.fromhex(ret)
            else:
                ret = ret.decode("hex")
        self._tmp_off = ""
        return ret

    def string(self, offset=""):
        if offset == "":
            if self._tmp_off != "":
                offset = self._tmp_off
        else:
            offset = "@ %s" % offset
        # [:-1] to remove newline, probably r2pipe should be changed
        res = self._exec("psz %s" % offset, rstrip=False)[:-1]
        self._tmp_off = ""
        return res

    def bits(self, size=0):
        size = "" if size == 0 else size
        ret = self._exec("pb %s%s" % (size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def disassemble(self, size=0):
        size = "" if size == 0 else size
        ret = self._exec("pdj %s%s" % (size, self._tmp_off), json=True)
        self._tmp_off = ""
        return ResultArray(ret)

    def disasmBytes(self, size=0):
        size = "" if size == 0 else size
        ret = self._exec("pDj %s%s" % (size, self._tmp_off), json=True)
        self._tmp_off = ""
        return ResultArray(ret)

    def hexdump(self, size=0):
        size = "" if size == 0 else size
        ret = self._exec("p8 %s%s" % (size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def hash(self, h_type, size=0):
        if h_type not in self.hash_types:
            raise ValueError("Hash function not supported")
        size = "" if size == 0 else size
        ret = self._exec("ph %s %s%s" % (h_type, size, self._tmp_off))
        self._tmp_off = ""
        return ret

    @property
    def pwd(self):
        return self._exec("pwd")
