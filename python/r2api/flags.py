from .base import R2Base, ResultArray


class Flags(R2Base):

    def __init__(self, r2):
        super(Flags, self).__init__(r2)

    def all(self):
        return ResultArray(self._exec("fj", json=True))

    def exists(self, name):
        self._exec("f?%s" % name)
        res = int(self._exec("??"))
        return res == 1

    def new(self, name, offset=None):
        if offset is None:
            offset = self._tmp_off
        self._exec("f %s %s" % (name, offset))
        self._tmp_off = ""

    def delete(self, name="", offset=None):
        if offset is None:
            offset = self._tmp_off
        self._exec("f-%s%s" % (name, offset))
        self._tmp_off = ""

    def rename(self, old, new=""):
        self._exec("fr %s %s %s" % (old, new, self._tmp_off))
        self._tmp_off = ""
