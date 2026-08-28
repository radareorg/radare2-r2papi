from r2papi.base import R2Base, ResultArray


class Flags(R2Base):
    def __init__(self, r2):
        super().__init__(r2)

    def all(self):
        return ResultArray(self._exec("fj", json=True))

    def exists(self, name):
        flags = self._exec("fj", json=True) or []
        return any(f.get("name") == name for f in flags)

    def new(self, name, offset=None):
        if offset is None:
            offset = self.curr_seek_addr()
        else:
            self._tmp_off = ""
        self._exec(f"f {name} @ {offset}")

    def delete(self, name="", offset=None):
        if offset is not None:
            self._exec(f"f-{name}@{offset}")
        elif name:
            self._exec(f"f-{name}")
        elif self._tmp_off:
            self._exec(f"f-{self._tmp_off}")

    def rename(self, old, new=""):
        self._exec(f"fr {old} {new} {self._tmp_off}")
