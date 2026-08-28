from r2papi.base import R2Base


class IOMap(R2Base):
    def __init__(self, r2, mapNum):
        super().__init__(r2)
        self.num = mapNum

    def _mapObj(self):
        maps = self._exec("omj", json=True)
        for m in maps:
            if m["map"] == self.num:
                return m
        return None

    def setName(self, name):
        return self._exec(self._cmd_arg("omni", f"{self.num} {name}"))

    def setFlags(self, flags):
        """Change the user (perm) permissions of this map."""
        if not isinstance(flags, str) or len(flags) > 3:
            raise ValueError("flags must be a permission string like 'rwx'")
        self._exec(f"omp {self.num} {flags}")
        return self

    def relocateTo(self, addr):
        return self._exec(f"omv {self.num} {addr}")

    def remove(self):
        return self._exec(f"om-{self.num}")

    @property
    def flags(self):
        obj = self._mapObj()
        if obj is None:
            return None
        # radare2 stores the effective permission in `perm` and the
        # requested/suggested permission in `sperm`.  `omp` updates `sperm`,
        # but `omj` returns both; expose the requested one because that is
        # what callers set with this property.
        return obj.get("sperm") if "sperm" in obj else obj.get("perm")

    @flags.setter
    def flags(self, value):
        if isinstance(value, str) and len(value) <= 3:
            self.setFlags(value)

    def __getattr__(self, attr):
        obj = self._mapObj()
        if obj is None:
            return None
        # Using IOMap.form will cause a syntax error, so we use IOMap.offset
        attr = "from" if attr == "addr" else attr

        if attr in obj:
            return obj[attr]
        return None

    def __setattr__(self, attr, value):
        if attr in ("r2", "_tmp_off", "num"):
            self.__dict__[attr] = value
        elif attr == "name":
            self.setName(value)
        elif attr == "flags":
            if isinstance(value, str) and len(value) <= 3:
                self.setFlags(value)
        elif attr == "addr":
            self.relocateTo(value)
        else:
            self.__dict__[attr] = value
