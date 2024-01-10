from .base import R2Base


class IOMap(R2Base):

    def __init__(self, r2, mapNum):
        super(IOMap, self).__init__(r2)
        self.num = mapNum

    def _mapObj(self):
        maps = self._exec("omj", json=True)
        for m in maps:
            if m["map"] == self.num:
                return m
        return None

    def setName(self, name):
        return self._exec("omni %s %s" % (self.num, name))

    def setFlags(self, flags):
        return self._exec("omf %s %s" % (self.num, flags))

    def relocateTo(self, addr):
        return self._exec("omb %s %s" % (self.num, addr))

    def remove(self):
        return self._exec("om-%s" % self.num)

    def __getattr__(self, attr):
        obj = self._mapObj()
        # Using IOMap.form will cause a syntax error, se we use IOMap.offset
        attr = "from" if attr == "offset" else attr
        # Flags are now called "perm"
        attr = "perm" if attr == "flags" else attr
        if attr in self._mapObj().keys():
            return obj[attr] if obj else None

    def __setattr__(self, attr, value):
        if attr == "name":
            self.setName(value)
        elif attr == "flags":
            if type(value) == str and len(value) <= 3:
                self.setFlags(value)
        elif attr == "offset":
            self.relocateTo(value)
        else:
            self.__dict__[attr] = value
