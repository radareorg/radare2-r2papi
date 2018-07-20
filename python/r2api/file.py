from .utils import r2_is_valid
from .base import R2Base
from .iomap import IOMap


class File(R2Base):

    def __init__(self, r2, fd):
        super(File, self).__init__(r2)

        self.fd = fd

        if not self.fd:
            raise IOError("File not found")

    def _getCurrObject(self):
        files = self._exec("oj", json=True)
        for f in files:
            if f["fd"] == self.fd:
                return f

        return None

    @property
    def writable(self):
        obj = self._getCurrObject()
        return obj["writable"] if obj else None

    @writable.setter
    def writable(self, value):
        if type(value) == bool:
            if value:
                # TODO: this reopens in rw-, so if the file was loaded with
                # r-x we lose the x
                self._exec("oo+ %s" % self.fd)
            else:
                # TODO: How to set -w ?
                pass

    def getFilename(self):
        obj = self._getCurrObject()
        return obj["uri"] if obj else None

    def getSize(self):
        obj = self._getCurrObject()
        return obj["size"] if obj else None

    def getIOMaps(self):
        maps = self._exec("omj", json=True)
        ret_maps = []
        curr_fd = self.fd
        for m in maps:
            if m["fd"] == curr_fd:
                ret_maps.append(IOMap(self.r2, m["map"]))

        return ret_maps

    def getFrom(self):
        obj = self._getCurrObject()
        return obj["from"] if obj else None

    def __getattr__(self, attr):
        if attr == "uri" or attr == "filename":
            return self.getFilename()
        elif attr == "size":
            return self.getSize()
            # Offset instead of from because from is a reserved word
        elif attr == "offset":
            return self.getFrom()
        elif attr == "iomaps" or attr == "IOmaps":
            return self.getIOMaps()

    def close(self):
        self._exec("o-%s" % self.fd)
        self.fd = None
