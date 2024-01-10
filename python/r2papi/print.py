import sys
from .base import R2Base, ResultArray

PYTHON_VERSION = sys.version_info[0]


class Print(R2Base):
    """
    Class that represents the ``p`` command in radare2. It's used to read
    information.
    """

    def __init__(self, r2):
        super(Print, self).__init__(r2)
        self.hash_types = self._exec("ph").split()

    def byte(self):
        """
        Returns:
            int: One byte at current (or temporal) offset.
        """
        return self.bytes(1, asList=True)[0]

    def bytes(self, size=0, asList=False):
        """
        Args:
            size (int, optional):
                Number of bytes to return.
            asList (bool, optional):
                If True, a list is returned containing a byte on each element.
                If False, a bytes (python3) or str (python2) object is returned.

        Returns:
            bytes | str | list: Bytes object in python3, `str` in python2. If
            asList is set to true, a list of integers is returned.
        """
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

    def string(self):
        """
        Returns:
            str: Zero terminated string at current seek. Seek can be temporary
            changed with the :meth:`r2api.r2api.R2Api.at` method.
        """
        # [:-1] to remove newline, probably r2pipe should be changed
        res = self._exec("psz %s" % self._tmp_off, rstrip=False)[:-1]
        self._tmp_off = ""
        return res

    def bits(self, size=0):
        """
        Args:
            size (int, optional):
                Number of bits to be returned. If it's 0, the default block size
                will be returned.
        Returns:
            str: Specified number of bits from current (or temporary) offset.
        """
        size = "" if size == 0 else size
        ret = self._exec("pb %s%s" % (size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def disassemble(self, size=0):
        """
        Args:
            size (int, optional):
                Number of instructions to be returned. If it's 0, the default
                block size will be returned.
        Returns:
            list: List of :class:`r2api.base.Result` with the specified number
            of instructions from current (or temporary) offset.
        """
        size = "" if size == 0 else size
        ret = self._exec("pdj %s%s" % (size, self._tmp_off), json=True)
        self._tmp_off = ""
        return ResultArray(ret)

    def disasmBytes(self, size=0):
        """
        Args:
            size (int, optional):
                Number of bytes to be decoded into instructions. If it's 0, the
                default block size will be used.
        Returns:
            list: List of :class:`r2api.base.Result` containing the
            instructions.
        """
        size = "" if size == 0 else size
        ret = self._exec("pDj %s%s" % (size, self._tmp_off), json=True)
        self._tmp_off = ""
        return ResultArray(ret)

    def hexdump(self, size=0):
        """
        Args:
            size (int, optional):
                Number of bytes to be decoded as hexdump.
        Returns:
            str: Hexdump of ``size`` bytes as string.
        """
        size = "" if size == 0 else size
        ret = self._exec("p8 %s%s" % (size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def hash(self, h_type, size=0):
        """
        .. todo::

            Docs
        """
        if h_type not in self.hash_types:
            raise ValueError("Hash function not supported")
        size = "" if size == 0 else size
        ret = self._exec("ph %s %s%s" % (h_type, size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def debruijn(self, size=0):
        """
        Args:
            size (int, optional):
                Number of bytes from de Bruijn sequence to return.
        Returns:
            str: de Bruijn sequence as hexdump.
        """
        size = "" if size==0 else size
        ret = self._exec("ppd %s" % size)
        self._tmp_off = ""
        return ret

    @property
    def pwd(self):
        """
        Returns:
            str: Path working directory
        """
        return self._exec("pwd")
