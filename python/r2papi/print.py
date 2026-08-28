from r2papi.base import R2Base, ResultArray


class Print(R2Base):
    """
    Class that represents the ``p`` command in radare2. It's used to read
    information.
    """

    def __init__(self, r2):
        super().__init__(r2)
        self.hash_types = self._exec("ph").split()

    def byte(self, *, as_list=False):
        """
        Returns:
            int: One byte at current (or temporal) offset.
        """
        return self.bytes(1, as_list=as_list)[0]

    def bytes(self, size=0, as_list=False, asList=None):
        """
        Args:
            size (int, optional):
                Number of bytes to return.
            as_list (bool, optional):
                If True, a list is returned containing a byte on each element.
                If False, a bytes object is returned.

        Returns:
            bytes | list: Bytes object. If as_list is set to true, a list of
            integers is returned.
        """
        if asList is not None:
            as_list = asList
        size_str = "" if size == 0 else str(size)
        if as_list:
            ret = self._exec(f"p8j {size_str}{self._tmp_off}", json=True)
        else:
            ret = self._exec(f"p8 {size_str}{self._tmp_off}")
            ret = bytes.fromhex(ret)
        self._tmp_off = ""
        return ret

    def string(self):
        """
        Returns:
            str: Zero terminated string at current seek. Seek can be temporary
            changed with the :meth:`r2api.r2api.R2Api.at` method.
        """
        res = self._exec(f"psz {self._tmp_off}", rstrip=True)
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
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"pb {size_str}{self._tmp_off}")
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
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"pdj {size_str}{self._tmp_off}", json=True)
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
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"pDj {size_str}{self._tmp_off}", json=True)
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
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"p8 {size_str}{self._tmp_off}")
        self._tmp_off = ""
        return ret

    def hash(self, h_type, size=0):
        """
        .. todo::

            Docs
        """
        if h_type not in self.hash_types:
            raise ValueError("Hash function not supported")
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"ph {h_type} {size_str}{self._tmp_off}")
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
        size_str = "" if size == 0 else str(size)
        ret = self._exec(f"ppd {size_str}")
        self._tmp_off = ""
        return ret

    @property
    def pwd(self):
        """
        Returns:
            str: Path working directory
        """
        return self._exec("pwd")
