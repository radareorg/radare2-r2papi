from r2papi.base import R2Base


class Write(R2Base):
    def __init__(self, r2):
        super().__init__(r2)

    def reopen(self, mode=""):
        """
        Reopen the file in write/cache mode.
        If mode is "ow", it will overwrite the file i.e, reopen it in 'rw' mode.
        Default is 'cache' mode.
        """
        cmd = "e io.cache=1"
        if mode == "ow":  # overwrite
            cmd = "oo+"
        super()._exec(cmd)

    def bytes(self, buf):
        if isinstance(buf, str):
            # Just use this if you want to write utf-8 data, if not, write
            # bytes object.
            hex_data = buf.encode("utf-8").hex()
        elif isinstance(buf, bytes):
            hex_data = buf.hex()
        else:
            raise TypeError("You must write a string or bytes")

        res = self._exec(f"wx {hex_data}{self._tmp_off}|")
        self._tmp_off = ""
        return res

    def hex(self, hex_string):
        ret = self._exec(f"wx {hex_string}{self._tmp_off}")
        self._tmp_off = ""
        return ret

    def string(self, string, final_nullbyte=False):
        if final_nullbyte:
            string = string + "\x00"
        escaped = self._escaped_string(string)
        ret = self._exec(f'"w {escaped}" {self._tmp_off}')
        self._tmp_off = ""
        return ret

    def _escaped_string(self, string):
        """Escape a string for safe use inside a radare2 `w` command."""
        return "".join(f"\\x{ord(c):02x}" if not (32 <= ord(c) < 127) else c for c in string)

    def base64(self, string, encode=True):
        if encode:
            ret = self._exec(f"w6e {string} {self._tmp_off}")
        else:
            ret = self._exec(f"w6d {string} {self._tmp_off}")
        self._tmp_off = ""
        return ret

    def assembly(self, asm_str):
        ret = self._exec(f'"wa {asm_str}" {self._tmp_off}')
        self._tmp_off = ""
        return ret

    def random(self, size=0):
        ret = self._exec(f"wr {size}{self._tmp_off}")
        self._tmp_off = ""
        return ret

    def nop(self):
        ret = self._exec(f"wao nop {self._tmp_off}")
        self._tmp_off = ""
        return ret
