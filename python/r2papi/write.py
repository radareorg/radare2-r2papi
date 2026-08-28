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

        return self._exec(f"wx {hex_data}|")

    def hex(self, hex_string):
        return self._exec(f"wx {hex_string}")

    def string(self, string, final_nullbyte=False):
        if final_nullbyte:
            string = string + "\x00"
        return self._exec(self._cmd_arg("w", string))

    def base64(self, string, encode=True):
        subcmd = "w6e" if encode else "w6d"
        return self._exec(f"{subcmd} {string}")

    def assembly(self, asm_str):
        return self._exec(self._cmd_arg("wa", asm_str))

    def random(self, size=0):
        return self._exec(f"wr {size}")

    def nop(self):
        return self._exec("wao nop")
