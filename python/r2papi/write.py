import binascii
import codecs

from r2papi.base import R2Base


class Write(R2Base):
    def __init__(self, r2):
        super().__init__(r2)
    
    def reopen(self, mode = ""):
        """
        Reopen the file in write/cache mode.
        If mode is "ow", it will overwrite the file i.e, reopen it in 'rw' mode.
        Default is 'cache' mode.
        """
        cmd = "e io.cache=1"
        if mode == "ow": # overwrite
            cmd = "oo+"
        super()._exec(cmd)

    def bytes(self, buf):
        if type(buf) == str:
            # Just use this if you want to write utf-8 data, if not, write
            # bytes object.
            res = self._exec(
                "wx %s%s|"
                % (
                    binascii.hexlify(buf.encode("utf-8")).decode("ascii"),
                    self._tmp_off,
                )
            )
        elif type(buf) == bytes:
            res = self._exec(
                "wx %s%s|"
                % (codecs.encode(buf, "hex_codec").decode("ascii"), self._tmp_off)
            )
        else:
            raise TypeError("You must write an string or bytes")

        self._tmp_off = ""
        return res

    def hex(self, hex_string):
        ret = self._exec("wx %s%s" % (hex_string, self._tmp_off))
        self._tmp_off = ""
        return ret

    def string(self, string, final_nullbyte=False):
        if final_nullbyte:
            string = string + "\\x00"
        ret = self._exec('"w %s" %s' % (string, self._tmp_off))
        self._tmp_off = ""
        return ret

    def base64(self, string, encode=True):
        if encode:
            ret = self._exec("w6e %s %s" % (string, self._tmp_off))
        else:
            ret = self._exec("w6d %s %s" % (string, self._tmp_off))
        self._tmp_off = ""
        return ret

    def assembly(self, asm_str):
        ret = self._exec('"wa %s" %s' % (asm_str, self._tmp_off))
        self._tmp_off = ""
        return ret

    def random(self, size=0):
        ret = self._exec("wr %s%s" % (size, self._tmp_off))
        self._tmp_off = ""
        return ret

    def nop(self):
        self._exec("wao nop %s" % (self._tmp_off))
        self._tmp_off = ""
