import sys
import codecs
import binascii
from .base import R2Base

PYTHON_VERSION = sys.version_info[0]


class Write(R2Base):

    def __init__(self, r2):
        super(Write, self).__init__(r2)

    def bytes(self, buf):
        if PYTHON_VERSION == 3:
            # Fuck python3 strings
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

        else:
            # Python 2 strings best strings
            res = self._exec("wx %s%s|" % (buf.encode("hex"), self._tmp_off))
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
        # TODO: Check and finish this
        if encode:
            ret = self._exec("w6e %s %s" % (string, self._tmp_off))
        else:
            # TODO: Decode not working (?) w6d
            pass
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
