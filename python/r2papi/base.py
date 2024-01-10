from . import utils as r2_utils
import sys

PYTHON_VERSION = sys.version_info[0]


def ResultArray(o):
    self = []
    if o:
        for a in o:
            self.append(Result(a))
    return self


class Result:
    """Class to encapsulate the results of a json response.

    .. todo::

        Document this, implement this in a more elegant way?
    """

    def __init__(self, o):
        self._dict = {}
        try:
            for a in o["bin"]:
                setattr(self, a, o["bin"][a])
                self._dict[a] = o["bin"][a]
        except:
            for a in o:
                setattr(self, a, o[a])
                self._dict[a] = o[a]

    def pprint(self):
        ret_str = ""
        if PYTHON_VERSION == 3:
            items = self._dict.items()
        else:
            items = self._dict.iteritems()

        for k, v in items:
            ret_str += "{:<10}{}\n".format(k, v)
            # Don't return last newline
        return ret_str[:-1]

    def __str__(self):
        return self.pprint()


class R2Base(object):
    """Base class that have the essential functionality required by almost all
    subclasses of r2pipe-api. It accepts a r2pipe object and checks if it's
    valid, if not it raises a ValueError.
    """

    def __init__(self, r2):
        """
        Args:
            r2 (r2pipe.OpenBase):
                r2pipe object, this is what ``r2pipe.open`` returns.
        """
        if not r2_utils.r2_is_valid(r2):
            raise ValueError("Invalid r2pipe object")

        self.r2 = r2
        self._tmp_off = ""

    def _exec(self, cmd, json=False, rstrip=True):
        """Execute a radare2 command.

        Args:
            cmd (str):
                Command to be executed
            json (bool, optional):
                If True, it interprets the output as json, and returns a Python
                native object.
            rstrip (bool, optional):
                If True (default), it calls python rstrip function before
                returning the output. Not used in json mode.

        Returns:
            object:
                The result of the r2 command as a string, or as a python native
                object if the json parameter was True.
        """
        if json:
            return self.r2.cmdj(cmd)
        else:
            res = self.r2.cmd(cmd)
            return res if not rstrip else res.rstrip()

    def curr_seek_addr(self):
        try:
            res = int(self._exec("?vi $$ %s" % self._tmp_off))
            return res
        except:
            err_str = "Invalid address %s" % self._tmp_off
            raise ValueError(err_str)
        finally:
            self._tmp_off = ""

    def sym_to_addr(self, sym):
        if type(sym) != str:
            raise TypeError("Symbol type must be string")
        return self.at(sym).curr_seek_addr()

    def at(self, seek):
        """Temporal seek, it'll execute the next command at the specified
        seek, and then return to the current seek. It have the same effect as
        the ``@`` radare command.

        .. code-block:: python

            # current offset = 0x100
            R2Base.at('0x200')._exec('p8 1') # Prints 1 bytes at 0x200
            # current offset = 0x100

        Args:
            seek (str):
                Anything that radare accepts as an offset, function names, hex
                offset string, integers, flags...

        Returns:
            R2Base: Returns self, to be able to use other methods easily.
        """
        self._tmp_off = "@ %s" % (seek)
        return self
