from __future__ import print_function

import r2pipe

from r2papi.base import R2Base, Result, ResultArray
from r2papi.config import Config
from r2papi.debugger import Debugger
from r2papi.esil import Esil
from r2papi.file import File
from r2papi.flags import Flags
from r2papi.print import Print
from r2papi.write import Write


class Function(R2Base):
    """Class representing a function in radare2."""

    def __init__(self, r2, addr):
        """
        Args:
            addr (str): Beginning of the function, it can be an offset,
                function name...
        """
        super().__init__(r2)

        self.offset = addr

    def analyze(self):
        """Analyze the function. It uses the radare2 ``af`` command."""
        self._exec("af %s" % self.offset)

    def info(self):
        """Get the function information, using the radare2 ``afi`` command.

        Returns:
            :class:`r2api.base.Result`: Function information
        """
        # XXX: Is this [0] always correct?
        res = self._exec("afij @ %s" % self.offset, json=True)[0]
        return Result(res)

    def rename(self, name):
        """Uses the radare2 ``afn`` command"""
        self._exec("afn %s %s" % (name, self.offset))

    def graphImg(self, path=""):
        """
        .. todo::

            Return Graph object (does not exist yet), that should have a image
            method as there are more stuff that can be done with graphs?

        Save the function graph as a GIF image. By default, it's saved in
        ``{functionname}-graph.gif``

        Args:
            path (str, optional):
                Path to store the image (including filename).
        """
        path = "%s-graph.gif" % self.name if path == "" else path
        self._exec("e asm.comments=0")
        self._exec("e asm.var=0")
        self._exec("e asm.flags=0")
        self._exec("agfw %s @ %s" % (path, self.offset))

    @property
    def name(self):
        """
        Property where the getter returns the name of the function, and the
        setter changes it (using :meth:`r2api.r2api.Function.rename`).
        """
        return self.info().name

    @name.setter
    def name(self, value):
        self.rename(value)


class R2Api(R2Base):
    """Main class in ``r2papi``, it contains all the methods and objects
    used.

    A ``with`` statement can be used to make sure that the radare2 process is
    closed.

    .. code-block:: python

        with R2Api('/bin/ls') as r:
            r.print.hexdump()

    Attributes:
        print (:class:`r2pipe.print.Print`): Used only in Python3.
            All kind of things related with the print command in ``radare2``,
            this includes from getting an hexdump to get the dissasembly of a
            function.
        print2 (:class:`r2pipe.print.Print`): Used only in Python2 because
            ``print`` is a reserved keyword. see the previous attribute for
            further description.
        write (:class:`r2pipe.write.Write`): Write related operations, write
            binary data, strings, assembly...
        config (:class:`r2pipe.config.Config`): Configure radare2, like the
            ``e`` command in the radare console. Control all kind of stuff like
            architecture, analysis options...
        flags (:class:`r2pipe.flags.Flags`): Create and manage flags, those are
            conceptually similar to bookmarks. They associate a name with an
            offset.
        esil (:class:`r2pipe.flags.Esil`): Esil is the IL of radare2, it's
            string based and can be used, among others, to emulate code.
    """

    def __init__(self, filename=None, r2=None):
        """
        Args:
            filename (str): Filename to open, it accepts everything that radare
                accepts, so ``'-'`` opens ``malloc://512``.
            r2 (r2pipe.OpenBase): r2pipe object, only used if filename is None.
        """
        if filename:
            if r2pipe.in_r2():
                r2 = r2pipe.open()
            else:
                r2 = r2pipe.open(filename)
        super().__init__(r2)

        self.debugger = Debugger(r2)

        self.print = Print(r2)

        self.write = Write(r2)
        self.config = Config(r2)
        self.flags = Flags(r2)
        self.esil = Esil(r2)

        self.info = lambda: Result(self._exec("ij", json=True))
        self.searchIn = lambda x: self._exec("e search.in=%s" % (x))
        self.analyzeAll = lambda: self._exec("aaa")
        self.analyzeCalls = lambda: self._exec("aac")
        self.basicBlocks = lambda: ResultArray(self._exec("afbj", json=True))
        self.xrefsAt = lambda: ResultArray(
            self._exec("axtj %s" % self._tmp_off, json=True)
        )
        self.refsTo = lambda: ResultArray(self._exec("axfj", json=True))
        self.opInfo = lambda: ResultArray(
            self._exec("aoj %s" % self._tmp_off, json=True)
        )[0]
        self.seek = lambda x: self._exec("s %s" % (x))

    def __enter__(self):
        return self

    def __exit__(self, e_type, e_val, tb):
        self.quit()

    def open(self, filename, at="", perms=""):
        # See o?
        self._exec("o %s %s %s" % (filename, at, perms))

    @property
    def files(self):
        """
        list: returns a list of :class:`r2api.file.File` objects.
        """
        files = self._exec("oj", json=True)
        return [File(self.r2, f["fd"]) for f in files]

    def function(self):
        """Get the function at the current or temporary seek, if it exists.

        Example:

        .. code-block:: python

            with R2Api('bin') as r:
                r.analyzeAll()
                func = r.at(0x100).function()
                print(func.name)
                func = r.at('flag').function()
                print(func.offset)

        .. todo::

            Raise exception instead of returning None when the function does not
            exist?

        Returns:
            :class:`r2api.r2api.Function`: Function found or None.
        """
        function_name = self._exec("afn. %s" % self._tmp_off)
        self._tmp_off = ""
        return self.functionByName(function_name)

    def functions(self):
        """
        .. note::

            If no function is returned, remember to anaylze de binary first.

        Returns:
            list: List of :class:`r2api.r2api.Function` objects, representing
            all the functions in the binary.
        """
        res = self._exec("aflj", json=True)
        if not res:
            res = self._exec("isj", json=True)
        return [Function(self.r2, f["addr"]) for f in res] if res else []

    def functionByName(self, name):
        """
        Args:
            name (str): Name of the target function.
        Returns:
            :class:`r2api.r2api.Function`: Function or None.
        """
        res = [func for func in self.functions() if func.name == name]
        if not res:
            return None
        if len(res) == 1:
            return res[0]
        # TODO: Is this possible?
        raise ValueError("One name returned more than one function")

    def read(self, n):
        """Get ``n`` bytes as a binary string from the current offset.

        Args:
            n (int): Number of bytes to read.
        Returns:
            bytes: Binary string containing the data in python2, ``bytes``
                object in python3.
        """
        res = self._exec("p8 %s%s|" % (n, self._tmp_off))
        self._tmp_off = ""
        return bytes.fromhex(res)

    def __getitem__(self, k):
        if type(k) == slice:
            _from = k.start
            if type(k.start) == str:
                _from = self.sym_to_addr(k.start)

            _to = k.stop
            if type(k.stop) == str:
                _to = self.sym_to_addr(k.stop)

            read_len = _to - _from
            at_addr = _from
        else:
            read_len = 1
            at_addr = k
        return self.print.at(str(at_addr)).bytes(read_len)

    def __setitem__(self, k, v):
        return self.write.at(k).bytes(v)

    def quit(self):
        """Closes the radare2 process."""
        if self.r2:
            self.r2.quit()
        self.r2 = None
