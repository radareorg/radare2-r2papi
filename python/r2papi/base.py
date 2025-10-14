def ResultArray(o):
    """
    Convert an iterable of raw JSON objects into a list of ``Result`` instances.
    """
    results: list[Result] = []
    if o:
        for a in o:
            results.append(Result(a))
    return results


class Result:
    """Encapsulate a JSON response from radare2.

    The object's attributes mirror the keys of the provided dict, and a
    private ``_dict`` attribute holds the raw mapping for easy introspection.
    """

    def __init__(self, o: dict):
        self._dict: dict = {}
        # Prefer the ``bin`` sub‑dictionary if present
        try:
            bin_dict = o["bin"]
        except KeyError:
            bin_dict = o

        for key, value in bin_dict.items():
            setattr(self, key, value)
            self._dict[key] = value
    
    def __getitem__(self, key):
        return self._dict[key]

    def __contains__(self, key):
        return key in self._dict

    def pprint(self) -> str:
        """Pretty‑print the stored dictionary in a column‑aligned format."""
        lines = [f"{k:<10}{v}" for k, v in self._dict.items()]
        # Join without trailing newline
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.pprint()


class R2Base:
    """Base class providing common radare2‑pipe utilities."""

    def __init__(self, r2):
        """
        Args:
            r2 (r2pipe.OpenBase): An opened r2pipe instance.
        """
        self.r2 = r2
        self._tmp_off = ""

    def _exec(self, cmd: str, json: bool = False, rstrip: bool = True):
        """Execute a radare2 command.

        Args:
            cmd: Command string.
            json: If ``True`` parse output as JSON.
            rstrip: Strip trailing whitespace from non‑JSON output.

        Returns:
            Either a Python object (when ``json=True``) or a stripped string.
        """
        if json:
            return self.r2.cmdj(cmd)
        res = self.r2.cmd(cmd)
        return res.rstrip() if rstrip else res

    def curr_seek_addr(self) -> int:
        """Return the current address after a temporary seek."""
        try:
            return int(self._exec(f"?vi $$ {self._tmp_off}"))
        except ValueError as exc:
            raise ValueError(f"Invalid address {self._tmp_off}") from exc
        finally:
            self._tmp_off = ""

    def sym_to_addr(self, sym: str) -> int:
        """Resolve a symbol name to its address."""
        if not isinstance(sym, str):
            raise TypeError("Symbol type must be string")
        return self.at(sym).curr_seek_addr()

    def at(self, seek: str):
        """Temporarily seek to ``seek`` for the next command, then restore."""
        self._tmp_off = f"@ {seek}"
        return self
