from __future__ import annotations

import json as _json
from types import SimpleNamespace


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


class R2CommandError(Exception):
    """Raised when a radare2 command reports an error."""

    def __init__(self, cmd: str, value: int, output: str, logs: list | None = None):
        self.cmd = cmd
        self.value = value
        self.output = output
        self.logs = logs or []
        msgs = [f"Command {cmd!r} failed with value {value}"]
        for log in self.logs:
            msg = log.get("message")
            if msg:
                msgs.append(f"  {log.get('origin', 'r2')}: {msg}")
        super().__init__("\n".join(msgs))


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

        Raises:
            R2CommandError: If radare2 reports the command as failed.
        """
        full_cmd, tmp_off = self._build_cmd(cmd)
        res = self.r2.cmd2(full_cmd)
        self._tmp_off = tmp_off
        if res.error:
            logs = _logs(getattr(res, "logs", None))
            raise R2CommandError(full_cmd, res.value, getattr(res, "res", ""), logs)
        if json:
            out = res.res.strip()
            if not out:
                return None
            return _json.loads(out)
        out = res.res
        return out.rstrip() if rstrip else out

    def _exec_quiet(self, cmd: str, json: bool = False, rstrip: bool = True):
        """Execute a radare2 command and return ``None`` on failure.

        This is a transitional helper for commands where failure is expected
        or where callers currently rely on silent ``None`` returns. New code
        should prefer :meth:`_exec` and handle :exc:`R2CommandError`.
        """
        try:
            return self._exec(cmd, json=json, rstrip=rstrip)
        except R2CommandError:
            return None

    def _build_cmd(self, cmd: str) -> tuple[str, str]:
        """Combine ``cmd`` with the temporary seek stored in ``_tmp_off``.

        Returns a tuple ``(full_cmd, remaining_tmp_off)``.  The temporary
        seek is appended at the end so radare2 restores the original offset
        automatically, and the remaining temporary seek is cleared.
        """
        tmp_off = self._tmp_off
        if tmp_off:
            return f"{cmd} {tmp_off}", ""
        return cmd, ""

    def curr_seek_addr(self) -> int:
        """Return the current address after a temporary seek."""
        try:
            res = self.r2.cmd2("?vi $$")
            self._tmp_off = ""
            if res.error:
                raise R2CommandError("?vi $$", res.value, res.res, _logs(res.logs))
            return int(res.res)
        except ValueError as exc:
            raise ValueError("Invalid address") from exc

    def sym_to_addr(self, sym: str) -> int:
        """Resolve a symbol name to its address."""
        if not isinstance(sym, str):
            raise TypeError("Symbol type must be string")
        return self.at(sym).curr_seek_addr()

    def at(self, seek: str):
        """Temporarily seek to ``seek`` for the next command, then restore."""
        self._tmp_off = f"@ {seek}"
        return self

    def _cmd_arg(self, cmd: str, arg) -> str:
        """Build a command with an argument that should not be evaluated.

        The whole command+argument block is wrapped in double quotes so
        radare2 treats it as a single command string.  This preserves
        ``;`` or spaces inside the argument while still allowing ``@``
        temporary seeks appended outside the quotes.  Non-printable
        bytes are hex-escaped so they survive the radare2 parser.
        """
        def _escape(c):
            if 32 <= ord(c) < 127 and c not in ('"', '\\'):
                return c
            return f"\\x{ord(c):02x}"

        escaped = "".join(_escape(c) for c in str(arg))
        return f'"{cmd} {escaped}"'


    def curr_seek_addr(self) -> int:
        """Return the current address after a temporary seek."""
        try:
            return int(self._exec("?vi $$"))
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


def _logs(logs):
    if logs is None:
        return []
    return [
        {"type": getattr(l, "type", None), "origin": getattr(l, "origin", None),
         "message": getattr(l, "message", None)}
        for l in logs
    ]

