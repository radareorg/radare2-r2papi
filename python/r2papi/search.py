from r2papi.base import R2Base, ResultArray


class Search(R2Base):
    """
    Wrapper for radare2 ``/`` (search) commands.
    """

    def _clean_output(self, raw: str) -> list[str]:
        """
        Return a list of non‑warning lines from ``raw``.
        Lines that start with ``WARN:`` or ``INFO:`` (case‑insensitive) are
        discarded because they do not contain the usual ``offset hit data``
        format expected by the parsers.
        """
        return [
            ln
            for ln in raw.strip().splitlines()
            if ln and not ln.lower().startswith(("warn:", "info:"))
        ]

    def string(self, pattern: str):
        """
        Search for a null‑terminated string ``pattern``.
        """
        return self._exec(f"/ {pattern}")

    def string_json(self, pattern: str):
        """
        JSON version of :meth:`string`.
        """
        ret = self._exec(f"/j {pattern}", json=True)
        return ResultArray(ret)

    def inverse_hex(self, hexbytes: str):
        """
        Inverse hex‑search (find first byte *different* from ``hexbytes``).
        Returns a ``ResultArray`` where each ``Result`` has ``offset``, ``hit`` and ``data`` fields.
        """
        raw = self._exec(f"/!x {hexbytes}")

        # Split output into separate lines – the command may return many hits.
        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def base_address(self):
        """Search for a possible base address – ``/B``."""
        return self._exec("/B")

    def deltified(self, hexseq: str):
        """
        Search for a *deltified* sequence of bytes.
        ``/d <hexseq>``.
        """
        raw = self._exec(f"/d {hexseq}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def file(self, filename: str, offset: int = None, size: int = None):
        """
        Search the contents of a file with offset and size.
        """
        cmd = f"/F {filename}"
        if offset is not None:
            cmd += f" {offset}"
        if size is not None:
            cmd += f" {size}"
        raw = self._exec(cmd)

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset_val = int(offset_str, 16)
            except ValueError:
                offset_val = offset_str

            results.append({"offset": offset_val, "hit": hit, "data": data})

        return ResultArray(results)

    def case_insensitive(self, pattern: str):
        """Case‑insensitive string search – ``/i <pattern>``."""
        raw = self._exec(f"/i {pattern}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def rabin_karp(self, pattern: str):
        """Search using the Rabin‑Karp algorithm – ``/k <pattern>``."""
        raw = self._exec(f"/k {pattern}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def entropy(self, threshold: int = None):
        """
        Find sections by grouping blocks with similar entropy.
        ``/s[*] [threshold]`` – ``*`` can be omitted; *threshold* is optional.
        Returns a ``ResultArray`` where each entry has ``start``, ``end`` and
        ``entropy`` fields.
        """
        cmd = "/s"
        if threshold is not None:
            cmd += f" {threshold}"
        raw = self._exec(cmd)

        #   0x100002000 - 0x100002100 ~ 4.535647
        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                parts = line.split()
                start_str, _, end_str, _, entropy_str = parts[:5]

                start = int(start_str, 16)
                end = int(end_str, 16)
                entropy = float(entropy_str)
                results.append(
                    {"start": start, "end": end, "entropy": entropy, "raw": line}
                )
            except Exception:
                results.append({"error": "unexpected line format", "raw": line})

        return ResultArray(results)

    def wide_string(self, pattern: str):
        """Wide string search – ``/w <pattern>``."""
        raw = self._exec(f"/w {pattern}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def wide_string_json(self, pattern: str):
        """Wide string search – JSON output – ``/wj <pattern>``."""
        ret = self._exec(f"/wj {pattern}", json=True)
        return ResultArray(ret)

    def wide_string_ci(self, pattern: str):
        """Case‑insensitive wide‑string search – ``/wi <pattern>``."""
        raw = self._exec(f"/wi {pattern}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)

    def wide_string_ci_json(self, pattern: str):
        """Case‑insensitive wide‑string search – JSON output – ``/wij <pattern>``."""
        ret = self._exec(f"/wij {pattern}", json=True)
        return ResultArray(ret)

    def size_range(self, min_len: int, max_len: int):
        """
        Search for strings whose length is between *min_len* and *max_len*.
        ``/z <min> <max>``.
        """
        raw = self._exec(f"/z {min_len} {max_len}")

        lines = self._clean_output(raw)

        results = []
        for line in lines:
            try:
                offset_str, hit, data = line.split(maxsplit=2)
            except ValueError:
                results.append({"error": "unexpected line format", "raw": line})
                continue

            try:
                offset = int(offset_str, 16)
            except ValueError:
                offset = offset_str

            results.append({"offset": offset, "hit": hit, "data": data})

        return ResultArray(results)
