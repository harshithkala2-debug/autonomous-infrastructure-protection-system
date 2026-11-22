"""Tolerant version parsing and range checks for advisories.

Handles semantic versions (``1.2.3``, ``1.2.3-rc.1``), Debian-style epochs
(``1:2.3-4``), OpenSSL-style letter suffixes (``1.1.1k``) and differing
segment counts (``1.0 == 1.0.0``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_PRE = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "pre": 3, "preview": 3, "c": 4, "rc": 4}
_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


@total_ordering
class Version:
    def __init__(self, raw: str):
        self.raw = str(raw).strip()
        s = self.raw.lower().lstrip("v")
        if ":" in s and s.split(":", 1)[0].isdigit():
            self.epoch, s = int(s.split(":", 1)[0]), s.split(":", 1)[1]
        else:
            self.epoch = 0
        tokens: list[int | str] = [int(t) if t.isdigit() else t for t in _TOKEN.findall(s)]
        rel: list[int] = []
        i = 0
        while i < len(tokens) and isinstance(tokens[i], int):
            rel.append(tokens[i])  # type: ignore[arg-type]
            i += 1
        while rel and rel[-1] == 0:
            rel.pop()
        self.release = tuple(rel)
        self.suffix = tuple(tokens[i:])

    @staticmethod
    def _suffix_key(suffix: tuple) -> tuple:
        if not suffix:
            return (1,)                         # plain release
        head = suffix[0]
        # pre-release (rc, beta, ...) sorts before the plain release; patch letters / post-releases after
        kind = 0 if isinstance(head, str) and head in _PRE else 2
        parts = tuple((1, t, "") if isinstance(t, int) else (0, _PRE.get(t, 99), t) for t in suffix)
        return (kind, parts)

    def _cmp_release(self, other: "Version") -> int:
        a, b = list(self.release), list(other.release)
        n = max(len(a), len(b))
        a += [0] * (n - len(a))
        b += [0] * (n - len(b))
        return (a > b) - (a < b)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        return self.epoch == other.epoch and self._cmp_release(other) == 0 and \
            self._suffix_key(self.suffix) == self._suffix_key(other.suffix)

    def __lt__(self, other: "Version") -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        if self.epoch != other.epoch:
            return self.epoch < other.epoch
        c = self._cmp_release(other)
        if c:
            return c < 0
        return self._suffix_key(self.suffix) < self._suffix_key(other.suffix)

    def __hash__(self) -> int:
        return hash((self.epoch, self.release, self._suffix_key(self.suffix)))

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


@dataclass
class AffectedRange:
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None      # == first fixed version
    exact: str | None = None

    def contains(self, version: str) -> bool:
        v = Version(version)
        if self.exact and self.exact not in ("*", "-"):
            return v == Version(self.exact)
        if self.start_including and v < Version(self.start_including):
            return False
        if self.start_excluding and v <= Version(self.start_excluding):
            return False
        if self.end_including and v > Version(self.end_including):
            return False
        if self.end_excluding and v >= Version(self.end_excluding):
            return False
        return any([self.start_including, self.start_excluding, self.end_including, self.end_excluding,
                    self.exact in ("*",)])

    @property
    def fixed(self) -> str | None:
        return self.end_excluding
