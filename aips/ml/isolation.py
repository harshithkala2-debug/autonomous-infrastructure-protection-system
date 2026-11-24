"""Isolation Forest (Liu, Ting and Zhou, 2008) in pure Python.

Anomalies are few and different, so random axis-aligned splits isolate them in fewer steps. The score is
``2 ** (-E[h(x)] / c(n))``: about 0.5 for ordinary points and close to 1 for anomalies. Suitable for the small,
low-dimensional vectors AIPS scores (node telemetry, per-agent behaviour), not for big data.
"""

from __future__ import annotations

import math
import random
from typing import Sequence

_EULER = 0.5772156649


def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self, feature: int = -1, split: float = 0.0, left: "_Node | None" = None,
                 right: "_Node | None" = None, size: int = 0):
        self.feature, self.split, self.left, self.right, self.size = feature, split, left, right, size


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 128, seed: int = 11):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self._rng = random.Random(seed)
        self.trees: list[_Node] = []
        self._psi = 0
        self.dims = 0

    def fit(self, data: Sequence[Sequence[float]]) -> "IsolationForest":
        rows = [list(map(float, r)) for r in data]
        if len(rows) < 2:
            raise ValueError("IsolationForest needs at least 2 samples")
        self.dims = len(rows[0])
        self._psi = min(self.sample_size, len(rows))
        limit = math.ceil(math.log2(self._psi))
        self.trees = [self._grow(self._rng.sample(rows, self._psi), 0, limit) for _ in range(self.n_trees)]
        return self

    def _grow(self, rows: list[list[float]], depth: int, limit: int) -> _Node:
        if depth >= limit or len(rows) <= 1:
            return _Node(size=len(rows))
        feats = [f for f in range(self.dims) if min(r[f] for r in rows) < max(r[f] for r in rows)]
        if not feats:
            return _Node(size=len(rows))
        f = self._rng.choice(feats)
        lo, hi = min(r[f] for r in rows), max(r[f] for r in rows)
        s = self._rng.uniform(lo, hi)
        return _Node(f, s, self._grow([r for r in rows if r[f] < s], depth + 1, limit),
                     self._grow([r for r in rows if r[f] >= s], depth + 1, limit))

    def _path(self, x: Sequence[float], node: _Node, depth: int) -> float:
        while node.left is not None and node.right is not None:
            node = node.left if x[node.feature] < node.split else node.right
            depth += 1
        return depth + _c(node.size)

    def score(self, x: Sequence[float]) -> float:
        if not self.trees:
            raise RuntimeError("fit() first")
        x = list(map(float, x))
        mean = sum(self._path(x, t, 0) for t in self.trees) / len(self.trees)
        return round(2.0 ** (-mean / _c(self._psi)), 4)
