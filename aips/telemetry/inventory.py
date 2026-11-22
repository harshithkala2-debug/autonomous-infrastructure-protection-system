"""Asset inventory: what exists, what it runs, what it depends on, how critical it is."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class SoftwareComponent:
    name: str
    version: str
    vendor: str = ""
    ecosystem: str = ""            # e.g. PyPI, npm, Debian, Maven - used for OSV queries

    @property
    def normalized(self) -> str:
        return normalize_product(self.name)


@dataclass
class Certificate:
    name: str
    expires_at: float


@dataclass
class Asset:
    id: str
    kind: str                       # host | service | database | network | storage | queue
    criticality: int = 3            # 1 (low) .. 5 (business critical)
    depends_on: list[str] = field(default_factory=list)
    software: list[SoftwareComponent] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Asset":
        return cls(
            id=d["id"],
            kind=d.get("kind", "service"),
            criticality=int(d.get("criticality", 3)),
            depends_on=list(d.get("depends_on", [])),
            software=[SoftwareComponent(**s) for s in d.get("software", [])],
            allowed_ports=[int(p) for p in d.get("allowed_ports", [])],
            certificates=[Certificate(**c) for c in d.get("certificates", [])],
            attributes=dict(d.get("attributes", {})),
            tags=list(d.get("tags", [])),
        )


_ALIASES = {
    "httpd": "http_server",
    "apache_http_server": "http_server",
    "apache2": "http_server",
    "postgres": "postgresql",
    "openssh_server": "openssh",
    "sshd": "openssh",
    "nodejs": "node.js",
    "node": "node.js",
}


def normalize_product(name: str) -> str:
    n = name.strip().lower().replace(" ", "_").replace("-", "_")
    return _ALIASES.get(n, n)


class Inventory:
    def __init__(self, assets: Iterable[Asset] = ()):
        self._assets: dict[str, Asset] = {}
        for a in assets:
            self.add(a)

    def add(self, asset: Asset) -> None:
        self._assets[asset.id] = asset

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def __iter__(self):
        return iter(self._assets.values())

    def __len__(self) -> int:
        return len(self._assets)

    def ids(self) -> list[str]:
        return list(self._assets)

    def criticality(self, asset_id: str) -> int:
        a = self._assets.get(asset_id)
        return a.criticality if a else 3

    def dependents(self, asset_id: str) -> list[str]:
        """Assets that (directly) depend on ``asset_id``."""
        return [a.id for a in self._assets.values() if asset_id in a.depends_on]

    def upstream_closure(self, asset_id: str) -> list[str]:
        """All transitive dependencies of an asset, nearest first."""
        seen: list[str] = []
        frontier = list(self._assets[asset_id].depends_on) if asset_id in self._assets else []
        while frontier:
            nxt = frontier.pop(0)
            if nxt in seen:
                continue
            seen.append(nxt)
            if nxt in self._assets:
                frontier.extend(self._assets[nxt].depends_on)
        return seen

    def find_software(self, product: str) -> list[tuple[Asset, SoftwareComponent]]:
        p = normalize_product(product)
        return [(a, s) for a in self._assets.values() for s in a.software if s.normalized == p]

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        path = Path(path)
        if path.suffix == ".toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Inventory":
        return cls(Asset.from_dict(a) for a in data.get("assets", []))
