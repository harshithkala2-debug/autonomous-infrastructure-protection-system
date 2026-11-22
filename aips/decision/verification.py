"""Post-action verification: how repair actions are checked (concept section 5, step 6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..core.models import Incident
from ..repair.baseline import DesiredStateStore
from ..telemetry.sources import Observation
from .playbooks import Check


@dataclass
class CheckResult:
    check: str
    ok: bool
    detail: str


class Verifier:
    def __init__(self, baselines: DesiredStateStore, is_frozen: Callable[[str], bool] | None = None,
                 adapter_health: Callable[[str], bool | None] | None = None):
        self.baselines = baselines
        self.is_frozen = is_frozen or (lambda _i: False)
        self.adapter_health = adapter_health or (lambda _a: None)

    def run(self, check: Check, inc: Incident, obs: Observation | None, current_keys: set[str],
            render: Callable[[Any], Any], keys: set[str] | None = None) -> CheckResult:
        params = render(check.params)
        asset = inc.asset_id
        obs = obs or Observation(ts=0.0)
        k = check.kind
        if k == "healthy":
            up = obs.service_up.get(asset)
            if up is None:
                up = self.adapter_health(asset)
            ok = up is not False
            return CheckResult(k, ok, f"{asset} up={up}")
        if k == "metric_below":
            v = obs.metric(asset, params["metric"])
            ok = v is None or v < float(params["value"])
            return CheckResult(k, ok, f"{params['metric']}={v} (< {params['value']})")
        if k == "config_matches":
            cfg = obs.configs.get(asset)
            if cfg is None:
                return CheckResult(k, True, "configuration not observed this cycle")
            diffs = self.baselines.compare_config(asset, cfg)
            return CheckResult(k, not diffs, f"{len(diffs)} difference(s) from baseline")
        if k == "port_closed":
            port = int(params["port"])
            ports = obs.open_ports.get(asset, [])
            return CheckResult(k, port not in ports, f"port {port} open={port in ports}")
        if k == "identity_frozen":
            ident = str(params["identity"])
            fr = self.is_frozen(ident)
            return CheckResult(k, fr, f"{ident} frozen={fr}")
        if k == "signal_clear":
            still = sorted((keys or {inc.key}) & current_keys)
            return CheckResult(k, not still, "signal cleared" if not still else f"still present: {', '.join(still)}")
        return CheckResult(k, False, f"unknown check '{k}'")
