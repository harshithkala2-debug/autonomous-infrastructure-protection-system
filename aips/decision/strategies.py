"""Automatic strategy exploration.

Most problems can be fixed in more than one way (restart first? add capacity
first? shed load first?). Each alternative is a playbook *variant* for the
same signals. The ``StrategySelector`` picks between them with **Thompson
sampling** over the persistent experience store:

* every strategy has a Beta(1 + reward, 1 + (trials - reward)) belief about
  how well it works for this signal (episodes on the same asset count double);
* a sample is drawn from each belief and the highest sample wins, so untried
  or uncertain strategies are naturally *explored*, and proven ones are
  *exploited* more and more often as evidence accumulates;
* inside one incident, a strategy whose attempt failed verification is not
  retried blindly: the next attempt switches to the best *untried* variant -
  but never to one whose learned mean reward is below ``min_switch_mean``
  (known-bad fallbacks are skipped; the current strategy escalates instead).

Safety limits on exploration:

* playbooks marked ``explorable=False`` (containment, data integrity, security)
  never take part: they always run their single, reviewed playbook;
* every step of every variant still goes through the authorisation policy, so
  exploring can never grant more autonomy than a fixed playbook would have;
* selection is seeded, so runs are reproducible.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Iterable

from .playbooks import Playbook


@dataclass
class Choice:
    playbook: Playbook
    explored: bool
    mode: str                                       # single | fixed | thompson | switch
    beliefs: dict[str, dict[str, float]] = field(default_factory=dict)

    def describe(self) -> str:
        if self.mode in ("single", "fixed"):
            return f"strategy {self.playbook.name} ({self.mode})"
        b = ", ".join(f"{k}: mean {v['mean']:.2f} n={v['trials']:.0f} sample {v['sample']:.2f}"
                      for k, v in self.beliefs.items())
        return f"strategy {self.playbook.name} via {self.mode}{' (exploring)' if self.explored else ''} [{b}]"


class StrategySelector:
    def __init__(self, store: Any, seed: int = 0, enabled: bool = True, min_trials: int = 1,
                 min_switch_mean: float = 0.5, evidence_horizon_s: float = 90 * 86400):
        self.store = store
        self.rng = random.Random(seed)
        self.enabled = enabled
        self.min_trials = min_trials     # every variant gets at least this many real trials before sampling
        self.min_switch_mean = min_switch_mean   # variants history shows to be bad are not chosen
        self.evidence_horizon_s = evidence_horizon_s   # older evidence ages out, so a bad verdict is not forever

    def choose(self, candidates: Iterable[Playbook], signal: str, asset: str,
               exclude: Iterable[str] = (), mode: str = "thompson", now: float | None = None) -> Choice | None:
        cands = [c for c in candidates if c.name not in set(exclude)]
        if not cands:
            return None
        if len(cands) == 1 and (mode != "switch" or self.store is None):
            return Choice(cands[0], False, "single")      # a mid-incident switch still checks history below
        if (not self.enabled or not all(c.explorable for c in cands)) and mode != "switch":
            return Choice(cands[0], False, "fixed")
        since = (now - self.evidence_horizon_s) if now is not None else None
        stats = self.store.strategy_stats(signal, asset, since)
        beliefs: dict[str, dict[str, float]] = {}
        for c in cands:
            s = stats.get(c.name, {})
            reward = float(s.get("reward_sum", 0.0))
            weight = float(s.get("weight", 0.0))
            alpha, beta = 1.0 + reward, 1.0 + max(0.0, weight - reward)
            beliefs[c.name] = {"mean": alpha / (alpha + beta), "trials": float(s.get("trials", 0)),
                               "sample": self.rng.betavariate(alpha, beta)}
        # never choose a variant that recent history shows to be bad while a viable alternative exists;
        # mid-incident (switch) there is no fallback to a bad variant at all
        viable = [c for c in cands if beliefs[c.name]["trials"] < 1 or beliefs[c.name]["mean"] >= self.min_switch_mean]
        if mode == "switch" and not viable:
            return None
        if viable:
            cands = viable
        best_mean = max(cands, key=lambda c: (beliefs[c.name]["mean"], -cands.index(c)))
        untried =[c for c in cands if beliefs[c.name]["trials"] < self.min_trials]
        if untried and mode == "thompson":
            # forced exploration: an alternative that has never been tried cannot be judged
            pick = untried[0]
            return Choice(pick, pick is not best_mean, "explore-untried", beliefs)
        best_sample = max(cands, key=lambda c: (beliefs[c.name]["sample"], -cands.index(c)))
        return Choice(best_sample, best_sample is not best_mean, mode, beliefs)
