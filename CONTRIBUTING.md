# Contributing

Contributions are welcome: bug reports, new detectors, platform adapters, agent integrations, docs.

## Set up

```bash
git clone https://github.com/harshithkala2-debug/autonomous-infrastructure-protection-system.git
cd autonomous-infrastructure-protection-system
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q
ruff check .
```

## Rules of the road

* **Zero runtime dependencies.** The core uses the Python standard library only; optional extras are fine.
* **Every action goes through the authorisation policy.** New action kinds get an entry in
  `aips/core/policy.py` (risk, reversibility, minimum level) and a rollback where one is possible.
* **Tests with every change.** Unit tests in `tests/`; behaviour changes that affect incidents need a simulator
  scenario or must keep `aips bench --seeds 1-20` at 100 %.
* **No secrets in issues, tests or fixtures.** Use obviously fake values.
* Keep docs in step with the code (`docs/`, `CHANGELOG.md`).

By contributing you agree that your contribution is licensed under the MIT License (see [LICENSE](LICENSE)).
