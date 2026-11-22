# Contributing

```bash
pip install -e ".[dev,crypto]"
ruff check aips tests
python -m pytest
aips demo
```

* Keep the core free of third-party runtime dependencies.
* Any new action kind needs an `ActionSpec` (risk, reversibility, minimum level), adapter support, and a test
  showing the policy outcome.
* Any new detector or playbook needs a scenario or unit test with explicit success criteria.
* A behaviour change must keep `aips bench --seeds 1-10` at 100 % pass. If a scenario has to change, explain why
  in the pull request.
