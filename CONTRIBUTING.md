# Contributing

AIPS is proprietary software shared for evaluation only (see [LICENSE](LICENSE)). **External code contributions
are not accepted without a prior written agreement with the owner.**

What evaluators can do:

* open an issue for bugs, questions or evaluation feedback;
* open a **Permission request** issue to ask for any use beyond evaluation (see [NOTICE.md](NOTICE.md));
* report security issues privately (see [SECURITY.md](SECURITY.md)).

To evaluate locally (run unmodified, in a test environment):

```bash
pip install -e .
aips demo
python -m pytest
```
