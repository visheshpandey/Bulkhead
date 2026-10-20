# Contributing

Use Python 3.11.9 from `.python-version` and Node 22.14.0 from `.nvmrc` for
reproducible local checks. Install into a project virtual environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --requirement requirements.lock
python -m pip install --no-deps --no-build-isolation --editable .
npm ci
```

Run `make lint`, `make type`, `make test`, and `npm test` before proposing a
change. For changes to the browser or container, also run the optional browser
check (see README) or `docker build --tag bulkhead:local .` as appropriate.
Install the local Git hook with `pre-commit install`; it uses only the project
virtual environment and runs Ruff, Mypy, and pytest.

Describe the impact and checks in a pull request. Use only synthetic attack
values; never include real keys, cookies, production targets, or personal data.
Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
