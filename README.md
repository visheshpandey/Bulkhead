# AIRLOCK

## The self-defending operating system for AI agents

AIRLOCK is an open-source zero-trust gateway for agent tool calls. It compares actions against user intent, detects prompt injection and sensitive-data risks, quarantines suspicious behavior in a HoneyWorld sandbox, and records an explainable Black Box timeline.

### Product loop

```text
Protect → Attack → Observe → Learn → Harden → Re-test
```

### Initial MVP

- Intercept `read_file`, `write_file`, `run_command`, `http_request`, and `github_action` events.
- Return an explainable `allow`, `block`, or `quarantine` decision.
- Detect prompt-injection and secret-exfiltration patterns.
- Record every decision in an audit timeline.
- Quarantine suspicious actions in HoneyWorld and mint automatic immunity rules for repeat attacks.

## Development assumptions

The implementation uses Python 3.11.9, FastAPI, Pydantic, and a vanilla HTML/CSS/JS dashboard. The gateway is local-only by default and uses mock tools for the demo so no real credentials or external actions are needed. Dependencies are pinned in `requirements.lock`.

## Setup on a clean Linux machine

```bash
git clone <repository-url>
cd AIRLOCK
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements.lock
cp .env.example .env
```

The `.env` file contains local settings only. Do not put credentials in it or commit it.

## Run locally

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

## Run with Docker

```bash
docker build --tag airlock:local .
docker run --rm --publish 8000:8000 airlock:local
```

Open <http://127.0.0.1:8000>.

## Test

```bash
python -m pytest
```

The same command is used locally and in the Docker image.

## Project layout

```text
app/
├── agents/       # OmniRush-facing orchestration boundary
├── api/          # HTTP routes and request/response models
├── audit/        # Black Box event and incident records
├── core/         # intent, policy, risk, and detection logic
├── honeyworld/   # isolated decoy runtime
└── static/       # local dashboard
docs/             # architecture and demo notes
examples/         # safe attack fixtures and policies
scripts/          # repeatable local commands
tests/            # fast offline tests
.python-version   # pinned developer runtime: Python 3.11.9
requirements.lock # pinned runtime, test, and lint dependencies
Dockerfile        # reproducible container build and run
```

## Safety boundary

The initial demo must use fake secrets and mock tools. AIRLOCK should not receive real API keys, browser cookies, or production credentials while the policy engine is being developed.
