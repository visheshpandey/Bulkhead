# AIRLOCK

## A self-defending gateway for AI-agent actions

AIRLOCK is a local, zero-trust gateway that evaluates an agent's proposed tool
call before the tool is invoked. It compares the action with user intent,
detects prompt injection and sensitive-data handling, quarantines suspicious
actions in a fully simulated HoneyWorld, and records an explainable Black Box
timeline. A quarantined fingerprint becomes an immunity rule, so a repeat is
blocked immediately.

The complete product loop is:

```text
Protect → Attack → Observe → Learn → Harden → Re-test
```

AIRLOCK never executes submitted shell commands, reads host files, calls a
network, or performs GitHub actions. Demo attacks and HoneyWorld values are
synthetic.

## Implemented behavior

- Supported action types: `read_file`, `write_file`, `run_command`,
  `http_request`, and `github_action`.
- Decisions: `allow`, `block`, or `quarantine`.
- Deterministic detectors normalize common encodings, Unicode disguises, and
  path spellings before checking prompt injection, sensitive paths/fields,
  secret material, exfiltration, and destructive commands.
- Quarantine creates an incident, runs the descriptive action against fake
  HoneyWorld decoys, stores a capture receipt, and generates an immunity rule.
- Every event, incident, immunity rule, and HoneyWorld capture is persisted by
  the SQLite-backed `EventLedger`.

## Requirements and clean setup

The project is pinned to Python **3.11.9** (`.python-version`). On a clean
Linux machine:

```bash
git clone <repository-url>
cd AIRLOCK
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --requirement requirements.lock
cp .env.example .env
```

`requirements.lock` contains runtime, test, and Ruff dependencies. No global
package installation is required.

### Environment variables

The project configuration surface documents the following variables. The
values in `.env.example` are safe local defaults; `.env` is ignored and must
never contain real credentials. The running gateway currently consumes
`AIRLOCK_DB_PATH` and `AIRLOCK_API_KEY`; the host/port values are passed by the
run commands and `AIRLOCK_LLM_JUDGE` reserves the optional judge integration
flag.

| Variable | Example | Purpose |
| --- | --- | --- |
| `AIRLOCK_ENV` | `development` | Environment label for local configuration. |
| `AIRLOCK_HOST` | `127.0.0.1` | Documented local bind host. The run commands pass the host explicitly. |
| `AIRLOCK_PORT` | `8000` | Documented local bind port. The run commands pass the port explicitly. |
| `AIRLOCK_DB_PATH` | `./data/airlock.db` | SQLite file for events, incidents, immunity rules, and capture receipts. Use `:memory:` for an ephemeral process. |
| `AIRLOCK_API_KEY` | *(blank)* | Optional API key. When set, evaluation requests require `X-Airlock-Key`, `X-API-Key`, or `Authorization: Bearer ...`. |
| `AIRLOCK_LLM_JUDGE` | `0` | Enables the optional `{risk, rationale}` second check for borderline risk scores (30–69); deterministic policy remains authoritative. |

The default database path is relative to the working directory. SQLite creates
the parent directory, enables WAL mode for file databases, and reloads the
four persisted collections when a new `EventLedger` opens the same file.
HoneyWorld's active decoy filesystem remains process-local; its captured
receipts are persisted in SQLite.

## Run locally

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host "${AIRLOCK_HOST:-127.0.0.1}" --port "${AIRLOCK_PORT:-8000}"
```

Open <http://127.0.0.1:8000> (or the configured host and port).

## Run with Docker

```bash
docker build --tag airlock:local .
docker run --rm --publish 8000:8000 --env AIRLOCK_DB_PATH=/app/data/airlock.db \
  --volume airlock-data:/app/data airlock:local
```

The image is based on Python 3.11.9, installs `requirements.lock`, creates
`/app/data`, and runs as the unprivileged `airlock` user. The named volume is
optional but preserves the SQLite ledger between container restarts. Runtime
data is ignored by Git.

## API quick reference

| Method | Endpoint | Use |
| --- | --- | --- |
| `GET` | `/health` | Liveness check. |
| `GET` | `/api/state` | Events, incidents, rules, counts, and HoneyWorld state. |
| `GET` | `/api/default-intent` | Canonical zero-trust intent used by the server and dashboard. |
| `GET` | `/api/stream` | Live `audit_event` decisions and `reset` notifications (SSE). |
| `GET` | `/api/events` | Black Box events. |
| `POST` | `/api/evaluate` | Evaluate an action object or flat action fields. |
| `POST` | `/api/demo` | Reset and run the deterministic `allow → quarantine → block` demo. |
| `POST` | `/api/reset-demo` | Clear the SQLite-backed demo collections and reset HoneyWorld decoys. |
| `GET` | `/api/attacks` | List the built-in synthetic attack presets. |
| `GET` | `/api/rules` | List immunity rules. |
| `PATCH/DELETE` | `/api/rules/{id}` | Toggle or delete an immunity rule. |

Resets clear audit data but preserve persistent event, incident, and rule ID
counters. Existing dashboards immediately clear on the SSE `reset` notification,
then reload `/api/state`; they also reconcile state every three seconds.
Send `X-Agent-Id` to record the caller in each event's top-level `agent_id` and
CSV export. Missing headers are stored as JSON `null` (empty CSV cell), not
inferred from the compatibility `action.agent_id` field.

Example safe request:

```bash
curl -X POST http://127.0.0.1:8000/api/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"read_file","target":"/workspace/README.md"}'
```

## Attack library and agent demo

`examples/attacks/` is the synthetic attack-library boundary. The built-in
presets cover path traversal, workspace-prefix tricks, `.env` and private-key
access, shell/network secret exfiltration, leetspeak/zero-width/base64
prompt-injection disguises, destructive commands, a webpage injection, and a
safe README read. Add fake values only.

With the server running, execute the agent-facing standard-library demo:

```bash
python examples/agent_demo.py
```

It sends a safe read through `AirlockClient`, then submits a synthetic
malicious webpage action through `client.guard`; the output shows the decision
and whether HoneyWorld produced a simulated receipt. The dashboard's **Run
demo sequence** button and `POST /api/demo` run the three-step flow described
in [`docs/demo-script.md`](docs/demo-script.md).

## Test and CI workflow

```bash
ruff check .
python -m pytest
```

GitHub Actions uses Python 3.11.9, installs `requirements.lock`, then runs
those exact Ruff and pytest commands. The checks are offline after dependency
installation.

With Node.js available, pytest also runs the dependency-free dashboard behavior
tests; they can be run directly with `node --test tests/frontend.behavior.test.cjs`.
That optional test is skipped on Python-only installations.

## Project layout

```text
app/core/       intent, fingerprints, policy, and deterministic detectors
app/audit/      SQLite-backed Black Box ledger
app/honeyworld/ fake decoys and no-op quarantine simulation
app/agents/     agent HTTP client and guard helpers
app/api/        FastAPI routes and request models
app/static/     local dashboard
examples/       synthetic attack guidance and agent demo
docs/           architecture and presenter script
tests/          offline policy, API, detector, and persistence tests
data/           ignored SQLite runtime data
```

See [`docs/architecture.md`](docs/architecture.md) for the exact evaluation
pipeline and [`docs/demo-script.md`](docs/demo-script.md) for a reproducible
walkthrough.

## Safety boundary

Use only fake secrets, mock tools, and non-production targets while developing
or demonstrating AIRLOCK. Never put API keys, browser cookies, private keys, or
production credentials in fixtures, requests, logs, or the repository.
