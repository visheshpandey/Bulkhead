# Bulkhead — stop the tool call before it becomes an incident

[![CI](https://github.com/visheshpandey/Bulkhead/actions/workflows/ci.yml/badge.svg)](https://github.com/visheshpandey/Bulkhead/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-CI%20enforced-blue.svg)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Bulkhead is a local, zero-trust policy gateway for AI agents. It evaluates
every proposed tool call against user intent, catches prompt injection and
sensitive-data handling, sends suspicious actions to a synthetic Decoy, and
keeps an explainable Black Box timeline.

![Bulkhead demo](docs/demo.gif)

**Live demo:** [run the isolated demo locally](#run-locally). A hosted demo is
not assumed by the repository; `render.yaml` contains the reproducible deploy
definition.

## Clean Linux setup

```bash
git clone https://github.com/visheshpandey/Bulkhead.git
cd Bulkhead
test "$(tr -d '\r\n' < .python-version)" = "3.11.9"
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --requirement requirements.lock
python -m pip install --no-deps --no-build-isolation --editable .
cp .env.example .env
```

The package supports Python **3.11 or newer**. The reproducible baseline is
Python **3.11.9**, pinned in `.python-version`, Docker, and CI. Dependencies
are installed from `requirements.lock`; the editable install provides the
`bulkhead-mcp` console command. No global packages or secrets are required.
Install Python 3.11.9 with your preferred local version manager before these
commands; `python --version` should report `Python 3.11.9`.

## Run locally

```bash
source .venv/bin/activate
set -a; . ./.env; set +a
python -m uvicorn app.main:app --host "${BULKHEAD_HOST:-127.0.0.1}" --port "${BULKHEAD_PORT:-8000}"
```

Open <http://127.0.0.1:8000>. The dashboard is safe to demo: it never reads
host files, runs submitted shell commands, calls an external network, or
performs GitHub actions. All attacks and Decoy values are synthetic.

## How it works

```text
Protect → Attack → Observe → Learn → Harden → Re-test
```

Bulkhead checks the descriptive action before the agent invokes a tool. A
safe action is Allowed, a dangerous action is Blocked, and a suspicious action
is Decoyed with fake data. A Decoyed fingerprint becomes a learned Rule that
blocks the same attack on replay.

## Add it to an agent

- **MCP:** install the project locally, then configure `{ "command": "bulkhead-mcp" }`.
- **Coding-agent hook:** run `python examples/hooks/pretooluse.py < action.json` before a tool call.
- **Python:** use `BulkheadClient` and `@bulkhead_guard` from `app.agents`.

The full copy-ready snippets are in the dashboard's **Add to your agent** page.

## Test

```bash
python -m pytest
```

`python -m pytest` is the single canonical test command. It runs the offline
Python suite; when Node.js 22.14.0 is available, the frontend behavior test is
also run by the suite. `make test` is a convenience alias. Ruff is the separate
lint check used by CI.

Run the frontend suite directly with `npm ci && npm test`. `make type` runs
Mypy, and the optional browser layout/interaction check is
`make accessibility` after provisioning Chromium as described below.

## Build and run with Docker

```bash
docker build --tag bulkhead:local .
docker run --rm --publish 8000:8000 \
  --env PORT=8000 \
  --env BULKHEAD_DB_PATH=/app/data/bulkhead.db \
  --volume bulkhead-data:/app/data \
  bulkhead:local
```

The container runs as the unprivileged `bulkhead` user and listens on the
container `PORT` variable. The named volume is optional and preserves the
SQLite ledger between restarts.

## Deploy a public demo

The repository includes `render.yaml` for a Render Blueprint. Create a new
Blueprint from `https://github.com/visheshpandey/Bulkhead`, select the
`bulkhead-demo` service, and deploy it. Render supplies `PORT`, uses `/healthz`
for health checks, and sets `BULKHEAD_PUBLIC_DEMO=1`.

## Implemented behavior

The complete product loop is:

```text
Protect → Attack → Observe → Learn → Harden → Re-test
```

- Supported action types: Read file, Write file, Run command, Web request, and
  GitHub action. The API wire values remain `read_file`, `write_file`,
  `run_command`, `http_request`, and `github_action`.
- Decisions: Allowed, Blocked, or Decoyed. The API wire values remain `allow`,
  `block`, and `quarantine`.
- Deterministic detectors normalize common encodings, Unicode disguises, and
  path spellings before checking prompt injection, sensitive paths/fields,
  secret material, exfiltration, and destructive commands.
- A Decoyed action creates an Attack, runs the descriptive action against fake
  data, stores a capture receipt, and generates a Rule that blocks a repeat
  attack.
- Every event, Attack, Rule, and Decoy capture is persisted by
  the SQLite-backed `EventLedger`.

### Environment variables

The project configuration surface documents the following variables. The
values in `.env.example` are safe local defaults; `.env` is ignored and must
never contain real credentials. The running gateway currently consumes the
`BULKHEAD_*` variables; the host/port values are passed by the run commands and
`BULKHEAD_LLM_JUDGE` reserves the optional judge integration flag.
The application does not load `.env` itself; source the file into your shell
before starting Uvicorn, as in the local run command above.

| Variable | Example | Purpose |
| --- | --- | --- |
| `BULKHEAD_ENV` | `development` | Environment label for local configuration. |
| `BULKHEAD_HOST` | `127.0.0.1` | Documented local bind host. The run commands pass the host explicitly. |
| `BULKHEAD_PORT` | `8000` | Documented local bind port. The run commands pass the port explicitly. |
| `BULKHEAD_DB_PATH` | `./data/bulkhead.db` | SQLite file for events, Attacks, Rules, and capture receipts. Use `:memory:` for an ephemeral process. |
| `BULKHEAD_API_KEY` | *(blank)* | Optional API key. When set, evaluation requests require `X-Bulkhead-Key`, `X-API-Key`, or `Authorization: Bearer ...`. |
| `BULKHEAD_LLM_JUDGE` | `0` | Enables the optional `{risk, rationale}` second check for borderline risk scores (30–69); deterministic policy remains authoritative. |
| `BULKHEAD_PUBLIC_DEMO` | `0` | Enables isolated two-hour visitor sessions, public request limits, and the Arena/Attack lab sandbox. |

The default database path is relative to the working directory. SQLite creates
the parent directory, enables WAL mode for file databases, and reloads the
four persisted collections when a new `EventLedger` opens the same file.
The active Decoy filesystem remains process-local; its captured
receipts are persisted in SQLite.

Public mode gives each visitor an expiring, httpOnly session cookie. Events,
Attacks, Rules, Decoy receipts, lab scores, and reset operations
stay inside that visitor's in-memory sandbox. Requests are limited to 60 per
minute per session and per IP, and request bodies are limited to 20 KB. The
demo only evaluates descriptive actions; it never reads real files, runs shell
commands, or makes outbound network calls.

## API quick reference

See [`docs/API.md`](docs/API.md) for endpoint details and the live generated
schema at `/openapi.json`.

| Method | Endpoint | Use |
| --- | --- | --- |
| `GET` | `/health` | Liveness check. |
| `GET` | `/api/health` | Compatibility liveness check. |
| `GET` | `/api/state` | Events, Attacks, Rules, counts, and Decoy state. |
| `GET` | `/api/default-intent` | Canonical zero-trust intent used by the server and dashboard. |
| `GET` | `/api/stream` | Live `audit_event` decisions and `reset` notifications (SSE). |
| `GET` | `/api/events` | Black Box events. |
| `POST` | `/api/evaluate` | Evaluate an action object or flat action fields. |
| `POST` | `/api/demo` | Reset and run the deterministic Allowed → Decoyed → Blocked demo. |
| `POST` | `/api/reset-demo` | Clear the SQLite-backed demo collections and reset Decoy data. |
| `GET` | `/api/attacks` | List the built-in synthetic attack presets. |
| `GET` | `/api/rules` | List Rules. |
| `PATCH/DELETE` | `/api/rules/{id}` | Toggle or delete a Rule. |

Resets clear audit data but preserve persistent event, Attack, and Rule ID
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

The example evaluates a safe read and a synthetic malicious webpage, then
prints the containment and immunity decisions. It uses only simulated tools.
The dashboard's **Run demo** button presents four steps with **Next**:
safe read, decoyed attack, repeat blocked by a Rule, and disguised repeat
blocked by the same rule. `POST /api/demo` and its aliases retain the original
three-step API response. See [`docs/demo-script.md`](docs/demo-script.md).

## Dashboard

The vanilla HTML/CSS/JavaScript interface has no build step or remote assets.
It defaults to a light theme; **Dark mode** saves a local preference.

- **Activity:** searchable, filterable decision log; keyboard row navigation;
  full event drawer; routing diagram; persisted Decoy receipts.
- **Test:** editable intent and action, 15 grouped scenarios, expected/actual
  comparisons, and **Run all scenarios**. Each batch uses a unique synthetic
  content marker so previously learned rules do not spoil repeat test runs.
  Tests create real audit events; they do not clear existing data or disable rules.
- **Rules:** enable/disable with rollback on error, confirm deletion, inspect
  fingerprints, and open the originating Attack.
- **Exports:** events JSON, CSV, Rules JSON, Attacks JSON, and individual Markdown
  report preview/download.

Use **Ctrl/Cmd+Enter** to evaluate on Test, arrow keys and **Enter** in the log,
and **Esc** to close the drawer. **Reset** clears the board for all connected
dashboards while keeping ID counters monotonic.

## Test and CI workflow

```bash
ruff check .
python -m pytest
```

GitHub Actions uses Python 3.11.9 and the Node version pinned in `.nvmrc`,
installs `requirements.lock`, and runs lint, type, Python tests, frontend,
browser layout/interaction, static accessibility smoke, and Docker checks.
The checks are offline after
dependency installation.

With Node.js available, pytest also runs the dependency-free dashboard behavior
tests; they can be run directly with `node --test tests/frontend.behavior.test.cjs`.
That optional test is skipped on Python-only installations.

For optional real-browser checks, install the separate pinned test dependencies
inside the project's virtual environment and provision Chromium:

```bash
python -m pip install --requirement requirements-browser.lock
python -m playwright install chromium
python scripts/check_frontend.py
```

Chromium needs the operating system libraries listed by Playwright on Linux;
the normal FastAPI container does not need browser packages. The browser check
starts its own loopback server with an in-memory database, never touches the
running demo database, checks all seven pages at 1280/768/414/375px, and saves light
and dark screenshots to `artifacts/frontend/` (Git-ignored). It exercises all
15 scenarios twice, the four demo steps, rules, exports, and a cross-client reset,
and fails on console errors or page overflow.

## Project layout

```text
app/core/       intent, fingerprints, policy, and deterministic detectors
app/audit/      SQLite-backed Black Box ledger
app/honeyworld/ fake Decoy data and no-op simulation
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

## Stack and entry points

| Layer | Technology |
| --- | --- |
| Runtime | Python 3.11+, FastAPI, Pydantic v2, Uvicorn, SQLite |
| Dashboard | Vanilla JavaScript (ES modules), HTML, CSS |
| Quality | pytest, Ruff, Mypy, axe-core via Playwright |
| Delivery | Docker, GitHub Actions, MCP |

Entry points:

- **Server:** `bulkhead-server` or `python -m uvicorn app.main:app` (`app.main:app`).
- **MCP server:** `bulkhead-mcp` (`app.agents.mcp_server:main`).
- **Hook:** `python examples/hooks/pretooluse.py < action.json`.
- **Python guard:** `BulkheadClient` and `bulkhead_guard` from `app.agents`.
- **CLI demo:** `python examples/agent_demo.py`.

Configuration uses `BULKHEAD_*` variables in [`.env.example`](.env.example)
and the environment table above.

See [features](docs/FEATURES.md), [architecture](docs/ARCHITECTURE.md),
[API](docs/API.md), and [security](docs/SECURITY.md) for focused references.

## Limitations

Bulkhead evaluates descriptive actions; it does not execute tools, read host
files, run commands, or make outbound requests. The Decoy and attack library
are synthetic. SQLite is the default ledger, while active Decoy files and
public-demo sessions/rate limits are process-local. Durable multi-process
storage and centralized identity are outside this demo gateway.

## Safety boundary

Use only fake secrets, mock tools, and non-production targets while developing
or demonstrating Bulkhead. Never put API keys, browser cookies, private keys, or
production credentials in fixtures, requests, logs, or the repository.
