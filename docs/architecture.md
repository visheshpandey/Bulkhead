# Bulkhead architecture

## Exact evaluation pipeline

Every descriptive `AgentAction` follows this ordered pipeline inside
`PolicyGateway`:

```text
normalise → fingerprint → immunity → detectors → intent → decision → ledger/HoneyWorld
```

1. **normalize** — canonicalize the target path and normalize detector text
   (URL/HTML decoding, Unicode confusables, zero-width characters, common
   leetspeak, and separator changes).
2. **fingerprint** — hash the canonical action type, target, detector labels,
   and content into a stable short fingerprint. Agent ID and metadata are not
   part of the operation identity.
3. **Rule** — look up an enabled fingerprint Rule. A match is immediately
   `Blocked` with the `known_quarantined_action` finding and increments the
   Rule's match count.
4. **detectors** — inspect target, content, payload, and metadata for prompt
   injection, sensitive files/fields/material, secret exfiltration, and
   destructive commands. Base64 and hex text are decoded for inspection.
5. **intent** — compare action type, normalized target, denied/allowed target
   roots, and network permission with the supplied `UserIntent`.
6. **decision** — choose Allowed, Blocked, or Decoyed (wire values remain
   `allow`, `block`, or `quarantine`). Destructive commands and intent violations
   block; high-severity security findings are decoyed unless an enabled Rule
   already blocked them.
7. **ledger/Decoy** — persist the `AuditEvent` in SQLite. A Decoyed action
   also persists an `Attack`, generates a Rule, and (when `run_honeyworld` is
   true) records a simulated Decoy capture. No shell,
   filesystem, network, or GitHub operation is executed.

## Components

```text
AgentClient / dashboard
          │ descriptive HTTP request
          ▼
FastAPI routes → PolicyGateway → EventLedger (SQLite)
                         │                 └→ events, incidents, rules, captures
                          └→ Decoy (fake data; no-op external actions)
```

The API accepts either an `action` object or flat `action_type`, `target`,
`payload`, `content`, `agent_id`, and `metadata` fields. Supported action types
are Read file, Write file, Run command, Web request, and GitHub action. The
wire values are `read_file`, `write_file`, `run_command`, `http_request`, and
`github_action`.

## SQLite persistence

`EventLedger` defaults to `./data/bulkhead.db`, overridable with
`BULKHEAD_DB_PATH`. File-backed ledgers create their parent directory, enable
SQLite WAL mode, and persist these collections:

- `events`: every evaluation and its decision/findings;
- `incidents`: Attack records and fingerprints;
- `immunity_rules`: generated Rules, enabled state, match count, and timestamp;
- `honeyworld_captures`: simulated Decoy receipts.

Opening another `EventLedger` on the same database reloads those records. The
active HoneyWorld decoy files and its in-process action list are reset when the
process starts, while capture receipts remain durable in SQLite. `/api/reset-demo`
deletes all four collections and resets the decoys. `:memory:` remains available
for isolated tests.

## Security boundaries

- The HTTP service is local-first; configure an API key with `BULKHEAD_API_KEY`
  when a caller must authenticate.
- `AgentAction` is descriptive data. Bulkhead never executes the proposed tool
  call or makes external network requests.
- HoneyWorld contains only fake files and returns explicit
  `network_called: false` and `shell_called: false` receipts.
- `examples/attacks/` is a synthetic attack library. Never add real secrets,
  cookies, private keys, or production targets.
- Docker creates writable `/app/data` and runs as the non-root `bulkhead` user;
  `data/` and `.env` are ignored by Git.

## Attack library and agent integration

`GET /api/attacks` exposes the dashboard presets for path traversal,
workspace-prefix confusion, secret paths and payloads, shell/network
exfiltration, encoded/obfuscated prompt injection, destructive commands, and a
safe control. The standard-library agent integration is in `app/agents/`; run
its end-to-end example with:

```bash
python examples/agent_demo.py
```

The API demo (`POST /api/demo`) resets the ledger and evaluates a safe README
read, a synthetic webpage instruction aimed at `.env`, and the same action a
second time. The expected decisions are Allowed → Decoyed → Blocked.

## Configuration and delivery

`.env.example` documents every supported variable: `BULKHEAD_ENV`,
`BULKHEAD_HOST`, `BULKHEAD_PORT`, `BULKHEAD_DB_PATH`, `BULKHEAD_API_KEY`, and
`BULKHEAD_LLM_JUDGE`. The host/port variables are documentation-friendly local
settings; the documented commands pass them to Uvicorn explicitly.

CI provisions Python 3.11.9, installs the pinned `requirements.lock`, and runs
`ruff check .` followed by `python -m pytest`.
