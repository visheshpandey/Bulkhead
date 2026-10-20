# HTTP API

Run `python -m uvicorn app.main:app`; the local API defaults to
`http://127.0.0.1:8000`. FastAPI serves the authoritative live schema at
`/openapi.json` and interactive reference at `/docs`.

| Method | Path | Request | Successful response | Errors |
| --- | --- | --- | --- | --- |
| GET | `/health`, `/healthz`, `/api/health` | none | `{"status":"ok","service":"bulkhead"}` | 200 |
| GET | `/api/default-intent` | none | `UserIntent` JSON | 200 |
| GET | `/api/state`, `/api/stats` | none | state or aggregate counts | 200 |
| GET | `/api/events`, `/api/events/{event_id}` | optional `limit`, `offset` | event list or event object | 200 / 404 |
| GET | `/api/stream` | none | `text/event-stream` audit/reset frames | 200 |
| POST | `/api/evaluate` | action JSON below | decision, findings, event, optional decoy | 200 / 401 / 422 / 429 |
| POST | `/api/demo`, `/api/demo/run` | optional `X-Agent-Id` | three-step demo response | 200 / 422 |
| POST | `/api/reset-demo`, `/api/reset` | none | reset status and state | 200 |
| GET | `/api/attacks`, `/api/incidents`, `/api/rules` | none | synthetic presets or collection | 200 |
| GET | `/api/incidents/{incident_id}/report` | none | Markdown attack report | 200 / 404 |
| PATCH | `/api/rules/{rule_id}` | `{"enabled":true}` | updated Rule | 200 / 404 / 422 |
| DELETE | `/api/rules/{rule_id}` | none | `{"status":"deleted","id":"..."}` | 200 / 404 |
| GET | `/api/events/export?format=json` | `format=json` or `csv` | export object or CSV | 200 / 422 |
| POST | `/api/lab/run`, `/api/lab/report` | `{"page":"..."}` | lab score or recorded note | 200 / 422 / 429 |

`POST /api/evaluate` accepts either an `action` object or flat `action_type`
and `target` fields. Wire action types: `read_file`, `write_file`,
`run_command`, `http_request`, `github_action`. Decisions: `allow`, `block`,
`quarantine`. When `BULKHEAD_API_KEY` is set, evaluation requires
`X-Bulkhead-Key`, `X-API-Key`, or `Authorization: Bearer ...`. Optional
`X-Agent-Id` records caller identity.

```bash
curl -X POST http://127.0.0.1:8000/api/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"read_file","target":"/workspace/README.md"}'
```

Example response:

```json
{"decision":"allow","allowed":true,"risk_score":0,"reason":"Action matches the current user intent; low-severity keyword signals were recorded without blocking."}
```

The request may instead contain `action: { ... }`. All JSON bodies reject
unknown fields. `X-Agent-Id` is optional and is stored separately from the
compatibility `action.agent_id` field.

Compatibility aliases exist for selected routes; inspect the live schema for
the current complete list.
