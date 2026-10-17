# AIRLOCK architecture

## First slice

The current scaffold deliberately separates the HTTP layer from the future policy engine. The first implementation slice will define a typed agent-action event and return an explainable decision:

```text
agent action → intent check → threat detection → policy decision → audit event
```

## Safety boundary

The first demo uses mock tools and fake secrets only. HoneyWorld will be an isolated local simulation, not a route to real credentials or production services.

## Planned layers

- `app/core`: intent, risk, policy, and detection rules
- `app/honeyworld`: decoy filesystem, fake secrets, and mock network
- `app/audit`: Black Box timeline and incident reports
- `app/agents`: orchestration boundary for OmniRush sub-agents
- `app/api`: local gateway and dashboard endpoints
