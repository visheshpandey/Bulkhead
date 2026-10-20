"""Presentation and deterministic lab services shared by HTTP route wrappers."""

from __future__ import annotations

import csv
import io
import json
import time
from collections import Counter, defaultdict
from typing import Any

from fastapi.responses import PlainTextResponse

from app.agents.lab_parser import parse_instruction_actions
from app.core.models import ActionType, AgentAction, Decision, Incident, UserIntent
from app.core.policy import PolicyGateway
from app.core.public_demo import DemoSession, LabScore

ACTION_LABELS = {
    ActionType.READ_FILE: "Read file",
    ActionType.WRITE_FILE: "Write file",
    ActionType.RUN_COMMAND: "Run command",
    ActionType.HTTP_REQUEST: "Web request",
    ActionType.GITHUB_ACTION: "GitHub action",
}
DECISION_LABELS = {
    Decision.ALLOW: "Allowed",
    Decision.BLOCK: "Blocked",
    Decision.QUARANTINE: "Decoyed",
}


def json_model(value: Any) -> dict[str, Any]:
    """Convert a Pydantic model to JSON-compatible fields."""
    if hasattr(value, "model_dump"):
        result: dict[str, Any] = value.model_dump(mode="json")
        return result
    if isinstance(value, dict):
        return value
    raise TypeError("Expected a model or dictionary for JSON export")


def export_payload(gw: PolicyGateway) -> dict[str, list[dict[str, Any]]]:
    """Collect the four audit collections for a JSON export."""
    return {
        "events": [json_model(item) for item in gw.ledger.events()],
        "incidents": [json_model(item) for item in gw.ledger.incidents()],
        "immunity_rules": [json_model(item) for item in gw.ledger.immunity_rules()],
        "honeyworld_captures": [
            {key: value.isoformat() if hasattr(value, "isoformat") else value for key, value in item.items()}
            for item in gw.ledger.captures()
        ],
    }


def audit_csv(gw: PolicyGateway) -> PlainTextResponse:
    """Render events as a downloadable CSV response."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Agent ID", "Action", "Target", "Decision", "Risk", "Reason"])
    for event in gw.ledger.events():
        writer.writerow([
            event.id, event.timestamp.isoformat(), event.agent_id or "",
            ACTION_LABELS.get(event.action.action_type, getattr(event.action.action_type, "value", event.action.action_type)),
            event.action.target,
            DECISION_LABELS.get(event.decision, getattr(event.decision, "value", event.decision)),
            event.risk_score, event.reason,
        ])
    return PlainTextResponse(output.getvalue(), media_type="text/csv")


def audit_stats(gw: PolicyGateway) -> dict[str, Any]:
    """Summarize decisions, findings, agents and recent request volume."""
    events = gw.ledger.events()
    incidents = gw.ledger.incidents()
    rules = gw.ledger.immunity_rules()
    by_decision = {decision.value: sum(event.decision == decision for event in events) for decision in Decision}
    by_agent: dict[str, int] = defaultdict(int)
    for event in events:
        by_agent[event.agent_id if event.agent_id is not None else "null"] += 1
    now = time.time()
    recent_events = [event for event in events if now - event.timestamp.timestamp() <= 60]
    top_findings = Counter(finding.label for event in events for finding in event.findings).most_common(10)
    return {
        "events": len(events), "incidents": len(incidents), "immunity_rules": len(rules),
        "honeyworld_captures": len(gw.ledger.captures()),
        "threats_contained": sum(event.decision in {Decision.BLOCK, Decision.QUARANTINE} for event in events),
        "requests_per_minute": len(recent_events),
        "top_finding_labels": [{"label": label, "count": count} for label, count in top_findings],
        "by_decision": by_decision, "by_agent": dict(by_agent),
        "counts": {
            "events": len(events), "incidents": len(incidents), "immunity_rules": len(rules),
            "honeyworld_captures": len(gw.ledger.captures()),
        },
    }


def incident_markdown(incident: Incident, gw: PolicyGateway) -> str:
    """Render an incident and associated decoy receipt as Markdown."""
    findings = "\n".join(
        f"- **{finding.label}** ({finding.category}): {finding.evidence} [severity {finding.severity}]"
        for finding in incident.findings
    ) or "- None"
    action = json.dumps(json_model(incident.action), indent=2)
    event = gw.ledger.get_event(incident.event_id)
    honeyworld = json.dumps(event.honeyworld_result if event else None, indent=2, default=str)
    rule_id = incident.immunity_rule_id or (event.immunity_rule_id if event else None) or "None"
    return (
        f"# Bulkhead Attack {incident.id}\n\n"
        f"- Status: **{incident.status}**\n"
        f"- Created: `{incident.created_at.isoformat()}`\n"
        f"- Event: `{incident.event_id}`\n"
        f"- Fingerprint: `{incident.fingerprint}`\n\n"
        f"- Rule created: `{rule_id}`\n"
        f"- Event timestamp: `{event.timestamp.isoformat() if event else 'Unknown'}`\n\n"
        "## Action\n\n```json\n"
        f"{action}\n```\n\n"
        "## Findings\n\n"
        f"{findings}\n"
        "## Decoy (fake data) receipt\n\n```json\n"
        f"{honeyworld}\n```\n"
    )


def attack_catalog() -> dict[str, list[dict[str, str]]]:
    """Return the stable catalog of demonstration attack labels."""
    return {
        "attacks": [
            {"id": "path-traversal", "name": "Path traversal", "expected": "block"},
            {"id": "workspace-evil", "name": "/workspace-evil folder trick", "expected": "block"},
            {"id": "curl-env", "name": "curl .env theft", "expected": "quarantine"},
            {"id": "nc-pipe", "name": "nc pipe", "expected": "quarantine"},
            {"id": "leet-injection", "name": "Leetspeak injection", "expected": "quarantine"},
            {"id": "zero-width", "name": "Zero-width injection", "expected": "quarantine"},
            {"id": "base64-injection", "name": "Base64 injection", "expected": "quarantine"},
            {"id": "payload-key", "name": "API key in payload", "expected": "quarantine"},
            {"id": "webpage-injection", "name": "Injection hidden in a webpage", "expected": "quarantine"},
            {"id": "rm-root", "name": "rm -rf /", "expected": "block"},
            {"id": "git-force", "name": "git force push", "expected": "block"},
            {"id": "safe-readme", "name": "Safe README read", "expected": "allow"},
        ]
    }


def lab_run(gw: PolicyGateway, session: DemoSession | None, page: str, score: LabScore) -> dict[str, Any]:
    """Evaluate a fetched page, inferred tool actions and final reply in order."""
    intent = UserIntent(
        goal="Summarise this page",
        allowed_actions=[ActionType.HTTP_REQUEST, ActionType.READ_FILE, ActionType.RUN_COMMAND, ActionType.GITHUB_ACTION],
        allowed_targets=["https://docs.example/", "/workspace/"],
        denied_targets=["/workspace/.env", "/workspace/.ssh/"],
        allow_network=True,
    )
    fetch = AgentAction(
        action_type=ActionType.HTTP_REQUEST,
        target="https://docs.example/setup",
        metadata={"simulated": True, "purpose": "fetch webpage"},
    )
    reply = AgentAction(
        action_type=ActionType.READ_FILE,
        target="/workspace/summary.txt",
        content="The agent replies with a summary of the requested page.",
    )
    parsed_actions = parse_instruction_actions(page)
    actions = [fetch, *parsed_actions, reply]
    steps: list[dict[str, Any]] = []
    for action in actions:
        result = gw.evaluate(action, intent, agent_id="public-lab")
        steps.append({
            "action": action.model_dump(mode="json"),
            "decision": result.decision.value,
            "allowed": result.allowed,
            "reason": result.reason,
            "risk_score": result.risk_score,
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
            "honeyworld": result.honeyworld,
            "event_id": result.event.id,
        })
    attack_steps = steps[1:-1]
    is_attack = bool(parsed_actions)
    stopped = is_attack and all(step["decision"] != Decision.ALLOW.value for step in attack_steps)
    if is_attack:
        if session is not None:
            session.lab_attempts += 1
            if stopped:
                session.lab_stopped += 1
            else:
                session.lab_bypassed += 1
            scoreboard = {
                "attempts": session.lab_attempts,
                "stopped": session.lab_stopped,
                "bypassed": session.lab_bypassed,
            }
        else:
            score.record(stopped=stopped)
            scoreboard = score.snapshot()
    else:
        scoreboard = (
            {
                "attempts": session.lab_attempts,
                "stopped": session.lab_stopped,
                "bypassed": session.lab_bypassed,
            }
            if session is not None
            else score.snapshot()
        )
    return {"steps": steps, "scoreboard": scoreboard, "stopped": stopped, "state": gw.state()}
