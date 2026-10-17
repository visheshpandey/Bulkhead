"""Small deterministic detectors used by the local MVP policy engine."""

from __future__ import annotations

import re

from .models import AgentAction, ThreatCategory, ThreatFinding


class ThreatDetector:
    """Detect common prompt-injection and credential handling signals."""

    _injection_patterns = (
        ("ignore_previous_instructions", r"ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?"),
        ("override_system_prompt", r"(?:override|reveal|show|print)\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|message|instructions?)"),
        ("jailbreak_request", r"\b(?:jailbreak| DAN mode|developer mode)\b"),
        ("untrusted_page_instruction", r"(?:webpage|page|document)\s+(?:says|instructs?|tells?)\s+you"),
    )
    _secret_patterns = (
        ("dotenv_access", r"(?:^|[\s/])\.env(?:$|[\s/?#])"),
        ("private_key_access", r"(?:id_rsa|private[_ -]?key|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)"),
        ("credential_access", r"\b(?:api[_ -]?key|access[_ -]?token|password|secret|credentials?)\b"),
    )
    _exfil_patterns = (
        ("secret_to_network", r"(?:send|upload|post|put|exfiltrat\w*|forward).{0,100}(?:secret|token|key|credential|\.env)"),
        ("network_sink", r"(?:webhook|https?://|curl\s|http_request).{0,100}(?:secret|token|key|credential|\.env)"),
    )

    def inspect(self, action: AgentAction) -> list[ThreatFinding]:
        text = action.searchable_text()
        lowered = text.lower()
        findings: list[ThreatFinding] = []
        for label, pattern in self._injection_patterns:
            match = re.search(pattern, lowered, flags=re.IGNORECASE)
            if match:
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        label=label,
                        evidence=match.group(0)[:160],
                        severity=75,
                    )
                )
        secret_matches: list[str] = []
        for label, pattern in self._secret_patterns:
            match = re.search(pattern, lowered, flags=re.IGNORECASE)
            if match:
                secret_matches.append(label)
        exfil_match = next(
            (re.search(pattern, lowered, flags=re.IGNORECASE) for _, pattern in self._exfil_patterns),
            None,
        )
        if secret_matches and (action.action_type in {"read_file", "write_file", "http_request"} or exfil_match):
            evidence = ", ".join(secret_matches)
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.SECRET_EXFILTRATION,
                    label="sensitive_data_access",
                    evidence=evidence,
                    severity=90 if exfil_match else 80,
                )
            )
        if exfil_match:
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.SECRET_EXFILTRATION,
                    label="secret_to_network",
                    evidence=exfil_match.group(0)[:160],
                    severity=95,
                )
            )
        return findings
