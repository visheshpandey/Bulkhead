"""Deterministic, conservative detectors used by the local policy engine."""

from __future__ import annotations

import base64
import binascii
import html
import posixpath
import re
import unicodedata
from collections.abc import Iterator
from re import Pattern
from typing import Any, ClassVar
from urllib.parse import unquote

from .models import AgentAction, ThreatCategory, ThreatFinding

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f\u206a\u206b\u206c\u206d\u206e\u206f\ufeff"))
_ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_SEPARATOR_PATTERN = re.compile(r"[^a-z0-9]+")
_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
_HEX_PATTERN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_DECODE_ROUNDS = 2

# A small, intentional confusable map catches common Cyrillic/Greek substitutions
# without trying to transliterate arbitrary user content.
_CONFUSABLES = str.maketrans({
    "а": "a", "с": "c", "е": "e", "і": "i", "ο": "o", "о": "o",
    "р": "p", "ѕ": "s", "х": "x", "у": "y", "Α": "a", "Ε": "e",
    "Ι": "i", "Ο": "o", "Ρ": "p", "Χ": "x", "Υ": "y", "А": "a", "С": "c",
    "Е": "e", "І": "i", "О": "o", "Р": "p", "Ѕ": "s", "Х": "x", "У": "y",
})


def normalize_posix_target(value: str) -> str:
    """Normalize a local target without allowing traversal outside its root.

    Bulkhead targets are POSIX paths even when the gateway runs on Windows.  URL
    targets are returned as URLs because collapsing ``https://`` would change
    their meaning; filesystem targets use POSIX separators and ``normpath``.
    """
    if not isinstance(value, str):
        raise TypeError("target must be a string")
    value = value.strip()
    if not value:
        return ""
    if "\x00" in value or any(ord(character) < 32 for character in value):
        raise ValueError("target contains a control character")
    if "://" in value:
        return value.rstrip("/")
    candidate = value.replace("\\", "/")
    normalized = posixpath.normpath(candidate)
    if normalized == ".." or normalized.startswith("../"):
        raise ValueError("target escapes its POSIX root")
    if candidate.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def normalize_detection_text(value: str) -> str:
    """Decode common disguises and create a separator-insensitive text view."""
    if not isinstance(value, str):
        raise TypeError("detection text must be a string")
    text = value
    for _ in range(_DECODE_ROUNDS):
        text = html.unescape(unquote(text))
        text = _ESCAPE_PATTERN.sub(lambda match: chr(int(match.group(1) or match.group(2), 16)), text)
    text = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES).translate(_ZERO_WIDTH)
    text = text.translate(str.maketrans("013457@$", "oieast as".replace(" ", "")))
    text = text.casefold()
    return _SEPARATOR_PATTERN.sub(" ", text).strip()


normalize_text = normalize_detection_text


def _decode_common_text(value: str) -> str:
    """Decode transport escapes while retaining punctuation for path/shell rules."""
    text = value
    for _ in range(_DECODE_ROUNDS):
        text = html.unescape(unquote(text))
        text = _ESCAPE_PATTERN.sub(lambda match: chr(int(match.group(1) or match.group(2), 16)), text)
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES).translate(_ZERO_WIDTH)


def _iter_values(value: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, str(key)
            yield from _iter_values(child, child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{path}[{index}]")
    else:
        yield path, str(value)


def _decoded_base64_text(values: Iterator[tuple[str, str]]) -> str:
    decoded: list[str] = []
    for _, value in values:
        for token in _BASE64_PATTERN.findall(value):
            try:
                raw = base64.b64decode(token, validate=True)
                text = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if text and sum(character.isprintable() or character.isspace() for character in text) / len(text) > 0.85:
                decoded.append(text)
    return "\n".join(decoded)


def _decoded_hex_text(values: Iterator[tuple[str, str]]) -> str:
    decoded: list[str] = []
    for _, value in values:
        for token in _HEX_PATTERN.findall(value):
            try:
                text = bytes.fromhex(token).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if text and all(character.isprintable() or character.isspace() for character in text):
                decoded.append(text)
    return "\n".join(decoded)


class ThreatDetector:
    """Detect prompt injection, sensitive-data handling, and dangerous shell use."""

    _injection_patterns: ClassVar[tuple[tuple[str, Pattern[str]], ...]] = tuple(
        (label, re.compile(pattern, re.IGNORECASE))
        for label, pattern in (
            ("ignore_previous_instructions", r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b"),
            ("disregard_previous_instructions", r"\bdisregard\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b"),
            ("override_system_prompt", r"\b(?:override|reveal|show|print)\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|message|instructions?)\b"),
            ("jailbreak_request", r"\b(?:jailbreak|dan\s+mode|developer\s+mode)\b"),
            ("untrusted_page_instruction", r"\b(?:webpage|page|document)\s+(?:says|instructs?|tells?)\s+you\b"),
        )
    )
    _secret_path_patterns: ClassVar[tuple[tuple[str, Pattern[str]], ...]] = tuple(
        (label, re.compile(pattern, re.IGNORECASE))
        for label, pattern in (
            ("dotenv_access", r"(?:^|[\s/])\.env(?:$|[\s/?#])"),
            ("private_key_access", r"(?:id[_ -]?rsa|id[_ -]?ed25519|private[_ -]?key|begin\s+(?:rsa\s+)?private\s+key)"),
            ("credential_path_access", r"(?:\.ssh|\.aws/credentials|kubeconfig|credentials?\.json|[^\s/]+\.pem)"),
        )
    )
    _secret_field_pattern: ClassVar[Pattern[str]] = re.compile(
        r"(?:^|[._\[ -])(?:api[_ -]?key|apikey|access[_ -]?(?:token|key)|auth[_ -]?token|password|passwd|secret|token|authorization|credential|private[_ -]?key)(?:$|[._\] -])",
        re.IGNORECASE,
    )
    _secret_material_patterns: ClassVar[tuple[Pattern[str], ...]] = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"-----begin\s+(?:rsa\s+)?private\s+key-----",
            r"\b(?:sk-[a-z0-9]{10,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]+|AKIA[0-9A-Z]{16}|xox[baprs]-[a-z0-9-]+)\b",
            r"\beyJ[a-z0-9_-]+\.eyJ[a-z0-9_-]+\.[a-z0-9_-]+\b",
            r"\b(?:bearer|basic)\s+[a-z0-9+/=_-]{12,}",
            r"\b(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]",
        )
    )
    # A keyword in prose is useful telemetry, but is not evidence that a secret
    # was accessed.  These words deliberately produce only a low-risk finding;
    # policy decides whether a network/exfiltration signal raises the outcome.
    _sensitive_mention_pattern = re.compile(
        r"\b(?:api\s*key|access\s*token|auth\s*token|password|passwd|credential(?:s)?|private\s*key|secret|token)\b",
        re.IGNORECASE,
    )
    _exfil_patterns: ClassVar[tuple[Pattern[str], ...]] = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\b(?:send|upload|post|put|exfiltrat\w*|forward|share)\b.{0,120}\b(?:secret|token|key|credential|password|dotenv|env)\b",
            r"\b(?:webhook|https?://|curl|wget|http_request)\b.{0,120}\b(?:secret|token|key|credential|password|dotenv|env)\b",
        )
    )
    _shell_exfil_patterns: ClassVar[tuple[Pattern[str], ...]] = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\b(?:cat|head|tail|grep|awk|sed|cut|env|printenv|set)\b[^\n]{0,180}(?:\.env|credentials?|private[_ -]?key|secret|token)[^\n]{0,180}\b(?:curl|wget|nc|netcat|scp|ftp)\b",
            r"\b(?:curl|wget|nc|netcat)\b[^\n]{0,180}(?:--data|--data-raw|-d|--upload-file|--post-file)[^\n]{0,180}(?:cat|printenv|env|\.env|credentials?|secret|token)\b",
            r"\$\([^)]*(?:cat|printenv|env)[^)]*(?:\.env|credentials?|secret|token)[^)]*\)[^\n]{0,120}\b(?:curl|wget|nc|netcat)\b",
            r"\b(?:curl|wget)\b[^\n]*(?:-d|--data(?:-raw|-binary)?|-F|--form|-T|--upload-file|--post-file|@)[^\n]*(?:\.env|\.ssh|\.aws|credentials?|secret|token|key)",
            r"\b(?:nc|ncat|netcat|socat)\b[^\n]*(?:\.env|credentials?|secret|token|key|cat\s+)",
            r"\b(?:scp|rsync)\b[^\n]*(?:@|:)[^\n]*(?:\.env|credentials?|secret|token|key)",
            r"\b(?:scp|rsync)\b[^\n]*(?:\.env|credentials?|secret|token|key)[^\n]*(?:@|:)",
            r"(?:\.env|credentials?|secret|token|key)[^\n]*\|\s*(?:base64|xxd)\b",
            r"/dev/tcp/",
            r"\b(?:python|python3|powershell)(?:\s+-c)?[^\n]*(?:https?://|curl|wget|Invoke-WebRequest)",
        )
    )
    _destructive_patterns: ClassVar[tuple[tuple[str, Pattern[str]], ...]] = tuple(
        (label, re.compile(pattern, re.IGNORECASE))
        for label, pattern in (
            ("recursive_root_delete", r"\brm\s+(?:-\w*\s+)*-?r\w*(?:\s+-\w+)*\s+/(?:\s|$)"),
            ("root_delete_with_override", r"\brm\b[^\n]*\s--no-preserve-root\s+/(?:\s|$)"),
            ("filesystem_format", r"\b(?:mkfs(?:\.[a-z0-9]+)?|fdisk|format\s+[a-z]:)\b"),
            ("raw_disk_overwrite", r"\bdd\b[^\n]*\bif="),
            ("chmod_world_writable_root", r"\bchmod\s+(?:-R\s+)?777\s+/"),
            ("fork_bomb", r":\s*\(\s*\)\s*\{[^}]*:\s*\|[^}]*&[^}]*\}\s*;\s*:"),
            ("system_shutdown", r"\b(?:shutdown|poweroff|reboot|halt)\b"),
            ("force_push", r"\bgit\s+push\b[^\n]*--force(?:\s|$)"),
            ("hard_reset_main", r"\bgit\s+reset\s+--hard\b[^\n]*\bmain\b"),
        )
    )

    def inspect(self, action: AgentAction) -> list[ThreatFinding]:
        """Inspect all action fields and return deduplicated threat findings."""
        fields = list(_iter_values({"target": action.target, "content": action.content or "", "payload": action.payload, "metadata": action.metadata}, "action"))
        raw_text = "\n".join(value for _, value in fields)
        detection_text = normalize_detection_text(raw_text)
        decoded_source_text = "\n".join(_decode_common_text(value) for _, value in fields)
        decoded_source_text += "\n" + _decoded_base64_text(iter(fields)) + "\n" + _decoded_hex_text(iter(fields))
        decoded_text = normalize_detection_text(decoded_source_text)
        combined = f"{detection_text} {decoded_text}".strip()
        findings: list[ThreatFinding] = []

        for label, pattern in self._injection_patterns:
            match = pattern.search(raw_text) or pattern.search(combined)
            if match:
                findings.append(self._finding(ThreatCategory.PROMPT_INJECTION, label, match.group(0), 75))

        secret_path_labels, keyword_labels = self._secret_labels(fields, raw_text, decoded_source_text, combined)

        shell_sources = (raw_text, decoded_source_text, detection_text)
        shell_exfil_match = next(
            (
                match
                for source in shell_sources
                for pattern in self._shell_exfil_patterns
                if (match := pattern.search(source))
            ),
            None,
        )
        exfil_match = next((pattern.search(combined) for pattern in self._exfil_patterns), None)
        if shell_exfil_match:
            exfil_match = exfil_match or shell_exfil_match
            findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "shell_secret_exfiltration", shell_exfil_match.group(0), 98))
            findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "secret_to_network", shell_exfil_match.group(0), 95))
        if secret_path_labels:
            findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "sensitive_file_access", ", ".join(secret_path_labels), 80))
        if keyword_labels:
            findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "sensitive_keyword_mention", ", ".join(keyword_labels), 30))
            findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "sensitive_data_access", ", ".join(keyword_labels), 30))
        findings.extend(self._mentions(fields, action.target))
        findings = self._deduplicate_findings(findings)
        network_action = action.action_type in {"http_request", "github_action"}
        keyword_mention_present = any(finding.label == "sensitive_keyword_mention" for finding in findings)
        sensitive_signal_present = bool(secret_path_labels or keyword_labels or keyword_mention_present)
        if (exfil_match or network_action and sensitive_signal_present) and sensitive_signal_present:
            evidence = exfil_match.group(0) if exfil_match else "network action with sensitive payload"
            if not any(finding.label == "secret_to_network" for finding in findings):
                findings.append(self._finding(ThreatCategory.SECRET_EXFILTRATION, "secret_to_network", evidence, 95))

        for label, pattern in self._destructive_patterns:
            match = pattern.search(raw_text)
            if match:
                findings.append(self._finding(ThreatCategory.DESTRUCTIVE_COMMAND, label, match.group(0), 85))
        return findings

    def _secret_labels(
        self, fields: list[tuple[str, str]], raw_text: str, decoded_source_text: str, combined: str,
    ) -> tuple[list[str], list[str]]:
        secret_path_labels = [
            label for label, pattern in self._secret_path_patterns if pattern.search(raw_text) or pattern.search(decoded_source_text)
        ]
        keyword_labels = [
            f"sensitive_field:{path}"
            for path, _ in fields
            if path != "action.target" and self._secret_field_pattern.search(normalize_detection_text(path))
        ]
        secret_path_labels = list(dict.fromkeys(secret_path_labels))
        keyword_labels = list(dict.fromkeys(keyword_labels))
        if any(
            pattern.search(source)
            for pattern in self._secret_material_patterns
            for source in (raw_text, decoded_source_text, combined)
        ):
            keyword_labels.append("secret_material")
        return secret_path_labels, keyword_labels

    def _mentions(self, fields: list[tuple[str, str]], target: str) -> list[ThreatFinding]:
        mentions = [value for path, value in fields if path != "action.target"]
        if any(self._sensitive_mention_pattern.search(normalize_detection_text(value)) for value in mentions) or self._sensitive_mention_pattern.search(normalize_detection_text(target)):
            return [self._finding(ThreatCategory.SECRET_EXFILTRATION, "sensitive_keyword_mention", "sensitive keyword in user content or target", 30)]
        return []

    @staticmethod
    def _deduplicate_findings(findings: list[ThreatFinding]) -> list[ThreatFinding]:
        unique: list[ThreatFinding] = []
        seen: set[tuple[str, str, str, int]] = set()
        for finding in findings:
            key = (str(finding.category), finding.label, finding.evidence, finding.severity)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    @staticmethod
    def _finding(category: ThreatCategory, label: str, evidence: str, severity: int) -> ThreatFinding:
        return ThreatFinding(category=category, label=label, evidence=evidence[:160], severity=severity)
