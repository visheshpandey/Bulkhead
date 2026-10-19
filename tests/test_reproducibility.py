"""Repository contracts for clean-checkout setup and reproducible execution."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_reproducible_project_contract() -> None:
    assert (ROOT / ".git").exists()
    assert (ROOT / "requirements.lock").exists()
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.11.9"
    assert (ROOT / ".nvmrc").read_text(encoding="utf-8").strip() == "22.14.0"

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11.9-slim-bookworm" in dockerfile
    assert "COPY requirements.lock" in dockerfile
    assert "python -m uvicorn app.main:app" in dockerfile
    assert "/healthz" in dockerfile

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"(?m)^test:\s*$", makefile)
    assert "python -m pytest" in makefile

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = "==3.11.9"' in pyproject
    assert 'setuptools==84.0.0' in pyproject
    assert '[tool.setuptools.package-data]' in pyproject
    assert 'app = ["static/*"]' in pyproject

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for command in ("python -m pip install --requirement requirements.lock", "python -m pytest", "docker build", "docker run"):
        assert command in readme

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "BULKHEAD_API_KEY=" in env_example
    assert not re.search(r"(?:sk-|ghp_|password|secret)\s*[:=]\s*\S+", env_example, re.IGNORECASE)


def test_tracked_text_has_no_machine_absolute_paths() -> None:
    forbidden = (re.compile(r"[A-Za-z]:\\Users\\"), re.compile(r"/Users/"))
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    for raw_path in tracked:
        if not raw_path:
            continue
        path = ROOT / raw_path.decode("utf-8")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not any(pattern.search(content) for pattern in forbidden), path
