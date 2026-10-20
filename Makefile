.PHONY: test lint type frontend accessibility

test:
	python -m pytest

lint:
	ruff check .

type:
	python -m mypy

frontend:
	npm test

accessibility:
	python scripts/check_frontend.py
