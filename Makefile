.PHONY: test

test:
	python -m pytest
	node --test tests/frontend.behavior.test.cjs
