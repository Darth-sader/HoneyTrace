# HoneyTrace developer workflow. The runtime targets Linux; these targets
# also work on any POSIX-ish host for development and test purposes.
PYTHON ?= python3

.PHONY: help setup install lint test unit integration performance run demo clean verify clean-decoys

help:
	@echo "setup        - create .venv and install package with extras"
	@echo "install      - pip install -e . into the active environment"
	@echo "lint         - compile-check every python file"
	@echo "test         - run the full test suite (skip slow perf tests)"
	@echo "unit         - unit tests only"
	@echo "integration  - integration tests only"
	@echo "run          - start the daemon in the foreground (observe mode)"
	@echo "demo         - run the one-click isolated demo scenario"
	@echo "verify       - verify the evidence journal, chain and manifest"
	@echo "clean        - remove caches and build droppings (keeps evidence)"

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -U pip
	.venv/bin/pip install -e ".[decoys,gui,capture,dev]"
	@echo "Activate with: source .venv/bin/activate"

install:
	$(PYTHON) -m pip install -e ".[decoys,gui,capture,dev]"

lint:
	$(PYTHON) -m compileall -q src tests scripts || true
	$(PYTHON) -m compileall -q src tests

test:
	$(PYTHON) -m pytest -m "not slow"

unit:
	$(PYTHON) -m pytest tests/unit

integration:
	$(PYTHON) -m pytest tests/integration

performance:
	$(PYTHON) -m pytest tests/performance -m slow

run:
	$(PYTHON) -m honeytrace run

demo:
	./scripts/demo.sh

verify:
	$(PYTHON) -m honeytrace verify

clean-decoys:
	$(PYTHON) -m honeytrace decoys clean

clean:
	rm -rf .pytest_cache build dist src/*.egg-info
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
