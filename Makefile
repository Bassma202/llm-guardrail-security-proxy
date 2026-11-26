PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
BANDIT ?= .venv/bin/bandit

.PHONY: test lint security benchmark serve

test:
	$(PYTEST) -v --cov=src/aletheia

lint:
	$(RUFF) check src tests scripts

security:
	$(BANDIT) -r src -q --severity-level high

benchmark:
	$(PYTHON) scripts/run_aletheia_benchmark.py

benchmark-live:
	$(PYTHON) scripts/run_aletheia_benchmark.py --live-ollama

serve:
	.venv/bin/uvicorn aletheia.web:create_app --factory --host 127.0.0.1 --port 8005
