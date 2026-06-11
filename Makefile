# Aegis Foundry developer tasks.
# Windows users without make can run the underlying python commands directly,
# e.g.  python demo/run_pipeline.py --auto-approve

PYTHON ?= python

.PHONY: install test demo demo-interactive fixtures app lint up

# Install the package in editable mode with dev extras (pytest).
install:
	$(PYTHON) -m pip install -e .[dev]

# Run the unit test suite.
test:
	$(PYTHON) -m pytest

# Run the deterministic offline demo end-to-end (governor auto-approves).
demo:
	$(PYTHON) demo/run_pipeline.py --auto-approve

# Same demo but with the interactive human-approval gate.
demo-interactive:
	$(PYTHON) demo/run_pipeline.py

# Regenerate the deterministic event/advisory fixtures.
fixtures:
	$(PYTHON) demo/fixtures/generate_fixtures.py

# Package the Splunk app into dist/aegis_foundry.spl.
app:
	$(PYTHON) scripts/package_app.py

# Static lint (config in ruff.toml).
lint:
	ruff check aegis_foundry tests

# Start local Splunk + ollama containers (see docker-compose.yml).
up:
	docker compose up -d splunk ollama
