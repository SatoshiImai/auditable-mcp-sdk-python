PYTHON_VER			:= 3.14.6
VENV				:= $(PYTHON_VER)-amcp
ACTIVATE			:= . ~/.pyenv/versions/$(VENV)/bin/activate

.DEFAULT_GOAL := help
.PHONY: help env/init env/destroy env/sync env/freeze test test/target lint format spec/sync spec/check clean __require_target__

help:
	@echo 'auditable-mcp-sdk (Python) — development commands'
	@echo ''
	@echo '  make env/init      Create the pyenv virtualenv ($(VENV)) and install the project + dev deps'
	@echo '  make env/destroy   Remove the pyenv virtualenv'
	@echo '  make env/sync      Reinstall the project + dev deps into the virtualenv'
	@echo '  make env/freeze    Show installed packages'
	@echo ''
	@echo '  make test          Run the test suite (unit + conformance vectors)'
	@echo '  make test/target   Run a specific test (TARGET=tests/test_canonical.py)'
	@echo '  make lint          ruff check + mypy --strict'
	@echo '  make format        ruff format + ruff check --fix'
	@echo ''
	@echo '  make spec/check    Fail if the vendored spec/ drifted from its source'
	@echo '  make spec/sync     Re-vendor spec/ from ../mcp-audit-extension/spec'
	@echo ''
	@echo '  make clean         Remove caches and build artifacts'

# Environment: pyenv owns isolation, uv is the installer.
env/init:
	$(eval ret := $(shell pyenv versions | grep $(PYTHON_VER)))
	@if [ -n "$(ret)" ]; then \
		echo '$(PYTHON_VER) exists'; \
	else \
		(pyenv install -s $(PYTHON_VER)); \
	fi
	$(eval ret := $(shell pyenv versions | grep -P "\s$(VENV)(?=\s|$$)"))
	@if [ -n "$(ret)" ]; then \
		echo '$(VENV) exists'; \
	else \
		(pyenv virtualenv -f $(PYTHON_VER) $(VENV)); \
	fi
	@$(MAKE) env/sync
	@echo '✅ Environment ready: $(VENV)'

env/destroy:
	(pyenv uninstall -f $(VENV))

env/sync:
	( \
		$(ACTIVATE) && \
		python -m pip install --upgrade pip uv && \
		uv pip install -e . --group dev 2>&1 \
	)

env/freeze:
	( \
		$(ACTIVATE) && \
		pip freeze \
	)

test:
	( \
		$(ACTIVATE) && \
		pytest -q 2>&1 \
	)

test/target: __require_target__
	( \
		$(ACTIVATE) && \
		pytest -v $(TARGET) 2>&1 \
	)

lint:
	( \
		$(ACTIVATE) && \
		ruff check . && \
		ruff format --check . && \
		mypy 2>&1 \
	)

format:
	( \
		$(ACTIVATE) && \
		ruff format . && \
		ruff check --fix . \
	)

# Vendored spec integrity: the golden vectors must reproduce byte-for-byte (spec §8.4, §11.1).
spec/check:
	( \
		$(ACTIVATE) && \
		python scripts/sync_spec.py --check 2>&1 \
	)

spec/sync:
	( \
		$(ACTIVATE) && \
		python scripts/sync_spec.py 2>&1 \
	)

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.mypy_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.ruff_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf dist/ build/ *.egg-info

__require_target__:
	@[ -n "$(TARGET)" ] || (echo "[ERROR] Parameter [TARGET] is required" 1>&2 && echo "(e.g) make test/target TARGET=tests/test_models.py" 1>&2 && exit 1)
