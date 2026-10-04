PY := python3
E2E_DIR := tests/e2e

.PHONY: build test test-e2e lint precommit clean

# nothing to compile, but every file has to at least parse and import
build:
	$(PY) -m compileall -q dexter.py mixer.py tests
	$(PY) dexter.py --help > /dev/null

test: test-e2e

test-e2e: build
	$(PY) -m unittest discover -s $(E2E_DIR) -p 'test_*.py' -v

# the config is data the tool acts on, so it is linted as such
lint:
	ruff check .

precommit: lint test-e2e

clean:
	rm -rf $(E2E_DIR)/__pycache__ __pycache__
