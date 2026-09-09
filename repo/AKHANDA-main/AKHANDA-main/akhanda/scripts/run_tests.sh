#!/usr/bin/env bash
# Full test suite. No hardware required.
#   bash scripts/run_tests.sh            all tests
#   bash scripts/run_tests.sh -k witness just the witness ones
set -e
export PYTHONPATH=src
python -m pytest tests/ -v "$@"
