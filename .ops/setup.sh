#!/usr/bin/env bash
# .ops/setup.sh — acef-v0.4-freddy-adoption
#
# Idempotent environment setup. Workers MUST run this before any other work.
# Safe to re-run; checks state before mutating.
#
# Sets up: Python venv, dependencies, pre-commit hooks. M2 also: Node deps.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> ACEF v0.4 operation setup starting in $REPO_ROOT"

# --- 1. Python venv ---
if [ ! -d "venv" ]; then
  echo "==> Creating Python venv (Python 3.11+ required)"
  python3 -m venv venv
else
  echo "==> venv/ exists, skipping creation"
fi

# Activate
# shellcheck disable=SC1091
source venv/bin/activate

PY_VERSION=$(python --version 2>&1)
echo "==> Active Python: $PY_VERSION"

case "$PY_VERSION" in
  *"Python 3.11"*|*"Python 3.12"*|*"Python 3.13"*|*"Python 3.14"*)
    ;;
  *)
    echo "ERROR: Python 3.11+ required (per pyproject.toml). Got: $PY_VERSION" >&2
    exit 1
    ;;
esac

# --- 2. Python dependencies ---
echo "==> Installing/updating Python dependencies (editable + dev extras)"
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]" 2>/dev/null || pip install --quiet -e .

# Critical packages must be present
python -c "import jsonschema" 2>/dev/null || pip install --quiet jsonschema
python -c "import pydantic" 2>/dev/null || pip install --quiet pydantic
python -c "import pytest" 2>/dev/null || pip install --quiet pytest
python -c "import ruff" 2>/dev/null || pip install --quiet ruff
python -c "import mypy" 2>/dev/null || pip install --quiet mypy

# --- 3. Pre-commit hooks (optional — skip if config absent) ---
if [ -f ".pre-commit-config.yaml" ]; then
  if command -v pre-commit >/dev/null 2>&1; then
    echo "==> Installing pre-commit hooks"
    pre-commit install
  else
    echo "==> WARNING: .pre-commit-config.yaml present but pre-commit not installed; skip"
  fi
fi

# --- 4. Verify ACEF SDK importable ---
echo "==> Verifying acef package imports"
python -c "import acef; print(f'acef v{acef.__version__ if hasattr(acef, \"__version__\") else \"unknown\"}')" || {
  echo "ERROR: acef package failed to import. Investigate before continuing." >&2
  exit 1
}

# --- 5. Verify CLI entry point ---
if command -v acef >/dev/null 2>&1; then
  echo "==> acef CLI entry point available"
else
  echo "==> WARNING: acef CLI not on PATH (may need pip install -e .)"
fi

# --- 6. Snapshot fixtures presence (informational; created by F-M1-SNAPSHOT-FIXTURES) ---
FIXTURE_DIR="tests/conformance/fixtures"
if [ -d "$FIXTURE_DIR" ]; then
  for f in v1.0-schema-hashes.json v1.0-variants.json v1.0-errors.json; do
    if [ -f "$FIXTURE_DIR/$f" ]; then
      echo "==> Found pre-existing snapshot fixture: $FIXTURE_DIR/$f"
    fi
  done
fi

# --- 7. TS SDK setup (M2 only; only if directory exists) ---
if [ -d "packages/sdk-typescript" ]; then
  if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node --version)
    echo "==> Node detected: $NODE_VERSION (M2 work)"
    case "$NODE_VERSION" in
      v18.*|v20.*)
        ;;
      *)
        echo "==> WARNING: Node 18 or 20 LTS recommended. Got: $NODE_VERSION"
        ;;
    esac
    if [ -f "packages/sdk-typescript/package.json" ]; then
      echo "==> Installing TS SDK dependencies"
      (cd packages/sdk-typescript && npm install --silent)
    fi
  else
    echo "==> WARNING: packages/sdk-typescript/ exists but node not installed; M2 work blocked"
  fi
fi

echo "==> Setup complete."
echo "==> Activate venv in your shell with: source venv/bin/activate"
