#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python3 ]; then
    python_bin=.venv/bin/python3
else
    python_bin=python3
fi
"$python_bin" -m ruff check custom_components tests scripts/check_version.py scripts/package.py scripts/smoke_gateway_artifact.py
"$python_bin" -m ruff format --check custom_components tests scripts/check_version.py scripts/package.py scripts/smoke_gateway_artifact.py
"$python_bin" -m unittest discover -s tests -v
"$python_bin" scripts/check_version.py
if [ -n "${HA_PYTHON:-}" ]; then
    "$HA_PYTHON" -I tests/real_ha_lifecycle.py
fi
if [ -n "$(gofmt -l gateway cmd)" ]; then
    echo 'Run gofmt on the reported Go source files.' >&2
    gofmt -l gateway cmd
    exit 1
fi
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=1 ./...
