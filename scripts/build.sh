#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python_bin=${PYTHON:-python3}
"$python_bin" scripts/check_version.py
mkdir -p dist/bin
release_version=$(cat version)
for architecture in amd64 arm64; do
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=$architecture \
        go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$release_version" \
        -o "dist/bin/ha-access-gateway-linux-$architecture" ./cmd/ha-access-gateway
done
"$python_bin" scripts/package.py
