#!/usr/bin/env bash
# @license
# SPDX-License-Identifier: Apache-2.0
#
# NeuralWAF Production Edge Proxy Runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo "  NeuralWAF: Enterprise Deep Learning Web Application Firewall"
echo "  Architecture: Ingestion Data Plane -> LSTM Autoencoder Inference -> Kafka Telemetry"
echo "================================================================================"

CONFIG_FILE="${PROJECT_ROOT}/configs/waf.yaml"
BIN_PATH="${PROJECT_ROOT}/bin/edge-proxy"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "Error: Configuration file not found at ${CONFIG_FILE}" >&2
  exit 1
fi

if [[ ! -f "${BIN_PATH}" ]]; then
  echo "==> Binary not found. Building bin/edge-proxy..."
  if command -v go >/dev/null 2>&1; then
    (cd "${PROJECT_ROOT}" && go build -v -ldflags="-s -w" -o bin/edge-proxy cmd/edge-proxy/main.go)
  else
    echo "Warning: Go compiler not found in PATH. Please run 'make build' or use Docker." >&2
    echo "Using docker-compose is recommended: docker compose up -d"
    exit 1
  fi
fi

echo "==> Starting NeuralWAF Edge Proxy..."
exec "${BIN_PATH}" -config "${CONFIG_FILE}" -port 8080 -upstream "${UPSTREAM_URL:-http://127.0.0.1:8000}"
