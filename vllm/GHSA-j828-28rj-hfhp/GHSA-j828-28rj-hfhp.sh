#!/bin/bash
# GHSA-j828-28rj-hfhp: vLLM Multiple ReDoS Vulnerabilities (CWE-1333)
# Reference: https://github.com/vllm-project/vllm/security/advisories/GHSA-j828-28rj-hfhp
#
# Vulnerability: Multiple regex patterns across vLLM source files use
# nested quantifiers and overlapping alternatives, causing catastrophic
# backtracking with crafted inputs. Affected files:
#   - vllm/lora/utils.py (LoRA module spec parsing)
#   - benchmarks/benchmark_serving_structured_output.py
#   - vllm/entrypoints/openai/serving_chat.py (parameter extraction)
#
# This PoC tests each vulnerable regex with crafted payloads to demonstrate
# the exponential time growth. No vLLM server or GPU is needed.

set -e

echo "=== GHSA-j828-28rj-hfhp PoC Environment ==="
echo "    Multiple ReDoS Vulnerabilities in vLLM"
echo ""

echo "[1] Building Docker image (Python + vLLM source for reference)..."
docker compose build

echo ""
echo "[2] Running ReDoS tests across multiple vulnerable patterns..."
echo ""
docker compose up --abort-on-container-exit 2>&1

echo ""
echo "=== Done ==="
echo "To clean up: docker compose down"
echo ""
