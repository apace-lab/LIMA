#!/bin/bash
# NEW vulnerability discovery: grammar/JSON-schema fuzzing for llama.cpp b8149
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=llama-b8149-grammar
TEST_DIR="$DIR/grammar_tests"

echo "=============================================="
echo "llama.cpp b8149 Grammar/Schema Vulnerability Discovery"
echo "=============================================="

# Step 1: Generate test payloads and get a real tiny model
echo ""
echo "[1/3] Generating test payloads and downloading tiny model..."
python3 "$DIR/create_grammar_tests.py" "$TEST_DIR"

# Download a tiny real model (~1MB) that llama.cpp can actually load
MODEL="$TEST_DIR/stories260K.gguf"
if [ ! -f "$MODEL" ]; then
    echo "  Downloading stories260K.gguf (tiny test model, ~1MB)..."
    curl -L -o "$MODEL" \
        "https://huggingface.co/ggml-org/models-moved/resolve/main/tinyllamas/stories260K.gguf" 2>&1
fi
echo "  Model: $(ls -lh "$MODEL" | awk '{print $5}')"

# Step 2: Build and start container
echo ""
echo "[2/3] Building llama.cpp b8149 (with llama-server)..."
cd "$DIR"
docker compose -f docker-compose.grammar.yml build
docker compose -f docker-compose.grammar.yml up -d
sleep 2

echo ""
echo "[3/3] Running grammar/schema tests..."
echo ""

CRASHES=0
TOTAL=0

# ──────────────────────────────────────
# Grammar tests via llama-cli
# ──────────────────────────────────────

# First check if the minimal model loads at all
echo "----------------------------------------------"
echo "Pre-check: Testing minimal.gguf loading..."
echo "----------------------------------------------"
EXIT_CODE=0
docker exec $CONTAINER timeout 10 \
    llama-cli -m /workspace/grammar_tests/stories260K.gguf -p "test" -n 1 \
    > "$TEST_DIR/precheck.stdout" 2> "$TEST_DIR/precheck.stderr" || EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "  Minimal model loads successfully!"
    MODEL_LOADS=true
elif [ $EXIT_CODE -eq 124 ]; then
    echo "  Minimal model timed out (may be loading slowly)"
    MODEL_LOADS=false
else
    echo "  Minimal model failed to load (exit $EXIT_CODE)"
    echo "  stderr: $(tail -3 "$TEST_DIR/precheck.stderr" 2>/dev/null)"
    MODEL_LOADS=false
fi
echo ""

# Even if model doesn't load, grammar parsing may still be reached in llama-server
# Start llama-server for API-based tests
echo "Starting llama-server for API tests..."
# Try to start server - it may fail if model doesn't load, that's OK
docker exec -d $CONTAINER sh -c \
    "llama-server -m /workspace/grammar_tests/stories260K.gguf --port 8080 \
     > /workspace/grammar_tests/server.stdout 2> /workspace/grammar_tests/server.stderr" || true
sleep 5

SERVER_OK=false
if docker exec $CONTAINER curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo "  llama-server is running!"
    SERVER_OK=true
else
    echo "  llama-server not responding (model may not have loaded)"
    echo "  Will test grammar via llama-cli --grammar flag instead"
fi
echo ""

# ─── Test 1: Deeply nested parentheses ───
echo "=============================================="
echo "Test 1: Deeply nested parentheses (stack overflow in parse_alternates)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

if [ "$SERVER_OK" = true ]; then
    # Test via server API
    EXIT_CODE=0
    GRAMMAR=$(cat "$TEST_DIR/test_nested_parens.gbnf")
    docker exec $CONTAINER timeout 15 curl -sf -X POST http://localhost:8080/completion \
        -H "Content-Type: application/json" \
        -d "{\"prompt\":\"x\",\"grammar\":$(python3 -c "import json; print(json.dumps(open('$TEST_DIR/test_nested_parens.gbnf').read()))"),\"n_predict\":1}" \
        > "$TEST_DIR/test1.stdout" 2> "$TEST_DIR/test1.stderr" || EXIT_CODE=$?
else
    # Test via llama-cli
    EXIT_CODE=0
    docker exec $CONTAINER timeout 15 \
        llama-cli -m /workspace/grammar_tests/stories260K.gguf \
        --grammar-file /workspace/grammar_tests/test_nested_parens.gbnf \
        -p "test" -n 1 \
        > "$TEST_DIR/test1.stdout" 2> "$TEST_DIR/test1.stderr" || EXIT_CODE=$?
fi

if [ $EXIT_CODE -eq 139 ]; then
    echo "  RESULT: SIGSEGV (139) — STACK OVERFLOW CRASH!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 134 ]; then
    echo "  RESULT: SIGABRT (134) — CRASH!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137)"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 124 ]; then
    echo "  RESULT: TIMEOUT (15s)"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "  RESULT: Clean exit"
else
    echo "  RESULT: Exit code $EXIT_CODE"
    if [ $EXIT_CODE -gt 128 ]; then
        CRASHES=$((CRASHES + 1))
    fi
fi
STDERR=$(tail -5 "$TEST_DIR/test1.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"

# Check if server survived (for server tests)
if [ "$SERVER_OK" = true ]; then
    if ! docker exec $CONTAINER curl -sf http://localhost:8080/health > /dev/null 2>&1; then
        echo "  *** SERVER CRASHED! ***"
        CRASHES=$((CRASHES + 1))
        # Restart server
        docker exec -d $CONTAINER sh -c \
            "llama-server -m /workspace/grammar_tests/stories260K.gguf --port 8080 \
             > /workspace/grammar_tests/server.stdout 2> /workspace/grammar_tests/server.stderr" || true
        sleep 5
    fi
fi
echo ""

# ─── Test 2: Deeply chained rules ───
echo "=============================================="
echo "Test 2: Deeply chained rules (advance_stack recursion)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 15 \
    llama-cli -m /workspace/grammar_tests/stories260K.gguf \
    --grammar-file /workspace/grammar_tests/test_chained_rules.gbnf \
    -p "test" -n 1 \
    > "$TEST_DIR/test2.stdout" 2> "$TEST_DIR/test2.stderr" || EXIT_CODE=$?

if [ $EXIT_CODE -eq 139 ]; then
    echo "  RESULT: SIGSEGV (139) — STACK OVERFLOW CRASH!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 134 ]; then
    echo "  RESULT: SIGABRT (134) — CRASH!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137)"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 124 ]; then
    echo "  RESULT: TIMEOUT (15s)"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "  RESULT: Clean exit"
else
    echo "  RESULT: Exit code $EXIT_CODE"
    if [ $EXIT_CODE -gt 128 ]; then CRASHES=$((CRASHES + 1)); fi
fi
STDERR=$(tail -5 "$TEST_DIR/test2.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── Test 3: Repetition near threshold ───
echo "=============================================="
echo "Test 3: Repetition near MAX_REPETITION_THRESHOLD (memory amplification)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 30 \
    llama-cli -m /workspace/grammar_tests/stories260K.gguf \
    --grammar-file /workspace/grammar_tests/test_max_repetition.gbnf \
    -p "test" -n 1 \
    > "$TEST_DIR/test3.stdout" 2> "$TEST_DIR/test3.stderr" || EXIT_CODE=$?

if [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137) — MEMORY EXHAUSTION!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 139 ] || [ $EXIT_CODE -eq 134 ]; then
    echo "  RESULT: CRASH (exit $EXIT_CODE)!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 124 ]; then
    echo "  RESULT: TIMEOUT (30s)"
else
    echo "  RESULT: Exit code $EXIT_CODE"
fi
STDERR=$(tail -5 "$TEST_DIR/test3.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── JSON schema tests use --jinja + file approach or server API ───
# Since JSON schemas can be huge, we use files mounted into the container.
# llama-cli -j expects a JSON string but ARG_MAX limits apply.
# We use llama-server API or write a wrapper script inside container.

# For JSON schema tests, create a helper script inside the container
docker exec $CONTAINER sh -c 'cat > /tmp/test_schema.sh << "SCRIPT"
#!/bin/sh
SCHEMA_FILE=$1
MODEL=$2
TIMEOUT=$3
# Start llama-server in background, send request, then kill
llama-server -m "$MODEL" --port 9090 &
SERVER_PID=$!
sleep 3
# Send the schema via curl (reads from file)
PAYLOAD=$(python3 -c "
import json, sys
schema = json.load(open(sys.argv[1]))
print(json.dumps({\"prompt\":\"x\",\"json_schema\":schema,\"n_predict\":1}))
" "$SCHEMA_FILE" 2>/dev/null || echo "FAIL")
if [ "$PAYLOAD" = "FAIL" ]; then
    # Schema too deep for python json too, construct manually
    echo "{\"prompt\":\"x\",\"json_schema\":$(cat "$SCHEMA_FILE"),\"n_predict\":1}" > /tmp/req.json
    timeout "$TIMEOUT" curl -sf -X POST http://localhost:9090/completion \
        -H "Content-Type: application/json" \
        -d @/tmp/req.json 2>&1
else
    echo "$PAYLOAD" | timeout "$TIMEOUT" curl -sf -X POST http://localhost:9090/completion \
        -H "Content-Type: application/json" \
        -d @- 2>&1
fi
EXIT=$?
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
exit $EXIT
SCRIPT
chmod +x /tmp/test_schema.sh' 2>/dev/null || true

# ─── Test 4: Deeply nested JSON schema ───
echo "=============================================="
echo "Test 4: Deeply nested JSON schema (visit() stack overflow)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 30 sh -c '
    llama-server -m /workspace/grammar_tests/stories260K.gguf --port 9090 > /dev/null 2>&1 &
    PID=$!; sleep 3
    echo "{\"prompt\":\"x\",\"json_schema\":$(cat /workspace/grammar_tests/test_nested_schema.json),\"n_predict\":1}" > /tmp/req4.json
    curl -sf -X POST http://localhost:9090/completion -H "Content-Type: application/json" -d @/tmp/req4.json > /workspace/grammar_tests/test4.stdout 2> /workspace/grammar_tests/test4.stderr
    CURL_EXIT=$?
    # Check if server is still alive
    if ! curl -sf http://localhost:9090/health > /dev/null 2>&1; then
        echo "SERVER_CRASHED" > /workspace/grammar_tests/test4.status
    else
        echo "SERVER_OK" > /workspace/grammar_tests/test4.status
    fi
    kill $PID 2>/dev/null; wait $PID 2>/dev/null
    exit $CURL_EXIT
' > "$TEST_DIR/test4_outer.stdout" 2> "$TEST_DIR/test4_outer.stderr" || EXIT_CODE=$?

STATUS=$(cat "$TEST_DIR/test4.status" 2>/dev/null || echo "UNKNOWN")
if [ "$STATUS" = "SERVER_CRASHED" ]; then
    echo "  RESULT: SERVER CRASHED — stack overflow in visit()!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137)!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 139 ]; then
    echo "  RESULT: SIGSEGV (139)!"
    CRASHES=$((CRASHES + 1))
else
    echo "  RESULT: Exit code $EXIT_CODE, server status: $STATUS"
fi
STDERR=$(tail -5 "$TEST_DIR/test4.stderr" 2>/dev/null || tail -5 "$TEST_DIR/test4_outer.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── Test 5: JSON schema huge minItems ───
echo "=============================================="
echo "Test 5: JSON schema huge minItems (build_repetition OOM)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 60 sh -c '
    llama-server -m /workspace/grammar_tests/stories260K.gguf --port 9091 > /dev/null 2>&1 &
    PID=$!; sleep 3
    echo "{\"prompt\":\"x\",\"json_schema\":$(cat /workspace/grammar_tests/test_huge_minitems.json),\"n_predict\":1}" > /tmp/req5.json
    curl -sf -X POST http://localhost:9091/completion -H "Content-Type: application/json" -d @/tmp/req5.json > /workspace/grammar_tests/test5.stdout 2> /workspace/grammar_tests/test5.stderr
    CURL_EXIT=$?
    if ! curl -sf http://localhost:9091/health > /dev/null 2>&1; then
        echo "SERVER_CRASHED" > /workspace/grammar_tests/test5.status
    else
        echo "SERVER_OK" > /workspace/grammar_tests/test5.status
    fi
    kill $PID 2>/dev/null; wait $PID 2>/dev/null
    exit $CURL_EXIT
' > "$TEST_DIR/test5_outer.stdout" 2> "$TEST_DIR/test5_outer.stderr" || EXIT_CODE=$?

STATUS=$(cat "$TEST_DIR/test5.status" 2>/dev/null || echo "UNKNOWN")
if [ "$STATUS" = "SERVER_CRASHED" ]; then
    echo "  RESULT: SERVER CRASHED — OOM in build_repetition!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137)!"
    CRASHES=$((CRASHES + 1))
else
    echo "  RESULT: Exit code $EXIT_CODE, server status: $STATUS"
fi
STDERR=$(tail -5 "$TEST_DIR/test5.stderr" 2>/dev/null || tail -5 "$TEST_DIR/test5_outer.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── Test 6: Deeply nested anyOf ───
echo "=============================================="
echo "Test 6: Deeply nested anyOf (visit() recursion via union)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 30 sh -c '
    llama-server -m /workspace/grammar_tests/stories260K.gguf --port 9092 > /dev/null 2>&1 &
    PID=$!; sleep 3
    echo "{\"prompt\":\"x\",\"json_schema\":$(cat /workspace/grammar_tests/test_nested_anyof.json),\"n_predict\":1}" > /tmp/req6.json
    curl -sf -X POST http://localhost:9092/completion -H "Content-Type: application/json" -d @/tmp/req6.json > /workspace/grammar_tests/test6.stdout 2> /workspace/grammar_tests/test6.stderr
    CURL_EXIT=$?
    if ! curl -sf http://localhost:9092/health > /dev/null 2>&1; then
        echo "SERVER_CRASHED" > /workspace/grammar_tests/test6.status
    else
        echo "SERVER_OK" > /workspace/grammar_tests/test6.status
    fi
    kill $PID 2>/dev/null; wait $PID 2>/dev/null
    exit $CURL_EXIT
' > "$TEST_DIR/test6_outer.stdout" 2> "$TEST_DIR/test6_outer.stderr" || EXIT_CODE=$?

STATUS=$(cat "$TEST_DIR/test6.status" 2>/dev/null || echo "UNKNOWN")
if [ "$STATUS" = "SERVER_CRASHED" ]; then
    echo "  RESULT: SERVER CRASHED — stack overflow in visit()!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 139 ]; then
    echo "  RESULT: SIGSEGV (139)!"
    CRASHES=$((CRASHES + 1))
else
    echo "  RESULT: Exit code $EXIT_CODE, server status: $STATUS"
fi
STDERR=$(tail -5 "$TEST_DIR/test6.stderr" 2>/dev/null || tail -5 "$TEST_DIR/test6_outer.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── Test 7: Truncated UTF-8 ───
echo "=============================================="
echo "Test 7: Truncated UTF-8 in grammar (decode_utf8 OOB)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 10 \
    llama-cli -m /workspace/grammar_tests/stories260K.gguf \
    --grammar-file /workspace/grammar_tests/test_truncated_utf8.gbnf \
    -p "test" -n 1 \
    > "$TEST_DIR/test7.stdout" 2> "$TEST_DIR/test7.stderr" || EXIT_CODE=$?

if [ $EXIT_CODE -eq 139 ]; then
    echo "  RESULT: SIGSEGV (139) — OOB READ!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 134 ]; then
    echo "  RESULT: SIGABRT (134)"
    CRASHES=$((CRASHES + 1))
else
    echo "  RESULT: Exit code $EXIT_CODE"
fi
STDERR=$(tail -5 "$TEST_DIR/test7.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ─── Test 8: Huge minLength ───
echo "=============================================="
echo "Test 8: JSON schema huge minLength (build_repetition string explosion)"
echo "=============================================="
TOTAL=$((TOTAL + 1))

EXIT_CODE=0
docker exec $CONTAINER timeout 60 sh -c '
    llama-server -m /workspace/grammar_tests/stories260K.gguf --port 9094 > /dev/null 2>&1 &
    PID=$!; sleep 3
    curl -sf -X POST http://localhost:9094/completion -H "Content-Type: application/json" \
        -d "{\"prompt\":\"x\",\"json_schema\":$(cat /workspace/grammar_tests/test_huge_minlength.json),\"n_predict\":1}" \
        > /workspace/grammar_tests/test8.stdout 2> /workspace/grammar_tests/test8.stderr
    CURL_EXIT=$?
    if ! curl -sf http://localhost:9094/health > /dev/null 2>&1; then
        echo "SERVER_CRASHED" > /workspace/grammar_tests/test8.status
    else
        echo "SERVER_OK" > /workspace/grammar_tests/test8.status
    fi
    kill $PID 2>/dev/null; wait $PID 2>/dev/null
    exit $CURL_EXIT
' > "$TEST_DIR/test8_outer.stdout" 2> "$TEST_DIR/test8_outer.stderr" || EXIT_CODE=$?

STATUS=$(cat "$TEST_DIR/test8.status" 2>/dev/null || echo "UNKNOWN")
if [ "$STATUS" = "SERVER_CRASHED" ]; then
    echo "  RESULT: SERVER CRASHED — OOM from huge grammar string!"
    CRASHES=$((CRASHES + 1))
elif [ $EXIT_CODE -eq 137 ]; then
    echo "  RESULT: SIGKILL/OOM (137)!"
    CRASHES=$((CRASHES + 1))
else
    echo "  RESULT: Exit code $EXIT_CODE, server status: $STATUS"
fi
STDERR=$(tail -5 "$TEST_DIR/test8.stderr" 2>/dev/null || tail -5 "$TEST_DIR/test8_outer.stderr" 2>/dev/null || true)
[ -n "$STDERR" ] && echo "  stderr: $STDERR"
echo ""

# ──────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────
echo "=============================================="
echo "SUMMARY — llama.cpp b8149 Grammar/Schema Vulnerability Discovery"
echo "=============================================="
echo "Total tests: $TOTAL"
echo "Crashes: $CRASHES"
echo ""
echo "Results saved in $TEST_DIR/test*.stdout and *.stderr"

echo ""
echo "Stopping container..."
docker compose -f docker-compose.grammar.yml down
echo "Done."
