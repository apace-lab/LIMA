#!/bin/bash
# NEW vulnerability discovery: fuzz Ollama v0.17.0 with novel GGUF patterns
set -e

PORT=11460
CONTAINER=ollama-v0170-retest
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=============================================="
echo "Ollama v0.17.0 NEW Vulnerability Discovery"
echo "=============================================="

# Step 1: Generate new fuzz GGUF files
echo ""
echo "[1/3] Generating 10 new fuzz GGUF files..."
python3 "$DIR/create_new_fuzz_gguf.py" "$DIR/poc"

# Step 2: Start Ollama
echo ""
echo "[2/3] Starting Ollama v0.17.0..."
cd "$DIR"
docker compose up -d
echo "Waiting 10s for Ollama to initialize..."
sleep 10

if ! curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "ERROR: Ollama not responding on port $PORT"
    docker compose logs
    exit 1
fi
OLLAMA_VER=$(curl -sf "http://localhost:$PORT/api/version" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null || echo "unknown")
echo "Ollama version: $OLLAMA_VER"

# Step 3: Test each new GGUF
echo ""
echo "[3/3] Running new fuzz tests..."

CRASHES=0
TOTAL=0

for gguf in "$DIR"/poc/new_*.gguf; do
    name=$(basename "$gguf" .gguf)
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "=============================================="
    echo "Testing: $name"
    echo "=============================================="

    # Create a Modelfile pointing to this GGUF
    cat > "$DIR/poc/Modelfile.${name}" <<EOF
FROM /poc/${name}.gguf
EOF

    # Try to create the model (this triggers GGUF parsing)
    docker exec $CONTAINER ollama create "test-${name}" \
        -f "/poc/Modelfile.${name}" \
        > "$DIR/poc/${name}.stdout" 2> "$DIR/poc/${name}.stderr" || true
    sleep 3

    # Check if server survived
    if curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
        STDERR=$(cat "$DIR/poc/${name}.stderr" 2>/dev/null | tail -5 || true)
        if [ -n "$STDERR" ]; then
            echo "  Server survived. stderr: $STDERR"
        else
            echo "  Server survived (no stderr)"
        fi
    else
        CRASHES=$((CRASHES + 1))
        echo "  *** SERVER CRASHED! *** Potential NEW vulnerability!"
        echo "  Collecting logs..."
        docker compose logs --tail 30 > "$DIR/poc/${name}.crash_log" 2>&1 || true

        echo "  Restarting Ollama for next test..."
        docker compose restart
        sleep 10

        # Verify restart
        if ! curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
            echo "  WARNING: Ollama failed to restart"
            docker compose down -v
            docker compose up -d
            sleep 15
        fi
    fi
done

# Summary
echo ""
echo "=============================================="
echo "SUMMARY - Ollama $OLLAMA_VER NEW Vulnerability Discovery"
echo "=============================================="
echo "Total tests: $TOTAL"
echo "Crashes: $CRASHES"
echo ""

if [ $CRASHES -gt 0 ]; then
    echo "CRASHES FOUND (potential NEW vulnerabilities):"
    for log in "$DIR"/poc/*.crash_log; do
        if [ -f "$log" ]; then
            echo "  - $(basename "$log" .crash_log)"
        fi
    done
fi

echo ""
echo "Stopping container..."
docker compose down -v
echo "Done."
