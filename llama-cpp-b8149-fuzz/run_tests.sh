#!/bin/bash
# Pattern-based GGUF fuzzing for llama.cpp b8149
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=llama-b8149-fuzz

echo "=============================================="
echo "llama.cpp b8149 Pattern-Based GGUF Fuzzing"
echo "=============================================="

# Step 1: Generate test GGUF files
echo ""
echo "[1/3] Generating 12 test GGUF files..."
python3 "$DIR/create_fuzz_gguf.py" "$DIR/poc"

# Step 2: Build and start container
echo ""
echo "[2/3] Building llama.cpp b8149..."
cd "$DIR"
docker compose build
docker compose up -d
sleep 2

# Step 3: Run each test
echo ""
echo "[3/3] Running tests..."
echo ""

for gguf in "$DIR"/poc/test*.gguf; do
    name=$(basename "$gguf" .gguf)
    echo "----------------------------------------------"
    echo "Testing: $name"
    echo "----------------------------------------------"

    # Run llama-cli with the crafted GGUF, capture exit code
    # Timeout after 10 seconds to catch hangs
    EXIT_CODE=0
    docker exec $CONTAINER timeout 10 \
        llama-cli -m "/workspace/poc/${name}.gguf" -p "test" -n 1 \
        > "$DIR/poc/${name}.stdout" 2> "$DIR/poc/${name}.stderr" || EXIT_CODE=$?

    # Check for crashes
    if [ $EXIT_CODE -eq 139 ]; then
        echo "  RESULT: SIGSEGV (exit 139) - CRASH!"
    elif [ $EXIT_CODE -eq 134 ]; then
        echo "  RESULT: SIGABRT (exit 134) - CRASH!"
    elif [ $EXIT_CODE -eq 136 ]; then
        echo "  RESULT: SIGFPE (exit 136) - CRASH!"
    elif [ $EXIT_CODE -eq 137 ]; then
        echo "  RESULT: SIGKILL/OOM (exit 137) - KILLED!"
    elif [ $EXIT_CODE -eq 124 ]; then
        echo "  RESULT: TIMEOUT (10s) - HANG!"
    elif [ $EXIT_CODE -eq 0 ]; then
        echo "  RESULT: Clean exit (0) - no crash"
    else
        echo "  RESULT: Exit code $EXIT_CODE"
    fi

    # Show last few lines of stderr for context
    STDERR=$(tail -3 "$DIR/poc/${name}.stderr" 2>/dev/null || true)
    if [ -n "$STDERR" ]; then
        echo "  stderr: $STDERR"
    fi
    echo ""
done

echo "=============================================="
echo "SUMMARY"
echo "=============================================="
echo "Results saved in $DIR/poc/*.stdout and *.stderr"
echo ""
echo "Crashes found:"
grep -l "SIGSEGV\|SIGABRT\|SIGFPE\|SIGKILL" "$DIR"/poc/*.stderr 2>/dev/null || echo "  (check above output)"
echo ""

echo "Stopping container..."
docker compose down
echo "Done."
