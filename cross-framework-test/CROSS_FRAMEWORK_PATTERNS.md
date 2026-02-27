# Cross-Framework Vulnerability Pattern Analysis

## Purpose

Extract vulnerability patterns from ALL CVEs across the four LIF repos (llama-cpp, Ollama, LocalAI, vLLM),
then systematically test each pattern against all repos where it has NOT been found yet.

> Professor: "One pattern is discovered in one repo, which does not mean the pattern won't appear in other repos."

## Source Data

| Repo | CSV | CVE Count |
|------|-----|-----------|
| llama-cpp | sources/llama-cpp.csv | 17 (incl. LIMA-NEW-003/004) |
| Ollama | sources/ollama.csv | 17 (incl. LIMA-NEW-001/002) |
| LocalAI | sources/localAI.csv | 8 (incl. LIMA-NEW-005/006) |
| vLLM | sources/vllm.csv | 26 |
| **Total** | | **68 CVEs** |

---

## Extracted Patterns and Cross-Framework Matrix

### P1: Integer Overflow / Narrow Casting (CWE-190, CWE-681, CWE-119, CWE-195)

**Root cause:** Unsafe cast between integer types (size_t→int32_t in C++, uint64→int in Go)
causes bounds checks to be bypassed or allocations to underflow.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (9 CVEs) | CVE-2025-49847, CVE-2025-52566, CVE-2024-23605, CVE-2024-21825, CVE-2024-21836, CVE-2024-23496, CVE-2024-21802, CVE-2025-53630, CVE-2024-42477 |
| Ollama | FOUND (2 CVEs) | LIMA-NEW-001, LIMA-NEW-002 |
| LocalAI | **TO TEST** | Uses gpustack/gguf-parser-go (different Go GGUF parser). Preliminary: panics caught by recover(). Also bundles llama.cpp C backend (build 8119). |
| vLLM | N/A | Uses safetensors/PyTorch, not GGUF. No C integer casting. |

**Test:** Feed crafted GGUF files with uint64 values >= 2^63 to LocalAI's model import path.

---

### P2: Heap Buffer Overflow in GGUF Parsing (CWE-787, CWE-122, CWE-125, CWE-457, CWE-476)

**Root cause:** GGUF parser reads attacker-controlled sizes/counts from file, uses them
for memory allocation or array indexing without bounds checking.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (6 CVEs) | GHSA-g4cc-763q-h9h6, CVE-2024-42478, CVE-2024-42479, CVE-2024-32878, CVE-2024-41130, CVE-2024-42477 |
| Ollama | FOUND (5 CVEs) | CVE-2025-0317, CVE-2025-0315, CVE-2025-0312, CVE-2024-39720, CVE-2024-12055 |
| LocalAI | **TO TEST** | Bundles llama.cpp b8119 for inference. Go-level GGUF parser for config guessing. |
| vLLM | N/A | No GGUF parsing. |

**Test:** Feed the same GGUF PoCs (null tensor names, tiny vocab, zero alignment, huge dims)
to LocalAI. Some will hit the Go parser, some will hit the C llama.cpp backend.

---

### P3: Unsafe Deserialization (CWE-502)

**Root cause:** Use of Python pickle/cloudpickle for deserializing untrusted data.

| Repo | Status | CVEs |
|------|--------|------|
| vLLM | FOUND (7 CVEs) | CVE-2025-47277, CVE-2025-29783, CVE-2025-30165, CVE-2025-24357, CVE-2024-9053, CVE-2024-9052, CVE-2024-11041 |
| llama-cpp | N/A | C/C++, no pickle |
| Ollama | N/A | Go, no pickle |
| LocalAI | N/A | Go, no pickle |

**Test:** Not applicable cross-framework. Python pickle is language-specific.

---

### P4: Command / Code Injection (CWE-78, CWE-94, CWE-76)

**Root cause:** User-controlled input flows into command execution or code evaluation
without validation/sanitization.

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (3 CVEs) | CVE-2024-5181 (backend param), CVE-2024-6983 (model param), LIMA-NEW-005 (MCP STDIO) |
| llama-cpp | FOUND (1 CVE) | CVE-2024-34359 (Jinja2 SSTI via llama-cpp-python) |
| vLLM | FOUND (2 CVEs) | CVE-2025-32444 (ZMQ RCE), CVE-2025-32434 (torch.load RCE) |
| Ollama | PARTIAL (1 CVE) | CVE-2024-37032 (path traversal → file write → RCE) |

**Test:** Already found in all 4 repos via different vectors. No gap.

---

### P5: Path Traversal / Arbitrary File Ops (CWE-22, CWE-552)

**Root cause:** User-controlled file paths passed to OS file operations without validation.

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (3 CVEs) | CVE-2025-44779, CVE-2024-45436, CVE-2024-39722 |
| LocalAI | FOUND (1 CVE) | CVE-2024-6095 (SSRF + LFI via file://) |
| llama-cpp | **TO TEST** | llama-server has --path flag for serving static files. Does it validate paths? |
| vLLM | **TO TEST** | vLLM API has no file-serving, but check model loading paths. |

**Test:** Send path traversal payloads (../../etc/passwd) to llama-server and vLLM endpoints.

---

### P6: SSRF (CWE-918)

**Root cause:** Server makes HTTP requests to user-controlled URLs without validation.

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (1 CVE) | CVE-2024-6095 (/models/apply accepts http:// and file://) |
| Ollama | **TO TEST** | /api/pull fetches from user-specified registries — already known to be redirectable (CVE-2025-51471) |
| llama-cpp | N/A | No URL fetching in API |
| vLLM | **TO TEST** | Check if model loading accepts URLs |

**Test:** Send SSRF payloads to Ollama /api/pull and vLLM model endpoints.

---

### P7: ReDoS / Regex Denial of Service (CWE-1333)

**Root cause:** Complex regex patterns with catastrophic backtracking on crafted input.

| Repo | Status | CVEs |
|------|--------|------|
| vLLM | FOUND (3 CVEs) | GHSA-j828-28rj-hfhp, CVE-2025-48887, CVE-2025-48943 |
| llama-cpp | **TO TEST** | llama.cpp uses regex in grammar/sampling code (C++ std::regex). |
| Ollama | **TO TEST** | Ollama uses Go regexp (Thompson NFA, immune to backtracking). |
| LocalAI | **TO TEST** | LocalAI uses Go regexp (same — immune). But template parsing? |

**Test:** Send crafted tool-call outputs with backtracking-inducing patterns to llama-server.
Go's regexp engine uses NFA so Ollama/LocalAI are likely immune. Focus on llama-cpp.

---

### P8: Recursion / Stack Overflow (CWE-674)

**Root cause:** Recursive descent parsers (grammar, JSON schema, xgrammar) with no depth limit.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (2 CVEs) | LIMA-NEW-003 (GBNF grammar), LIMA-NEW-004 (JSON schema) |
| vLLM | FOUND (3 CVEs) | CVE-2025-48944, CVE-2025-48942, CVE-2025-32381 (xgrammar crashes) |
| Ollama | TESTED — NOT VULNERABLE | Go's encoding/json rejects deeply nested JSON (max depth limit). Schema never reaches llama.cpp CGo bridge. |
| LocalAI | **TO TEST** | Bundles llama.cpp. Needs a loaded model to exercise grammar/schema code path. |

**Test:** Send nested JSON schema via response_format to LocalAI with a working model loaded.

---

### P9: CSRF / No Authentication (CWE-352, CWE-346)

**Root cause:** API endpoints accessible without authentication or CSRF protection.

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (1 CVE) | CVE-2024-28224 (DNS rebinding) |
| LocalAI | FOUND (2 CVEs) | CVE-2024-48057, CVE-2024-3135 |
| vLLM | FOUND (1 CVE) | CVE-2024-4839 |
| llama-cpp | **TO TEST** | llama-server has no auth by default. Vulnerable to same patterns. |

**Test:** Verify llama-server accepts requests without any auth. (Trivial — known by design.)

---

### P10: Null Pointer / Uninitialized Memory (CWE-476, CWE-457)

**Root cause:** GGUF parser doesn't validate pointer/field existence before dereferencing.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (2 CVEs) | CVE-2024-41130 (null tensor name), CVE-2024-32878 (uninitialized heap) |
| Ollama | FOUND (1 CVE) | CVE-2025-0312 (nil pointer in metadata) |
| LocalAI | **TO TEST** | Same GGUF inputs could crash the Go or C parser. |
| vLLM | N/A | No GGUF parsing. |

**Test:** Feed GGUF with null/truncated fields to LocalAI.

---

### P11: Resource Exhaustion / No Limits (CWE-400, CWE-770, CWE-369)

**Root cause:** API parameters or model metadata values used without upper bounds,
causing excessive memory allocation, CPU usage, or division by zero.

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (3 CVEs) | CVE-2025-0317 (alignment=0 div-by-zero), CVE-2025-0315 (huge dims alloc), CVE-2024-8063 (block_count=0) |
| vLLM | FOUND (2 CVEs) | CVE-2025-48956 (header size), CVE-2024-8939 (best_of param) |
| llama-cpp | **TO TEST** | Does llama-server validate API parameters like n_predict, n_ctx? |
| LocalAI | **TO TEST** | Does LocalAI validate API parameters? GGUF alignment=0? |

**Test:** Send extreme API parameter values (n_predict=999999999, best_of=10000) to
llama-server and LocalAI. Feed GGUF with alignment=0 to LocalAI.

---

### P12: SSTI / Template Injection (CWE-1336)

**Root cause:** Template engine evaluates user-controlled template strings with dangerous functions available.

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (1 CVE) | LIMA-NEW-006 (Sprig env function in Go templates) |
| Ollama | TESTED — NOT VULNERABLE | Uses text/template with 4 safe custom functions only (no Sprig). |
| llama-cpp | N/A | No template engine in C++ server. |
| vLLM | **TO TEST** | vLLM uses Jinja2 for chat templates — does it sandbox? |

**Test:** Check if vLLM's Jinja2 chat template rendering is sandboxed.

---

## Cross-Framework Test Results (2026-02-25)

### Results Matrix

| Pattern | Test | LocalAI v3.12.1 | llama-cpp b8149 | Ollama v0.17.0 | vLLM 0.8.3 |
|---------|------|-----------------|-----------------|----------------|------------|
| P1: Integer Overflow | negative_key_length | PANIC_RECOVERED | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| P1: Integer Overflow | negative_array_count | NOT_VULNERABLE | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| P1: Integer Overflow | negative_value_length | PANIC_RECOVERED | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| **P2: Heap Overflow** | **large_n_kv** | **CRASHED (OOM)** | N/A (hardened) | CRASHED (CVE-2024-23605) | N/A |
| P2: Heap Overflow | large_n_tensors | NOT_VULNERABLE | N/A (hardened) | CRASHED (CVE-2024-21836) | N/A |
| P2: Heap Overflow | small_vocab | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| P2: Heap Overflow | large_key_length | PANIC_RECOVERED | N/A (hardened) | N/A | N/A |
| P5: Path Traversal | url_traversal | NOT_VULNERABLE | NOT_VULNERABLE | FOUND (3 CVEs) | not tested |
| P7: ReDoS | grammar_regex | N/A (Go NFA) | NOT_VULNERABLE | N/A (Go NFA) | FOUND (3 CVEs) |
| P9: No Auth | no_auth | FOUND (2 CVEs) | VULNERABLE (by design) | FOUND (1 CVE) | FOUND (1 CVE) |
| P10: Null/Truncated | truncated_magic | NOT_VULNERABLE | N/A (hardened) | FOUND (1 CVE) | N/A |
| P10: Null/Truncated | null_tensor_name | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| P10: Null/Truncated | truncated_after_header | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| **P11: Resource** | **zero_alignment** | NOT_VULNERABLE | not tested | **CRASHED (CVE-2025-0317)** | N/A |
| P11: Resource | huge_dims | NOT_VULNERABLE | not tested | NOT_VULNERABLE | N/A |
| P11: Resource | zero_block_count | NOT_VULNERABLE | not tested | NOT_VULNERABLE | N/A |
| P11: Resource | extreme_api_params | NOT_VULNERABLE | NOT_VULNERABLE | not tested | FOUND (1 CVE) |
| P12: SSTI | template_injection | FOUND (LIMA-NEW-006) | N/A | NOT_VULNERABLE | not tested |

### Key New Findings

1. **P2 → LocalAI v3.12.1: CRASHED (NEW VULNERABILITY)**
   - Payload: `p2a_large_n_kv.gguf` (n_kv = 0xFFFFFFFF = 4 billion)
   - Root cause: `gpustack/gguf-parser-go v0.23.1` attempts to allocate memory for 4B KV pairs
   - Crash: OOMKilled=true, exit code 137 (SIGKILL from Linux OOM killer)
   - The `recover()` in `core/config/guesser.go:27` CANNOT catch kernel SIGKILL
   - Impact: Remote DoS — any user who can upload a GGUF file can crash the server
   - CWE: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits)

2. **P11 → Ollama v0.17.0: CRASHED (CVE-2025-0317 still unfixed)**
   - Payload: `p11a_zero_alignment.gguf` (general.alignment = 0)
   - Crash: `panic: runtime error: integer divide by zero` at `fs/ggml/gguf.go:673`
   - Stack trace: `ggufPadding` → `gguf.Decode` → `containerGGUF.Decode` → `ggml.Decode` → `ggufLayers` → `convertModelFromFiles`
   - Using the new v0.17.0 `files` API for model creation from uploaded blobs

3. **P1 → LocalAI: PANIC_RECOVERED (partial vulnerability)**
   - Payloads p1a and p1c trigger Go panics in `gpustack/gguf-parser-go`
   - Panics caught by `recover()` in `guesser.go:27` — server survives
   - Not a full DoS but indicates parser doesn't validate uint64 values

### Defense Analysis

- **llama-cpp b8149**: Well-hardened against GGUF attacks (all P1/P2/P10 = N/A). API params (P11) also handled safely (n_predict clamped). Path traversal (P5) blocked. GBNF grammar regex (P7) doesn't trigger ReDoS.
- **LocalAI v3.12.1**: Go-level GGUF parser (`gpustack/gguf-parser-go`) is vulnerable to OOM via large n_kv. Other malformed inputs cause panics caught by `recover()`. Not vulnerable to P5 path traversal or P11 resource exhaustion via API.
- **Ollama v0.17.0**: Still vulnerable to CVE-2025-0317 (alignment=0 div-by-zero). The `files` API in v0.17.0 allows blob upload + model creation, making the attack surface accessible.

---

## Test Infrastructure

| Framework | Version | Container | Port | Docker Compose |
|-----------|---------|-----------|------|----------------|
| llama-cpp | b8149 | llama-b8149-grammar | 18080 | llama-cpp-b8149-fuzz/docker-compose.grammar.yml |
| Ollama | v0.17.0 | ollama-v0170-retest | 11460 | ollama-v0.17.0-retest/docker-compose.yml |
| LocalAI | v3.12.1 | localai-v3121-retest | 11480 | localai-v3.12.1-retest/docker-compose.yml |
| vLLM | 0.8.3 | N/A (needs GPU) | N/A | server-dependent tests only |

---

## What the Test Script Does

`run_full_cross_tests.sh`:

1. Generates ALL payload types (GGUF variants, JSON schemas, API parameter extremes, regex, path traversal)
2. Starts each framework container in sequence
3. For each framework, runs all applicable pattern tests
4. Checks container state including OOMKilled, exit code, restart count
5. Collects logs and crash evidence (stack traces, panic messages)
6. Produces a summary matrix showing CRASHED / PANIC_RECOVERED / VULNERABLE / NOT_VULNERABLE for each cell
