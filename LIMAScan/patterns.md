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
| LocalAI | sources/localAI.csv | 9 (incl. LIMA-NEW-005/006/007) |
| vLLM | sources/vllm.csv | 26 |
| **Total** | | **69 CVEs** |

---

## Root Cause Categories

We identified 5 root cause categories across all 69 CVEs:

| Root Cause | Sub-Patterns | CVE Count | Repos Affected |
|------------|-------------|-----------|----------------|
| **Unsafe Model File Parsing** | Integer Overflow, Heap Overflow, Null Pointer | 19 | llama-cpp, Ollama, LocalAI (3/4) |
| **Untrusted Code Execution** | Unsafe Deserialization, Code Injection, SSTI | 14 | vLLM, LocalAI, llama-cpp-python (3/4) |
| **Resource Exhaustion / DoS** | ReDoS, Recursion, Resource Exhaustion | 22 | All 4 repos |
| **Insufficient Access Control** | Path Traversal, SSRF, No Auth | 10 | Ollama, LocalAI, llama-cpp, vLLM (4/4) |
| **Information Leakage** | Timing, hash | 3 | vLLM (1/4) |

Top 3 root causes account for **55/69 = 80%** of all CVEs.

---

## Unsafe Model File Parsing (19 CVEs)

**Core problem:** GGUF/model file parsers read attacker-controlled values from file headers
and use them for memory allocation, array indexing, or type casting without validation.

### Integer Overflow / Narrow Casting (CWE-190, CWE-681, CWE-119, CWE-195)

**Root cause:** Unsafe cast between integer types (size_t→int32_t in C++, uint64→int in Go)
causes bounds checks to be bypassed or allocations to underflow.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (2 CVEs) | CVE-2025-49847, CVE-2025-52566 |
| Ollama | FOUND (2 CVEs) | LIMA-NEW-001, LIMA-NEW-002 |
| LocalAI | TESTED — PANIC_RECOVERED | Go panics caught by recover(); not full DoS but parser doesn't validate uint64 |
| vLLM | N/A | Uses safetensors/PyTorch, not GGUF |

### Heap Buffer Overflow / Unbounded Allocation (CWE-787, CWE-122, CWE-125, CWE-770)

**Root cause:** GGUF parser reads attacker-controlled sizes/counts from file, uses them
for memory allocation or array indexing without bounds checking.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (7 CVEs) | CVE-2024-23605, CVE-2024-21825, CVE-2024-21836, CVE-2024-23496, CVE-2024-21802, CVE-2025-53630, GHSA-g4cc-763q-h9h6 |
| Ollama | FOUND (3 CVEs) | CVE-2025-0315, CVE-2024-39720, CVE-2024-12055 |
| LocalAI | **FOUND (1 CVE)** | **LIMA-NEW-007** (large n_kv → OOM kill) — *discovered via cross-framework testing* |
| vLLM | N/A | No GGUF parsing |

### Null Pointer / Uninitialized Memory (CWE-476, CWE-457)

**Root cause:** GGUF parser doesn't validate pointer/field existence before dereferencing.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (2 CVEs) | CVE-2024-41130, CVE-2024-32878 |
| Ollama | FOUND (2 CVEs) | CVE-2025-0312, CVE-2024-39720 |
| LocalAI | TESTED — NOT_VULNERABLE | Go parser handles gracefully |
| vLLM | N/A | No GGUF parsing |

**Cross-framework insight:** Unsafe Model File Parsing is the most transferable category. The *same crafted GGUF file*
(e.g., n_kv=0xFFFFFFFF) crashes llama-cpp (heap overflow), Ollama (makeslice panic), and
LocalAI (OOM kill) through three *different* parsers (C/C++, Go-ollama, Go-gpustack).

---

## Untrusted Code Execution (14 CVEs)

**Core problem:** User-controlled input (model files, configs, network data) flows into code
execution or deserialization without validation/sandboxing.

### Unsafe Deserialization (CWE-502)

**Root cause:** Python pickle/cloudpickle used for deserializing untrusted network data.

| Repo | Status | CVEs |
|------|--------|------|
| vLLM | FOUND (7 CVEs) | CVE-2025-47277, CVE-2025-29783, CVE-2025-30165, CVE-2025-32444, CVE-2024-9053, CVE-2024-9052, CVE-2024-11041 |
| Others | N/A | C/C++ and Go don't use pickle |

### Code Injection (CWE-78, CWE-94, CWE-76)

**Root cause:** User-controlled input flows into command execution or code evaluation.

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (3 CVEs) | CVE-2024-5181, CVE-2024-6983, LIMA-NEW-005 (MCP STDIO) |
| vLLM | FOUND (2 CVEs) | CVE-2025-32434 (torch.load), CVE-2025-24357 (torch.load) |
| llama-cpp-python | FOUND (1 CVE) | CVE-2024-34359 (Jinja2 SSTI) |
| Ollama | PARTIAL (1 CVE) | CVE-2024-37032 (path traversal → file write → RCE) |

### SSTI / Template Injection (CWE-1336)

**Root cause:** Template engine evaluates user-controlled template strings with dangerous functions.

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (1 CVE) | LIMA-NEW-006 (Sprig env function) |
| llama-cpp-python | FOUND (1 CVE) | CVE-2024-34359 (Jinja2 SSTI — same CVE as Code Injection, dual classification) |
| Ollama | TESTED — NOT_VULNERABLE | Uses text/template with 4 safe custom functions only |
| vLLM | not tested | Jinja2 chat template — sandboxing status unknown |

**Cross-framework insight:** RCE via model content is found in 3/4 repos through completely
different mechanisms: pickle (vLLM), exec.Command (LocalAI), Jinja2 (llama-cpp-python), torch.load (vLLM).

---

## Resource Exhaustion / DoS (22 CVEs)

**Core problem:** API parameters, model metadata values, or input patterns used without
upper bounds, causing excessive memory allocation, CPU usage, stack overflow, or division by zero.

### ReDoS / Regex Denial of Service (CWE-1333)

**Root cause:** Complex regex patterns with catastrophic backtracking on crafted input.

| Repo | Status | CVEs |
|------|--------|------|
| vLLM | FOUND (2 CVEs) | GHSA-j828-28rj-hfhp, CVE-2025-48887 |
| llama-cpp | TESTED — NOT_VULNERABLE | C++ std::regex doesn't backtrack on tested patterns |
| Ollama | N/A | Go regexp uses NFA (immune to backtracking) |
| LocalAI | N/A | Go regexp (same — immune) |

### Recursion / Stack Overflow (CWE-674)

**Root cause:** Recursive descent parsers (grammar, JSON schema, xgrammar) with no depth limit.

| Repo | Status | CVEs |
|------|--------|------|
| llama-cpp | FOUND (2 CVEs) | LIMA-NEW-003 (GBNF grammar), LIMA-NEW-004 (JSON schema) |
| vLLM | FOUND (3 CVEs) | CVE-2025-48944, CVE-2025-48943, CVE-2025-48942 (xgrammar crashes) |
| Ollama | TESTED — NOT_VULNERABLE | Go's encoding/json rejects deeply nested JSON |
| LocalAI | not tested | Needs loaded model to exercise grammar/schema path |

### Resource Exhaustion / No Limits (CWE-400, CWE-770, CWE-369)

**Root cause:** API parameters or model metadata values used without upper bounds.

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (3 CVEs) | CVE-2025-0317 (alignment=0), CVE-2025-0315 (huge dims), CVE-2024-8063 (block_count=0) |
| vLLM | FOUND (8 CVEs) | CVE-2025-48956, CVE-2024-8939, CVE-2024-8768, CVE-2025-46560, CVE-2025-32381, CVE-2025-29770, CVE-2025-48942, CVE-2025-48943 |
| Ollama | FOUND (1 CVE) | CVE-2024-39721 (/dev/random DoS) |
| LocalAI | TESTED — NOT_VULNERABLE | API params and GGUF alignment/dims handled safely |
| llama-cpp | TESTED — NOT_VULNERABLE | n_predict clamped, alignment validated |

**Cross-framework insight:** Both llama-cpp and vLLM crash on structured output specifications
(grammar/JSON schema), showing that the "grammar as attack surface" pattern transfers across
C++ and Python backends.

---

## Insufficient Access Control (10 CVEs)

**Core problem:** API endpoints accessible without authentication or CSRF protection;
file paths not validated.

### Path Traversal / Arbitrary File Ops (CWE-22, CWE-552)

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (3 CVEs) | CVE-2025-44779, CVE-2024-45436, CVE-2024-39722 |
| LocalAI | FOUND (1 CVE) | CVE-2024-6095 (SSRF + LFI) |
| llama-cpp | TESTED — NOT_VULNERABLE | Path traversal blocked |
| vLLM | not tested | No file-serving endpoints |

### SSRF (CWE-918)

| Repo | Status | CVEs |
|------|--------|------|
| LocalAI | FOUND (1 CVE) | CVE-2024-6095 (/models/apply http:// and file://) |
| Ollama | PARTIAL | CVE-2025-51471 (auth token redirect, related) |

### No Auth / CSRF (CWE-352, CWE-346)

| Repo | Status | CVEs |
|------|--------|------|
| Ollama | FOUND (1 CVE) | CVE-2024-28224 (DNS rebinding) |
| LocalAI | FOUND (2 CVEs) | CVE-2024-48057, CVE-2024-3135 |
| vLLM | FOUND (1 CVE) | CVE-2025-30202 (ZMQ binds all interfaces) |
| llama-cpp | TESTED — VULNERABLE (by design) | No auth in default config |

---

## Information Leakage (3 CVEs)

**Core problem:** Predictable cache behavior or timing differences leak information.

| Repo | Status | CVEs |
|------|--------|------|
| vLLM | FOUND (3 CVEs) | CVE-2025-46570 (timing side-channel), CVE-2025-25183 (hash collision), CVE-2025-46722 (image hash collision) |
| Others | N/A | No shared prefix caching |

---

## Cross-Framework Test Results (2026-02-25)

### Results Matrix

| Pattern | Test | LocalAI v3.12.1 | llama-cpp b8149 | Ollama v0.17.0 | vLLM 0.8.3 |
|---------|------|-----------------|-----------------|----------------|------------|
| Integer Overflow | negative_key_length | PANIC_RECOVERED | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| Integer Overflow | negative_array_count | NOT_VULNERABLE | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| Integer Overflow | negative_value_length | PANIC_RECOVERED | N/A (hardened) | CRASHED (LIMA-NEW-001/002) | N/A |
| **Heap Overflow** | **large_n_kv** | **CRASHED (OOM)** | N/A (hardened) | CRASHED (CVE-2024-23605) | N/A |
| Heap Overflow | large_n_tensors | NOT_VULNERABLE | N/A (hardened) | CRASHED (CVE-2024-21836) | N/A |
| Heap Overflow | small_vocab | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| Heap Overflow | large_key_length | PANIC_RECOVERED | N/A (hardened) | N/A | N/A |
| Null Pointer | truncated_magic | NOT_VULNERABLE | N/A (hardened) | FOUND (1 CVE) | N/A |
| Null Pointer | null_tensor_name | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| Null Pointer | truncated_after_header | NOT_VULNERABLE | N/A (hardened) | N/A | N/A |
| ReDoS | grammar_regex | N/A (Go NFA) | NOT_VULNERABLE | N/A (Go NFA) | FOUND (2 CVEs) |
| Recursion | nested_grammar | not tested | CRASHED (LIMA-NEW-003) | NOT_VULNERABLE | CRASHED (3 CVEs) |
| Recursion | nested_json_schema | not tested | CRASHED (LIMA-NEW-004) | NOT_VULNERABLE | CRASHED (3 CVEs) |
| **Resource Exhaustion** | **zero_alignment** | NOT_VULNERABLE | not tested | **CRASHED (CVE-2025-0317)** | N/A |
| Resource Exhaustion | huge_dims | NOT_VULNERABLE | not tested | NOT_VULNERABLE | N/A |
| Resource Exhaustion | zero_block_count | NOT_VULNERABLE | not tested | NOT_VULNERABLE | N/A |
| Resource Exhaustion | extreme_api_params | NOT_VULNERABLE | NOT_VULNERABLE | not tested | FOUND (1 CVE) |
| Path Traversal | url_traversal | NOT_VULNERABLE | NOT_VULNERABLE | FOUND (3 CVEs) | not tested |
| No Auth | no_auth | FOUND (2 CVEs) | VULNERABLE (by design) | FOUND (1 CVE) | FOUND (1 CVE) |
| SSTI | template_injection | FOUND (LIMA-NEW-006) | N/A | NOT_VULNERABLE | not tested |

### Key New Findings (from cross-framework testing)

1. **Heap Overflow → LocalAI v3.12.1: CRASHED (LIMA-NEW-007)**
   - Payload: `p2a_large_n_kv.gguf` (n_kv = 0xFFFFFFFF = 4 billion)
   - Root cause: `gpustack/gguf-parser-go v0.23.1` attempts to allocate memory for 4B KV pairs
   - Crash: OOMKilled=true, exit code 137 (SIGKILL from Linux OOM killer)
   - The `recover()` in `core/config/guesser.go:27` CANNOT catch kernel SIGKILL
   - CWE: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits)

2. **Resource Exhaustion → Ollama v0.17.0: CRASHED (CVE-2025-0317 still unfixed)**
   - Payload: `p11a_zero_alignment.gguf` (general.alignment = 0)
   - Crash: `panic: runtime error: integer divide by zero` at `fs/ggml/gguf.go:673`
   - Stack trace: `ggufPadding` → `gguf.Decode` → `containerGGUF.Decode` → `ggml.Decode` → `ggufLayers` → `convertModelFromFiles`

3. **Integer Overflow → LocalAI: PANIC_RECOVERED (partial vulnerability)**
   - Payloads p1a and p1c trigger Go panics in `gpustack/gguf-parser-go`
   - Panics caught by `recover()` in `guesser.go:27` — server survives
   - Not a full DoS but indicates parser doesn't validate uint64 values

### Defense Analysis

- **llama-cpp b8149**: Well-hardened against Unsafe Parsing (all GGUF attacks = N/A). Resource Exhaustion API params handled safely. Path Traversal blocked. However, Recursion is still exploitable (LIMA-NEW-003/004).
- **LocalAI v3.12.1**: Unsafe Parsing partially vulnerable (LIMA-NEW-007 OOM). Code Execution has 3 RCE vectors. Resource Exhaustion and Access Control handled well via API validation.
- **Ollama v0.17.0**: Unsafe Parsing most vulnerable (5 GGUF parsing CVEs + 2 LIMA-NEW). Resource Exhaustion still has unfixed CVE-2025-0317. Path Traversal mostly patched.
- **vLLM 0.8.3**: Not affected by Unsafe Parsing (no GGUF). Code Execution most vulnerable (7 pickle RCE). Resource Exhaustion has 13 DoS CVEs across ReDoS, xgrammar, cache, and API params.

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
3. For each framework, runs all applicable root cause tests:
   - **Unsafe Parsing tests**: Integer Overflow GGUFs, Heap Overflow GGUFs, Null Pointer / Truncated GGUFs
   - **Resource Exhaustion tests**: Resource Exhaustion GGUFs + API params, ReDoS (regex/grammar)
   - **Access Control tests**: Path Traversal, No Auth check
4. Checks container state including OOMKilled, exit code, restart count
5. Collects logs and crash evidence (stack traces, panic messages)
6. Produces a summary matrix showing CRASHED / PANIC_RECOVERED / VULNERABLE / NOT_VULNERABLE

---

## Remaining Gaps

| Root Cause | Test | Framework | Status | Notes |
|------------|------|-----------|--------|-------|
| Resource Exhaustion | Recursion → LocalAI | LocalAI | not tested | Needs a real loaded model to exercise grammar converter |
| Code Execution | SSTI → vLLM | vLLM | not tested | Check if Jinja2 chat templates are sandboxed (needs GPU) |
| Unsafe Parsing | Heap Overflow GGUF → llama-cpp | llama-cpp | not tested | Feed alignment=0 / huge dims GGUFs to llama-server directly |
| Resource Exhaustion | API params → Ollama | Ollama | not tested | Test extreme API params (n_predict, temperature) |
